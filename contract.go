package solution

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/codefly-dev/core/resources"
)

// ContractSchema is the version of the contract document this runtime
// publishes. A reader branches on it rather than on the presence of a field, so
// a later shape is a new version and never a stricter reading of these bytes.
//
// It is deliberately *not* `codefly/module-contract/v1`. That string belongs to
// the document the renderer reads — `module.contract.codefly.yaml`, YAML,
// strict-decoded, at the module directory the composition resolved, carrying
// slots rather than literals (codefly-dev/cli#855). This runtime's document is
// JSON, has a different shape, and answers a different question: what a process
// holds *itself* to, resolved for the one profile it runs under.
//
// Sharing the string was worse than a mismatch. Strict decoding refuses the
// unknown fields, and because the schema matched, the renderer would report this
// as a *malformed* `module-contract` rather than as a document meant for
// somebody else — a version skew that is not one, pointing at the wrong owner.
// Two shapes under one schema string is the one thing a reader branching on that
// string cannot survive.
const ContractSchema = "codefly/solution-runtime-contract/v1"

// RendererContractSchema and RendererContractFile name what the *renderer*
// reads, so the distinction above is greppable from here rather than folklore.
// Nothing in this package writes that file; a generator for it would be a
// separate deliverable in this repository, and the renderer stays a reader of
// one file.
const (
	RendererContractSchema = "codefly/module-contract/v1"
	RendererContractFile   = "module.contract.codefly.yaml"
)

// ContractPath is where a running solution publishes its effective contract.
//
// Published, not announced: nothing is pushed anywhere, and answering here
// makes this solution present to nobody. It is the same document the build-time
// artifact carries (ContractArtifact), narrowed to the one profile this process
// actually runs under, so an operator can read what a process holds itself to
// without inferring it from the composition's inputs.
const ContractPath = "/.well-known/module-contract"

// ModuleContract is the authority contract a solution declares: the ceiling
// this runtime holds its own declaration to at boot, and the ceiling an
// operator reads off a running process.
//
// It is the author's declaration of the most authority this solution may ever
// ask for. It is not the renderer's input — that is RendererContractFile, whose
// shape resolves audiences from the composition per environment rather than
// keying ceilings by profile (codefly-dev/cli#855).
//
// It is declared, never derived from what the code happens to ask for. A
// ceiling computed from the declaration would be satisfied by construction: a
// method that asked for one more action would widen the ceiling that was
// supposed to refuse it, and a reviewer approving the contract would be
// approving whatever the next commit asks for. So the author declares the
// ceiling, the runtime refuses a declaration that exceeds it, and the two
// disagreeing is a boot failure naming the scope.
//
// What *is* derived is the binding set: the audiences are the `as` of the
// solution's api.consumes entries, which Codefly projects and the passthrough
// declaration is already checked against. Restating them here would be a second
// source for one fact.
type ModuleContract struct {
	// Ceilings is the most authority this solution may ever ask a consumed
	// module for, keyed by configuration profile and then by the audience it is
	// asked of (the `as` of that module's api.consumes entry). Every audience
	// the solution mints authority for needs a ceiling in the profile this
	// process runs under, and every scope the declaration asks for must fall
	// inside it.
	//
	// The profile key is why this is a map of maps rather than one table. A
	// deployment and a developer machine do not grant the same authority, and a
	// deployed environment reads its own profile — "staging", say — never the
	// local one. That distinction is recent: a deployed environment used to
	// render under the local profile (codefly-dev/core#687, closed in core
	// v0.7.1), which is exactly the mistake this keying makes impossible. A
	// contract that declares only "local" is refused in a deployment rather
	// than read as if the deployment were somebody's laptop.
	Ceilings map[string]map[string][]Scope
}

// Contract declares the authority contract this solution publishes. Chainable.
//
// Not to be confused with Manifest.Contract, which is the capability contract
// id the host's handshake reads. This one is about authority: which audiences
// this solution holds bindings for, and how much it may ever ask of each.
func (s *Server) Contract(contract ModuleContract) *Server {
	s.declaredContract = contract
	return s
}

// effectiveContract is the contract of the one profile this process runs under:
// what it publishes, and what its declaration was held to at boot.
type effectiveContract struct {
	Schema    string            `json:"schema"`
	Solution  string            `json:"solution"`
	Profile   string            `json:"profile"`
	Principal string            `json:"principal"`
	Bindings  []contractBinding `json:"bindings"`
}

// contractBinding is one audience this solution holds authority for, and the
// ceiling it holds it within.
type contractBinding struct {
	Audience string  `json:"audience"`
	Ceiling  []Scope `json:"ceiling"`
	// Asked is what the declaration actually asks for inside that ceiling —
	// the authority a reviewer is approving rather than the authority the
	// ceiling would allow a later commit to ask for.
	Asked []Scope `json:"asked"`
}

// resolveContract is the contract this process publishes, refused rather than
// guessed. Every refusal names the value that is missing or the scope that
// exceeds its ceiling, because the fix for each is a different edit in a
// different file: a missing profile is a contract change, a scope outside its
// ceiling is either a declaration change or a ceiling the reviewer has to widen
// deliberately.
func (s *Server) resolveContract() (effectiveContract, error) {
	contract := effectiveContract{
		Schema:   ContractSchema,
		Solution: s.manifest.ID,
		Profile:  s.cfg.profile,
		// The principal is not declared here: it is one of the
		// authority-bearing values the platform provisioned and this process
		// froze at boot, so the contract reports who this workload actually is
		// rather than who its author believed it would be. A contract that
		// restated it would be a second source for one fact, and the one that
		// disagreed would be this one.
		Principal: s.principal,
	}
	bindings, err := checkContract(s.consumed, s.declaredContract, s.cfg.profile)
	if err != nil {
		return contract, err
	}
	contract.Bindings = bindings
	return contract, nil
}

// checkContract is the whole of the contract's substantive rules, for one
// profile, and it returns the bindings that profile publishes.
//
// One function, called by the boot *and* by the artifact a renderer reads. They
// used to be separate, and the artifact checked only profile names and scope
// syntax: a declaration consuming `things` could publish an artifact whose only
// ceiling was `ghost`, and the artifact is the document authority is derived
// from. A rule enforced on the running process and not on the published
// document is a rule that governs the half nobody reads.
func checkContract(modules []ConsumedModule, contract ModuleContract, profile string) ([]contractBinding, error) {
	ceilings, declared := contract.Ceilings[profile]
	if !declared && mintsAuthority(modules) {
		return nil, fmt.Errorf("the published contract declares no %q profile (it declares: %s): a deployed environment reads its own profile and never the local one, so declare this one — or set %s if this process runs under another",
			profile, declaredProfiles(contract), ContractProfileEnvironmentVariable)
	}
	var bindings []contractBinding
	for _, module := range modules {
		ceiling, declared := ceilings[module.As]
		if module.ViewerBearer {
			// A ViewerBearer module is called with the viewer's bearer and no
			// minted capability, so there is no authority to cap — and a
			// ceiling declared for one would describe authority nothing asks
			// for. Refused rather than ignored: a reviewer who wrote it down
			// believes it governs something.
			if declared {
				return nil, fmt.Errorf("the published contract declares a scope ceiling for %q in the %q profile, but that module is declared ViewerBearer: it mints no authority, so the ceiling governs nothing",
					module.As, profile)
			}
			bindings = append(bindings, contractBinding{Audience: module.As})
			continue
		}
		if !declared {
			return nil, fmt.Errorf("the published contract declares no scope ceiling for %q in the %q profile: every consumed module this solution mints authority for needs one, and this runtime refuses an ask it cannot check against a declared ceiling",
				module.As, profile)
		}
		if err := checkScopes(ceiling); err != nil {
			return nil, fmt.Errorf("the scope ceiling for %q in the %q profile is unusable: %w", module.As, profile, err)
		}
		asked := askedScopes(module)
		for _, scope := range asked {
			if err := withinCeiling(scope, ceiling); err != nil {
				return nil, fmt.Errorf("this solution asks %q for authority outside the ceiling its contract publishes for the %q profile: %w",
					module.As, profile, err)
			}
		}
		bindings = append(bindings, contractBinding{Audience: module.As, Ceiling: ceiling, Asked: asked})
	}
	// A ceiling for an audience this solution does not consume is authority
	// nobody can ask for, and the renderer would grant it: the solution's
	// api.consumes is the binding set, so a name that is not in it is either a
	// typo or a grant that outlives the consumption it was written for.
	for audience := range ceilings {
		if !slices.ContainsFunc(modules, func(m ConsumedModule) bool { return m.As == audience }) {
			return nil, fmt.Errorf("the published contract declares a scope ceiling for %q in the %q profile, which this solution does not consume: it is a ceiling governing a call that cannot happen, and whoever wrote it believes otherwise",
				audience, profile)
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Audience < bindings[j].Audience })
	return bindings, nil
}

// declaredProfiles lists the profiles a contract does declare, so a refusal
// naming the missing one also says which ones exist — the difference between
// "add staging" and "the profile name is not what you think it is".
func declaredProfiles(contract ModuleContract) string {
	if len(contract.Ceilings) == 0 {
		return "none"
	}
	names := make([]string, 0, len(contract.Ceilings))
	for name := range contract.Ceilings {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// mintsAuthority reports whether any consumed module has authority to cap. A
// solution whose every module is ViewerBearer mints nothing, and a solution
// that consumes none mints nothing either: requiring a profile from them would
// be requiring a declaration about authority that does not exist.
func mintsAuthority(modules []ConsumedModule) bool {
	return slices.ContainsFunc(modules, func(m ConsumedModule) bool { return !m.ViewerBearer })
}

// askedScopes is every scope this solution's declaration asks of one module:
// the module's own, plus each method's override. The union is what the ceiling
// is checked against, because a per-method scope replaces the module's rather
// than narrowing it, so the widest ask is not the module-level one.
func askedScopes(module ConsumedModule) []Scope {
	asked := append([]Scope{}, module.Scopes...)
	for _, method := range module.Methods {
		asked = append(asked, method.Scopes...)
	}
	return asked
}

// withinCeiling reports whether one asked scope falls inside a ceiling: some
// one entry of the ceiling must cover its resource kind, every action it asks
// for, and — when that entry names resource ids — every id it names.
//
// Every entry of that kind is examined before anything is refused. It used to
// return the first matching kind's verdict, which made the answer depend on the
// order the ceiling was written in: with `things/read/{a}` and
// `things/read/{b}` declared in that order, an ask for `b` was refused against
// the first entry and the second was never read. A ceiling is a set, and a
// reviewer who writes one does not also choose a traversal order.
//
// Coverage has to come from a single entry rather than from the union of
// several. Two entries that each cover half an ask describe two grants, and
// treating their union as one would let a ceiling of "read on a" plus "list on
// b" authorize "read and list on a and b" — authority nobody declared.
//
// An entry with no resource ids covers the whole resource kind, which is how
// Scope itself reads an empty ResourceIDs. An ask with no ids against entries
// that all name some is therefore refused: "every document" is not inside
// "these two documents", and silently reading it as the narrower ask would mint
// authority the declaration did not write.
func withinCeiling(asked Scope, ceiling []Scope) error {
	var reasons []string
	kindNamed := false
	for _, allowed := range ceiling {
		if allowed.ResourceKind != asked.ResourceKind {
			continue
		}
		kindNamed = true
		if reason := coveredBy(asked, allowed); reason != "" {
			reasons = append(reasons, reason)
			continue
		}
		return nil
	}
	if !kindNamed {
		return fmt.Errorf("the ceiling names no resource kind %q at all", asked.ResourceKind)
	}
	// Every entry of that kind was read and none covers the ask. The reasons
	// are reported together, because "which of the three entries did you mean"
	// is the first question a reader has.
	return fmt.Errorf("no single ceiling entry for %q covers it: %s", asked.ResourceKind, strings.Join(reasons, "; "))
}

// coveredBy is why one ceiling entry does not cover an ask, or "" when it does.
func coveredBy(asked, allowed Scope) string {
	for _, action := range asked.Actions {
		if !slices.Contains(allowed.Actions, action) {
			return fmt.Sprintf("the entry allowing [%s] does not allow %q", strings.Join(allowed.Actions, ", "), action)
		}
	}
	if len(allowed.ResourceIDs) == 0 {
		return ""
	}
	if len(asked.ResourceIDs) == 0 {
		return fmt.Sprintf("the entry names only the resources [%s], and the ask covers the whole resource kind", strings.Join(allowed.ResourceIDs, ", "))
	}
	for _, id := range asked.ResourceIDs {
		if !slices.Contains(allowed.ResourceIDs, id) {
			return fmt.Sprintf("the entry naming [%s] does not name %q", strings.Join(allowed.ResourceIDs, ", "), id)
		}
	}
	return ""
}

func (s *Server) handleContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.contract)
}

// ContractArtifact renders this runtime's contract document at build time: the
// binding set derived from this solution's api.consumes declaration, and the
// scope ceiling it may ever ask of each, per profile — the bytes to write beside
// the interface artifact (InterfaceArtifact).
//
// It is *not* the document the renderer derives authority from. The renderer
// reads RendererContractFile under RendererContractSchema, a YAML shape with
// `{from: <group>/<key>}` slots that a composition resolves per environment
// (codefly-dev/cli#855); these bytes are this runtime's own document, under this
// runtime's own schema string, and the renderer does not read them. What they
// are good for is review and diffing a build: the ceiling an author declared,
// checked by exactly the rule the boot applies.
//
// It takes the declaration rather than a running server, because a render
// happens where no solution is running, and it resolves no profile for the same
// reason: which profile applies is the renderer's to decide, and a build-time
// document that had already chosen one would be a document that is true in one
// environment.
//
// It carries no principal. The principal is an authority-bearing value the
// platform provisions and the running process freezes at boot
// (AuthorityGroup/PRINCIPAL); a build-time document that named one would be
// asserting at render time what only the deployment knows.
func ContractArtifact(id string, contract ModuleContract, modules ...ConsumedModule) ([]byte, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("a contract artifact names no solution: pass the manifest id")
	}
	document := struct {
		Schema   string                        `json:"schema"`
		Solution string                        `json:"solution"`
		Bindings []artifactBinding             `json:"bindings"`
		Profiles map[string]map[string][]Scope `json:"profiles"`
	}{Schema: ContractSchema, Solution: id, Profiles: map[string]map[string][]Scope{}}

	for _, module := range modules {
		document.Bindings = append(document.Bindings, artifactBinding{Audience: module.As, ViewerBearer: module.ViewerBearer})
	}
	sort.Slice(document.Bindings, func(i, j int) bool { return document.Bindings[i].Audience < document.Bindings[j].Audience })

	for profile, ceilings := range contract.Ceilings {
		if err := resources.ValidateConfigurationProfileName(profile); err != nil {
			return nil, fmt.Errorf("the contract declares an unusable profile name: %w", err)
		}
		// Every rule the boot holds a running process to, held here too, per
		// profile — so a document that would refuse to boot cannot be
		// published at all.
		if _, err := checkContract(modules, contract, profile); err != nil {
			return nil, err
		}
		document.Profiles[profile] = ceilings
	}
	if mintsAuthority(modules) && len(document.Profiles) == 0 {
		// Says what it checks. It used to demand "a deployed one beside local"
		// while accepting a contract that declared only local, which is a
		// refusal promising a stricter rule than the one it applies — and the
		// reader who satisfies the message learns nothing, because they were
		// already passing.
		//
		// Which profiles will be deployed is not knowable here: a build-time
		// document is rendered once and read under whichever profile a
		// composition runs. A deployed environment missing its profile is
		// refused at boot, where the profile it ran under is a fact and the
		// refusal can name it, rather than guessed at here — and a
		// local-only contract is the correct contract for a solution that is
		// only ever run locally.
		return nil, fmt.Errorf("the contract declares no profile at all, and this solution mints authority for %d consumed module(s): declare the scope ceilings per profile — a deployed environment missing its own profile is then refused at boot, naming the profile it ran under",
			len(modules))
	}
	return json.MarshalIndent(document, "", "  ")
}

// artifactBinding is one audience the solution holds a binding for. A
// ViewerBearer module is reported as one, with the flag set: this solution mints
// no authority for it, and a binding simply missing from the document would read
// as a module the solution does not consume. (The renderer's own shape takes the
// opposite convention — a binding it derives no authority for is one you do not
// declare, so absence there means "asks for nothing" — which is one more reason
// these two documents do not share a schema string.)
type artifactBinding struct {
	Audience     string `json:"audience"`
	ViewerBearer bool   `json:"viewerBearer,omitempty"`
}

// localProfile is the profile a local run resolves to: the local environment's
// own name, which is what Core uses for an environment that declares no profile
// of its own.
const localProfile = "local"
