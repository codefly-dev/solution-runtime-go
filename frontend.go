package solution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// FrontendFileName is the one file a solution declares its frontend in, beside
// the backend service's service.codefly.yaml. The backend embeds it
// (Manifest.Frontend) and serves its manifest route from it; the CLI reads the
// same file into the presence document's frontend block. There is no other
// source: the manifest this runtime used to report to the host with its mint
// is gone, because a presence document is delivered and a process cannot
// declare what the composition did not.
//
// The file is YAML, decoded strictly — an unknown key is refused by name — and
// its top-level mapping is the block itself, no wrapper, so the CLI can decode
// it straight into core's type. Its keys are core's field names, field for
// field, and every scalar is declared: core refuses an omitted one rather than
// reading it as zero, and a file this runtime accepted that the CLI refuses
// would be the two readers disagreeing.
//
//	title: Widgets           # nav title; one non-empty line
//	order: 10                # nav order; declared, zero included
//	exposed_module: ./Page   # Module Federation exposed module; one non-empty line
//	host_contract: 1         # host page-contract major; at least 1
//	dashboard: {...}         # optional; a mapping, served as JSON, bounded at 64 KiB
//	surfaces:                # optional; what the solution offers inside a client
//	  - id: footnote         # lowercase letters and digits, dashes between
//	    client: word         # word, powerpoint, excel or slack
//	    title: Footnote
//	    description: ...     # optional
//	    module: /surfaces/word/footnote.js
//	    contract: 1          # surface contract major; at least 1
//	    applies: always      # declared: "always", or {tagged: [one or more tags]}
//	    events: [documents.entry]   # optional; journal namespaces, lowercase dotted names, each once
const FrontendFileName = "solution.frontend.codefly.yaml"

// frontendDashboardMaxBytes bounds the dashboard once encoded as JSON. The
// host carries the declaration inside a signed presence document and bounds it
// there too; the bound that fires is the one that can name the file.
const frontendDashboardMaxBytes = 64 << 10

// frontendDeclaration is the declared file as this runtime holds it. The
// struct mirrors core's frontend block rather than importing it: the runtime
// serves the fields, it does not sign or parse a presence document.
type frontendDeclaration struct {
	Title         string
	Order         int64
	ExposedModule string
	HostContract  uint64
	Dashboard     any
	Surfaces      []frontendSurface
}

// frontendFile is the file's shape on the way in. The scalars are pointers so
// an omitted one is told apart from a zero: core refuses an omitted scalar,
// and this runtime reads the same file.
type frontendFile struct {
	Title         *string           `yaml:"title"`
	Order         *int64            `yaml:"order"`
	ExposedModule *string           `yaml:"exposed_module"`
	HostContract  *int64            `yaml:"host_contract"`
	Dashboard     any               `yaml:"dashboard"`
	Surfaces      []frontendSurface `yaml:"surfaces"`
}

// frontendSurface is one offering a solution makes inside a client application
// — a Word add-in, a Slack app — rather than as a page the host renders. The
// host's registry projects them so a client can discover, without a table of
// its own, which solutions offer it something.
type frontendSurface struct {
	ID     string `yaml:"id"`     // unique per client, e.g. "footnote"
	Client string `yaml:"client"` // client kind: word, powerpoint, excel, slack
	Title  string `yaml:"title"`  // what the client labels the surface with
	// Description is the longer explanation a client may show beside the
	// title. Optional, and omitted from the manifest when empty so a client
	// renders no description rather than an empty one.
	Description string `yaml:"description"`
	// Module is the path, on this solution's own origin, of a self-contained
	// ES module the client loads, resolved against the origin the client loaded
	// this solution from. The check on it catches an author reaching off that
	// origin by mistake; it is not what keeps a hostile solution from doing so
	// deliberately, since a solution serves its own manifest and need not use
	// this runtime at all. The host's registry and the client's loader own
	// that boundary and have to enforce it themselves.
	Module string `yaml:"module"`
	// Contract is the surface contract major this module is built against, as
	// the host client's own surface documentation defines it, so a client
	// refuses a surface it cannot run rather than loading it and failing
	// inside.
	Contract int64 `yaml:"contract"`
	// Applies is "always" or a {tagged: [...]} selector, declared rather than
	// defaulted: core carries no default, so a file that left it out would be
	// accepted here and refused by the CLI. Events are the journal namespaces
	// the surface reconciles on. What a tag selects and what a namespace names
	// are the client's to interpret, not this runtime's; what is held to here
	// is the shape core signs.
	Applies any      `yaml:"applies"`
	Events  []string `yaml:"events"`
}

// surfaceAppliesAlways is the one selector keyword; the other shape is a
// {tagged: [...]} mapping.
const surfaceAppliesAlways = "always"

// eventNamespace is a journal namespace as core signs it: lowercase dotted
// names, each segment letters and digits separated by a dot, dash or
// underscore.
var eventNamespace = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// surfaceClients are the client kinds a surface may declare. A client loads
// only what names it, so an unknown kind is a surface nothing will ever load —
// caught at boot rather than showing up as a solution that simply never
// appears in the add-in.
var surfaceClients = map[string]bool{"word": true, "powerpoint": true, "excel": true, "slack": true}

// parseFrontend decodes and checks the declared file. Every refusal names the
// file, because the author wrote it by hand and a boot is where a mistake in
// it should surface — not as a solution the host lists under no title.
func parseFrontend(raw []byte) (frontendDeclaration, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return frontendDeclaration{}, fmt.Errorf("this solution declares no frontend: embed %s (go:embed) into Manifest.Frontend — it is the one source of the title, order, exposed module, host contract, dashboard and surfaces the host lists this solution under, and the CLI delivers the same file in the presence document", FrontendFileName)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var file frontendFile
	if err := decoder.Decode(&file); err != nil {
		return frontendDeclaration{}, fmt.Errorf("%s cannot be decoded: %w", FrontendFileName, err)
	}
	// One document. A second one would be silently dropped otherwise, and a
	// file that looks like two declarations is not one somebody meant.
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return frontendDeclaration{}, fmt.Errorf("%s carries more than one YAML document; it declares one frontend", FrontendFileName)
	}
	// Every scalar declared. Core reads an omitted one as a refusal rather
	// than as zero, so the file this runtime accepts is the file the CLI
	// delivers, or the boot says which key is missing.
	for _, scalar := range []struct {
		key      string
		declared bool
	}{
		{"title", file.Title != nil}, {"order", file.Order != nil},
		{"exposed_module", file.ExposedModule != nil}, {"host_contract", file.HostContract != nil},
	} {
		if !scalar.declared {
			return frontendDeclaration{}, fmt.Errorf("%s declares no %s: every scalar of the frontend block is declared, and the presence document the CLI reads from this file refuses an omitted one", FrontendFileName, scalar.key)
		}
	}
	declared := frontendDeclaration{
		Title: strings.TrimSpace(*file.Title), Order: *file.Order,
		ExposedModule: strings.TrimSpace(*file.ExposedModule), Surfaces: file.Surfaces,
	}
	if declared.Title == "" || strings.ContainsAny(declared.Title, "\r\n") {
		return frontendDeclaration{}, fmt.Errorf("%s: title must be one non-empty line: the host lists this solution in its navigation under it", FrontendFileName)
	}
	if declared.ExposedModule == "" || strings.ContainsAny(declared.ExposedModule, "\r\n") {
		return frontendDeclaration{}, fmt.Errorf("%s: exposed_module must be one non-empty line, the Module Federation module the host loads this solution's page from, e.g. ./Page", FrontendFileName)
	}
	// The host runs a page only when it recognises the contract major it
	// declares, so a zero is not a lenient default: it is a solution every
	// host refuses, in a boot that otherwise looks entirely healthy.
	if *file.HostContract < 1 {
		return frontendDeclaration{}, fmt.Errorf("%s: host_contract %d is not a host contract major; declare the major this solution's page is built against (>= 1)", FrontendFileName, *file.HostContract)
	}
	declared.HostContract = uint64(*file.HostContract)
	if file.Dashboard != nil {
		// Opaque, but it has to BE the JSON object the host reads: it is
		// served as the manifest's dashboard slot and carried as JSON in the
		// presence document, where core refuses what JSON spells more than
		// one way. So it is a mapping, every mapping key is a string and no
		// value is a fraction — held to here rather than left to the encoder,
		// which stringifies an integer key and would serve a dashboard the
		// file did not say.
		dashboard, err := jsonValue(file.Dashboard)
		if err != nil {
			return frontendDeclaration{}, fmt.Errorf("%s: dashboard is not a JSON value the host can read (%v)", FrontendFileName, err)
		}
		if _, ok := dashboard.(map[string]any); !ok {
			return frontendDeclaration{}, fmt.Errorf("%s: dashboard must be a mapping, the JSON object the host's data-graph validator reads", FrontendFileName)
		}
		encoded, err := json.Marshal(dashboard)
		if err != nil {
			return frontendDeclaration{}, fmt.Errorf("%s: dashboard is not a JSON value (%v)", FrontendFileName, err)
		}
		if len(encoded) > frontendDashboardMaxBytes {
			return frontendDeclaration{}, fmt.Errorf("%s: dashboard is %d bytes as JSON and at most %d are carried", FrontendFileName, len(encoded), frontendDashboardMaxBytes)
		}
		declared.Dashboard = dashboard
	}
	for i := range declared.Surfaces {
		if declared.Surfaces[i].Applies == nil {
			continue
		}
		applies, err := jsonValue(declared.Surfaces[i].Applies)
		if err != nil {
			return frontendDeclaration{}, fmt.Errorf("%s: surface %q: applies is not a JSON value (%v)", FrontendFileName, declared.Surfaces[i].ID, err)
		}
		declared.Surfaces[i].Applies = applies
	}
	if err := validateSurfaces(declared.Surfaces); err != nil {
		return frontendDeclaration{}, fmt.Errorf("%s: %w", FrontendFileName, err)
	}
	return declared, nil
}

// jsonValue is a decoded YAML value as JSON holds it: every mapping keyed by
// strings, recursively. yaml.v3 decodes a mapping with a non-string key into a
// map keyed by interface values, and Go's JSON encoder then stringifies an
// integer key and refuses a boolean one — so a YAML `1:` would be served as
// "1" and a `true:` would fail at the encoder. Both are refused by name.
func jsonValue(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			converted, err := jsonValue(inner)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("mapping key %v is not a string", key)
			}
			converted, err := jsonValue(inner)
			if err != nil {
				return nil, err
			}
			out[name] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			converted, err := jsonValue(inner)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case float64, float32:
		return nil, fmt.Errorf("value %v is a fraction, which JSON spells more than one way", v)
	}
	return value, nil
}

// validateSurfaces refuses a surface declaration no client could use.
func validateSurfaces(surfaces []frontendSurface) error {
	// Keyed by client and id together: two clients never see each other's
	// surfaces, so the same offering carries the same id in Word and in
	// PowerPoint, and only a collision within one client is ambiguous. The id
	// and client checks below run first, so neither half of the key can contain
	// the separator and no two distinct pairs can collide into one string.
	seen := make(map[string]bool, len(surfaces))
	for i, surface := range surfaces {
		switch {
		case surface.ID == "":
			return fmt.Errorf("surface %d has no id", i)
		case !isSurfaceID(surface.ID):
			return fmt.Errorf("surface %q: id must be lowercase letters and digits, separated by dashes", surface.ID)
		case surface.Title == "":
			return fmt.Errorf("surface %q has no title: a client labels the surface with it, and renders a blank control without one", surface.ID)
		case !surfaceClients[surface.Client]:
			return fmt.Errorf("surface %q: unknown client kind %q", surface.ID, surface.Client)
		case seen[surface.Client+"/"+surface.ID]:
			return fmt.Errorf("surface %q declared twice for client %q: a client addresses a surface by id, so two of its own cannot share one",
				surface.ID, surface.Client)
		case surface.Contract < 1:
			// A client runs a surface only when it recognises the contract
			// major it declares, so the zero an author leaves behind is not a
			// lenient default: it is a surface every client refuses, in a boot
			// that otherwise looks entirely healthy.
			return fmt.Errorf("surface %q: contract %d is not a surface contract major; declare the major this module is built against (>= 1)",
				surface.ID, surface.Contract)
		case !isSameOriginPath(surface.Module):
			return fmt.Errorf("surface %q: module %q must be a path on this solution's own origin, e.g. %q",
				surface.ID, surface.Module, "/surfaces/"+surface.Client+"/"+surface.ID+".js")
		}
		if err := validateApplies(surface.Applies); err != nil {
			return fmt.Errorf("surface %q: %w", surface.ID, err)
		}
		if err := validateEvents(surface.Events); err != nil {
			return fmt.Errorf("surface %q: %w", surface.ID, err)
		}
		seen[surface.Client+"/"+surface.ID] = true
	}
	return nil
}

// validateApplies holds a surface's selector to the two shapes the host client
// reads: the keyword "always", or {tagged: [one or more non-empty tags]}.
// Declared, never defaulted: core refuses a surface declaring none.
func validateApplies(applies any) error {
	switch selector := applies.(type) {
	case nil:
		return fmt.Errorf("declares no applies: write `applies: always`, or `applies: {tagged: [...]}` naming one or more tags")
	case string:
		if selector != surfaceAppliesAlways {
			return fmt.Errorf("applies %q is neither %q nor a {tagged: [...]} selector", selector, surfaceAppliesAlways)
		}
		return nil
	case map[string]any:
		tagged, ok := selector["tagged"]
		if !ok || len(selector) != 1 {
			return fmt.Errorf("applies must be %q or a mapping with the one key tagged", surfaceAppliesAlways)
		}
		tags, ok := tagged.([]any)
		if !ok || len(tags) == 0 {
			return fmt.Errorf("applies.tagged must name one or more tags")
		}
		for _, tag := range tags {
			if name, ok := tag.(string); !ok || strings.TrimSpace(name) == "" {
				return fmt.Errorf("applies.tagged names an empty tag, which selects nothing")
			}
		}
		return nil
	}
	return fmt.Errorf("applies must be %q or a {tagged: [...]} selector", surfaceAppliesAlways)
}

// validateEvents holds a surface's journal namespaces to the grammar core
// signs: lowercase dotted names, each named once.
func validateEvents(events []string) error {
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		if !eventNamespace.MatchString(event) {
			return fmt.Errorf("event %q is not a journal namespace: lowercase letters and digits, in segments separated by a dot, dash or underscore", event)
		}
		if seen[event] {
			return fmt.Errorf("event %q is named twice", event)
		}
		seen[event] = true
	}
	return nil
}

// isSurfaceID accepts lowercase letters and digits separated by dashes. A
// leading or trailing dash is refused so that an id is never a prefix game, and
// so the empty string cannot pass by having no characters to object to.
func isSurfaceID(id string) bool {
	if id == "" {
		return false
	}
	for i, r := range id {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		if r != '-' || i == 0 || i == len(id)-1 {
			return false
		}
	}
	return true
}

// isSameOriginPath reports whether p addresses this solution's own origin: a
// rooted path and nothing else.
//
// Whether a path is rooted is decided by the parser that will resolve it — the
// client's, not Go's — and the two disagree on three inputs. A browser follows
// WHATWG URL, where a backslash beside the leading slash is read as a slash and
// what follows it as an authority, so "/\host/x.js" resolves to https://host/x.js
// while net/url reads that backslash as an ordinary path byte and reports no
// host at all; and where ASCII tab and newline are removed from the input before
// it is parsed, so "/<tab>/host/x.js" becomes protocol-relative on arrival. None
// of the three can be seen in net/url's answer, so they are refused here by
// inspecting the bytes rather than by asking net/url what it made of them.
func isSameOriginPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	for _, r := range p {
		if r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// manifestMap is the manifest this runtime serves at /.well-known/solution.json:
// the declared frontend, and the constants of this runtime's own layout — the
// federation manifest path, the backend's service alias and the capability
// path. The host builds its registry entry from the delivered presence and the
// same constants; this route is what the solution says about itself to
// whoever asks it directly.
func (s *Server) manifestMap() map[string]any {
	m := map[string]any{
		"id":            s.manifest.ID,
		"schemaVersion": solutionManifestSchemaMajor,
		"nav":           map[string]any{"title": s.frontend.Title, "path": "/s/" + s.manifest.ID, "order": s.frontend.Order},
		"frontend": map[string]any{
			"type":          "module-federation",
			"manifestUrl":   s.frontendManifestURL(),
			"exposedModule": s.frontend.ExposedModule,
			"hostContract":  s.frontend.HostContract,
			"reactRange":    "^19",
		},
		"backend": map[string]any{"serviceAlias": s.manifest.ID, "capabilityPath": "/.well-known/capabilities"},
	}
	// Only emit the slot when declared: a null dashboard would break a host that
	// feeds a present slot straight into its data-graph validator, and it keeps
	// the wire byte-identical for solutions that declare no dashboard.
	if s.frontend.Dashboard != nil {
		m["dashboard"] = s.frontend.Dashboard
	}
	if len(s.frontend.Surfaces) > 0 {
		surfaces := make([]any, 0, len(s.frontend.Surfaces))
		for _, surface := range s.frontend.Surfaces {
			entry := map[string]any{
				"id":       surface.ID,
				"client":   surface.Client,
				"title":    surface.Title,
				"module":   surface.Module,
				"contract": surface.Contract,
				"applies":  surface.Applies,
			}
			// Absent, these two say something a client can act on — no
			// description to show, nothing to reconcile on — where a null would
			// only be a slot the client still has to interpret.
			if surface.Description != "" {
				entry["description"] = surface.Description
			}
			if len(surface.Events) > 0 {
				entry["events"] = surface.Events
			}
			surfaces = append(surfaces, entry)
		}
		m["surfaces"] = surfaces
	}
	return m
}
