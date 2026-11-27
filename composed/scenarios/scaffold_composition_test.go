//go:build composition

// The scaffolded solution on a real composition: `codefly add solution`'s
// output (..), with the one consumed module filled in as the scaffold says to,
// built on THIS checkout of the runtime, started by Codefly behind the real
// local authority, its edge and its hop, in front of the real document store.
//
// Every call here is the page's: a fixture person signed in at the edge calls
// the backend's relayed route (/v1/codefly-base/modules/documents/...), the
// runtime asks the authority who the viewer is, is issued a child of their
// Work Context through the solution's binding, and relays the call to the hop,
// where the store authorizes it. Nothing stands in for any of them.
//
//	cd composed && make scenarios
//
// What this run does not show. A person taken out of a team: the local
// authority changes a team's members in process only, and no interface a
// scenario can call does it; what is revoked here is the team's grant. A Work
// Context replayed as issued and the authority stopped are in
// held_composition_test.go, the runtime's child replayed at the hop in
// tap_composition_test.go, and the authority's process ended in
// zz_gone_composition_test.go.
package scenarios

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	scenario "github.com/codefly-dev/authority/libraries/scenario/go"
	"github.com/google/uuid"
)

const (
	solution = "codefly-base"
	// relayed is where the runtime serves the solution's consumed module.
	relayed = "POST /v1/" + solution + "/modules/documents/documents.v1.DocumentsService/"
	// installations is the host's installation interface as the edge serves
	// it to a signed-in administrator.
	installations = "host.installation.v1.InstallationService/"
	noRole        = "holds no role on " + solution
	markdown      = "text/markdown"
	shared        = "COLLECTION_VISIBILITY_SHARED"
)

var (
	composed *scenario.Composition
	people   = scenario.Cast
	// stamp tells this run's documents from another's: a path binds once.
	stamp = time.Now().UnixNano()
)

func TestMain(m *testing.M) {
	// The tap the backend's module calls pass through (tap_composition_test.go).
	var err error
	if relayTap, err = startTap(); err != nil {
		fmt.Fprintln(os.Stderr, "scenario: the tap did not start:", err)
		os.Exit(1)
	}
	os.Exit(scenario.Main(m, &composed, scenario.Options{
		Administrator: people.Admin,
		Anchor:        "../anchor/services/scenarios",
		Scope:         "scaffold-scenarios",
		// Every document here is text: the office converters are left out.
		Without:               []string{"documents/docx", "documents/pdf", "documents/libreoffice", "documents/xlsx"},
		WithoutConfigurations: []string{"document-formats"},
		// The administrator installs the solution, with the consent the
		// authority reviews: sign-in, installation, issuance, as a host does.
		Install: []string{solution},
		// The fixture's people hold the solution's roles and nothing on the
		// store's own page: a read here is reached through the product's role.
		Seated: []string{solution},
		Set: []scenario.Value{
			// No page is served: the scenarios are the page's calls.
			{Name: "edge", Key: "FRONTEND", Value: ""},
			// The store's local stub embedder: no model is asked.
			{Name: "embeddings", Key: "provider", Value: "stub"},
			{Name: "embeddings", Key: "binding", Value: ""},
			// Where the backend is told the consumed module is: the tap, which
			// sends every call on to the hop the run resolved.
			{Name: solution, Key: "DOCUMENTS_ENDPOINT", Value: relayTap.address},
		},
	}))
}

// ---------------------------------------------------------------- Calls

func said(out scenario.Outcome) string {
	return fmt.Sprintf("%s (%d %s): %s %s", out.Verdict, out.Status, out.Code, out.Reason, out.Body)
}

// relay makes one of the page's module calls as id, through the backend.
func relay(t *testing.T, id, method string, request any) scenario.Outcome {
	t.Helper()
	return composed.As(t, id).Do(t, scenario.Call{Procedure: relayed + method, Request: request})
}

// administers makes one call of the host's installation interface as id, on
// their own session, through the edge.
func administers(t *testing.T, id, what, method string, request any) scenario.Outcome {
	t.Helper()
	out := composed.As(t, id).Do(t, scenario.Call{Procedure: installations + method, Request: request})
	if out.Verdict != scenario.Allowed {
		t.Fatalf("%s %s (%s): %s", id, what, method, said(out))
	}
	return out
}

func organization(t *testing.T, id string) string {
	t.Helper()
	return composed.As(t, id).Organization
}

func count(out scenario.Outcome, path string) int {
	list, _ := out.Value(path).([]any)
	return len(list)
}

// grant is one grant of a role on the solution's installation: to a person,
// or to a team.
type grant struct{ installation, role, person, team string }

// grants is who holds what on the solution's installation in id's
// organisation, as the host lists it to that administrator.
func grants(t *testing.T, id string) []grant {
	t.Helper()
	return grantsOn(t, id, solution)
}

// grantsOn is who holds what on target's installation in id's organisation.
func grantsOn(t *testing.T, id, target string) []grant {
	t.Helper()
	org := organization(t, id)
	listed := administers(t, id, "lists the installations", "List", map[string]any{"organization_id": org})
	installation := ""
	for i := range count(listed, "installations") {
		if at := fmt.Sprintf("installations.%d.", i); listed.Text(at+"target") == target {
			installation = listed.Text(at + "id")
		}
	}
	if installation == "" {
		t.Fatalf("%s lists no installation of %s: %s", id, target, listed.Body)
	}
	held := administers(t, id, "lists the roles granted", "ListRoleGrants", map[string]any{"organization_id": org, "installation_id": installation})
	var out []grant
	for i := range count(held, "grants") {
		at := fmt.Sprintf("grants.%d.", i)
		out = append(out, grant{installation, held.Text(at + "role"), held.Text(at + "personId"), held.Text(at + "teamId")})
	}
	return out
}

// change grants or revokes g as the administrator id.
func change(t *testing.T, id, method string, g grant) {
	t.Helper()
	administers(t, id, method+" "+g.role+" for "+g.person+g.team, method, map[string]any{
		"organization_id": organization(t, id), "installation_id": g.installation, "role": g.role, "person_id": g.person, "team_id": g.team})
}

// userTeam is the one grant of the user role on the solution in the
// administrator's organisation, which must be a team's and nobody's own.
func userTeam(t *testing.T) grant {
	t.Helper()
	var team []grant
	for _, g := range grants(t, people.Admin) {
		if g.role != "user" {
			continue
		}
		if g.person != "" {
			t.Fatalf("%s holds the user role in person: this scenario is about a role held through a team", g.person)
		}
		team = append(team, g)
	}
	if len(team) != 1 {
		t.Fatalf("want one team holding the user role on %s, got %v", solution, team)
	}
	return team[0]
}

// document is one document a person wrote through the backend.
type document struct{ tenant, entry, version string }

func (d document) read() map[string]any {
	return map[string]any{"tenant": d.tenant, "entry_id": d.entry, "version": d.version}
}

// write adds a document as id through the backend's relayed CreateDocument.
func write(t *testing.T, id, name string) document {
	t.Helper()
	created := relay(t, id, "CreateDocument", map[string]any{
		"producer": "scaffold-scenarios", "path": fmt.Sprintf("%s/%s-%d.md", id, name, stamp),
		"content_type": markdown, "content_b64": []byte("# " + name + "\n"), "collection_visibility": shared})
	if created.Verdict != scenario.Allowed {
		t.Fatalf("%s writes %s through the backend: %s", id, name, said(created))
	}
	d := document{organization(t, id), created.Text("entryId"), created.Text("version")}
	if d.entry == "" || d.version == "" {
		t.Fatalf("%s writes %s and the store names no version: %s", id, name, created.Body)
	}
	return d
}

// reads holds id's read of d through the backend to the store's own answer
// for that exact document.
func reads(t *testing.T, id string, d document) {
	t.Helper()
	got := relay(t, id, "GetDocument", d.read())
	if got.Verdict != scenario.Allowed {
		t.Fatalf("%s reads %s through the backend: %s", id, d.entry, said(got))
	}
	if have := got.Text("document.entry.entryId"); have != d.entry {
		t.Errorf("%s reads %s and is answered entry %q: %s", id, d.entry, have, got.Body)
	}
}

// refused holds id's read of d to a refusal for who they are, naming reason,
// that carries nothing of the document.
func refused(t *testing.T, id string, d document, reason string) {
	t.Helper()
	got := relay(t, id, "GetDocument", d.read())
	if got.Verdict != scenario.Denied || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s reads %s: want a refusal saying %q, got %s", id, d.entry, reason, said(got))
	}
	if strings.Contains(string(got.Body), d.version) {
		t.Errorf("%s is refused %s and the answer names its version: %s", id, d.entry, got.Body)
	}
}

// ---------------------------------------------------------------- Scenarios

// The scaffold's whole path, for a person seated through a team. Dana, the
// administrator who installed the solution, writes a document through the
// backend; Carol holds the user role through the role's team and in no other
// way, and reads that exact document: edge, backend, the authority's Check,
// a child through the solution's binding, the hop, the store. The role is
// what the child carries: Carol's write is refused, and Bob, in no team, is
// refused by name before any module is asked.
func TestComposedTeamSeatedViewerReadsThroughTheHop(t *testing.T) {
	userTeam(t)
	d := write(t, people.Admin, "team-seated")
	reads(t, people.Admin, d)
	reads(t, people.User, d)
	refused(t, people.None, d, noRole)

	out := relay(t, people.User, "CreateDocument", map[string]any{
		"producer": "scaffold-scenarios", "path": fmt.Sprintf("carol/refused-%d.md", stamp),
		"content_type": markdown, "content_b64": []byte("# no\n"), "collection_visibility": shared})
	if out.Verdict != scenario.Denied {
		t.Errorf("Carol holds the user role, which reads; her write through the backend: want a refusal, got %s", said(out))
	}
	// The solution's own route is decided on the same role.
	overview := scenario.Call{Procedure: "GET /v1/" + solution + "/overview"}
	if got := composed.As(t, people.User).Do(t, overview); got.Verdict != scenario.Allowed || !strings.Contains(string(got.Body), "documents") {
		t.Errorf("Carol reads the solution's overview: %s", said(got))
	}
	if got := composed.As(t, people.None).Do(t, overview); got.Verdict != scenario.Denied {
		t.Errorf("Bob reads the solution's overview: want a refusal, got %s", said(got))
	}
}

// The team's grant removed, the same operation on the same session is refused
// on the very next call, and nothing is issued again. Carol reads; Dana
// revokes the user role from the team; Carol's session, opened before the
// revocation, makes the same request and is refused by name, at the relayed
// route and at the solution's own. Dana still reads. Granted back to the
// team, Carol reads again. Nothing waits: the retry is the next call.
//
// A grant held twice is held until both are gone. Carol is granted the role
// in person beside the team's; the team's grant is revoked and she still
// reads, on the grant that is left; that one revoked too, she is refused.
func TestComposedRevokedTeamGrantRefusesTheNextCall(t *testing.T) {
	team := userTeam(t)
	d := write(t, people.Admin, "revoked-team")
	reads(t, people.User, d)

	seated := true
	t.Cleanup(func() {
		if !seated {
			change(t, people.Admin, "GrantRole", team)
		}
	})
	change(t, people.Admin, "RevokeRole", team)
	seated = false
	refused(t, people.User, d, noRole)
	if got := composed.As(t, people.User).Do(t, scenario.Call{Procedure: "GET /v1/" + solution + "/overview"}); got.Verdict != scenario.Denied {
		t.Errorf("Carol, her team's role revoked, reads the solution's overview: want a refusal, got %s", said(got))
	}
	reads(t, people.Admin, d)

	change(t, people.Admin, "GrantRole", team)
	seated = true
	reads(t, people.User, d)

	// Held twice: in person, and through the team.
	own := grant{installation: team.installation, role: "user", person: people.User}
	change(t, people.Admin, "GrantRole", own)
	direct := true
	t.Cleanup(func() {
		if direct {
			change(t, people.Admin, "RevokeRole", own)
		}
	})
	change(t, people.Admin, "RevokeRole", team)
	seated = false
	reads(t, people.User, d)
	change(t, people.Admin, "RevokeRole", own)
	direct = false
	refused(t, people.User, d, noRole)
}

// neverWritten is an entry id of e's own form that no organisation wrote.
func neverWritten(e string) string {
	if _, err := uuid.Parse(e); err == nil {
		return uuid.NewString()
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return '0' + ('9' - r)
		case r >= 'a' && r <= 'f':
			return 'a' + ('f' - r)
		case r >= 'A' && r <= 'F':
			return 'A' + ('F' - r)
		}
		return r
	}, e)
}

// The same document id under another organisation is not there, and nothing
// tells it from one that was never written. Zoë, the administrator of the
// other organisation, installs the solution herself and writes her own
// document. Each administrator reads her own through the backend; naming the
// other's entry, in her own organisation, in the other's or in none, she is
// refused or told it does not exist and is never answered. And the answer is
// the one an entry nobody wrote gets from the same person in the same words:
// the same status, the same code, the same message once each names its own
// id. A person learns nothing of what another organisation holds.
func TestComposedAnotherOrganizationsDocumentIsNotThere(t *testing.T) {
	outsider := composed.Outsider(t).ID
	composed.Install(t, outsider, solution)
	mine := write(t, people.Admin, "isolation")
	theirs := write(t, outsider, "isolation")
	reads(t, people.Admin, mine)
	reads(t, outsider, theirs)

	for _, tc := range []struct {
		person string
		other  document
	}{{people.Admin, theirs}, {people.User, theirs}, {outsider, mine}} {
		home := organization(t, tc.person)
		absent := neverWritten(tc.other.entry)
		if absent == tc.other.entry {
			t.Fatalf("no entry id of the form of %q that was never written", tc.other.entry)
		}
		for name, request := range map[string]map[string]any{
			"in the caller's organisation":  {"tenant": home, "entry_id": tc.other.entry, "version": tc.other.version},
			"naming the other organisation": tc.other.read(),
			"naming no organisation":        {"entry_id": tc.other.entry},
		} {
			t.Run(tc.person+"/"+name, func(t *testing.T) {
				got := relay(t, tc.person, "GetDocument", request)
				withheld := got.Verdict == scenario.Denied || got.Verdict == scenario.Admitted && got.Code == "not_found"
				if !withheld || strings.Contains(string(got.Body), tc.other.version) {
					t.Errorf("%s reads another organisation's %s: want a refusal or not_found and nothing of it, got %s", tc.person, tc.other.entry, said(got))
				}
				never := map[string]any{}
				for k, v := range request {
					never[k] = v
				}
				never["entry_id"] = absent
				none := relay(t, tc.person, "GetDocument", never)
				named := func(out scenario.Outcome, id string) string {
					return strings.ReplaceAll(said(out), id, "<entry>")
				}
				if a, b := named(got, tc.other.entry), named(none, absent); a != b {
					t.Errorf("%s can tell another organisation's entry from one never written:\n  theirs: %s\n  absent: %s", tc.person, a, b)
				}
			})
		}
	}
}
