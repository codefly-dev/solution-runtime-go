//go:build composition

package scenarios

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	scenario "github.com/codefly-dev/authority/libraries/scenario/go"
	"github.com/codefly-dev/core/composition"
)

// route is one served route and how a person calls it: on their session at
// the edge (call), and with a Work Context they hold, sent where the edge
// sends it (audience, method, path).
type route struct {
	name string
	call scenario.Call
	// audience is who the Work Context sent to this route is issued for; own
	// is whether the solution's backend serves it, and the hop otherwise.
	audience, method, path string
	own                    bool
}

// store is the consumed module, and the audience of a call to it.
const store = "documents"

// declaredRoutes is every route this composition serves a person, read from
// the contract catalogs the modules publish and never listed here: the
// solution's own catalog (../contracts/api/catalog.codefly.json: its routes
// and the ones its backend relays), and every procedure the consumed module's
// catalog routes, called on the person's own session at the module's page.
func declaredRoutes(t *testing.T) (own, module []route) {
	t.Helper()
	catalog, err := composition.LoadAPIContractCatalog("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range catalog.Endpoints {
		for _, r := range endpoint.Routes {
			own = append(own, route{r.Method + " " + r.Path, scenario.Call{Procedure: r.Method + " " + r.Path}, solution, r.Method, r.Path, true})
		}
	}
	published, err := composed.Published(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for procedure := range published[store] {
		module = append(module, route{procedure, scenario.Call{Procedure: strings.TrimPrefix(procedure, "/")}, store, http.MethodPost, procedure, false})
	}
	slices.SortFunc(module, func(a, b route) int { return strings.Compare(a.name, b.name) })
	if len(own) == 0 || len(module) == 0 {
		t.Fatalf("the catalogs declare %d routes of the solution and %d of the store: nothing to hold", len(own), len(module))
	}
	return own, module
}

// through is whether a call was let through to its method: it answered, or the
// method itself refused the empty request it was handed.
func through(out scenario.Outcome) bool {
	return out.Verdict == scenario.Allowed || out.Verdict == scenario.Admitted
}

// unconfigured is a method that answered for itself that this composition does
// not configure what it needs (the store's publication, which the scenarios
// leave out). The method said so, by name: a hop or an authority that could
// not decide says something else, and is not this.
func unconfigured(out scenario.Outcome) bool {
	return out.Verdict == scenario.Failed && out.Code == "unavailable" && strings.HasSuffix(out.Reason, "is not configured")
}

// sent sends a Work Context the test holds to r, where the edge sends one:
// the solution's backend for its own routes, the hop in front of the store
// for the store's. The request is empty.
func (r route) sent(t *testing.T, token string) answer {
	t.Helper()
	at := delivered(t, "authority", "hop", "http")
	if r.own {
		at = delivered(t, solution, "backend", "http")
	}
	var request any
	if r.method != http.MethodGet {
		request = map[string]any{}
	}
	header := map[string]string{workContextHeader: token}
	if !r.own {
		// A Connect call, as the edge forwards a page's.
		header["Connect-Protocol-Version"] = "1"
	}
	got, err := send(r.method, "http://"+at+r.path, header, request)
	if err != nil {
		t.Fatalf("%s, sent a held Work Context: %v", r.name, err)
	}
	return got
}

// let is whether a held Work Context was let through to the method: it
// answered, or the method itself refused the empty request it was handed
// (the scenario library's Allowed and Admitted, for an answer read here).
func let(a answer) bool {
	switch a.code {
	case "invalid_argument", "not_found", "already_exists", "failed_precondition", "out_of_range", "aborted":
		return true
	case "":
		switch a.status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusRequestTimeout, http.StatusTooManyRequests, 499:
			return false
		}
		return a.status == http.StatusOK || a.status >= 400 && a.status < 500
	}
	return false
}

// refusal is whether a held Work Context was refused for who it is for.
func refusal(a answer) bool {
	return a.code == "permission_denied" || a.code == "unauthenticated" || a.code == "" && (a.status == http.StatusForbidden || a.status == http.StatusUnauthorized)
}

// seat is one person and every grant that seats them.
type seat struct {
	person string
	grants []grant
}

// minted is the seat's Work Context at each audience, as the authority issues
// it to their session now.
func minted(t *testing.T, s session, routes []route) map[string]string {
	t.Helper()
	held := map[string]string{}
	for _, r := range routes {
		if _, ok := held[r.audience]; ok {
			continue
		}
		token, err := s.issuedAt(t, r.audience)
		if err != nil {
			t.Fatalf("%s is issued no Work Context at %s: %v", s.person, r.audience, err)
		}
		held[r.audience] = token
	}
	return held
}

// revoked holds every route to one revocation of one seat, twice over: on the
// seat's session at the edge, and with the Work Context the authority issued
// that session before the revocation, sent byte for byte where the edge sends
// it. Each route is called with an empty request both ways; the seat's grants
// are revoked; every route, called again on the same session, refuses, and
// the Work Context issued before, replayed, is refused at every route; granted
// back, each answers as it did, to the session and to a context issued then.
// It answers, per route, whether the seat's roles reached it both ways (shown)
// and what it answered before the revocation.
func revoked(t *testing.T, s seat, routes []route) (shown map[string]bool, first map[string]string) {
	t.Helper()
	who := composed.As(t, s.person)
	own := signIn(t, s.person)
	held := minted(t, own, routes)
	before, sentBefore := map[string]scenario.Outcome{}, map[string]answer{}
	shown, first = map[string]bool{}, map[string]string{}
	for _, r := range routes {
		before[r.name] = who.Do(t, r.call)
		sentBefore[r.name] = r.sent(t, held[r.audience])
		first[r.name] = fmt.Sprintf("as %s: session %s; held Work Context %s", s.person, said(before[r.name]), sentBefore[r.name])
		switch {
		case through(before[r.name]) != let(sentBefore[r.name]):
			t.Errorf("%s as %s, before any revocation: the session's call and the held Work Context disagree: %s", r.name, s.person, first[r.name])
		case through(before[r.name]):
			shown[r.name] = true
		case unconfigured(before[r.name]):
			// Not shown, and still held to a refusal once the role is revoked.
		case before[r.name].Verdict != scenario.Denied:
			t.Errorf("%s as %s, before any revocation: %s: neither let through nor a refusal, so it shows nothing", r.name, s.person, said(before[r.name]))
		}
	}
	seated := true
	t.Cleanup(func() {
		if !seated {
			for _, g := range s.grants {
				change(t, people.Admin, "GrantRole", g)
			}
		}
	})
	for _, g := range s.grants {
		change(t, people.Admin, "RevokeRole", g)
	}
	seated = false
	for _, r := range routes {
		if got := who.Do(t, r.call); got.Verdict != scenario.Denied {
			t.Errorf("%s as %s, the roles revoked: want a refusal, got %s (before: %s)", r.name, s.person, said(got), before[r.name].Verdict)
		}
		if got := r.sent(t, held[r.audience]); !refusal(got) {
			t.Errorf("%s as %s, the Work Context issued before the revocation, replayed after it: want a refusal, got %s (before: %s)", r.name, s.person, got, sentBefore[r.name])
		}
	}
	for _, g := range s.grants {
		change(t, people.Admin, "GrantRole", g)
	}
	seated = true
	fresh := minted(t, own, routes)
	for _, r := range routes {
		if got := who.Do(t, r.call); got.Verdict != before[r.name].Verdict {
			t.Errorf("%s as %s, the roles granted back: %s, and before the revocation %s", r.name, s.person, said(got), before[r.name].Verdict)
		}
		if got := r.sent(t, fresh[r.audience]); let(got) != let(sentBefore[r.name]) {
			t.Errorf("%s as %s, a Work Context issued after the roles were granted back: %s, and before the revocation %s", r.name, s.person, got, sentBefore[r.name])
		}
	}
	return shown, first
}

// pageGrant grants person role on the store's own page for this scenario, and
// answers the grant as the host lists it.
func pageGrant(t *testing.T, person, role string) grant {
	t.Helper()
	composed.Grant(t, people.Admin, store, role, person)
	for _, g := range grantsOn(t, people.Admin, store) {
		if g.role == role && g.person == person {
			t.Cleanup(func() { change(t, people.Admin, "RevokeRole", g) })
			return g
		}
	}
	t.Fatalf("%s was granted the store's %s role and the host lists no such grant", person, role)
	return grant{}
}

// unshown is every declared route no seat of this composition reaches, and
// why. It is the one list here, and it is held both ways: a declared route
// that is neither shown nor named fails the run, and so does a name that is
// shown or that no catalog declares. A route added to either catalog
// therefore arrives with its revocation shown, or with a line here saying
// why not.
var unshown = map[string]string{
	"/documents.v1.DocumentsService/AbortUpload":                      writeThroughABinding,
	"/documents.v1.DocumentsService/AppendUploadPart":                 writeThroughABinding,
	"/documents.v1.DocumentsService/ApplyDocumentTransformation":      writeThroughABinding,
	"/documents.v1.DocumentsService/ApplyPublicationProducer":         ingestOnly,
	"/documents.v1.DocumentsService/ArchiveDocument":                  writeThroughABinding,
	"/documents.v1.DocumentsService/AttachExtractor":                  writeThroughABinding,
	"/documents.v1.DocumentsService/BeginUpload":                      writeThroughABinding,
	"/documents.v1.DocumentsService/CloseSync":                        ingestOnly,
	"/documents.v1.DocumentsService/CopyDocument":                     writeThroughABinding,
	"/documents.v1.DocumentsService/CreateDocument":                   writeThroughABinding,
	"/documents.v1.DocumentsService/CreateDocumentVersion":            writeThroughABinding,
	"/documents.v1.DocumentsService/CreateTextDocument":               writeThroughABinding,
	"/documents.v1.DocumentsService/DeleteDocument":                   deleteThroughABinding,
	"/documents.v1.DocumentsService/DeleteDocumentVersion":            deleteThroughABinding,
	"/documents.v1.DocumentsService/EditWorkbook":                     writeThroughABinding,
	"/documents.v1.DocumentsService/FinishUpload":                     writeThroughABinding,
	"/documents.v1.DocumentsService/Freeze":                           noRoleHolds,
	"/documents.v1.DocumentsService/GetDocumentTransformationReceipt": notConfigured,
	"/documents.v1.DocumentsService/GetPublicationEvidence":           notConfigured,
	"/documents.v1.DocumentsService/GetPublicationProductionPlan":     notConfigured,
	"/documents.v1.DocumentsService/GetPublicationReadiness":          notConfigured,
	"/documents.v1.DocumentsService/GetPublicationReceipt":            notConfigured,
	"/documents.v1.DocumentsService/IngestDocument":                   ingestOnly,
	"/documents.v1.DocumentsService/ListDeadLetters":                  operatorOnly,
	"/documents.v1.DocumentsService/ListHolds":                        operatorOnly,
	"/documents.v1.DocumentsService/ListSyncPage":                     ingestOnly,
	"/documents.v1.DocumentsService/LookupCloseSync":                  ingestOnly,
	"/documents.v1.DocumentsService/LookupIngestDocument":             ingestOnly,
	"/documents.v1.DocumentsService/LookupListSyncPage":               ingestOnly,
	"/documents.v1.DocumentsService/LookupPlanSyncPages":              ingestOnly,
	"/documents.v1.DocumentsService/LookupPublicationProducer":        notConfigured,
	"/documents.v1.DocumentsService/MoveDocument":                     moveThroughABinding,
	"/documents.v1.DocumentsService/PlaceHold":                        operatorOnly,
	"/documents.v1.DocumentsService/PlanSyncPages":                    ingestOnly,
	"/documents.v1.DocumentsService/PrepareDerivedDocument":           noRoleHolds,
	"/documents.v1.DocumentsService/PublishDerivedDocument":           noRoleHolds,
	"/documents.v1.DocumentsService/PublishDocumentTransformation":    noRoleHolds,
	"/documents.v1.DocumentsService/RecordConfirmation":               writeThroughABinding,
	"/documents.v1.DocumentsService/RedriveDeadLetters":               operatorOnly,
	"/documents.v1.DocumentsService/ReleaseHold":                      operatorOnly,
	"/documents.v1.DocumentsService/RestoreDocumentVersion":           writeThroughABinding,
	"/documents.v1.DocumentsService/Subscribe":                        writeThroughABinding,
	"/documents.v1.DocumentsService/TransferOwnership":                noRoleHolds,
	"/documents.v1.DocumentsService/UnarchiveDocument":                writeThroughABinding,
	"/documents.v1.DocumentsService/Unsubscribe":                      writeThroughABinding,
}

// Why a declared route is reached by no seat here.
const (
	// The store's own page roles hold reads alone (its contract, by the
	// owner's decision): a person writes only through a product's binding.
	// The one write this solution relays is shown, at its own route.
	writeThroughABinding = "requires documents:write, which no person's role at the store holds: a write reaches the store through a product's binding, and the one this solution relays is shown at its own CreateDocument route"
	// documents.ingest and documents:ingest are the store's own runtime
	// binding's and a publication producer's.
	ingestOnly            = "requires documents.ingest or documents:ingest, which no person holds: it is the store's own sync binding's and a publication producer's"
	deleteThroughABinding = "requires documents:delete from the manage bundle, which neither solution role includes"
	moveThroughABinding   = "requires documents:write and documents.collection:transfer, which neither role holds at the store"
	// Dead letters and holds require collection administration.
	operatorOnly = "requires documents.collection:admin, the operator's, which no role holds"
	// Publish, freeze and transfer: no screen calls them, so no role of the
	// store holds them, and this solution's roles include neither bundle.
	noRoleHolds = "requires documents.collection publish, freeze or transfer, which no role of the store and no bundle this solution's roles include holds"
	// The scenarios leave the store's publication out.
	notConfigured = "its method answers that publication is not configured in this composition, which is a failure and not an answer; it is still held to a refusal once the role is revoked"
)

// Every declared route, one revocation per seat, and a new route with no case
// fails. Carol holds the solution's user role through its team and, for this
// scenario, the store's own user role in person; Dana holds the solution's
// admin role through its team and the store's admin role in person. Each
// route a seat's roles reach is let through to its method, on their session
// and with a Work Context issued to it; refuses that session on the next call
// after the revocation, and refuses the Work Context issued before it,
// replayed as issued; and is let through again once granted back (revoked).
// A route neither seat reaches shows nothing of revocation: it was a refusal
// throughout, and it must be named in unshown with the reason. Every route of
// the solution's own catalog must be among those shown.
func TestComposedEveryDeclaredRouteRefusesARevokedRole(t *testing.T) {
	own, module := declaredRoutes(t)
	all := append(slices.Clone(own), module...)

	carol := seat{person: people.User, grants: []grant{userTeam(t), pageGrant(t, people.User, "user")}}
	dana := seat{person: people.Admin}
	for _, g := range grants(t, people.Admin) {
		if g.role == "admin" && g.team != "" {
			dana.grants = append(dana.grants, g)
		}
	}
	if len(dana.grants) != 1 {
		t.Fatalf("want one team holding the admin role on %s, got %v", solution, dana.grants)
	}
	dana.grants = append(dana.grants, pageGrant(t, people.Admin, "admin"))

	shown, asCarol := revoked(t, carol, all)
	more, asDana := revoked(t, dana, all)
	for name := range more {
		shown[name] = true
	}
	declared := map[string]bool{}
	for _, r := range all {
		declared[r.name] = true
		switch why, named := unshown[r.name]; {
		case shown[r.name] && named:
			t.Errorf("%s is named unshown (%s) and a seat's role reached it: take it off the list", r.name, why)
		case !shown[r.name] && r.own:
			t.Errorf("%s is the solution's own route and no seat's role reached it, so its revocation is not shown: %s; %s", r.name, asCarol[r.name], asDana[r.name])
		case !shown[r.name] && !named:
			t.Errorf("%s is declared and has no case: no seat's role reached it and unshown does not say why: %s; %s", r.name, asCarol[r.name], asDana[r.name])
		case !shown[r.name]:
			t.Logf("not shown: %s: %s", r.name, why)
		}
	}
	for name := range unshown {
		if !declared[name] {
			t.Errorf("unshown names %s, which no catalog declares", name)
		}
	}
	t.Logf("%d declared routes (%d the solution's, %d the store's): %d let through, refused once the role was revoked (the session's next call, and the Work Context issued before, replayed), and let through again; %d no seat's role reached, refused throughout",
		len(all), len(own), len(module), len(shown), len(all)-len(shown))
}
