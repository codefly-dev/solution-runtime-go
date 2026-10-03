package solution

import (
	"net/http"
	"strings"
	"testing"
)

// perMethodModule declares two methods of one module that need different
// authority: Search a member's read, Get an administrator's inspect.
func perMethodModule() ConsumedModule {
	return ConsumedModule{
		As: "things",
		Methods: []ConsumedMethod{
			{
				Name:          "/things.v1.Things/Search",
				Scopes:        []Scope{{ResourceKind: "things", Actions: []string{"list"}}},
				WholeResponse: true,
			},
			{
				Name:          "/things.v1.Things/Get",
				Scopes:        []Scope{{ResourceKind: "things", Actions: []string{"inspect"}}},
				WholeResponse: true,
			},
		},
	}
}

const getPath = "/modules/things/things.v1.Things/Get"

func mintedActions(m mintRequest) string {
	var parts []string
	for _, scope := range m.AuthorityScopes {
		parts = append(parts, scope.ResourceKind+":"+strings.Join(scope.Actions, ","))
	}
	return strings.Join(parts, " ")
}

func TestPassthroughMintsOnlyTheCalledMethodsScopes(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1"}`)
	s := passthroughServer(t, gw.URL, perMethodModule())

	if status, body := call(t, s, searchPath, "Bearer viewer", `{"entryId":"e1"}`); status != http.StatusOK {
		t.Fatalf("search: status %d: %v", status, body)
	}
	if status, body := call(t, s, getPath, "Bearer viewer", `{"entryId":"e1"}`); status != http.StatusOK {
		t.Fatalf("get: status %d: %v", status, body)
	}
	if len(gw.mints) != 2 {
		t.Fatalf("mints = %+v, want one per call", gw.mints)
	}
	// Least privilege: each mint carries its own method's scope and nothing
	// of the other's — never the union.
	if got := mintedActions(gw.mints[0]); got != "things:list" {
		t.Fatalf("search minted %q, want things:list only", got)
	}
	if got := mintedActions(gw.mints[1]); got != "things:inspect" {
		t.Fatalf("get minted %q, want things:inspect only", got)
	}
	if gw.mints[0].Audience != "things" || gw.mints[1].Audience != "things" {
		t.Fatalf("both mints are for the module's one audience: %+v", gw.mints)
	}
}

func TestPassthroughMethodScopesReplaceTheModules(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1"}`)
	module := perMethodModule()
	module.Scopes = []Scope{{ResourceKind: "things", Actions: []string{"read"}}}
	module.Methods[0].Scopes = nil // Search falls back to the module's.
	s := passthroughServer(t, gw.URL, module)

	call(t, s, searchPath, "Bearer viewer", `{}`)
	call(t, s, getPath, "Bearer viewer", `{"entryId":"e1"}`)
	if len(gw.mints) != 2 || mintedActions(gw.mints[0]) != "things:read" || mintedActions(gw.mints[1]) != "things:inspect" {
		t.Fatalf("mints = %+v, want module scope for search and method scope (alone) for get", gw.mints)
	}
}

func TestPassthroughRefusesOnlyTheMethodWhoseAuthorityTheViewerLacks(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1"}`)
	gw.deny = "inspect"
	s := passthroughServer(t, gw.URL, perMethodModule())

	status, body := call(t, s, getPath, "Bearer member", `{"entryId":"e1"}`)
	if status != http.StatusForbidden || body["code"] != "permission_denied" {
		t.Fatalf("get without inspect: status %d, body %v; want 403 permission_denied", status, body)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "things:inspect") {
		t.Fatalf("message %q does not name the missing permission", msg)
	}
	if len(gw.calls) != 0 {
		t.Fatalf("the module was called without a capability: %v", gw.calls)
	}
	// The member's own method is unaffected, and its mint was not widened.
	status, body = call(t, s, searchPath, "Bearer member", `{"entryId":"e1"}`)
	if status != http.StatusOK || body["entryId"] != "e1" {
		t.Fatalf("search after a refused get: status %d, body %v", status, body)
	}
	if last := gw.mints[len(gw.mints)-1]; mintedActions(last) != "things:list" {
		t.Fatalf("search minted %q, want things:list only", mintedActions(last))
	}
	if len(gw.calls) != 1 {
		t.Fatalf("module calls = %d, want only the search", len(gw.calls))
	}
}

func TestPassthroughRefusesAnUnservableScopeDeclarationAtBoot(t *testing.T) {
	search := func(scopes ...Scope) ConsumedMethod {
		return ConsumedMethod{Name: "/things.v1.Things/Search", Scopes: scopes, WholeResponse: true}
	}
	read := Scope{ResourceKind: "things", Actions: []string{"read"}}
	cases := map[string]struct {
		module ConsumedModule
		want   string
	}{
		"method scopes on a viewer-bearer module": {
			ConsumedModule{As: "things", ViewerBearer: true, Methods: []ConsumedMethod{search(read)}},
			"ViewerBearer",
		},
		"no scopes anywhere": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search()}},
			"declares no Scopes",
		},
		"one method without scopes and none on the module": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search(read), {Name: "/things.v1.Things/Get", WholeResponse: true}}},
			"Get declares no Scopes",
		},
		"empty action list on a method": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search(Scope{ResourceKind: "things"})}},
			"names no action",
		},
		"empty action list on the module": {
			ConsumedModule{As: "things", Scopes: []Scope{{ResourceKind: "things", Actions: []string{}}}, Methods: []ConsumedMethod{search()}},
			"names no action",
		},
		"blank action": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search(Scope{ResourceKind: "things", Actions: []string{" "}})}},
			"blank action",
		},
		"no resource kind": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search(Scope{Actions: []string{"read"}})}},
			"no resource kind",
		},
		"duplicated action": {
			ConsumedModule{As: "things", Methods: []ConsumedMethod{search(Scope{ResourceKind: "things", Actions: []string{"read", "read"}})}},
			"twice",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := resolvePassthrough([]ConsumedModule{tc.module})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestPassthroughOperationsDocumentEachMethodsOwnScopes(t *testing.T) {
	ops, err := PassthroughOperations(perMethodModule())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, op := range ops {
		found[op.Path] = op.Callers
	}
	if !strings.Contains(found[searchPath], "things:[list]") || strings.Contains(found[searchPath], "inspect") {
		t.Fatalf("search callers = %q", found[searchPath])
	}
	if !strings.Contains(found[getPath], "things:[inspect]") || strings.Contains(found[getPath], "list") {
		t.Fatalf("get callers = %q", found[getPath])
	}
}
