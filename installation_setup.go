package solution

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
)

// SetupModule names exact unary methods used only during OnInstall. Authority
// derives their grants from the delivered setup declaration and callee policy.
// These methods are not exposed by the browser passthrough.
type SetupModule struct {
	As        string
	Authority AuthorityRelay
	Methods   []string
}

type installationSetup struct {
	ctx    context.Context
	server *Server
	token  string
}

// Call invokes a declared setup method for this verified pending attempt. The
// authority issues a fresh, method-confined capability for every call. A retained
// Installation cannot call after its callback has returned.
func (i Installation) Call(ctx context.Context, as, method string, request, response proto.Message) error {
	if i.setup == nil {
		return fmt.Errorf("no verified installation attempt")
	}
	a := i.setup
	if err := a.ctx.Err(); err != nil {
		return err
	}
	declared := false
	for _, module := range a.server.setupModules {
		if module.As != as {
			continue
		}
		for _, allowed := range module.Methods {
			if allowed == method {
				declared = true
			}
		}
	}
	if !declared {
		return fmt.Errorf("setup method %q is not declared for %q", method, as)
	}
	relay := a.server.setupRelays[as]
	if relay == nil {
		return fmt.Errorf("setup module %q is not connected", as)
	}
	md, err := methodDescriptor(method)
	if err != nil {
		return err
	}
	if request == nil || response == nil || !request.ProtoReflect().IsValid() || !response.ProtoReflect().IsValid() || request.ProtoReflect().Descriptor().FullName() != md.Input().FullName() || response.ProtoReflect().Descriptor().FullName() != md.Output().FullName() {
		return fmt.Errorf("setup method %q requires its declared request and response types", method)
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	defer cancel()
	issued, err := a.server.host.outbound.IssueForInstallationSetup(callCtx, a.token, relay.binding, method)
	if err != nil {
		return err
	}
	return relay.conn.Invoke(issued.Carry(callCtx), method, request, response)
}

func (s *Server) openSetupRelays(lookup func(string, string) (string, error)) (map[string]*moduleRelay, error) {
	modules := make([]ConsumedModule, 0, len(s.setupModules))
	seen := map[string]bool{}
	for _, m := range s.setupModules {
		a := m.Authority
		if m.As == "" || seen[m.As] || a.Group == "" || a.EndpointKey == "" || a.BindingKey == "" || len(m.Methods) == 0 {
			return nil, fmt.Errorf("setup module %q requires a unique alias, authority slots and exact methods", m.As)
		}
		seen[m.As] = true
		for _, method := range m.Methods {
			md, err := methodDescriptor(method)
			if err != nil {
				return nil, err
			}
			canonical := "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
			if method != canonical || strings.ContainsAny(method, "* ") || md.IsStreamingClient() || md.IsStreamingServer() {
				return nil, fmt.Errorf("setup method %q must name an exact unary RPC", method)
			}
		}
		modules = append(modules, ConsumedModule{As: m.As, Authority: a})
	}
	return s.openModuleRelays(modules, lookup)
}
