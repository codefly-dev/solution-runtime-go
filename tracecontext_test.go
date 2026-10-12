package solution

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/sdk-go/workcontext"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	callerTraceID    = "4bf92f3577b34da6a3ce929d0e0e4736"
	callerSpanID     = "00f067aa0ba902b7"
	callerTraceparnt = "00-" + callerTraceID + "-" + callerSpanID + "-01"
)

// callWithHeaders is call with the caller's own headers added, and returns
// the request the module received.
func callWithHeaders(t *testing.T, header http.Header) *http.Request {
	t.Helper()
	return callWithContext(t, context.Background(), header)
}

func callWithContext(t *testing.T, ctx context.Context, header http.Header) *http.Request {
	t.Helper()
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1"}`)
	s := passthroughServer(t, gw.URL, passthroughModule())
	routes, err := resolvePassthrough(s.consumed)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, searchPath, strings.NewReader(`{"entryId":"e1"}`))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("connect-protocol-version", "1")
	req.Header.Set("authorization", "Bearer viewer")
	req.Header.Set(orgHeader, "org-1")
	req.Header.Set(sessionHeader, "session-1")
	req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.passthroughHandler(routes).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(gw.calls) != 1 {
		t.Fatalf("module calls = %d, want 1", len(gw.calls))
	}
	return gw.calls[0]
}

func TestPassthroughCarriesTheCallersTraceContextToTheModule(t *testing.T) {
	got := callWithHeaders(t, http.Header{
		"Traceparent": {callerTraceparnt},
		"Tracestate":  {"vendor=abc,other=xyz"},
	})
	// Same trace, and the caller's span is the parent: no span was started here.
	if tp := got.Header.Get("traceparent"); tp != callerTraceparnt {
		t.Fatalf("traceparent = %q, want %q", tp, callerTraceparnt)
	}
	if ts := got.Header.Get("tracestate"); ts != "vendor=abc,other=xyz" {
		t.Fatalf("tracestate = %q", ts)
	}
	// The authority headers are unchanged by it.
	if got.Header.Get("authorization") != "Bearer viewer" {
		t.Fatal("the viewer's bearer was not forwarded")
	}
}

func TestPassthroughNeverForwardsBaggage(t *testing.T) {
	got := callWithHeaders(t, http.Header{
		"Traceparent": {callerTraceparnt},
		"Baggage":     {"user=alice,tenant=t1"},
	})
	if b := got.Header.Get("baggage"); b != "" {
		t.Fatalf("baggage = %q forwarded to the module", b)
	}
	if got.Header.Get("traceparent") != callerTraceparnt {
		t.Fatal("traceparent not forwarded alongside the dropped baggage")
	}
}

func TestPassthroughForwardsNoTraceContextTheCallerDidNotSend(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Tracestate": {"vendor=abc"}})
		if got.Header.Get("traceparent") != "" || got.Header.Get("tracestate") != "" {
			t.Fatalf("forwarded %q / %q with no traceparent from the caller", got.Header.Get("traceparent"), got.Header.Get("tracestate"))
		}
	})
	for name, tp := range map[string]string{
		"malformed":      "not-a-traceparent",
		"zero trace id":  "00-00000000000000000000000000000000-" + callerSpanID + "-01",
		"zero span id":   "00-" + callerTraceID + "-0000000000000000-01",
		"uppercase hex":  "00-" + strings.ToUpper(callerTraceID) + "-" + callerSpanID + "-01",
		"trailing bytes": callerTraceparnt + "-extra",
		"version ff":     "ff-" + callerTraceID + "-" + callerSpanID + "-01",
	} {
		t.Run(name, func(t *testing.T) {
			got := callWithHeaders(t, http.Header{"Traceparent": {tp}, "Tracestate": {"vendor=abc"}})
			if got.Header.Get("traceparent") != "" || got.Header.Get("tracestate") != "" {
				t.Fatalf("forwarded %q / %q for traceparent %q", got.Header.Get("traceparent"), got.Header.Get("tracestate"), tp)
			}
		})
	}
	t.Run("a span already in the request context is not substituted", func(t *testing.T) {
		outer := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
		})
		got := callWithContext(t, trace.ContextWithSpanContext(context.Background(), outer), nil)
		if tp := got.Header.Get("traceparent"); tp != "" {
			t.Fatalf("traceparent = %q, want none: the caller sent none", tp)
		}
	})
}

func TestPassthroughRewritesAForgedTraceStateRatherThanCopyingIt(t *testing.T) {
	t.Run("invalid tracestate is dropped, traceparent kept", func(t *testing.T) {
		for _, ts := range []string{
			"vendor=abc\r\nx-injected: 1",
			"UPPER=abc",
			"vendor=abc,vendor=dup",
			"=novalue",
			"vendor=a b=c",
		} {
			got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {ts}})
			if got.Header.Get("traceparent") != callerTraceparnt {
				t.Fatalf("traceparent dropped for tracestate %q", ts)
			}
			if out := got.Header.Get("tracestate"); out != "" {
				t.Fatalf("tracestate %q forwarded as %q", ts, out)
			}
			if got.Header.Get("x-injected") != "" {
				t.Fatal("header injected through tracestate")
			}
		}
	})
	t.Run("non-canonical tracestate is never copied raw", func(t *testing.T) {
		raw := "vendor=abc ,  ,other=xyz"
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {raw}})
		if out := got.Header.Get("tracestate"); out == raw {
			t.Fatalf("tracestate copied byte for byte: %q", out)
		}
	})
	t.Run("more than 32 members is dropped", func(t *testing.T) {
		members := make([]string, 33)
		for i := range members {
			members[i] = "k" + strings.Repeat("a", i) + "=v"
		}
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {strings.Join(members, ",")}})
		if out := got.Header.Get("tracestate"); out != "" {
			t.Fatalf("tracestate with 33 members forwarded as %q", out)
		}
	})
	t.Run("oversized tracestate is capped by W3C truncation", func(t *testing.T) {
		big := "big=" + strings.Repeat("x", 200) // > 128: dropped first
		var members []string
		members = append(members, "first=1")
		for i := range 20 {
			members = append(members, "m"+strings.Repeat("a", i)+"="+strings.Repeat("v", 20))
		}
		members = append(members, big)
		in := strings.Join(members, ",")
		if len(in) <= maxForwardedTraceState {
			t.Fatalf("fixture is %d bytes, want over %d", len(in), maxForwardedTraceState)
		}
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {in}})
		out := got.Header.Get("tracestate")
		if len(out) > maxForwardedTraceState || out == "" {
			t.Fatalf("tracestate forwarded at %d bytes, want 1..%d", len(out), maxForwardedTraceState)
		}
		if strings.Contains(out, "big=") {
			t.Fatal("the over-128-byte member survived truncation")
		}
		if !strings.HasPrefix(out, "first=1,") {
			t.Fatalf("truncation dropped from the left: %q", out)
		}
		if !strings.HasPrefix(in, out) {
			t.Fatalf("tracestate %q is not a left prefix of the members sent", out)
		}
	})
}

func TestCapTraceStateKeepsWhatFits(t *testing.T) {
	ts, err := trace.ParseTraceState("a=1,b=2")
	if err != nil {
		t.Fatal(err)
	}
	if got := capTraceState(ts).String(); got != "a=1,b=2" {
		t.Fatalf("capTraceState = %q", got)
	}
}

func TestPassthroughStreamCarriesTheCallersTraceContextToTheModule(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	close(gw.lines)
	req := watchRequest("e1")
	req.Header().Set("traceparent", callerTraceparnt)
	req.Header().Set("tracestate", "vendor=abc")
	req.Header().Set("baggage", "user=alice")
	stream, err := watchClient(t, s).CallServerStream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiveAll(stream); err != nil {
		t.Fatal(err)
	}
	h := gw.watches[0].Header
	if h.Get("traceparent") != callerTraceparnt || h.Get("tracestate") != "vendor=abc" || h.Get("baggage") != "" {
		t.Fatalf("module stream headers: traceparent %q, tracestate %q, baggage %q", h.Get("traceparent"), h.Get("tracestate"), h.Get("baggage"))
	}
}

func TestPassthroughRequiresExactlyOneTraceparent(t *testing.T) {
	other := "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-01"
	for name, parents := range map[string][]string{
		"two distinct":   {callerTraceparnt, other},
		"two identical":  {callerTraceparnt, callerTraceparnt},
		"one empty, one": {"", callerTraceparnt},
	} {
		t.Run(name, func(t *testing.T) {
			got := callWithHeaders(t, http.Header{"Traceparent": parents, "Tracestate": {"vendor=abc"}})
			if got.Header.Get("traceparent") != "" || got.Header.Get("tracestate") != "" {
				t.Fatalf("forwarded %q / %q for traceparents %q", got.Header.Get("traceparent"), got.Header.Get("tracestate"), parents)
			}
		})
	}
}

func TestPassthroughJoinsTraceStateFieldsInOrder(t *testing.T) {
	t.Run("split across fields is merged", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {"vendor=abc,second=2", "other=xyz"}})
		if ts := got.Header.Get("tracestate"); ts != "vendor=abc,second=2,other=xyz" {
			t.Fatalf("tracestate = %q, want the fields joined in order", ts)
		}
		if len(got.Header.Values("tracestate")) != 1 {
			t.Fatalf("tracestate forwarded as %d fields, want 1", len(got.Header.Values("tracestate")))
		}
	})
	t.Run("an empty field adds no member", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {"vendor=abc", "", "other=xyz"}})
		if ts := got.Header.Get("tracestate"); ts != "vendor=abc,other=xyz" {
			t.Fatalf("tracestate = %q", ts)
		}
	})
	t.Run("a key repeated across fields drops the tracestate", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": {"vendor=abc", "vendor=forged"}})
		if got.Header.Get("traceparent") != callerTraceparnt {
			t.Fatal("traceparent dropped with the duplicate tracestate")
		}
		if ts := got.Header.Get("tracestate"); ts != "" {
			t.Fatalf("tracestate with a duplicate key forwarded as %q", ts)
		}
	})
	t.Run("the cap applies to the joined list", func(t *testing.T) {
		var fields []string
		for i := range 20 {
			fields = append(fields, "m"+strings.Repeat("a", i)+"="+strings.Repeat("v", 20))
		}
		got := callWithHeaders(t, http.Header{"Traceparent": {callerTraceparnt}, "Tracestate": fields})
		if ts := got.Header.Get("tracestate"); ts == "" || len(ts) > maxForwardedTraceState || !strings.HasPrefix(ts, fields[0]+",") {
			t.Fatalf("tracestate forwarded as %q (%d bytes)", ts, len(ts))
		}
	})
}

func TestPassthroughEnforcesTheVersion00TraceparentLength(t *testing.T) {
	for name, tp := range map[string]string{
		"trailing separator":  callerTraceparnt + "-",
		"54 bytes":            callerTraceparnt[:54],
		"56 bytes":            callerTraceparnt + "1",
		"trailing space":      callerTraceparnt + " ",
		"trailing tab":        callerTraceparnt + "\t",
		"leading space":       " " + callerTraceparnt,
		"trailing empty pair": callerTraceparnt + "--",
	} {
		t.Run(name, func(t *testing.T) {
			got := callWithHeaders(t, http.Header{"Traceparent": {tp}, "Tracestate": {"vendor=abc"}})
			if got.Header.Get("traceparent") != "" || got.Header.Get("tracestate") != "" {
				t.Fatalf("forwarded %q / %q for traceparent %q (%d bytes)", got.Header.Get("traceparent"), got.Header.Get("tracestate"), tp, len(tp))
			}
		})
	}
	t.Run("a later version may be longer", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Traceparent": {"01-" + callerTraceID + "-" + callerSpanID + "-01-future"}})
		// Re-serialized at the version this runtime speaks.
		if tp := got.Header.Get("traceparent"); tp != callerTraceparnt {
			t.Fatalf("traceparent = %q, want %q", tp, callerTraceparnt)
		}
	})
	t.Run("a later version still needs a separator after the flags", func(t *testing.T) {
		got := callWithHeaders(t, http.Header{"Traceparent": {"01-" + callerTraceID + "-" + callerSpanID + "-01x"}})
		if tp := got.Header.Get("traceparent"); tp != "" {
			t.Fatalf("traceparent = %q forwarded", tp)
		}
	})
}

// redirectingGateway is a gateway whose module answers at /moved and whose
// every other path redirects there: directly, on the gateway's own origin, or,
// when crossOrigin is set, by way of a second server that bounces the request
// back. It records the trace headers each hop received.
type redirectingGateway struct {
	gateway, foreign *httptest.Server
	mu               sync.Mutex
	hops             []traceHop
}

type traceHop struct {
	origin, path, traceparent, tracestate string
}

func newRedirectingGateway(t *testing.T, crossOrigin bool, answer http.HandlerFunc) *redirectingGateway {
	t.Helper()
	g := &redirectingGateway{}
	record := func(origin string, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.hops = append(g.hops, traceHop{origin, r.URL.Path, r.Header.Get("traceparent"), r.Header.Get("tracestate")})
	}
	g.gateway = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("gateway", r)
		switch {
		case r.URL.Path == "/moved":
			answer(w, r)
		case crossOrigin:
			http.Redirect(w, r, g.foreign.URL+"/bounce", http.StatusTemporaryRedirect)
		default:
			http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
		}
	}))
	g.foreign = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("foreign", r)
		http.Redirect(w, r, g.gateway.URL+"/moved", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(g.gateway.Close)
	t.Cleanup(g.foreign.Close)
	return g
}

// callerTraceContext is the context the passthrough hands a module call for a
// caller that sent callerTraceparnt and vendor=abc.
func callerTraceContext() context.Context {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("traceparent", callerTraceparnt)
	r.Header.Set("tracestate", "vendor=abc")
	return withInboundTraceContext(r).Context()
}

// checkHops asserts how a redirected module call went. Same origin, the
// redirect is followed and both hops carry the trace context. Cross origin,
// the gateway's origin pin refuses the hop before it is sent, so the foreign
// server receives nothing at all — the trace context included — and the call
// fails; the redirect policy strips the trace headers from that hop first,
// so they would not travel even past a transport without the pin (see
// TestTraceContextRedirectPolicyStripsOnceTheChainLeavesTheOrigin).
func (g *redirectingGateway) checkHops(t *testing.T, crossOrigin bool, err error) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if crossOrigin {
		if err == nil || !strings.Contains(err.Error(), "refusing to send") {
			t.Fatalf("err = %v, want the origin pin's refusal", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	want := 2
	if crossOrigin {
		want = 1
	}
	if len(g.hops) != want {
		t.Fatalf("hops = %+v, want %d", g.hops, want)
	}
	for _, hop := range g.hops {
		if hop.origin != "gateway" {
			t.Fatalf("hop %+v reached a server that is not the gateway", hop)
		}
		if hop.traceparent != callerTraceparnt || hop.tracestate != "vendor=abc" {
			t.Fatalf("same-origin hop %+v lost the trace context", hop)
		}
	}
	if last := g.hops[len(g.hops)-1]; !crossOrigin && last.path != "/moved" {
		t.Fatalf("the chain ended at %+v, want the gateway's /moved", last)
	}
}

func TestTranscodedDropsTraceContextOnACrossOriginRedirect(t *testing.T) {
	for name, crossOrigin := range map[string]bool{
		"same-origin redirect keeps it":                              false,
		"cross-origin redirect is refused, the trace context unsent": true,
	} {
		t.Run(name, func(t *testing.T) {
			g := newRedirectingGateway(t, crossOrigin, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"entryId":"e1"}`)
			})
			gw := newGateway(g.gateway.URL, "Bearer viewer", "org-1", "session-1")
			req := thingMessage("GetThingRequest")
			setField(req, "entry_id", protoreflect.ValueOfString("e1"))
			err := gw.Transcoded(callerTraceContext(), "/v1/things", "/things.v1.Things/Get", req, thingMessage("Thing"))
			g.checkHops(t, crossOrigin, err)
		})
	}
}

func TestTranscodedStreamDropsTraceContextOnACrossOriginRedirect(t *testing.T) {
	for name, crossOrigin := range map[string]bool{
		"same-origin redirect keeps it":                              false,
		"cross-origin redirect is refused, the trace context unsent": true,
	} {
		for _, firstAnswer := range []time.Duration{0, time.Minute} {
			t.Run(fmt.Sprintf("%s/first answer %s", name, firstAnswer), func(t *testing.T) {
				g := newRedirectingGateway(t, crossOrigin, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/x-ndjson")
					_, _ = io.WriteString(w, `{"result":{"entryId":"e1"}}`+"\n")
				})
				gw := newGateway(g.gateway.URL, "Bearer viewer", "org-1", "session-1")
				req := thingMessage("GetThingRequest")
				setField(req, "entry_id", protoreflect.ValueOfString("e1"))
				var opts []StreamOption
				if firstAnswer > 0 {
					opts = append(opts, StreamFirstAnswerWithin(firstAnswer))
				}
				n := 0
				err := gw.TranscodedStream(callerTraceContext(), "/v1/things", watchName, req,
					func() proto.Message { return thingMessage("Thing") },
					func(proto.Message) error { n++; return nil }, opts...)
				g.checkHops(t, crossOrigin, err)
				if want := map[bool]int{false: 1, true: 0}[crossOrigin]; n != want {
					t.Fatalf("messages = %d, want %d", n, want)
				}
			})
		}
	}
}

func TestTraceContextRedirectPolicyKeepsTheDefaultLimit(t *testing.T) {
	policy := traceContextRedirectPolicy("http://gateway.local")
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/x", nil)
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = req
	}
	if err := policy(req, via[:maxRedirects-1]); err != nil {
		t.Fatalf("redirect %d refused: %v", maxRedirects, err)
	}
	if err := policy(req, via); err == nil || err.Error() != "stopped after 10 redirects" {
		t.Fatalf("redirect %d: err = %v, want net/http's default", maxRedirects+1, err)
	}
}

func TestSameOrigin(t *testing.T) {
	gateway, _ := url.Parse("http://Gateway.local")
	for raw, want := range map[string]bool{
		"http://gateway.local:80/p":  true,
		"HTTP://GATEWAY.LOCAL/p":     true,
		"https://gateway.local/p":    false,
		"http://gateway.local:8080/": false,
		"http://other.local/":        false,
		"/relative":                  false,
	} {
		u, _ := url.Parse(raw)
		if got := sameOrigin(gateway, u); got != want {
			t.Errorf("sameOrigin(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestTraceContextRedirectPolicyStripsOnceTheChainLeavesTheOrigin(t *testing.T) {
	policy := traceContextRedirectPolicy("http://gateway.local")
	hop := func(raw string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, raw, nil)
		r.Header.Set("traceparent", callerTraceparnt)
		r.Header.Set("tracestate", "vendor=abc")
		return r
	}
	for name, tc := range map[string]struct {
		via  []string
		next string
		keep bool
	}{
		"same origin":                       {[]string{"http://gateway.local/a"}, "http://gateway.local/b", true},
		"to another origin":                 {[]string{"http://gateway.local/a"}, "http://other.local/b", false},
		"back to the gateway after leaving": {[]string{"http://gateway.local/a", "http://other.local/b"}, "http://gateway.local/c", false},
		"to another port":                   {[]string{"http://gateway.local/a"}, "http://gateway.local:8080/b", false},
		"to another scheme":                 {[]string{"http://gateway.local/a"}, "https://gateway.local/b", false},
	} {
		t.Run(name, func(t *testing.T) {
			var via []*http.Request
			for _, raw := range tc.via {
				via = append(via, hop(raw))
			}
			next := hop(tc.next)
			if err := policy(next, via); err != nil {
				t.Fatal(err)
			}
			kept := next.Header.Get("traceparent") != "" || next.Header.Get("tracestate") != ""
			if kept != tc.keep {
				t.Fatalf("trace context kept = %v, want %v", kept, tc.keep)
			}
			if next.Header.Get("authorization") != "" {
				t.Fatal("policy added a header")
			}
		})
	}
	t.Run("an unparseable gateway URL strips every hop", func(t *testing.T) {
		next := hop("http://gateway.local/b")
		if err := traceContextRedirectPolicy("http://[::1")(next, []*http.Request{hop("http://gateway.local/a")}); err != nil {
			t.Fatal(err)
		}
		if next.Header.Get("traceparent") != "" {
			t.Fatal("trace context kept with no gateway origin to hold it to")
		}
	})
}
