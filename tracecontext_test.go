package solution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codefly-dev/sdk-go/workcontext"
	"go.opentelemetry.io/otel/trace"
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
