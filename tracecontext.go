package solution

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// --- W3C trace context across the passthrough ---
//
// A page's call through the passthrough is one hop of a trace the page may
// have started: the module behind it should record its work under the same
// trace, as a child of the span that called. The passthrough therefore carries
// the W3C trace context (traceparent, tracestate) from the inbound call to the
// module call, and nothing else of the caller's.
//
// This runtime starts no span, installs no tracer provider and exports nothing:
// it is a library, and which exporter a deployment uses is not its business. It
// carries the caller's context through, unchanged in identity, so the module's
// span parents directly on the caller's.
//
// It uses its own TraceContext propagator rather than the global one. The
// global propagator is whatever the consumer's process installed — nothing, by
// default, which silently propagates nothing — or a composite that also
// carries baggage, which this runtime never forwards: baggage is caller-chosen
// key/values, and the module is a different trust domain.
//
// Nothing is copied byte for byte. The inbound headers are parsed into a span
// context, and the outbound headers are written from that parsed value, so a
// malformed traceparent forwards nothing, and a tracestate is forwarded only as
// the list members that parse, capped at the length W3C asks every vendor to
// propagate.
var traceContextPropagator = propagation.TraceContext{}

const (
	// traceparentHeader and tracestateHeader are the W3C Trace Context fields.
	traceparentHeader = "traceparent"
	tracestateHeader  = "tracestate"
	// traceparentVersion00 is the only traceparent version this runtime knows
	// the exact length of: version 00 is exactly traceparentV00Length bytes,
	// with nothing after the flags. A later version may be longer (§3.2.4).
	traceparentVersion00 = "00"
	traceparentV00Length = 55
	// maxRedirects is net/http's default redirect limit, kept by the module
	// client's redirect policy so it changes nothing but the trace headers.
	maxRedirects = 10
	// maxForwardedTraceState is the tracestate length W3C Trace Context asks
	// every platform to propagate at least (§3.3.1.5). Forwarding no more keeps
	// a caller from growing every downstream request's headers at will.
	maxForwardedTraceState = 512
	// largeTraceStateMember is the member length W3C names as the first to drop
	// when a tracestate must be truncated.
	largeTraceStateMember = 128
)

// withInboundTraceContext returns r with the W3C trace context its own headers
// carry — and only that. A request without a valid traceparent gets an empty
// span context, so a span some outer middleware put into the context is not
// forwarded in place of the caller's: what reaches the module is exactly what
// the caller sent, re-validated, or nothing.
func withInboundTraceContext(r *http.Request) *http.Request {
	sc := trace.SpanContextFromContext(traceContextPropagator.Extract(context.Background(), inboundTraceCarrier(r.Header)))
	if sc.IsValid() {
		sc = sc.WithTraceState(capTraceState(sc.TraceState()))
	} else {
		sc = trace.SpanContext{}
	}
	return r.WithContext(trace.ContextWithRemoteSpanContext(r.Context(), sc))
}

// inboundTraceCarrier reads the W3C trace context fields of header the way
// W3C Trace Context requires, not the way propagation.HeaderCarrier does (it
// reads only the first field of each name):
//
//   - traceparent must arrive as exactly one field. None, or two or more —
//     even identical ones — is not a traceparent, and nothing is forwarded.
//   - A version-00 traceparent must be exactly 55 bytes. The pinned parser
//     accepts one with a trailing "-" (an empty fifth field); this does not.
//     Other versions are left to the parser, which reads their version-00
//     prefix and requires a "-" after it when there is more (§3.2.4).
//   - tracestate may be split across fields (RFC 9110 §5.3): every field is
//     joined, in the order received, with a comma before it is parsed, so a
//     key repeated in a later field is the duplicate it is and the whole
//     tracestate is dropped (§3.3.1.4), and the cap applies to the whole list.
func inboundTraceCarrier(header http.Header) propagation.MapCarrier {
	carrier := propagation.MapCarrier{}
	parents := header.Values(traceparentHeader)
	if len(parents) != 1 || !traceparentLengthOK(parents[0]) {
		return carrier
	}
	carrier[traceparentHeader] = parents[0]
	if states := header.Values(tracestateHeader); len(states) > 0 {
		carrier[tracestateHeader] = strings.Join(states, ",")
	}
	return carrier
}

// traceparentLengthOK reports whether tp has the exact length its version
// requires; only version 00 has one.
func traceparentLengthOK(tp string) bool {
	if strings.HasPrefix(tp, traceparentVersion00) {
		return len(tp) == traceparentV00Length
	}
	return true
}

// capTraceState truncates ts to maxForwardedTraceState the way W3C Trace
// Context §3.3.1.5 prescribes: members longer than largeTraceStateMember go
// first, from the right; then members from the right until the rest fits.
func capTraceState(ts trace.TraceState) trace.TraceState {
	if len(ts.String()) <= maxForwardedTraceState {
		return ts
	}
	var keys []string
	var sizes []int
	ts.Walk(func(key, value string) bool {
		keys = append(keys, key)
		sizes = append(sizes, len(key)+1+len(value))
		return true
	})
	for i := len(keys) - 1; i >= 0 && len(ts.String()) > maxForwardedTraceState; i-- {
		if sizes[i] > largeTraceStateMember {
			ts = ts.Delete(keys[i])
		}
	}
	for i := len(keys) - 1; i >= 0 && len(ts.String()) > maxForwardedTraceState; i-- {
		ts = ts.Delete(keys[i])
	}
	return ts
}

// injectTraceContext writes the W3C trace context of ctx into an outbound
// module request: traceparent and tracestate, serialized from the parsed span
// context. A context without a valid span context writes nothing.
func injectTraceContext(ctx context.Context, header http.Header) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return
	}
	ctx = trace.ContextWithSpanContext(ctx, sc.WithTraceState(capTraceState(sc.TraceState())))
	traceContextPropagator.Inject(ctx, propagation.HeaderCarrier(header))
}

// moduleClient is HTTPClient for a module request that carries the caller's
// trace context. A redirect is followed as HTTPClient follows it, except that
// once a hop leaves the gateway's origin, traceparent and tracestate are
// dropped from it and from every hop after it: net/http copies every header
// that is not a credential onto a redirect, wherever it points, and the trace
// context is the caller's, meant for the module behind this gateway only.
//
// The policy is set on the client HTTPClient returns, which is built per call
// and shared with nothing, so no other request's redirects change.
func (g *Gateway) moduleClient() *http.Client {
	client := g.HTTPClient()
	client.CheckRedirect = traceContextRedirectPolicy(g.baseURL)
	return client
}

// traceContextRedirectPolicy is net/http's default redirect policy (stop after
// maxRedirects) that also strips the W3C trace context from a hop once the
// chain has left base's origin. A base that does not parse has no origin, and
// every hop is stripped.
func traceContextRedirectPolicy(base string) func(*http.Request, []*http.Request) error {
	gateway, err := url.Parse(base)
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		left := err != nil || !sameOrigin(gateway, req.URL)
		for _, hop := range via {
			left = left || !sameOrigin(gateway, hop.URL)
		}
		if left {
			req.Header.Del(traceparentHeader)
			req.Header.Del(tracestateHeader)
		}
		return nil
	}
}

// sameOrigin reports whether a and b share a scheme, host and port, the port
// defaulted from the scheme when either leaves it out.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}
