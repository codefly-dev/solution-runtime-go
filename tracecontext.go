package solution

import (
	"context"
	"net/http"

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
	sc := trace.SpanContextFromContext(traceContextPropagator.Extract(context.Background(), propagation.HeaderCarrier(r.Header)))
	if sc.IsValid() {
		sc = sc.WithTraceState(capTraceState(sc.TraceState()))
	} else {
		sc = trace.SpanContext{}
	}
	return r.WithContext(trace.ContextWithRemoteSpanContext(r.Context(), sc))
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
