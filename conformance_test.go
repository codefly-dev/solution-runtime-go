package solution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// Core's published conformance fixtures, driven through this package's
// *carriage* boundary.
//
// The earlier claim was that there is no conformance kit for this package to
// run, on the grounds that the kit is for verifiers and this runtime verifies
// nothing. That was half right and it was the convenient half. Minting with
// Core's fixture identities — which is what the rest of the suite does — shows
// successful carriage and nothing else: it never presents the kit's negative
// fixtures, so the refusals this package *is* responsible for were never
// exercised against the bytes Core publishes for exactly that purpose.
//
// What this runtime is responsible for is the boundary it owns: a capability it
// is handed gets carried, and one it cannot carry is refused before a call is
// made on it. So each fixture is offered to the carrier, and the assertion is
// the division of labour:
//
//   - a capability with no readable seal, and a token in another encoding, are
//     refused HERE, with Core's own sentinels. Those are properties of the
//     bytes in hand, and the moment to find them out is before a request is
//     sent rather than at the far end, where the refusal would name an
//     installation mismatch for a capability that never named an installation;
//   - a tampered payload, an unknown key, a wrong audience and a sealed value
//     the issuer has moved past are NOT refused here, and must not be. They
//     are judgements against live state and a signature, which only a verifier
//     holding the issuer's four sources can make. A carrier that refused them
//     would be claiming a strength it does not have — the silent-downgrade
//     failure this whole single-implementation effort exists to end.
//
// Running the kit this way is what makes that division checkable rather than
// asserted in a comment: if Core adds a fixture whose refusal belongs to the
// carrier, this test starts failing and the carrier has to grow.
func TestCoreConformanceFixturesThroughTheCarrier(t *testing.T) {
	fixtures, err := corework.Fixtures(time.Now())
	if err != nil {
		t.Fatalf("core conformance fixtures: %v", err)
	}
	if len(fixtures) < 39 {
		t.Fatalf("core published %d fixtures; the kit is 39 at core v0.9.0, so this test is reading a trimmed set", len(fixtures))
	}

	var carriedCount, refusedCount int
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			// Through *this package's* boundary, not the SDK's.
			//
			// This used to call workcontext.Attach directly, which a second
			// reviewer rightly said is not "through its carriage boundary": it
			// exercised sdk-go and touched no line of this runtime, so the
			// division of labour it asserts could have been true of the SDK
			// while this package did something else entirely. What carries a
			// capability here is bearerTransport, on a gateway derived for a
			// module, and that is what is driven now — the capability is put in
			// the cache the way a mint would, and a real request is made.
			request, err := carryThroughThisRuntime(t, fixture.Token)

			side, classified := boundary[fixture.Name]
			if !classified {
				t.Fatalf("core publishes a fixture this test does not classify (%s: %s). Decide which side of the carriage boundary its refusal belongs to and say so in `boundary`: a fixture nobody classified used to land in a bucket that accepted either answer, which is eight of twenty-one fixtures asserting nothing.",
					fixture.Name, fixture.Reason)
			}
			switch side {
			case carried:
				if err != nil {
					t.Fatalf("the carrier refused %s (%s) with %v: %s", fixture.Name, fixture.Reason, err, side.why())
				}
				if got := request.Header.Get(workcontext.HeaderName); got != fixture.Token {
					t.Error("the capability did not reach the request header")
				}
				if request.Header.Get(workcontext.InstallationIDHeaderName) == "" {
					t.Error("the installation the capability is sealed to did not travel beside it")
				}
				carriedCount++

			case refusedHere:
				if err == nil {
					t.Fatalf("the carrier accepted %s (%s): %s", fixture.Name, fixture.Reason, side.why())
				}
				// With one of Core's sentinels, never an error of this
				// package's own: the classification is Core's, and a refusal
				// this runtime invented a taxonomy for is the beginning of the
				// second implementation this module is gated against.
				//
				// ErrUnsealed was in this list and core v0.9.0 deleted it, for
				// a reason worth repeating: protovalidate refuses a capability
				// with no seal before anything in core's own reader is
				// reached, so no branch could produce that sentinel — and "a
				// sentinel no branch can produce is worse than no sentinel,
				// because a consumer writes a handler for it and the handler
				// never runs". An unsealed capability arrives as ErrInvalid.
				if !errors.Is(err, corework.ErrInvalid) && !errors.Is(err, corework.ErrNotACoreToken) {
					t.Errorf("the carrier refused %s with %v, which is none of Core's sentinels for a capability it cannot read", fixture.Name, err)
				}
				refusedCount++
			}
		})
	}

	if carriedCount == 0 || refusedCount == 0 {
		t.Errorf("the kit exercised carried=%d refused-here=%d: both have to be non-zero or this test is checking one side of the boundary",
			carriedCount, refusedCount)
	}
	if carriedCount+refusedCount != len(fixtures) {
		t.Errorf("classified %d of %d fixtures", carriedCount+refusedCount, len(fixtures))
	}
}

// carriage is which side of this runtime's boundary a fixture's refusal belongs
// to.
type carriage int

const (
	// carried: the capability goes on the request. Either it is sound, or
	// judging it needs something this runtime does not hold.
	carried carriage = iota
	// refusedHere: the capability never goes on a request, because what is
	// wrong with it is a property of the bytes in hand.
	refusedHere
)

func (c carriage) why() string {
	if c == carried {
		return "that judgement needs the issuer's live revision, replay, grant and seal sources, which this runtime does not hold — and a carrier that refused it would be claiming a strength it does not have, which is the silent downgrade this single-implementation effort exists to end"
	}
	return "this is a property of the bytes in hand, so the moment to find it out is before a request is sent: refused at the far end it would name an installation mismatch for a capability that never named an installation"
}

// boundary classifies every fixture Core publishes, by name, from Core's own
// stated reason for each.
//
// It is a table and not a rule because the previous version was a rule with a
// default branch, and the default accepted *either* answer for the eight
// fixtures Core refuses as ErrInvalid — a bucket spanning "not two base64
// segments", which this runtime must catch, and "one byte of the payload
// changed", which only a signature can catch. Eight of twenty-one fixtures
// therefore asserted nothing, and a reviewer showed the committed test passing
// with the runtime's carriage validation removed.
//
// The division itself is unchanged and is Core's: what is visible in the bytes
// is refused here, and what needs the issuer's four sources is carried.
var boundary = map[string]carriage{
	// Sound capabilities. They travel.
	"session":             carried,
	"operation":           carried,
	"delegated":           carried,
	"delegated-operation": carried,
	"grant":               carried,

	// Not the token shape at all: no separator, nothing after it, a payload
	// that is not base64, or nothing. Visible without a key, so this runtime
	// refuses them rather than sending a request that cannot succeed.
	"empty-token":     refusedHere,
	"no-separator":    refusedHere,
	"separator-only":  refusedHere,
	"payload-not-b64": refusedHere,

	// No readable seal. The carrier has to put the installation beside the
	// capability, and a capability that names none cannot be carried — Core
	// calls the one with a partial seal invalid and this runtime calls it
	// unsealed, which is the same refusal reached one field earlier.
	"missing-seal":              refusedHere,
	"seal-without-installation": refusedHere,

	// A genuinely signed token in another encoding. Refused as a foreign format
	// before any signature is considered, which is the diagnosis Core's own
	// fixture exists to protect.
	"foreign-encoding": refusedHere,

	// Signature judgements. A tampered payload and a key the verifier does not
	// hold are indistinguishable from a sound capability without the issuer's
	// keys, and an audience is a claim inside the payload — this runtime holds
	// none of what it would take to say so, and the far end says so for a
	// living.
	"tampered-payload": carried,
	"unknown-key":      carried,
	"another-audience": carried,

	// Live state moved under a sound capability: an installation revision, a
	// build incarnation, a principal epoch, a binding revision. Judging these
	// is exactly what a carrier cannot do.
	"stale-installation-revision":  carried,
	"future-installation-revision": carried,
	"unknown-installation":         carried,
	"stale-build-incarnation":      carried,
	"stale-principal-epoch":        carried,
	"wrong-binding-revision":       carried,
	// --- core v0.9.0 added eighteen fixtures. Each is classified by the one
	// question this boundary turns on: is the defect visible in the BYTES IN
	// HAND, or is it a judgement against the issuer's live state and keys?

	// Schema violations, refused by protovalidate inside core's own decode —
	// which this runtime's carrier reaches, because reading the sealed
	// installation decodes the claims. A counter at zero names nothing and
	// would compare equal to a source holding nothing; half a binding and half
	// an execution are not one; an unknown field nested in the seal lets data
	// ride inside a signed credential nothing here reads. All structural, all
	// decidable without a key.
	"zero-principal-epoch":       refusedHere,
	"zero-installation-revision": refusedHere,
	"zero-build-incarnation":     refusedHere,
	"seal-half-execution":        refusedHere,
	"partial-operation-binding":  refusedHere,
	"actor-without-epoch":        refusedHere,
	"unknown-field":              refusedHere,

	// Judgements this runtime cannot make. The issuer's identity is a claim
	// and the key is not the trust decision; a validity window needs a clock
	// this carrier does not apply; and every remaining one compares a sealed
	// value against live state only the issuer holds — an approved build, a
	// principal's epoch, an authorization revision, a binding's revision,
	// incarnation, grantee or installation. A carrier that refused any of
	// these would be claiming a strength it does not have.
	"another-issuer":                    carried,
	"expired":                           carried,
	"not-yet-valid":                     carried,
	"execution-missing":                 carried,
	"unapproved-build":                  carried,
	"stale-actor-epoch":                 carried,
	"superseded-authorization-revision": carried,
	"revoked-operation-binding":         carried,
	"wrong-binding-incarnation":         carried,
	"binding-of-another-principal":      carried,
	"binding-in-another-installation":   carried,
}

// carryThroughThisRuntime drives one capability through this package's carriage
// path and returns the request that reached the far end, or the refusal that
// stopped it before anything was sent.
//
// The path is the real one: a Gateway derived by ForModule holds a delegation,
// bearerTransport resolves the capability per round trip and attaches it, and
// the request only leaves if that succeeds. A capability this runtime cannot
// carry therefore has to fail here, before a module is called — which is the
// property the kit is being used to check, and the one that cannot be observed
// by calling the SDK directly.
func carryThroughThisRuntime(t *testing.T, token string) (*http.Request, error) {
	t.Helper()
	var reached *http.Request
	far := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.Clone(context.Background())
		writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	}))
	defer far.Close()

	gateway := newGateway(far.URL, "Bearer viewer", "org-1", "session-1")
	// The capability as a mint would have left it in the cache, so the
	// transport resolves this exact token rather than minting another.
	const key = "conformance"
	gateway.delegation = &delegation{key: key}
	if _, err := gateway.contexts.resolve(context.Background(), key,
		func(context.Context) (string, time.Time, error) {
			return token, time.Now().Add(time.Hour), nil
		}); err != nil {
		// The cache refused to hold it at all, which is this runtime refusing
		// to carry it — the same answer as a refusal at attach time.
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, far.URL+"/v1/things/search", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := gateway.HTTPClient().Do(request)
	if err != nil {
		return nil, unwrapURLError(err)
	}
	_ = resp.Body.Close()
	if reached == nil {
		t.Fatal("the far end was not reached and nothing refused the call")
	}
	return reached, nil
}

// unwrapURLError returns what a transport refusal actually was: http.Client
// wraps a RoundTrip error in *url.Error, which errors.Is sees through but a
// reader of the message does not.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}
