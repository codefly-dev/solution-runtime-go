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
	if len(fixtures) < 20 {
		t.Fatalf("core published %d fixtures; the kit is 21, so this test is reading a trimmed set", len(fixtures))
	}

	// What each outcome means for a *carrier*, as opposed to a verifier.
	//
	// The division is Core's, read off its own classification rather than
	// decided here: the two sentinels below are properties of the bytes in
	// hand, so the moment to find them out is before a request is sent;
	// ErrRevoked is a judgement against live state, which a carrier has no way
	// to make and must not appear to; ErrInvalid spans both — a token that is
	// not two base64 segments is visibly broken, while a tampered payload or an
	// unknown key is a signature judgement.
	var carried, refusedHere, mustNotJudge, eitherWay int
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

			switch {
			case fixture.Outcome == corework.OutcomeAccepted:
				if err != nil {
					t.Fatalf("the carrier refused an accepted fixture (%s): %v", fixture.Reason, err)
				}
				if got := request.Header.Get(workcontext.HeaderName); got != fixture.Token {
					t.Error("the capability did not reach the request header")
				}
				if request.Header.Get(workcontext.InstallationIDHeaderName) == "" {
					t.Error("the installation the capability is sealed to did not travel beside it")
				}
				carried++

			case errors.Is(fixture.Err, corework.ErrUnsealed), errors.Is(fixture.Err, corework.ErrNotACoreToken):
				// The carrier's own responsibility. A capability with no
				// readable seal must not be put on a request at all: refused at
				// the far end it would name an installation mismatch for a
				// capability that never named an installation.
				if err == nil {
					t.Fatalf("the carrier accepted %s (%s): this is a property of the bytes in hand, so the refusal belongs here", fixture.Name, fixture.Reason)
				}
				if !errors.Is(err, fixture.Err) {
					t.Errorf("the carrier refused %s with %v, want Core's own %v — a refusal for the wrong reason is a different guarantee, and these two sentinels are deliberately not reachable from one errors.Is branch",
						fixture.Name, err, fixture.Err)
				}
				refusedHere++

			case errors.Is(fixture.Err, corework.ErrRevoked):
				// Live state moved under a sound capability. The carrier holds
				// none of the issuer's sources, so it cannot know — and a
				// carrier that refused these would be claiming a strength it
				// does not have, which is the silent downgrade this whole
				// single-implementation effort exists to end.
				if err != nil {
					t.Errorf("the carrier refused %s (%s) with %v: that judgement needs the issuer's live revision, replay, grant and seal sources, which this runtime does not hold",
						fixture.Name, fixture.Reason, err)
				}
				mustNotJudge++

			default:
				// ErrInvalid spans visibly-broken bytes and signature
				// judgements. Either answer is correct; refusing for some other
				// reason is not.
				if err != nil && !errors.Is(err, corework.ErrInvalid) && !errors.Is(err, corework.ErrUnsealed) {
					t.Errorf("the carrier refused %s with an error of its own (%v): the refusal of %s is Core's to classify", fixture.Name, err, fixture.Reason)
				}
				eitherWay++
			}
		})
	}

	if carried == 0 || refusedHere == 0 || mustNotJudge == 0 {
		t.Errorf("the kit exercised carried=%d refused-here=%d must-not-judge=%d: all three have to be non-zero or this test is checking one side of the boundary",
			carried, refusedHere, mustNotJudge)
	}
	t.Logf("core's kit through the carrier: %d carried, %d refused here (unsealed / not-a-core-token), %d carried because only a verifier may judge them, %d either way (ErrInvalid)",
		carried, refusedHere, mustNotJudge, eitherWay)
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
