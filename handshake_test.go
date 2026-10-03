package solution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// What this file is for: every test here completes, or fails to complete, a
// real TLS 1.3 mutual-authentication handshake against the configuration this
// runtime would actually serve or dial with, and then asks what identity was on
// the wire.
//
// That is the only way to answer the question the posture checks kept getting
// wrong. A check that reads a *tls.Config and approves it is answering "is this
// configuration's description acceptable", and four separate shapes were
// demonstrated describing one identity and serving another: an SNI-keyed
// callback, a NameToCertificate map, a static certificate Go reaches without
// consulting the callback, and a tls.Certificate.Leaf that did not match its
// own DER. Nothing short of a handshake distinguishes those from a conforming
// configuration, so the tests do handshakes.
//
// net.Pipe rather than a socket, for the inbound ones: the subject is which
// certificate crypto/tls selected, which is settled before a byte of
// application data moves, and an in-memory pipe keeps it that way with no port
// to bind. The outbound ones use a real httptest TLS server, because what they
// assert is what the production http.Transport does with a connection.

// rivalPrincipal is a second workload in the same cell: a valid identity, under
// the same anchor, that this workload must never be able to present or serve.
const rivalPrincipal = "spiffe://codefly.test/ns/solutions/sa/rival"

// handshook is one handshake's outcome from both ends. Both are needed: in TLS
// 1.3 the client finishes before it learns whether the server accepted its
// certificate, so "the server refused this caller" is only visible on the
// server's side, while "which certificate was served" is only visible on the
// client's.
type handshook struct {
	served            *x509.Certificate
	serverErr, cliErr error
}

// refused reports that the handshake did not complete as an authenticated
// connection, from whichever side noticed.
func (h handshook) refused() bool { return h.serverErr != nil || h.cliErr != nil }

func (h handshook) reason() string {
	switch {
	case h.serverErr != nil:
		return h.serverErr.Error()
	case h.cliErr != nil:
		return h.cliErr.Error()
	}
	return ""
}

// servedTo performs one handshake against config, as a caller presenting
// caller, and reports the identity the caller was shown.
//
// The caller skips verification deliberately: the question is which certificate
// this listener selected, not whether a test client trusts it, and a client
// that verified would refuse before reporting what it saw. An empty serverName
// is a no-SNI hello — what a peer addressing a pod by IP sends, and the case
// the previous synthetic "localhost" probe never exercised.
func servedTo(t *testing.T, config *tls.Config, caller *tls.Certificate, serverName string) handshook {
	t.Helper()
	callerSide, listenerSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		listener := tls.Server(listenerSide, config)
		done <- listener.Handshake()
		_ = listener.Close()
	}()

	client := tls.Client(callerSide, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{*caller},
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
	})
	outcome := handshook{cliErr: client.Handshake()}
	if outcome.cliErr == nil {
		if state := client.ConnectionState(); len(state.PeerCertificates) > 0 {
			outcome.served = state.PeerCertificates[0]
		}
		// Drained while the listener finishes, because net.Pipe is unbuffered:
		// a TLS 1.3 server writes session tickets after the client's Finished,
		// and with nobody reading them its Handshake never returns.
		go func() { _, _ = io.Copy(io.Discard, client) }()
	}
	outcome.serverErr = <-done
	_ = callerSide.Close()
	return outcome
}

// identityOf is the SPIFFE ID a served certificate names, or "" for none.
func identityOf(leaf *x509.Certificate) string {
	if leaf == nil || len(leaf.URIs) == 0 {
		return ""
	}
	return leaf.URIs[0].String()
}

// shapeShifter is a consumer's IdentitySource that describes one identity and
// can serve another. Each field turns on one of the four demonstrated shapes;
// none of them is exotic, and all four passed the posture checks.
type shapeShifter struct {
	approved, rival *tls.Certificate
	roots           *x509.CertPool

	// keyedOnSNI serves approved for a hello naming "localhost" and rival for
	// anything else, including the no-SNI hello a peer addressed by IP sends.
	keyedOnSNI bool
	// rivalForNamed is the same trick the other way round: conforming for the
	// no-SNI hello a boot-time check can ask with, and the rival for a hello
	// that names anything. It is the case no probe can catch, whatever name the
	// probe uses, and the reason the selection is wrapped rather than sampled.
	rivalForNamed bool
	// byName puts both certificates in NameToCertificate, which crypto/tls
	// consults when there is more than one.
	byName bool
	// staticRivalBeside lists the rival first among several certificates and
	// returns approved from GetCertificate. Go consults the callback only when
	// the hello carries a name, and picks the first compatible chain from the
	// list otherwise — so this is a configuration whose served identity is
	// decided by selection, which is why selection is refused outright.
	staticRivalBeside bool
	// staticRival carries rival in Certificates while GetCertificate returns
	// approved. Go consults GetCertificate only when there is no certificate
	// list or the hello carries a name, so a no-SNI caller gets the static one.
	staticRival bool
	// lyingLeaf hands back a pair whose Leaf field describes approved and whose
	// DER is rival's.
	lyingLeaf bool
	// perConnection moves whichever shape is selected behind
	// GetConfigForClient, the callback this runtime's own default source uses.
	perConnection bool
}

func (s shapeShifter) ServerTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  s.roots,
	}
	s.apply(config)
	if !s.perConnection {
		return config, nil
	}
	// The conforming shape at the top level, the shifting one per connection.
	base := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      s.roots,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.approved, nil },
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return config, nil }
	return base, nil
}

func (s shapeShifter) apply(config *tls.Config) {
	switch {
	case s.byName:
		config.Certificates = []tls.Certificate{*s.approved, *s.rival}
		config.NameToCertificate = map[string]*tls.Certificate{"localhost": s.rival}
	case s.staticRivalBeside:
		config.Certificates = []tls.Certificate{*s.rival, *s.approved}
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.approved, nil }
	case s.staticRival:
		config.Certificates = []tls.Certificate{*s.rival}
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.approved, nil }
	case s.lyingLeaf:
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			lying := *s.rival
			lying.Leaf = leafOf(s.approved)
			return &lying, nil
		}
	case s.keyedOnSNI:
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "localhost" {
				return s.approved, nil
			}
			return s.rival, nil
		}
	case s.rivalForNamed:
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				return s.approved, nil
			}
			return s.rival, nil
		}
	default:
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.approved, nil }
	}
}

func leafOf(pair *tls.Certificate) *x509.Certificate {
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		panic(err)
	}
	return leaf
}

// TestTheCertificateServedIsTheCertificateChecked is the blocker, reproduced.
//
// The check it replaces called GetCertificate with a hello naming "localhost",
// parsed what came back, compared it to the frozen principal, and left the
// configuration untouched. Four handshakes completed under configurations that
// had passed it, serving a neighbouring workload's leaf — which is the identity
// the host, the gateway and the issuer hold this process to, and the identity a
// presence document names.
//
// Each case must now either be refused at boot or refuse the handshake. What it
// must never do is complete a handshake presenting the rival: a listener whose
// served identity depends on the hello it receives is a listener whose identity
// is the caller's choice.
func TestTheCertificateServedIsTheCertificateChecked(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	rival := c.identity(t, rivalPrincipal)
	caller := c.identity(t, testGatewayPrincipal)

	for _, tc := range []struct {
		name  string
		shape shapeShifter
		// sni is the hello this shape serves the rival for.
		sni string
	}{
		{
			name:  "a callback keyed on the server name, asked with the name nothing dials by",
			shape: shapeShifter{keyedOnSNI: true},
		},
		{
			name:  "a callback keyed on the server name, behind the per-connection callback",
			shape: shapeShifter{keyedOnSNI: true, perConnection: true},
		},
		{
			name:  "a callback that answers any boot-time probe correctly and the real hello otherwise",
			shape: shapeShifter{rivalForNamed: true},
			sni:   "localhost",
		},
		{
			name:  "the same, behind the per-connection callback",
			shape: shapeShifter{rivalForNamed: true, perConnection: true},
			sni:   "localhost",
		},
		{
			name:  "name selection among several certificates",
			shape: shapeShifter{byName: true},
			sni:   "localhost",
		},
		{
			name:  "selection among several certificates beside a conforming callback",
			shape: shapeShifter{staticRivalBeside: true},
		},
		{
			name:  "a static certificate Go reaches without consulting the callback",
			shape: shapeShifter{staticRival: true},
		},
		{
			name:  "a cached Leaf that does not describe its own DER",
			shape: shapeShifter{lyingLeaf: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shape := tc.shape
			shape.approved, shape.rival, shape.roots = approved, rival, c.roots
			server := New(Manifest{ID: testSolutionID}).Identity(shape)
			server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal), mintPeersFile: identitiesFile(t, testGatewayPrincipal),
				gatewayPeersFile: identitiesFile(t, testGatewayPrincipal)}
			server.principal = testPrincipal

			config, err := server.serverIdentity()
			if err != nil {
				// Refused at boot, which is the better of the two outcomes:
				// nothing is served and the mint has not happened yet. But
				// only for the right reason — returning on *any* boot error
				// made every case here pass the moment serverIdentity failed
				// over an unresolved path or an unreadable admission set,
				// which is a test reporting success for a cause it never
				// exercised.
				if !mentionsTheCertificate(err) {
					t.Fatalf("the boot refused this source for something other than the certificate it would serve, so this case never ran: %v", err)
				}
				return
			}
			outcome := servedTo(t, config, caller, tc.sni)
			if got := identityOf(outcome.served); got == rivalPrincipal {
				t.Fatalf("the listener served %s: the configuration passed every posture check describing %s, and the certificate on the wire is the identity the host holds this process to",
					got, testPrincipal)
			}
			if !outcome.refused() && identityOf(outcome.served) != testPrincipal {
				t.Fatalf("a handshake completed serving %q, which is neither this workload's principal nor a refusal", identityOf(outcome.served))
			}
			if outcome.refused() && !strings.Contains(outcome.reason(), "certificate") {
				t.Errorf("the handshake was refused with %q, which does not say it was about the certificate", outcome.reason())
			}
		})
	}

	t.Run("and the conforming shape still serves", func(t *testing.T) {
		// The control. Without it, refusing every handshake would pass every
		// case above, which is not a listener.
		shape := shapeShifter{approved: approved, rival: rival, roots: c.roots}
		server := New(Manifest{ID: testSolutionID}).Identity(shape)
		server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal), mintPeersFile: identitiesFile(t, testGatewayPrincipal),
			gatewayPeersFile: identitiesFile(t, testGatewayPrincipal)}
		server.principal = testPrincipal
		config, err := server.serverIdentity()
		if err != nil {
			t.Fatalf("a conforming source was refused: %v", err)
		}
		outcome := servedTo(t, config, caller, "")
		if outcome.refused() {
			t.Fatalf("a conforming listener refused a handshake from an admitted caller: %v", outcome.reason())
		}
		if got := identityOf(outcome.served); got != testPrincipal {
			t.Errorf("the listener served %q, want this workload's own %q", got, testPrincipal)
		}
	})
}

// TestANilPerConnectionAnswerCannotDropTheTrustAnchor: a callback answering nil
// means "serve the base configuration", and the base was admitted at boot only
// because a callback would resolve the anchor per handshake. A source that
// answers for one hello and not another therefore served a listener that
// requires a caller's certificate and verifies it against this host's system
// roots — mutual TLS in every log line, and a client certificate from any
// public CA admitted.
func TestANilPerConnectionAnswerCannotDropTheTrustAnchor(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	caller := c.identity(t, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID}).Identity(conditionalAnchor{approved: approved, roots: c.roots})
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal), mintPeersFile: identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		return // refused at boot is also fail-closed
	}
	outcome := servedTo(t, config, caller, "")
	if !outcome.refused() {
		t.Fatalf("a handshake completed under a configuration with no trust anchor: the callback answered nothing for this hello, so the base configuration served — and it verifies a caller's certificate against this host's system roots")
	}
	if !strings.Contains(outcome.reason(), "anchor") {
		t.Errorf("the refusal %q does not name the missing anchor", outcome.reason())
	}
	// The answered case still works, or this is a listener that refuses
	// everything rather than one that refuses the hole.
	if outcome := servedTo(t, config, caller, "localhost"); outcome.refused() {
		t.Errorf("the handshake the source does answer for was refused: %v", outcome.reason())
	}
}

// conditionalAnchor resolves the anchor per handshake for a hello naming
// "localhost" and answers nothing for any other, with no anchor on the base
// configuration to fall back to.
type conditionalAnchor struct {
	approved *tls.Certificate
	roots    *x509.CertPool
}

func (a conditionalAnchor) ServerTLSConfig() (*tls.Config, error) {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return a.approved, nil },
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "localhost" {
			return nil, nil
		}
		answered := base.Clone()
		answered.ClientCAs = a.roots
		answered.GetConfigForClient = nil
		return answered, nil
	}
	return base, nil
}

// TestTheAdmittedCallerSetIsResolvedPerHandshake: the set was read once at
// boot, and a snapshotted admission decision has the defect this runtime
// already refuses to accept for the trust anchor. Removing a compromised
// consumed module from the provisioned set left this listener admitting it
// until somebody restarted the process.
//
// The drift here is a rewrite of the provisioned file, which is what a platform
// rotating an admission set actually does. The previous version of this test
// drifted the set by mutating a closure the test itself supplied, and passed
// against a runtime where no deployment could drift it at all: the set was read
// through the SDK's value accessor, which is fixed at process start, so the
// production answer never changed and only the test's closure did.
func TestTheAdmittedCallerSetIsResolvedPerHandshake(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	caller := c.identity(t, testGatewayPrincipal)

	provisioned := identitiesFile(t, testGatewayPrincipal)
	server := New(Manifest{ID: testSolutionID}).Identity(shapeShifter{approved: approved, roots: c.roots})
	server.cfg = config{
		allowedCallersFile: provisioned,
		mintPeersFile:      identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile:   identitiesFile(t, testGatewayPrincipal),
	}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if outcome := servedTo(t, config, caller, ""); outcome.refused() {
		t.Fatalf("an admitted caller was refused: %v", outcome.reason())
	}

	// The platform removes that caller from the file. No restart, no new
	// listener.
	writeFile(t, provisioned, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")
	outcome := servedTo(t, config, caller, "")
	if !outcome.refused() {
		t.Fatal("a caller removed from the provisioned set was still admitted: the listener is judging by the set it booted with, so revocation needs a restart somebody has to remember to perform")
	}

	// A set that resolves to nothing refuses, rather than falling back to the
	// set this process booted with.
	writeFile(t, provisioned, "\n")
	if outcome := servedTo(t, config, caller, ""); !outcome.refused() {
		t.Fatal("a caller was admitted while the provisioned set resolved to nothing: an admission decision that cannot be resolved is not one to guess at")
	}

	// And so does one that cannot be read at all, for the same reason: an
	// unreadable set is not an empty set and it is not the boot set either.
	if err := os.Remove(provisioned); err != nil {
		t.Fatal(err)
	}
	if outcome := servedTo(t, config, caller, ""); !outcome.refused() {
		t.Fatal("a caller was admitted while the provisioned set could not be read: the only safe reading of an unreadable admission set is to refuse")
	}
}

// TestTheProvisionedCallerSetIsReadThroughLoadConfig is the other half: the
// path production reads has to be the one loadConfig resolves, through the
// documented override, and the content has to be re-read rather than captured.
//
// It is the test that could not have been written before. The set was a
// configuration *value*, and a configuration value is fixed at process start —
// inline or file-carried, the SDK reads it once and keeps it (sdk-go
// file_carrier.go) — so "re-resolved per handshake" returned the boot answer
// forever, and the only way to make a test show drift was to drift something no
// platform touches. Here the test changes what the platform changes.
func TestTheProvisionedCallerSetIsReadThroughLoadConfig(t *testing.T) {
	callers := identitiesFile(t, testGatewayPrincipal)
	t.Setenv(IdentityAllowedCallersFileEnvironmentVariable, callers)
	peers := identitiesFile(t, testGatewayPrincipal)
	t.Setenv(IdentityMintPeersFileEnvironmentVariable, peers)

	cfg := loadConfig(context.Background())
	if cfg.allowedCallersFile != callers {
		t.Fatalf("loadConfig resolved the caller set from %q, want the provisioned %q", cfg.allowedCallersFile, callers)
	}
	if cfg.mintPeersFile != peers {
		t.Fatalf("loadConfig resolved the mint peer set from %q, want the provisioned %q", cfg.mintPeersFile, peers)
	}

	server := New(Manifest{ID: testSolutionID})
	server.cfg = cfg
	admits := server.admittedCallers()
	got, err := admits()
	if err != nil {
		t.Fatalf("resolve the admitted callers: %v", err)
	}
	if len(got) != 1 || got[0] != testGatewayPrincipal {
		t.Fatalf("the admitted callers resolved to %v, want %q", got, testGatewayPrincipal)
	}

	// The platform rewrites it. Nothing restarts.
	writeFile(t, callers, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")
	got, err = admits()
	if err != nil {
		t.Fatalf("resolve the admitted callers after the set was rewritten: %v", err)
	}
	if len(got) != 1 || got[0] != "spiffe://codefly.test/ns/platform/sa/somebody-else" {
		t.Fatalf("the admitted callers resolved to %v after the provisioned set was rewritten: it is reading something it captured", got)
	}
}

// TestAnAdmissionSetIsNeitherCachedNorDefaulted pins the two answers that are
// not an identity list, since each one has a plausible-looking wrong behaviour:
// falling back to the boot set, or treating an empty file as "admit nobody" and
// carrying on.
func TestAnAdmissionSetIsNeitherCachedNorDefaulted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		write   bool
	}{
		{"an empty file", "", true},
		{"a file of only separators", ",,\n\n", true},
		{"a file of only comments", "# the gateway, once\n", true},
		{"no file at all", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identities")
			if tc.write {
				writeFile(t, path, tc.content)
			}
			if _, err := resolvedIdentities(path, "unresolved")(); err == nil {
				t.Error("an unusable admission set resolved without an error, so a handshake would be judged by something other than the provisioned set")
			}
		})
	}
	// And the path itself being unset is refused, not read as "no restriction".
	if _, err := resolvedIdentities("", "unresolved")(); err == nil {
		t.Error("an unset admission path resolved without an error")
	}
}

// platformHost is a platform endpoint — the mint, the gateway — served under
// the cell's anchor, requiring the caller's certificate, recording who called.
type platformHost struct {
	*httptest.Server
	callers chan string
}

func newPlatformHost(t *testing.T, c *cell, identity string) *platformHost {
	t.Helper()
	host := &platformHost{callers: make(chan string, 64)}
	host.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case host.callers <- callerIdentity(r):
		default:
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	}))
	host.Server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*c.identity(t, identity)},
		ClientCAs:    c.roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	host.Server.StartTLS()
	t.Cleanup(host.Close)
	return host
}

func (h *platformHost) called() []string {
	var seen []string
	for {
		select {
		case caller := <-h.callers:
			seen = append(seen, caller)
		default:
			return seen
		}
	}
}

// TestTheOutboundLeafIsHeldWhenItIsPresented: a projection that rotates to a
// neighbouring workload's identity before anything is dialled is refused, and
// the rival never reaches the platform.
//
// What this does NOT prove, despite its name, is that the hold runs at the
// moment of presentation. The outbound configuration is rebuilt per dial, so
// the check made while building it is already at-use for this case, and
// removing the wrapper around the callback leaves this test passing. The
// at-use half — a rotation landing between that check and the handshake — is
// TestARotationBetweenTheCheckAndTheHandshakeIsRefused, and the wrapper is
// driven directly by TestTheOutboundHoldRefusesTheAnswerAHandshakeGets.
// Saying so here because a test whose name claims the stronger property is
// how the weaker one gets mistaken for coverage.
func TestTheOutboundLeafIsHeldWhenItIsPresented(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The destination this test dials, so the authorization set for it is
		// the mint's: the set is chosen per destination now.
		mintURL: host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}

	// The projection is replaced after the client was built and before anything
	// was dialled: the window the preflight left open.
	rivalCert, rivalKey, _, _, _ := c.workload(t, rivalPrincipal)
	writeFile(t, certFile, readFile(t, rivalCert))
	writeFile(t, keyFile, readFile(t, rivalKey))

	resp, err := client.Get(host.URL + credentialMintPath)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the mint was called after the projected pair rotated to another workload's identity: the check ran before the handshake, and the handshake presented whatever the reloader held by then")
	}
	if !strings.Contains(err.Error(), rivalPrincipal) || !strings.Contains(err.Error(), testPrincipal) {
		t.Errorf("the refusal %q does not name both the identity that would have been presented and this workload's frozen principal", err)
	}
	for _, caller := range host.called() {
		if caller == rivalPrincipal {
			t.Error("the platform saw a request from the rival identity")
		}
	}
}

// TestTheOutboundPeerMustBeAProvisionedPlatformIdentity: verifying the chain
// and the hostname says a destination holds a certificate this cell issued,
// which every workload in the cell does. A neighbouring workload answering at
// the gateway's address under a certificate valid for that address completed
// this handshake and was handed the projected token, the viewer's bearer and
// this workload's own credential.
func TestTheOutboundPeerMustBeAProvisionedPlatformIdentity(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)

	build := func(t *testing.T, host *platformHost) *http.Client {
		t.Helper()
		server := New(Manifest{ID: testSolutionID})
		server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
			mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
			gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
			mintURL:          host.URL + credentialMintPath}
		server.principal = testPrincipal
		client, err := server.outboundClient(nil)
		if err != nil {
			t.Fatalf("outboundClient: %v", err)
		}
		return client
	}

	t.Run("the provisioned platform identity is dialled", func(t *testing.T) {
		host := newPlatformHost(t, c, testGatewayPrincipal)
		resp, err := build(t, host).Get(host.URL + credentialMintPath)
		if err != nil {
			t.Fatalf("the provisioned platform destination was refused: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("another workload at the same address is not", func(t *testing.T) {
		// A valid certificate from the same anchor, valid for this address,
		// naming a workload that is not the platform.
		host := newPlatformHost(t, c, rivalPrincipal)
		resp, err := build(t, host).Get(host.URL + credentialMintPath)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("this workload's credentials were presented to a destination that is not a provisioned platform identity: a chain and a hostname do not distinguish the gateway from any other workload in the cell")
		}
		if !strings.Contains(err.Error(), rivalPrincipal) {
			t.Errorf("the refusal %q does not name the identity that answered", err)
		}
	})
}

// TestABusyConnectionDoesNotOutliveTheTrustThatAuthenticatedIt is the second
// blocker, reproduced.
//
// Per-dial reloading was documented as bounding outbound trust staleness to
// IdleConnTimeout, and that bound only exists for a connection nobody is using.
// A connection carrying a request every 100ms was demonstrated still answering
// 31 seconds after the server's root was removed from the bundle, over a single
// handshake: traffic held the connection, and the trust decision behind it,
// open indefinitely. The committed test for per-dial reloading closed idle
// connections, which is exactly the case this one does not.
func TestABusyConnectionDoesNotOutliveTheTrustThatAuthenticatedIt(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The destination this test dials, so the authorization set for it is
		// the mint's: the set is chosen per destination now.
		mintURL: host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}

	// The control first, and it is the half that was missing: while trust is
	// intact, a connection kept this busy has to keep working across several
	// recheck intervals. Without this, a recheck that closed every connection
	// unconditionally — or one that closed them for an unrelated reason —
	// satisfied the assertion below and the test reported the guarantee.
	staysUsable(t, client, host.URL+credentialMintPath, 3*outboundTrustRecheckInterval)

	// The root is removed and replaced by an unrelated one: the bundle still
	// parses and no longer contains the issuer of the certificate the platform
	// presents. Nothing closes the connection, and traffic keeps arriving.
	other := newCell(t)
	writeFile(t, bundleFile, string(other.anchorPEM))

	err = busyUntilRefused(t, client, host.URL+credentialMintPath, 3*outboundTrustRecheckInterval)
	if err == nil {
		t.Fatalf("requests still succeeded %s after the platform's root was removed from the bundle, on a connection kept busy throughout: an inactivity timeout cannot bound a connection that is never inactive, so the documented staleness window held only for a quiet process",
			3*outboundTrustRecheckInterval)
	}
	// And it ended for the reason under test. Any-error was what let two
	// mutants through: a recheck broken in a way that fails requests for some
	// other cause looks identical to one that works.
	if !mentionsTrustFailure(err) {
		t.Errorf("the connection stopped being usable, but not over the peer's trust: %v", err)
	}
}

// staysUsable keeps one connection busy for d and fails if a request stops
// succeeding. It is the survive-control for every recheck test here.
func staysUsable(t *testing.T, client *http.Client, url string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("a request failed while trust was intact, so nothing this test goes on to assert is about trust being withdrawn: %v", err)
		}
		_ = resp.Body.Close()
		time.Sleep(outboundTrustRecheckInterval / 20)
	}
}

// busyUntilRefused keeps one connection busy until a request fails, and returns
// that error — or nil if requests were still succeeding after d, which is the
// defect these tests exist to catch.
func busyUntilRefused(t *testing.T, client *http.Client, url string, d time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(outboundTrustRecheckInterval / 20)
	}
}

// mentionsTrustFailure reports whether an error is the recheck's own judgement
// about the peer, rather than any other way a request can fail.
func mentionsTrustFailure(err error) bool {
	// Both the recheck's own judgement and the refusal a *re-dial* makes
	// count: once the recheck closes the connection, net/http dials again, and
	// that dial is refused by the same anchor and peer set. What must not pass
	// is an error from anywhere else.
	for _, named := range []string{
		"no longer verifies",
		"no longer one this runtime presents",
		"no longer one this solution admits",
		"refusing to present this workload's credentials",
		"certificate signed by unknown authority",
		"certificate is not trusted",
	} {
		if strings.Contains(err.Error(), named) {
			return true
		}
	}
	return false
}

// TestEveryPlatformConnectionIsWatched is the narrow half of the test above: it
// is the production transport's own dialler that has to attach the recheck, not
// a wrapper a test builds.
//
// It asserts the recheck's *behaviour* on the dialled connection, not its type.
// A type assertion on the wrapper proves the transport returned something
// named right, which survives a recheck that never fires — and a mutant that
// stopped the ticker left this test green.
func TestEveryPlatformConnectionIsWatched(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The destination this test dials, so the authorization set for it is
		// the mint's: the set is chosen per destination now.
		mintURL: host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("outbound transport is %T, want *http.Transport", client.Transport)
	}
	if transport.DialTLSContext == nil {
		t.Fatal("the outbound transport has no TLS dialler of its own, so every connection it makes is configured once and never re-judged")
	}
	address := strings.TrimPrefix(host.URL, "https://")
	conn, err := transport.DialTLSContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial the platform: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The connection is usable, and stays usable while trust holds.
	if _, err := conn.Write([]byte("GET " + credentialMintPath + " HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatalf("the dialled connection was not usable: %v", err)
	}
	time.Sleep(2 * outboundTrustRecheckInterval)

	// Now the root goes, and this connection — which no transport is polling,
	// so nothing but its own watcher can notice — has to close itself.
	other := newCell(t)
	writeFile(t, bundleFile, string(other.anchorPEM))

	deadline := time.Now().Add(5 * outboundTrustRecheckInterval)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(outboundTrustRecheckInterval / 4))
		var buf [1]byte
		_, err := conn.Read(buf[:])
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return // the watcher closed it, which is the whole point
		}
		if time.Now().After(deadline) {
			t.Fatalf("a connection the transport dialled was still open %s after the platform's root was removed: a connection whose trust is never re-verified is bounded only by how long it stays idle, which traffic prevents",
				5*outboundTrustRecheckInterval)
		}
	}
}

// TestALateSupersessionDoesNotEvictANewerCapability: the cache evicted by key
// alone, and two concurrent calls reach that without anything unusual. Both
// present carrier-1; the first refusal evicts it; a third call mints carrier-2;
// then the second, late refusal — still about carrier-1 — deleted carrier-2. The
// result is a third audited mint and a discarded capability nothing refused.
func TestALateSupersessionDoesNotEvictANewerCapability(t *testing.T) {
	cache := newWorkContextCache()
	var minted int
	issue := func(context.Context) (string, time.Time, error) {
		minted++
		return fmt.Sprintf("carrier-%d", minted), time.Now().Add(time.Hour), nil
	}
	const key = "things"

	first, err := cache.resolve(context.Background(), key, issue)
	if err != nil {
		t.Fatal(err)
	}
	// Two outstanding requests hold first. One is refused, which evicts it.
	cache.supersede(key, first)
	second, err := cache.resolve(context.Background(), key, issue)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("a superseded capability was served again: %q", second)
	}
	// The other request's refusal arrives now. It is about first.
	cache.supersede(key, first)

	third, err := cache.resolve(context.Background(), key, issue)
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Errorf("the cache minted %q after a late refusal naming a capability it no longer held: a refusal for one carrier evicted a newer one by key alone, costing an audited mint and discarding a capability nothing had refused", third)
	}
	if minted != 2 {
		t.Errorf("minted %d capabilities, want 2: one for the ask and one for the supersession it actually had", minted)
	}
}

// rotatingIdentity is a consumer's source whose leaf changes between calls:
// conforming the first time it is asked, a neighbouring workload's after that.
//
// It is the shape of a real rotation — the platform replaces the projected pair
// under a running process, deliberately and often — compressed so a test can
// land it in the window between a check and the handshake that check was meant
// to cover. Nothing about it is adversarial; the first call being the one a
// preflight makes is the whole defect.
type rotatingIdentity struct {
	approved, rival *tls.Certificate
	roots           *x509.CertPool
	asked           *int
}

func (r rotatingIdentity) ServerTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  r.roots,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			*r.asked++
			if *r.asked == 1 {
				return r.approved, nil
			}
			return r.rival, nil
		},
	}, nil
}

// TestARotationBetweenTheCheckAndTheHandshakeIsRefused is the outbound
// check/use gap on its own.
//
// The outbound configuration is rebuilt per dial, so its preflight runs close
// to the handshake — close enough that a file rotation rarely lands between
// them, which is why the busy-connection and rotation tests above cannot tell
// the preflight from the wrapper. A source asked twice can: the first answer is
// the one the check reads, the second is the one the handshake sends. Only
// holding the pair at presentation refuses that.
func TestARotationBetweenTheCheckAndTheHandshakeIsRefused(t *testing.T) {
	c := newCell(t)
	host := newPlatformHost(t, c, testGatewayPrincipal)
	asked := 0
	source := rotatingIdentity{approved: c.identity(t, testPrincipal), rival: c.identity(t, rivalPrincipal), roots: c.roots, asked: &asked}

	server := New(Manifest{ID: testSolutionID}).Identity(source)
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal), mintPeersFile: identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		mintURL:          host.URL + credentialMintPath}
	server.principal = testPrincipal
	identity, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("the first answer is this workload's own, so the boot must not be refused: %v", err)
	}
	client, err := server.outboundClient(identity)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	resp, err := client.Get(host.URL + credentialMintPath)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("the platform was dialled with the certificate the source produced *after* the one that was checked (asked %d times): a check that samples the source and leaves its callback installed is a check a rotation walks past",
			asked)
	}
	if !strings.Contains(err.Error(), rivalPrincipal) {
		t.Errorf("the refusal %q does not name the identity that would have been presented", err)
	}
	for _, caller := range host.called() {
		if caller == rivalPrincipal {
			t.Error("the platform saw a request from the rival identity")
		}
	}
}

// TestTheOutboundHoldRefusesTheAnswerAHandshakeGets is the same property as a
// unit, because the end-to-end window is too small to wedge a test into on the
// default path: the outbound configuration is rebuilt per dial, so its
// boot-time refusal runs microseconds before the handshake it covers. What
// closes the window is that the callback itself is wrapped, so the pair a
// handshake asks for is the pair that is compared — and that is checkable
// directly.
func TestTheOutboundHoldRefusesTheAnswerAHandshakeGets(t *testing.T) {
	c := newCell(t)
	approved, rival := c.identity(t, testPrincipal), c.identity(t, rivalPrincipal)
	asked := 0
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    c.roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			asked++
			if asked == 1 {
				return approved, nil
			}
			return rival, nil
		},
	}
	if err := holdPresentedCertificate(config, testPrincipal); err != nil {
		t.Fatalf("the first answer is this workload's own, so the hold must accept it: %v", err)
	}
	pair, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err == nil {
		t.Fatalf("the certificate a handshake asked for (%s) was returned unchecked: the hold read an earlier answer and left the source's callback installed, which is a check a rotation walks past",
			identityOf(leafOf(pair)))
	}
	if !strings.Contains(err.Error(), rivalPrincipal) {
		t.Errorf("the refusal %q does not name the identity that would have been presented", err)
	}
}

// TestAnEstablishedConnectionFollowsTheProvisionedPeerSet: the recheck is
// supposed to apply the *current* allowed-peer set, not only the current
// anchor. Without that, a destination removed from the provisioned set keeps
// every connection it already has — which is the same staleness the anchor half
// of this was fixed for, one field along.
func TestAnEstablishedConnectionFollowsTheProvisionedPeerSet(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	provisioned := identitiesFile(t, testGatewayPrincipal)
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    provisioned,
		gatewayPeersFile: provisioned,
		mintURL:          host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	staysUsable(t, client, host.URL+credentialMintPath, 3*outboundTrustRecheckInterval)

	// That destination is removed from the provisioned set, and traffic keeps
	// arriving on the connection it already has.
	writeFile(t, provisioned, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")
	err = busyUntilRefused(t, client, host.URL+credentialMintPath, 3*outboundTrustRecheckInterval)
	if err == nil {
		t.Fatalf("this workload kept presenting its credentials for %s after the destination was removed from the provisioned set, on the connection it already held",
			3*outboundTrustRecheckInterval)
	}
	if !mentionsTrustFailure(err) {
		t.Errorf("the connection ended for something other than the peer set it is held to: %v", err)
	}
}

// TestALeafReadFailureDoesNotCloseATrustedConnection: the recheck may only
// close a connection over a judgement about the PEER.
//
// Rebuilding the whole outbound configuration on every recheck, this workload's
// own certificate included, and closing the connection on any error from it,
// means a rotation of this pod's own key pair that is not atomic — the
// certificate replaced, the key a moment behind — makes X509KeyPair fail and
// tears down every established platform connection, streams included, while
// every peer on them is still perfectly trusted. The SDK's reloader exists to
// swallow exactly that and keep the last good pair; building a new one per
// recheck throws the property away.
//
// It counts CONNECTIONS, not successful requests. Asserting that requests keep
// working cannot see this defect at all: the recheck closes the connection and
// net/http immediately dials another, which succeeds, so every request
// succeeds while the connection underneath is being torn down and replaced
// once a second. Two mutants lived in that gap.
func TestALeafReadFailureDoesNotCloseATrustedConnection(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The destination this test dials, so the authorization set for it is
		// the mint's: the set is chosen per destination now.
		mintURL: host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}

	var dials atomic.Int64
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				dials.Add(1)
			}
		},
	}
	get := func(t *testing.T) {
		t.Helper()
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
			http.MethodGet, host.URL+credentialMintPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("a request failed while the peer was trusted throughout: %v", err)
		}
		_ = resp.Body.Close()
	}

	get(t)
	if dials.Load() != 1 {
		t.Fatalf("the first request took %d connections, want 1", dials.Load())
	}

	// A rotation caught halfway: this workload's certificate is replaced by
	// something that does not pair with the key on disk. Nothing about the
	// peer has changed.
	writeFile(t, certFile, "-----BEGIN CERTIFICATE-----\nhalf a rotation\n-----END CERTIFICATE-----\n")

	deadline := time.Now().Add(3 * outboundTrustRecheckInterval)
	for time.Now().Before(deadline) {
		get(t)
		time.Sleep(outboundTrustRecheckInterval / 10)
	}
	if redialled := dials.Load(); redialled != 1 {
		t.Errorf("the established connection was replaced %d times while its peer stayed trusted: a half-written copy of this workload's own key pair is not a judgement about the peer, and the recheck must not share a failure path with it", redialled-1)
	}
}

// TestAnEstablishedCallerDoesNotOutliveTheTrustThatAdmittedIt is the inbound
// half of the busy-connection finding, and it is the half that went unanswered.
//
// The argument — an inactivity timeout cannot bound a connection that is never
// inactive, so re-verify the established peer — was written down in this
// repository, reproduced outbound, fixed outbound, and documented as a property
// of the runtime. Inbound the listener was still `&http.Server{Handler: mux}`:
// no recheck, no IdleTimeout, no ReadHeaderTimeout. So a caller removed from
// the admitted set, or whose issuing root was pulled from the bundle, kept
// every keep-alive connection it already held — in the direction where the
// decision is whom to admit.
func TestAnEstablishedCallerDoesNotOutliveTheTrustThatAdmittedIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		// what the platform withdraws, after the caller is connected
		withdraw func(t *testing.T, bundleFile, callersFile string, c *cell)
	}{
		{
			"its issuing root is removed from the bundle",
			func(t *testing.T, bundleFile, _ string, _ *cell) {
				other := newCell(t)
				writeFile(t, bundleFile, string(other.anchorPEM))
			},
		},
		{
			"it is removed from the admitted set",
			func(t *testing.T, _, callersFile string, _ *cell) {
				writeFile(t, callersFile, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCell(t)
			certFile, keyFile, bundleFile, caller, roots := c.workload(t, testPrincipal)
			callersFile := identitiesFile(t, testGatewayPrincipal)

			server := New(Manifest{ID: testSolutionID})
			server.cfg = config{port: freePort(t), identityCertFile: certFile, identityKeyFile: keyFile,
				trustBundleFile: bundleFile, allowedCallersFile: callersFile}
			server.principal = testPrincipal

			ln, err := server.listen()
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			watch, err := server.watchInboundTrust()
			if err != nil {
				t.Fatalf("watchInboundTrust: %v", err)
			}
			// The production server, so the hook under test is the one a
			// deployment runs with rather than one this test installs.
			srv := &http.Server{
				Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
				ReadHeaderTimeout: inboundHandshakeTimeout,
				IdleTimeout:       inboundIdleTimeout,
				ConnState:         watch,
			}
			go func() { _ = srv.Serve(ln) }()
			defer func() { _ = srv.Close() }()

			client := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{*caller},
					MinVersion: tls.VersionTLS13, ServerName: "localhost"},
			}}
			url := "https://" + ln.Addr().String() + "/"

			// The control: an admitted caller is served, and keeps being
			// served on one busy connection while trust holds.
			resp, err := client.Get(url)
			if err != nil {
				t.Fatalf("an admitted caller was refused: %v", err)
			}
			_ = resp.Body.Close()
			staysUsable(t, client, url, 2*inboundTrustRecheckInterval)

			tc.withdraw(t, bundleFile, callersFile, c)

			if err := busyUntilRefused(t, client, url, 4*inboundTrustRecheckInterval); err == nil {
				t.Fatalf("this caller was still being served %s after the trust that admitted it was withdrawn, on the connection it already held: re-reading trust per handshake bounds nothing about a connection that has already handshaken",
					4*inboundTrustRecheckInterval)
			}
		})
	}
}

// TestTheListenerBoundsAStalledPeer: with no timeouts at all, a peer that
// completes a TCP connect and then says nothing holds a goroutine and a
// descriptor indefinitely, and each ClientHello costs a read of the trust
// bundle — the cheap half of which is the peer's.
func TestTheListenerBoundsAStalledPeer(t *testing.T) {
	if inboundHandshakeTimeout <= 0 {
		t.Fatal("the listener sets no handshake or header deadline, so a peer that stalls mid-ClientHello is bounded by nothing")
	}
	if inboundIdleTimeout <= 0 {
		t.Fatal("the listener sets no idle timeout, so a keep-alive connection nobody uses is never dropped")
	}
	// And neither of the two that would cut a conforming long-running stream.
	// A declared stream may run to MaxStreamDurationLimit, so bounding the
	// whole body would refuse conforming traffic to answer a question the
	// recheck already answers without refusing any.
	srv := &http.Server{ReadHeaderTimeout: inboundHandshakeTimeout, IdleTimeout: inboundIdleTimeout}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Error("the listener bounds the whole request or response, which cuts a declared long-running stream that is conforming")
	}
	if inboundHandshakeTimeout >= MaxStreamDurationLimit {
		t.Errorf("the handshake deadline %s is not shorter than the longest declared stream %s, so it is not bounding anything", inboundHandshakeTimeout, MaxStreamDurationLimit)
	}
}

// TestANonAtomicRotationDoesNotFailANewDial is the other half of the
// last-good-pair property, and the half only a fresh dial can show.
//
// The SDK's reloader swallows a failed or half-written re-read and keeps
// serving the pair it already has, which is what makes a rotation invisible to
// whoever is dialling. Building a new reloader per dial throws that away,
// because the constructor loads eagerly and returns the error: with the
// certificate replaced and the key a moment behind, every new dial fails until
// both files settle. Nothing about the destination is wrong.
func TestANonAtomicRotationDoesNotFailANewDial(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The destination this test dials, so the authorization set for it is
		// the mint's: the set is chosen per destination now.
		mintURL: host.URL + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("outbound transport is %T, want *http.Transport", client.Transport)
	}

	resp, err := client.Get(host.URL + credentialMintPath)
	if err != nil {
		t.Fatalf("the platform was not reachable: %v", err)
	}
	_ = resp.Body.Close()

	// Halfway through a rotation: the certificate on disk no longer pairs with
	// the key beside it.
	writeFile(t, certFile, "-----BEGIN CERTIFICATE-----\nhalf a rotation\n-----END CERTIFICATE-----\n")

	// Force a genuinely new connection, so the dial path resolves the leaf
	// rather than reusing one that already presented it.
	transport.CloseIdleConnections()
	resp, err = client.Get(host.URL + credentialMintPath)
	if err != nil {
		t.Fatalf("a new dial failed while a rotation was half-written: the reloader keeps the last good pair for exactly this, and resolving a new one per dial reports the half-written state as a failure to reach the platform: %v", err)
	}
	_ = resp.Body.Close()
}

// issueMultiURILeaf is a leaf naming two SPIFFE identities, which no SPIFFE
// certificate has. The rule it tests is not pedantry about a field: a leaf
// naming several identities could be admitted on whichever one happens to
// match, and the identity it would be held to anywhere else is unknowable from
// here.
func issueMultiURILeaf(t *testing.T, c *cell, first, second string) *tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	one, err := url.Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := url.Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: first},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		URIs:         []*url.URL{one, two},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.anchor, public, c.anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

// TestALeafNamingSeveralIdentitiesIsRefusedInEveryDirection: a mutation that
// accepted the first URI SAN of several survived in three places, because
// every committed test used a conforming single-SAN leaf.
func TestALeafNamingSeveralIdentitiesIsRefusedInEveryDirection(t *testing.T) {
	c := newCell(t)
	doubled := issueMultiURILeaf(t, c, testGatewayPrincipal, rivalPrincipal)

	t.Run("an inbound caller", func(t *testing.T) {
		approved := c.identity(t, testPrincipal)
		server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: serverConfigFor(t, approved, c)})
		server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
		server.principal = testPrincipal
		config, err := server.serverIdentity()
		if err != nil {
			t.Fatalf("boot: %v", err)
		}
		outcome := servedTo(t, config, doubled, "")
		if !outcome.refused() {
			t.Fatal("a caller whose leaf names two identities was admitted: it can be accepted on whichever one matches, and the identity it is held to elsewhere is unknowable here")
		}
	})

	t.Run("this workload's own leaf", func(t *testing.T) {
		if err := pairPresentsThisWorkload(doubled, testGatewayPrincipal); err == nil {
			t.Fatal("this workload's own leaf was accepted while naming two identities, one of which is another workload's")
		}
	})

	t.Run("an outbound platform destination", func(t *testing.T) {
		state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsedLeaf(t, doubled)}}
		if _, err := oneURIIdentity(state, "platform destination"); err == nil {
			t.Fatal("a platform destination naming two identities was accepted, so the one it is held to is whichever the check happened to read first")
		}
	})
}

// parsedLeaf is a pair's leaf, parsed from its own DER rather than read off the
// Leaf cache.
func parsedLeaf(t *testing.T, pair *tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// serverConfigFor is a conforming listening configuration presenting pair,
// verifying callers against the cell.
func serverConfigFor(t *testing.T, pair *tls.Certificate, c *cell) *tls.Config {
	t.Helper()
	return &tls.Config{
		Certificates: []tls.Certificate{*pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    c.roots,
		MinVersion:   tls.VersionTLS13,
	}
}

// TestAPerConnectionAnswerIsHeldToTheAdmittedSet: holdPerConnectionPosture
// re-imposes admitOnly on the configuration a callback returns, because that
// configuration REPLACES the base one for the connection — so without it a
// source's callback serves that connection admitting every identity in the
// cell. The mutation removing it survived: every committed test drove the base
// configuration.
func TestAPerConnectionAnswerIsHeldToTheAdmittedSet(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	stranger := c.identity(t, rivalPrincipal)

	base := serverConfigFor(t, approved, c)
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		// A conforming answer that simply says nothing about admission.
		answer := serverConfigFor(t, approved, c)
		return answer, nil
	}
	server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: base})
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}

	// The control: the admitted caller is served over the per-connection answer.
	admitted := c.identity(t, testGatewayPrincipal)
	if outcome := servedTo(t, config, admitted, ""); outcome.refused() {
		t.Fatalf("an admitted caller was refused over the per-connection answer, so nothing below is about admission: %s", outcome.reason())
	}
	// And a caller nobody admitted is refused on that same answer.
	if outcome := servedTo(t, config, stranger, ""); !outcome.refused() {
		t.Fatal("a caller outside the provisioned set was served over a per-connection answer: the configuration a callback returns replaces the base one, so the admission has to be re-imposed on it or that connection admits every identity in the cell")
	}
}

// TestASourcesOwnVerifyConnectionStillRuns: admitOnly composes over whatever
// the source already verifies instead of assigning over it. Assigning silently
// deletes a check the source author wrote, which is the opposite of what adding
// a check should do — and nothing committed noticed, because no test gave a
// source a VerifyConnection of its own.
func TestASourcesOwnVerifyConnectionStillRuns(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	admitted := c.identity(t, testGatewayPrincipal)

	var theirs atomic.Int64
	base := serverConfigFor(t, approved, c)
	base.VerifyConnection = func(tls.ConnectionState) error {
		theirs.Add(1)
		return fmt.Errorf("the source refuses this caller for a reason this runtime knows nothing about")
	}
	server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: base})
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	outcome := servedTo(t, config, admitted, "")
	if theirs.Load() == 0 {
		t.Fatal("the source's own VerifyConnection was never called: composing the admission check over it was replaced by assigning over it, which deletes a check the source author wrote")
	}
	if !outcome.refused() {
		t.Fatal("a caller the source itself refused was served: the source's check runs first, because a caller its rules refuse should be refused for its reason")
	}
	if reason := outcome.reason(); !strings.Contains(reason, "knows nothing about") {
		t.Errorf("the handshake was refused for %q, not for the source's own reason", reason)
	}
}

// mentionsTheCertificate reports whether a boot refusal is about the identity
// the listener would present, rather than any other way a boot can fail.
func mentionsTheCertificate(err error) bool {
	for _, named := range []string{
		"issued for another workload",
		"certificate",
		"identity source",
		"principal",
	} {
		if strings.Contains(err.Error(), named) {
			return true
		}
	}
	return false
}

// TestTheOutboundHandshakeIsBoundedWhateverTheCallerPassed: a custom
// DialTLSContext takes net/http out of the handshake, so
// Transport.TLSHandshakeTimeout does nothing and the only bound left is the
// caller's context.
//
// That is adequate for an ordinary request and wrong where it matters:
// Gateway.HTTPClient carries streams and therefore sets no client timeout on
// purpose, so a dial made for a stream was bounded by the method's declared
// MaxStreamDuration — up to thirty minutes — or by nothing at all. This dials
// with a context carrying no deadline at all, against a peer that accepts TCP
// and never speaks TLS.
func TestTheOutboundHandshakeIsBoundedWhateverTheCallerPassed(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)

	// A black hole: it accepts and says nothing, which is what a peer doing
	// this deliberately looks like.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			// Held open, never answered.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// The black hole is this test's "mint", so the dial has an
		// authorization set at all: the set is chosen per destination now.
		mintURL: "https://" + silent.Addr().String() + credentialMintPath}
	server.principal = testPrincipal
	server.handshakeTimeout = 750 * time.Millisecond
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("outbound transport is %T, want *http.Transport", client.Transport)
	}

	dialled := make(chan error, 1)
	go func() {
		// context.Background(): no deadline, which is what a stream's dial can
		// carry.
		conn, err := transport.DialTLSContext(context.Background(), "tcp", silent.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		dialled <- err
	}()
	select {
	case err := <-dialled:
		if err == nil {
			t.Fatal("the dial succeeded against a peer that never spoke TLS")
		}
	case <-time.After(10 * server.handshakeTimeout):
		t.Fatalf("the handshake was still running %s after a dial with no deadline on its context: the custom dialler means net/http does not bound it and TLSHandshakeTimeout does nothing, so a dial made for a stream is bounded by the stream's duration or by nothing",
			10*server.handshakeTimeout)
	}
}

// TestTheInboundWatchStartsAtAuthentication: the watch covered the connection
// from the first *request*, which is later than authentication. A caller could
// complete its handshake, have its issuing root pulled, and sit unwatched for
// as long as the header deadline allows.
//
// This caller authenticates and then sends nothing at all, which is the window
// in question.
func TestTheInboundWatchStartsAtAuthentication(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, caller, roots := c.workload(t, testPrincipal)
	callersFile := identitiesFile(t, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{port: freePort(t), identityCertFile: certFile, identityKeyFile: keyFile,
		trustBundleFile: bundleFile, allowedCallersFile: callersFile}
	server.principal = testPrincipal
	ln, err := server.listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	watch, err := server.watchInboundTrust()
	if err != nil {
		t.Fatalf("watchInboundTrust: %v", err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		ReadHeaderTimeout: inboundHandshakeTimeout,
		IdleTimeout:       inboundIdleTimeout,
		ConnState:         watch,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs: roots, Certificates: []tls.Certificate{*caller},
		MinVersion: tls.VersionTLS13, ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("an admitted caller could not connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Authenticated, and not one byte of a request sent.
	//
	// The control runs first, and it is also what makes the withdrawal below
	// unambiguous: while admission holds, this connection stays open across
	// several recheck intervals. Withdrawing immediately after tls.Dial raced
	// the server's own side of the handshake — the client finishes before the
	// server has evaluated admission, so the server read the *new* file and
	// refused the handshake, and the test passed on "bad certificate" whether
	// the watch worked or not.
	stillOpen := func(t *testing.T) bool {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(inboundTrustRecheckInterval / 4))
		var buf [1]byte
		_, err := conn.Read(buf[:])
		return errors.Is(err, os.ErrDeadlineExceeded)
	}
	settle := time.Now().Add(2 * inboundTrustRecheckInterval)
	for time.Now().Before(settle) {
		if !stillOpen(t) {
			t.Fatal("the connection was closed while this caller was still admitted, so nothing below is about the withdrawal")
		}
	}

	// The platform now removes this caller.
	writeFile(t, callersFile, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")

	// Well inside the header deadline, which is what would otherwise be the
	// only thing to end this connection.
	deadline := time.Now().Add(5 * inboundTrustRecheckInterval)
	if 5*inboundTrustRecheckInterval >= inboundHandshakeTimeout {
		t.Fatalf("this test needs to finish inside the header deadline (%s) to mean anything", inboundHandshakeTimeout)
	}
	for time.Now().Before(deadline) {
		if !stillOpen(t) {
			return // closed, which is the point
		}
	}
	t.Fatalf("a caller that authenticated and then sent nothing was still connected %s after its admission was withdrawn: the watch begins at the first request, so the whole pre-request window is unwatched", 5*inboundTrustRecheckInterval)
}

// TestAResumedConnectionCannotBeAdmittedWithoutACertificate is the executed
// bypass from round five, committed.
//
// A resumed TLS connection presents no certificate: the peer is accepted on a
// ticket. So anything able to forge a ticket is admitted as whoever the ticket
// was issued to, and a denylist could not close that — it caught
// SessionTicketKey and could not catch SetSessionTicketKeys, whose keys are
// unexported and unreadable from the configuration. The review drove it end to
// end: with a known key, a client holding only that key and an admitted
// caller's ticket resumed as that caller with DidResume=true, presenting
// nothing, and the per-second recheck then re-verified the stolen certificate
// and kept the connection open.
//
// Resumption is therefore off on everything this listener serves, which is why
// this test asserts a property of the configuration rather than replaying a
// ticket: there is no ticket to replay.
func TestAResumedConnectionCannotBeAdmittedWithoutACertificate(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, caller, roots := c.workload(t, testPrincipal)

	// A source that deliberately fixes its ticket key, which is the HA-replica
	// shape, and reaches the bypass through the field the denylist can see.
	keyed, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	keyed.SessionTicketKey = [32]byte{7}
	if err := usableServerIdentity(keyed); err == nil {
		t.Error("a source fixing its own resumption ticket key was accepted: anyone holding that key can forge a ticket this listener resumes, and a resumed connection presents no certificate")
	}

	// And the half a check cannot see: keys installed through the method.
	// Nothing can read them back, so the only sound answer is that this
	// listener does not resume at all.
	viaMethod, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	viaMethod.SetSessionTicketKeys([][32]byte{{9}})
	server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: viaMethod})
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	served, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if !served.SessionTicketsDisabled {
		t.Fatal("the configuration this listener serves permits resumption while the source controls the ticket keys: a ticket forged with those keys is admitted as whoever it was issued to, with no certificate presented and nothing in this package able to notice")
	}

	// Every per-connection answer too, since that configuration replaces the
	// base one for its connection.
	perConnection, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if perConnection.GetConfigForClient == nil {
		t.Fatal("the projected source stopped answering per connection, so this case no longer covers anything")
	}
	answered, err := served.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatalf("the per-connection answer was refused: %v", err)
	}
	if answered != nil && !answered.SessionTicketsDisabled {
		t.Error("a per-connection answer permits resumption: the configuration a callback returns replaces the base one for that connection, so disabling it on the base alone leaves the bypass open")
	}

	// The control: an admitted caller is still served, so this is not a
	// listener that refuses everything.
	if outcome := servedTo(t, served, caller, "localhost"); outcome.refused() {
		t.Fatalf("an admitted caller was refused with resumption off: %s", outcome.reason())
	}
	_ = roots
}

// TestEachDestinationHasItsOwnAuthorizationSet: the mint and the gateway are
// two parties, and one set spanning both authorises each to stand in for the
// other at the other's address. The set already excluded every other workload
// in the cell, which was the finding it was added for, and that is a different
// question from whether "the platform" is one party.
func TestEachDestinationHasItsOwnAuthorizationSet(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	const gatewayIdentity = "spiffe://codefly.test/ns/platform/sa/gateway"
	const mintIdentity = "spiffe://codefly.test/ns/platform/sa/mint"

	// Two hosts: one answering as the mint, one as the gateway.
	mint := newPlatformHost(t, c, mintIdentity)
	gateway := newPlatformHost(t, c, gatewayIdentity)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintURL:          mint.URL + credentialMintPath,
		gatewayURL:       gateway.URL,
		mintPeersFile:    identitiesFile(t, mintIdentity),
		gatewayPeersFile: identitiesFile(t, gatewayIdentity),
	}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}

	t.Run("each destination admits its own identity", func(t *testing.T) {
		for _, at := range []struct{ name, url string }{
			{"the mint", mint.URL + credentialMintPath},
			{"the gateway", gateway.URL + "/anything"},
		} {
			resp, err := client.Get(at.url)
			if err != nil {
				t.Errorf("%s was refused while answering under its own provisioned identity: %v", at.name, err)
				continue
			}
			_ = resp.Body.Close()
		}
	})

	t.Run("neither stands in for the other", func(t *testing.T) {
		// The gateway's identity, answering at the mint's address. Under one
		// shared set this was accepted, and the projected service-account
		// token went to it.
		impostor := newPlatformHost(t, c, gatewayIdentity)
		server.cfg.mintURL = impostor.URL + credentialMintPath
		impersonating, err := server.outboundClient(nil)
		if err != nil {
			t.Fatalf("outboundClient: %v", err)
		}
		resp, err := impersonating.Get(impostor.URL + credentialMintPath)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("the gateway's identity was accepted at the credential mint's address: a set spanning both parties lets either present itself as the other, and the mint is the destination that receives the projected service-account token")
		}
		if !strings.Contains(err.Error(), gatewayIdentity) {
			t.Errorf("the refusal %q does not name the identity that answered", err)
		}
	})

	t.Run("a third address has no set and is refused", func(t *testing.T) {
		// This runtime dials the mint and the gateway and nothing else, so
		// there is no set that should admit a third destination.
		server.cfg.mintURL = mint.URL + credentialMintPath
		fresh, err := server.outboundClient(nil)
		if err != nil {
			t.Fatalf("outboundClient: %v", err)
		}
		stranger := newPlatformHost(t, c, mintIdentity)
		resp, err := fresh.Get(stranger.URL + credentialMintPath)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("a destination that is neither the mint nor the gateway was dialled with this workload's credentials")
		}
		if !strings.Contains(err.Error(), "no authorization set") {
			t.Errorf("the refusal %q does not say the address has no set, so it may be refusing for some other reason", err)
		}
	})
}
