package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
			server.cfg = config{allowedCallers: testGatewayPrincipal, platformPeers: testGatewayPrincipal}
			server.principal = testPrincipal

			config, err := server.serverIdentity()
			if err != nil {
				// Refused at boot, which is the better of the two outcomes:
				// nothing is served and the mint has not happened yet.
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
		server.cfg = config{allowedCallers: testGatewayPrincipal, platformPeers: testGatewayPrincipal}
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
	server.cfg = config{allowedCallers: testGatewayPrincipal, platformPeers: testGatewayPrincipal}
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
func TestTheAdmittedCallerSetIsResolvedPerHandshake(t *testing.T) {
	c := newCell(t)
	approved := c.identity(t, testPrincipal)
	caller := c.identity(t, testGatewayPrincipal)

	provisioned := testGatewayPrincipal
	server := New(Manifest{ID: testSolutionID}).Identity(shapeShifter{approved: approved, roots: c.roots})
	server.cfg = config{
		allowedCallers:        provisioned,
		platformPeers:         testGatewayPrincipal,
		resolveAllowedCallers: func() string { return provisioned },
	}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if outcome := servedTo(t, config, caller, ""); outcome.refused() {
		t.Fatalf("an admitted caller was refused: %v", outcome.reason())
	}

	// The operator removes that caller. No restart, no new listener.
	provisioned = "spiffe://codefly.test/ns/platform/sa/somebody-else"
	outcome := servedTo(t, config, caller, "")
	if !outcome.refused() {
		t.Fatal("a caller removed from the provisioned set was still admitted: the listener is judging by the set it booted with, so revocation needs a restart somebody has to remember to perform")
	}

	// And a set that resolves to nothing refuses, rather than falling back to
	// the set this process booted with.
	provisioned = ""
	if outcome := servedTo(t, config, caller, ""); !outcome.refused() {
		t.Fatal("a caller was admitted while the provisioned set resolved to nothing: an admission decision that cannot be resolved is not one to guess at")
	}
}

// TestLoadConfigResolvesTheCallerSetThroughTheOverride is the other half of the
// test above, which supplies its own resolver: the resolver production uses has
// to be the one loadConfig builds, and it has to follow the documented override.
func TestLoadConfigResolvesTheCallerSetThroughTheOverride(t *testing.T) {
	t.Setenv(IdentityAllowedCallersEnvironmentVariable, testGatewayPrincipal)
	cfg := loadConfig(context.Background())
	if cfg.resolveAllowedCallers == nil {
		t.Fatal("loadConfig resolved no caller-set reader, so a handshake can only use the boot-time snapshot")
	}
	if got := cfg.resolveAllowedCallers(); got != testGatewayPrincipal {
		t.Errorf("the caller-set reader answered %q, want the provisioned %q", got, testGatewayPrincipal)
	}
	t.Setenv(IdentityAllowedCallersEnvironmentVariable, "spiffe://codefly.test/ns/platform/sa/somebody-else")
	if got := cfg.resolveAllowedCallers(); got != "spiffe://codefly.test/ns/platform/sa/somebody-else" {
		t.Errorf("the caller-set reader answered %q after the provisioned value changed: it is reading something it captured", got)
	}
	if cfg.resolvePlatformPeers == nil {
		t.Error("loadConfig resolved no platform-peer reader")
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

// TestTheOutboundLeafIsHeldWhenItIsPresented: the outbound check was a
// preflight. It called the reloader once, compared what came back, and left the
// source's own callback installed for the handshake — so a rotation between the
// two presented a neighbouring workload's leaf to the mint, successfully, with
// this workload's projected service-account token on the request.
func TestTheOutboundLeafIsHeldWhenItIsPresented(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		platformPeers: testGatewayPrincipal}
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

	build := func(t *testing.T) *http.Client {
		t.Helper()
		server := New(Manifest{ID: testSolutionID})
		server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
			platformPeers: testGatewayPrincipal}
		server.principal = testPrincipal
		client, err := server.outboundClient(nil)
		if err != nil {
			t.Fatalf("outboundClient: %v", err)
		}
		return client
	}

	t.Run("the provisioned platform identity is dialled", func(t *testing.T) {
		host := newPlatformHost(t, c, testGatewayPrincipal)
		resp, err := build(t).Get(host.URL + credentialMintPath)
		if err != nil {
			t.Fatalf("the provisioned platform destination was refused: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("another workload at the same address is not", func(t *testing.T) {
		// A valid certificate from the same anchor, valid for this address,
		// naming a workload that is not the platform.
		host := newPlatformHost(t, c, rivalPrincipal)
		resp, err := build(t).Get(host.URL + credentialMintPath)
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
		platformPeers: testGatewayPrincipal}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}

	resp, err := client.Get(host.URL + credentialMintPath)
	if err != nil {
		t.Fatalf("the platform was not reachable with its own root in the bundle: %v", err)
	}
	_ = resp.Body.Close()

	// The root is removed and replaced by an unrelated one: the bundle still
	// parses and no longer contains the issuer of the certificate the platform
	// presents. Nothing closes the connection, and traffic keeps arriving.
	other := newCell(t)
	writeFile(t, bundleFile, string(other.anchorPEM))

	deadline := time.Now().Add(3 * outboundTrustRecheckInterval)
	for {
		resp, err := client.Get(host.URL + credentialMintPath)
		if err != nil {
			return // the established connection stopped being used, which is the point
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatalf("requests still succeeded %s after the platform's root was removed from the bundle, on a connection kept busy throughout: an inactivity timeout cannot bound a connection that is never inactive, so the documented staleness window held only for a quiet process",
				3*outboundTrustRecheckInterval)
		}
		time.Sleep(outboundTrustRecheckInterval / 20)
	}
}

// TestEveryPlatformConnectionIsWatched is the narrow half of the test above: it
// is the production transport's own dialler that has to attach the recheck, not
// a wrapper a test builds.
func TestEveryPlatformConnectionIsWatched(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		platformPeers: testGatewayPrincipal}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("outbound transport is %T, want *http.Transport", client.Transport)
	}
	address := strings.TrimPrefix(host.URL, "https://")
	conn, err := transport.DialTLSContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial the platform: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, ok := conn.(*recheckedConn); !ok {
		t.Fatalf("the transport dialled a %T: a connection whose trust is never re-verified is bounded only by how long it stays idle, which traffic prevents", conn)
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
	server.cfg = config{allowedCallers: testGatewayPrincipal, platformPeers: testGatewayPrincipal}
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

	provisioned := testGatewayPrincipal
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		platformPeers:        provisioned,
		resolvePlatformPeers: func() string { return provisioned },
	}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	resp, err := client.Get(host.URL + credentialMintPath)
	if err != nil {
		t.Fatalf("the provisioned platform destination was refused: %v", err)
	}
	_ = resp.Body.Close()

	// That destination is removed from the provisioned set, and traffic keeps
	// arriving on the connection it already has.
	provisioned = "spiffe://codefly.test/ns/platform/sa/somebody-else"
	deadline := time.Now().Add(3 * outboundTrustRecheckInterval)
	for {
		resp, err := client.Get(host.URL + credentialMintPath)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatalf("this workload kept presenting its credentials for %s after the destination was removed from the provisioned set, on the connection it already held",
				3*outboundTrustRecheckInterval)
		}
		time.Sleep(outboundTrustRecheckInterval / 20)
	}
}
