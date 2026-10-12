package solution

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// executionCredential is private so the public SDK-based CredentialSource
// remains source compatible. Core alone reads capability bytes, through its
// structural Decode; this runtime never decodes a signed message itself and
// never treats that read as verification — core's Inspector, which does check
// a signature, is a verifier and is not reachable here.
type executionCredential interface {
	Token() string
	Seal() *workcontext.SealedValues
	ExpiresAt() time.Time
	Attach(*http.Request) error
}

type brokerCredential struct {
	token   string
	decoded *corework.Decoded
	expires time.Time
}

func (c brokerCredential) Token() string                   { return c.token }
func (c brokerCredential) Seal() *workcontext.SealedValues { return c.decoded.Seal() }
func (c brokerCredential) ExpiresAt() time.Time            { return c.expires }
func (c brokerCredential) Attach(r *http.Request) error    { return workcontext.Attach(r, c.token) }

type brokerMintOptions struct {
	URL, Prefix, InternalToken, ProjectionAudience string
	// Upstream is the origin this runtime serves its backend at, reported with
	// the mint as the dynamic half of its registration: the host records it
	// only for the workload the projected token proves, and reaches it only
	// under this workload's SVID. Empty reports nothing.
	Upstream string
	// Manifest is the solution's frontend manifest, as this runtime serves it:
	// the other dynamic half of a solution's registration. Empty for a module.
	Manifest          string
	Audience          workcontext.AuthorityValue
	Authority         workcontext.AuthorityPin
	ProjectedToken    workcontext.ProjectedTokenSource
	TrustAnchor       func() (*x509.CertPool, error)
	ClientCertificate func() (*tls.Certificate, error)
	AdmittedPeers     func() ([]string, error)
}

type brokerCredentialSource struct {
	options          brokerMintOptions
	client           *http.Client
	mu               sync.Mutex // the runtime's controller bounds waits and shares acquisition
	held             executionCredential
	renewAt          time.Time
	terminal         error
	identity         authorityHeldSource
	tokenReading     atomic.Bool
	transportReading atomic.Bool
}

func newBrokerCredentialSource(options brokerMintOptions) (*brokerCredentialSource, error) {
	u, err := url.Parse(options.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != credentialMintPath || u.RawPath != "" {
		return nil, errors.New("credential mint URL must be an https module broker endpoint at /modules/_work-context without userinfo, query or fragment")
	}
	if options.Prefix == "" || options.InternalToken == "" || options.ProjectedToken == nil || options.Authority == nil || options.TrustAnchor == nil || options.ClientCertificate == nil || options.AdmittedPeers == nil {
		return nil, errors.New("module broker requires a declared solution prefix, module-authority/INTERNAL_TOKEN, projected token, frozen authority and TLS identity readers")
	}
	if options.ProjectionAudience != "accounts" {
		return nil, errors.New("module-authority/PROJECTION_AUDIENCE must be accounts for the module broker")
	}
	c := &brokerCredentialSource{options: options}
	c.client = c.httpClient(u)
	return c, nil
}

func (c *brokerCredentialSource) Credential(ctx context.Context) (executionCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return workcontext.Credential{}, c.terminal
	}
	credential, err := c.obtain(ctx)
	if terminalCredentialFailure(err) {
		c.terminal = err
	}
	return credential, err
}

func (c *brokerCredentialSource) obtain(ctx context.Context) (executionCredential, error) {
	fail := func() (executionCredential, error) {
		return workcontext.Credential{}, &brokerMintError{class: brokerInvalidAnswer}
	}
	if err := c.options.Authority.Recheck(ctx); err != nil {
		return workcontext.Credential{}, workcontext.ErrMintRefused
	}
	if c.held != nil && time.Now().Before(c.renewAt) {
		return c.held, nil
	}
	// A FIFO or a consumer reader can ignore cancellation. Bound the wait and
	// allow at most one outstanding read, discarding any late result.
	projected, err := boundedBrokerRead(ctx, &c.tokenReading, c.options.ProjectedToken.ProjectedToken)
	if err != nil {
		var projection *projectedTokenError
		if errors.As(err, &projection) {
			return workcontext.Credential{}, &brokerMintError{class: brokerProjection}
		}
		return workcontext.Credential{}, classifyBrokerTransport(err)
	}
	if strings.TrimSpace(projected) == "" {
		return workcontext.Credential{}, &brokerMintError{class: brokerProjection}
	}
	body := map[string]string{"prefix": c.options.Prefix}
	if c.options.Upstream != "" {
		body["upstream"] = c.options.Upstream
	}
	if c.options.Manifest != "" {
		body["manifest"] = c.options.Manifest
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.options.URL, bytes.NewReader(payload))
	if err != nil {
		return workcontext.Credential{}, classifyBrokerTransport(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+projected)
	req.Header.Set("X-Codefly-Internal-Token", c.options.InternalToken)
	resp, err := c.client.Do(req)
	if err != nil {
		return workcontext.Credential{}, classifyBrokerTransport(err)
	}
	// The response is classified and bounded below; closing is cleanup only.
	// Do not drain an untrusted body to reuse a connection: every mint closes it.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return workcontext.Credential{}, brokerStatusError(resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return workcontext.Credential{}, classifyBrokerTransport(err)
	}
	if len(raw) > 64<<10 {
		return fail()
	}
	// These are the broker's HTTP fields, not fields of a signed capability.
	var issued struct {
		Token       string `json:"token"`
		ExpiresAt   string `json:"expiresAt"`
		PrincipalID string `json:"principalId"`
		Tenant      string `json:"tenant"`
	}
	if json.Unmarshal(raw, &issued) != nil {
		return fail()
	}
	expiry, err := time.Parse(time.RFC3339, issued.ExpiresAt)
	if err != nil || !expiry.After(time.Now()) {
		return fail()
	}
	decoded, err := corework.Decode(issued.Token)
	if err != nil {
		return fail()
	}
	audience, err := c.options.Authority.Value(c.options.Audience.Name, c.options.Audience.Key)
	if err != nil || decoded.Context().GetAudience() != audience {
		return fail()
	}
	if time.Now().Before(decoded.NotBefore().Add(-corework.DefaultSkew)) {
		return fail()
	}
	// The broker's expiry may shorten, never extend, the signed lifetime.
	if decoded.ExpiresAt().Before(expiry) {
		expiry = decoded.ExpiresAt()
	}
	credential := brokerCredential{token: issued.Token, decoded: decoded, expires: expiry}
	if err := usableCredential(credential); err != nil {
		if errors.Is(err, workcontext.ErrMintRefused) {
			return workcontext.Credential{}, err
		}
		return workcontext.Credential{}, &brokerMintError{class: brokerInvalidAnswer}
	}
	if err := c.options.Authority.Recheck(ctx); err != nil {
		return workcontext.Credential{}, workcontext.ErrMintRefused
	}
	if err := c.identity.holdSealedIdentity(credential.Seal()); err != nil {
		return workcontext.Credential{}, workcontext.ErrMintRefused
	}
	lead := min(30*time.Second, expiry.Sub(decoded.NotBefore())/5)
	c.renewAt = expiry.Add(-lead)
	if !time.Now().Before(c.renewAt) {
		return fail()
	}
	c.held = credential
	return credential, nil
}

// This transport is private, uses a fresh mutually authenticated handshake for
// every mint and rechecks trust after it, before any HTTP bytes can be sent.
func (c *brokerCredentialSource) httpClient(endpoint *url.URL) *http.Client {
	o := c.options
	trust := func() (*x509.CertPool, error) {
		pool, err := o.TrustAnchor()
		if err != nil || pool == nil {
			return nil, errors.New("broker trust anchor unavailable")
		}
		return pool, nil
	}
	// Build an owned transport; never inherit mutable global transport hooks.
	transport := &http.Transport{DisableKeepAlives: true}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(endpoint.Hostname(), port)
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != address {
			return nil, errors.New("broker origin mismatch")
		}
		ctx, cancel := context.WithTimeout(ctx, platformHandshakeTimeout)
		defer cancel()
		return boundedBrokerRead(ctx, &c.transportReading, func() (net.Conn, error) {
			anchor, err := trust()
			if err != nil || anchor == nil {
				return nil, errors.New("broker trust anchor unavailable")
			}
			presented := false
			config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: anchor, ServerName: endpoint.Hostname(), SessionTicketsDisabled: true}
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				pair, err := o.ClientCertificate()
				if err != nil || pair == nil || len(pair.Certificate) == 0 || pair.PrivateKey == nil {
					return nil, errors.New("broker client identity unavailable")
				}
				presented = true
				return pair, nil
			}
			admitOnlyPlatform(config, o.AdmittedPeers)
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, config)
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			if !presented {
				_ = conn.Close()
				return nil, errors.New("broker did not request a client identity")
			}
			if err := peerStillTrusted(conn.ConnectionState(), endpoint.Hostname(), trust, o.AdmittedPeers); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		})
	}
	return &http.Client{Transport: transport, Timeout: platformRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func boundedBrokerRead[T any](ctx context.Context, busy *atomic.Bool, read func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !busy.CompareAndSwap(false, true) {
		return zero, context.DeadlineExceeded
	}
	type result struct {
		value T
		err   error
	}
	answer := make(chan result)
	go func() {
		defer busy.Store(false)
		value, err := read()
		select {
		case answer <- result{value, err}:
		case <-ctx.Done():
			if closer, ok := any(value).(io.Closer); ok && closer != nil {
				_ = closer.Close()
			}
		}
	}()
	select {
	case got := <-answer:
		if err := ctx.Err(); err != nil {
			if closer, ok := any(got.value).(io.Closer); ok && closer != nil {
				_ = closer.Close()
			}
			return zero, err
		}
		return got.value, got.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
