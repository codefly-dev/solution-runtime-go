package solution

import (
	"bytes"
	"context"
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
	Audience                                       workcontext.AuthorityValue
	Authority                                      workcontext.AuthorityPin
	ProjectedToken                                 workcontext.ProjectedTokenSource
	// Transport answers whether a plaintext URL is admitted — the SDK's rule,
	// asked with the composition's mesh assertion as loadConfig read it.
	Transport workcontext.TransportSource
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
	// The SDK's rule decides whether the projected token may travel to this
	// URL: https anywhere; http only to a loopback host on a local run, or to
	// an in-cluster Service address under the composition's mesh assertion.
	// The path is the host's published route and nothing else.
	u, err := workcontext.AdmitEndpoint(options.URL, options.Transport, "credential mint")
	if err != nil {
		return nil, err
	}
	if u.Path != credentialMintPath || u.RawPath != "" {
		return nil, errors.New("credential mint URL must name the module broker endpoint " + credentialMintPath)
	}
	if options.Prefix == "" || options.InternalToken == "" || options.ProjectedToken == nil || options.Authority == nil {
		return nil, errors.New("module broker requires a declared solution prefix, module-authority/INTERNAL_TOKEN, a projected token and the frozen authority")
	}
	if options.ProjectionAudience != "accounts" {
		return nil, errors.New("module-authority/PROJECTION_AUDIENCE must be accounts for the module broker")
	}
	c := &brokerCredentialSource{options: options}
	c.client = c.httpClient(u)
	return c, nil
}

// body is the mint request: the declared prefix and nothing else. Where this
// runtime serves and what its frontend declares are not reported here: the
// gateway resolves this solution's address from the delivered presence
// document's endpoints, and the frontend travels in the same document, read by
// the CLI from the file this runtime embeds (FrontendFileName).
func (o brokerMintOptions) body() []byte {
	payload, _ := json.Marshal(map[string]string{"prefix": o.Prefix})
	return payload
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
			if projection.absent {
				return workcontext.Credential{}, &brokerMintError{class: brokerProjectionAbsent}
			}
			return workcontext.Credential{}, &brokerMintError{class: brokerProjection}
		}
		return workcontext.Credential{}, classifyBrokerTransport(err)
	}
	if strings.TrimSpace(projected) == "" {
		return workcontext.Credential{}, &brokerMintError{class: brokerProjection}
	}
	payload := c.options.body()
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

// httpClient is the transport the mint goes out on: owned, never the default
// one (which carries Proxy: ProxyFromEnvironment), pinned to the one origin the
// mint URL names, following no redirect and reusing no connection. Plain HTTP
// inside the cell, where the mesh carries the hop; https where the URL says
// so, verified against the system roots, since an https gateway is an edge
// presenting a public certificate. The transportReading slot bounds the dial
// as boundedBrokerRead bounds the token read: at most one outstanding,
// cancelled by the ask's own deadline.
func (c *brokerCredentialSource) httpClient(endpoint *url.URL) *http.Client {
	transport := newPlatformTransport()
	transport.DisableKeepAlives = true
	port := endpoint.Port()
	if port == "" {
		port = "80"
		if endpoint.Scheme == "https" {
			port = "443"
		}
	}
	address := net.JoinHostPort(endpoint.Hostname(), port)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != address {
			return nil, errors.New("broker origin mismatch")
		}
		ctx, cancel := context.WithTimeout(ctx, brokerDialTimeout)
		defer cancel()
		return boundedBrokerRead(ctx, &c.transportReading, func() (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		})
	}
	return &http.Client{Transport: transport, Timeout: platformRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// brokerDialTimeout bounds one dial of the mint on its own: a mint request may
// wait on the host, a dial never does.
const brokerDialTimeout = 10 * time.Second

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
