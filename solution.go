// Package solution is a generic runtime for "solution" modules — independently
// deployed extensions that plug into a host at runtime with no build-time
// coupling. It owns everything every solution needs identically: env/config,
// self-registration with the host and the gateway (with a heartbeat), CORS,
// static Module Federation asset serving, the capability handshake, and the
// solution manifest. A solution author supplies a manifest and one or more
// handlers; each handler receives a Gateway that forwards the caller's bearer.
//
// This package depends on nothing but the standard library and knows nothing
// about any specific host or solution.
package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
)

// Manifest is the small, solution-specific description the author provides.
type Manifest struct {
	ID            string   // logical id / gateway service alias, e.g. "lastlogin-go"
	Title         string   // nav title, e.g. "Last Login · GO"
	Order         int      // nav order
	ExposedModule string   // MF exposed module (default "./Page")
	Contract      string   // capability contract id (default: ID)
	Capabilities  []string // capability feature ids
}

// Handler is a solution endpoint. It receives a Gateway bound to the caller's
// bearer and returns any JSON-serializable value (or an error → 502).
type Handler func(ctx context.Context, gw *Gateway) (any, error)

// Server wires a manifest and handlers into a running solution.
type Server struct {
	manifest Manifest
	handlers map[string]Handler
	cfg      config
}

type config struct {
	port, publicURL, gatewayURL string
	hostRegisterURL             string
	gatewayRegisterURL          string
	selfUpstream, assetsDir     string
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadConfig(id string) config {
	port := env("PORT", "8090")
	public := env("PUBLIC_URL", "http://localhost:"+port)
	return config{
		port:               port,
		publicURL:          public,
		gatewayURL:         strings.TrimRight(env("GATEWAY_URL", "http://localhost:42152"), "/"),
		hostRegisterURL:    env("HOST_REGISTER_URL", "http://localhost:21931/api/solutions/register"),
		gatewayRegisterURL: env("GATEWAY_REGISTER_URL", "http://localhost:42152/solutions/_register"),
		selfUpstream:       env("SELF_UPSTREAM", public),
		assetsDir:          env("ASSETS_DIR", "../fe-remote/dist"),
	}
}

// New starts a solution builder for the given manifest.
func New(manifest Manifest) *Server {
	if manifest.ExposedModule == "" {
		manifest.ExposedModule = "./Page"
	}
	if manifest.Contract == "" {
		manifest.Contract = "lastlogin"
	}
	return &Server{manifest: manifest, handlers: make(map[string]Handler)}
}

// Handle registers a solution endpoint. Chainable.
func (s *Server) Handle(path string, handler Handler) *Server {
	s.handlers[path] = handler
	return s
}

// Serve reads env config, self-registers, and blocks serving the solution.
func (s *Server) Serve() error {
	s.cfg = loadConfig(s.manifest.ID)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/solution.json", withCORS(s.handleManifest))
	mux.HandleFunc("/.well-known/capabilities", withCORS(s.handleCapabilities))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for path, handler := range s.handlers {
		mux.HandleFunc(path, withCORS(s.wrap(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/",
		withCORSHandler(http.FileServer(http.Dir(s.cfg.assetsDir)))))

	manifestBody, _ := json.Marshal(s.manifestMap())
	upstreamBody, _ := json.Marshal(map[string]string{"id": s.manifest.ID, "upstream": s.cfg.selfUpstream})
	go s.heartbeat(s.cfg.hostRegisterURL, manifestBody, "host")
	go s.heartbeat(s.cfg.gatewayRegisterURL, upstreamBody, "gateway")

	log.Printf("solution %q listening on :%s (gateway=%s)", s.manifest.ID, s.cfg.port, s.cfg.gatewayURL)
	return http.ListenAndServe(":"+s.cfg.port, mux)
}

func (s *Server) manifestMap() map[string]any {
	return map[string]any{
		"id":  s.manifest.ID,
		"nav": map[string]any{"title": s.manifest.Title, "path": "/s/" + s.manifest.ID, "order": s.manifest.Order},
		"frontend": map[string]any{
			"type":          "module-federation",
			"manifestUrl":   s.cfg.publicURL + "/assets/mf-manifest.json",
			"exposedModule": s.manifest.ExposedModule,
			"reactRange":    "^19",
		},
		"backend": map[string]any{"serviceAlias": s.manifest.ID, "capabilityPath": "/.well-known/capabilities"},
	}
}

func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manifestMap())
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": 1,
		"contract":      s.manifest.Contract,
		"contractMajor": 1,
		"capabilities":  s.manifest.Capabilities,
	})
}

func (s *Server) wrap(handler Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("authorization")
		if bearer == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer"})
			return
		}
		result, err := handler(r.Context(), &Gateway{baseURL: s.cfg.gatewayURL, bearer: bearer})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (s *Server) heartbeat(url string, body []byte, label string) {
	logged := false
	for {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("content-type", "application/json")
			if resp, doErr := http.DefaultClient.Do(req); doErr == nil {
				resp.Body.Close()
				if resp.StatusCode < 300 && !logged {
					log.Printf("registered with %s as %q", label, s.manifest.ID)
					logged = true
				}
			}
		}
		time.Sleep(15 * time.Second)
	}
}

// Gateway is a client bound to the caller's bearer. It exposes an HTTP client
// that forwards that bearer and the gateway base URL, so a solution can drive
// its own generated SDK against the gateway — every call stays authenticated
// and routed through the gateway.
type Gateway struct {
	baseURL string
	bearer  string
}

func (g *Gateway) BaseURL() string { return g.baseURL }

// HTTPClient returns an http.Client that injects the caller's bearer on every
// request. Satisfies connect.HTTPClient. Advanced escape hatch — prefer Unary.
func (g *Gateway) HTTPClient() *http.Client {
	return &http.Client{Transport: bearerTransport{bearer: g.bearer, base: http.DefaultTransport}}
}

// Unary makes a typed Connect call to a fully-qualified procedure through the
// gateway. Req and Resp are generated protobuf messages; the gateway URL, the
// bearer, and the wire protocol are hidden so a handler only names a procedure
// and passes typed messages — the twin of the Python runtime's gateway.unary.
func Unary[Req, Resp any](ctx context.Context, gw *Gateway, procedure string, req *Req) (*Resp, error) {
	client := connect.NewClient[Req, Resp](gw.HTTPClient(), gw.baseURL+procedure)
	resp, err := client.CallUnary(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

type bearerTransport struct {
	bearer string
	base   http.RoundTripper
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("authorization", t.bearer)
	return t.base.RoundTrip(r)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func withCORSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		next.ServeHTTP(w, r)
	})
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("access-control-allow-origin", "*")
	w.Header().Set("access-control-allow-headers", "authorization, content-type")
	w.Header().Set("access-control-allow-methods", "GET, POST, OPTIONS")
}
