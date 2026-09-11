package solution

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestHandlerPreservesCallerAndInput(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer viewer" {
			t.Error("viewer credential lost")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	s := New(Manifest{ID: "test"})
	s.cfg.gatewayURL = upstream.URL
	s.HandleRequest("/ask", func(r *http.Request, gw *Gateway) (any, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if r.Method != "POST" || string(body) != `{"question":"why?"}` || r.URL.Query().Get("mode") != "wiki" {
			t.Error("request input lost")
		}
		if r.Context().Value(requestTestKey{}) != "request-context" {
			t.Error("request context lost")
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", gw.BaseURL(), nil)
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		return map[string]string{"answer": "ok"}, nil
	})
	for _, bearer := range []string{"", "Bearer viewer"} {
		req := httptest.NewRequest("POST", "/ask?mode=wiki", strings.NewReader(`{"question":"why?"}`))
		req = req.WithContext(context.WithValue(req.Context(), requestTestKey{}, "request-context"))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		s.wrapRequest(s.handlers["/ask"])(rec, req)
		want := http.StatusOK
		if bearer == "" {
			want = http.StatusUnauthorized
		}
		if rec.Code != want {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
	}
}

type requestTestKey struct{}
