package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestRequestHandlerRejectsInvalidInput(t *testing.T) {
	s := New(Manifest{ID: "test"})
	s.HandleRequest("/ask", func(r *http.Request, _ *Gateway) (any, error) {
		body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 32))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return nil, &ClientError{StatusCode: http.StatusRequestEntityTooLarge, Message: "question too large"}
			}
			return nil, err
		}
		var input struct {
			Question string `json:"question"`
		}
		if err := json.Unmarshal(body, &input); err != nil {
			return nil, &ClientError{StatusCode: http.StatusBadRequest, Message: "invalid JSON"}
		}
		if input.Question == "" {
			return nil, fmt.Errorf("private validation context: %w", &ClientError{StatusCode: http.StatusUnprocessableEntity, Message: "question required"})
		}
		return map[string]string{"answer": input.Question}, nil
	})
	for _, tc := range []struct {
		name, body string
		status     int
		message    string
	}{
		{"malformed", `{"question":`, 400, "invalid JSON"},
		{"oversized", `{"question":"` + strings.Repeat("x", 32) + `"}`, 413, "question too large"},
		{"missing question", `{}`, 422, "question required"},
		{"valid", `{"question":"why?"}`, 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ask", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer viewer")
			rec := httptest.NewRecorder()
			withCORS(s.wrapRequest(s.handlers["/ask"]))(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var response map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["error"] != tc.message {
				t.Fatalf("response: %v", response)
			}
			if tc.status == 200 && response["answer"] != "why?" {
				t.Fatalf("response: %v", response)
			}
			if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
				t.Fatalf("headers: %v", rec.Header())
			}
		})
	}
}

func TestHandlerErrorStatusContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"ordinary upstream error", errors.New("upstream failed"), 502},
		{"explicit client error", &ClientError{StatusCode: 400, Message: "invalid request"}, 400},
		{"zero status", &ClientError{Message: "invalid status"}, 502},
		{"informational status", &ClientError{StatusCode: 103, Message: "invalid status"}, 502},
		{"success status", &ClientError{StatusCode: 200, Message: "invalid status"}, 502},
		{"redirect status", &ClientError{StatusCode: 302, Message: "invalid status"}, 502},
		{"server status", &ClientError{StatusCode: 500, Message: "invalid status"}, 502},
		{"out of range status", &ClientError{StatusCode: 1000, Message: "invalid status"}, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Manifest{ID: "test"})
			s.Handle("/legacy", func(context.Context, *Gateway) (any, error) { return nil, tc.err })
			s.HandleRequest("/request", func(*http.Request, *Gateway) (any, error) { return nil, tc.err })
			for _, path := range []string{"/legacy", "/request"} {
				req := httptest.NewRequest("POST", path, nil)
				req.Header.Set("Authorization", "Bearer viewer")
				rec := httptest.NewRecorder()
				s.wrapRequest(s.handlers[path])(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body.String())
				}
			}
		})
	}
}
