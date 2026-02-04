// Package http provides HTTP server and routing for the MCP server.
package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter_RegisterHandler(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	router.Handle("/test", handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("Registered handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want 200", w.Code)
	}
}

func TestRouter_MultipleHandlers(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	handler1Called := false
	handler2Called := false

	router.Handle("/path1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler1Called = true
		w.WriteHeader(http.StatusOK)
	}))

	router.Handle("/path2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler2Called = true
		w.WriteHeader(http.StatusCreated)
	}))

	// Request to /path1
	req1 := httptest.NewRequest(http.MethodGet, "/path1", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	if !handler1Called {
		t.Error("Handler1 was not called for /path1")
	}
	if handler2Called {
		t.Error("Handler2 should not be called for /path1")
	}

	// Reset for second request
	handler1Called = false

	// Request to /path2
	req2 := httptest.NewRequest(http.MethodGet, "/path2", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if handler1Called {
		t.Error("Handler1 should not be called for /path2")
	}
	if !handler2Called {
		t.Error("Handler2 was not called for /path2")
	}
}

func TestRouter_NotFound(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	router.Handle("/exists", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/not-exists", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Unmatched path status = %v, want 404", w.Code)
	}
}

func TestRouter_MiddlewareChain(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	order := []string{}

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	router.Use(middleware1)
	router.Use(middleware2)

	router.Handle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Middleware should execute in order: m1 -> m2 -> handler -> m2 -> m1
	expectedOrder := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expectedOrder) {
		t.Errorf("Order length = %v, want %v", len(order), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if i < len(order) && order[i] != expected {
			t.Errorf("Order[%d] = %v, want %v", i, order[i], expected)
		}
	}
}

func TestRouter_MethodRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method     string
		wantStatus int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodPost, http.StatusOK},
		{http.MethodPut, http.StatusOK},
		{http.MethodDelete, http.StatusOK},
		{http.MethodPatch, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()

			router := NewRouter()

			router.Handle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tt.method, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Method %s status = %v, want %v", tt.method, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestRouter_HandleFunc(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	handlerCalled := false
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("HandleFunc handler was not called")
	}
}

func TestRouter_TrailingSlash(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	router.Handle("/test/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request with trailing slash
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Request with trailing slash status = %v, want 200", w.Code)
	}
}

func TestRouter_WellKnownPath(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	handlerCalled := false
	router.Handle("/.well-known/oauth-protected-resource", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("Well-known path handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Well-known path status = %v, want 200", w.Code)
	}
}

func TestRouter_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	router := NewRouter()

	router.Handle("/concurrent", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/concurrent", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Concurrent request status = %v, want 200", w.Code)
			}
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
