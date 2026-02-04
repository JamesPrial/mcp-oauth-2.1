// Package middleware provides HTTP middleware for the MCP server.
package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testLogHandler captures log entries for testing.
type testLogHandler struct {
	entries *[]map[string]any // Pointer for shared state
	attrs   []slog.Attr
}

func (h *testLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error {
	entry := map[string]any{
		"level":   r.Level.String(),
		"message": r.Message,
		"time":    r.Time,
	}
	r.Attrs(func(a slog.Attr) bool {
		entry[a.Key] = a.Value.Any()
		return true
	})
	*h.entries = append(*h.entries, entry)
	return nil
}

func (h *testLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandler := &testLogHandler{
		entries: h.entries,
		attrs:   append(h.attrs, attrs...),
	}
	return newHandler
}

func (h *testLogHandler) WithGroup(name string) slog.Handler {
	return h
}

func TestLogging_SuccessfulRequest(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &testLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	middleware := NewLoggingMiddleware(logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Logging middleware should call next handler")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify logging occurred
	if len(entries) == 0 {
		t.Fatal("Expected at least one log entry")
	}

	// Find the request log entry
	var foundMethod, foundPath, foundStatus, foundDuration bool
	for _, entry := range entries {
		if method, ok := entry["method"]; ok && method == "GET" {
			foundMethod = true
		}
		if path, ok := entry["path"]; ok && path == "/api/test" {
			foundPath = true
		}
		if status, ok := entry["status"]; ok {
			if s, ok := status.(int64); ok && s == 200 {
				foundStatus = true
			}
		}
		// Check for duration_ms (actual field name in implementation)
		if _, ok := entry["duration_ms"]; ok {
			foundDuration = true
		}
	}

	if !foundMethod {
		t.Error("Log should contain request method")
	}
	if !foundPath {
		t.Error("Log should contain request path")
	}
	if !foundStatus {
		t.Error("Log should contain response status")
	}
	if !foundDuration {
		t.Error("Log should contain request duration")
	}
}

func TestLogging_ErrorRequest(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &testLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	})

	middleware := NewLoggingMiddleware(logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodPost, "/api/error", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	// Verify logging occurred with error status
	if len(entries) == 0 {
		t.Fatal("Expected at least one log entry")
	}

	var foundStatus500 bool
	for _, entry := range entries {
		if status, ok := entry["status"]; ok {
			if s, ok := status.(int64); ok && s == 500 {
				foundStatus500 = true
				break
			}
		}
	}

	if !foundStatus500 {
		t.Error("Log should contain 500 status for error request")
	}
}

func TestLogging_ClientErrorRequest(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &testLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	middleware := NewLoggingMiddleware(logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodPut, "/api/resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Verify 4xx is logged
	if len(entries) == 0 {
		t.Fatal("Expected at least one log entry for 4xx response")
	}
}

func TestLogging_DifferentMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			entries := make([]map[string]any, 0)
			logHandler := &testLogHandler{entries: &entries}
			logger := slog.New(logHandler)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := NewLoggingMiddleware(logger)
			handler := middleware(next)

			req := httptest.NewRequest(method, "/test", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if len(entries) == 0 {
				t.Fatalf("Expected log entry for %s request", method)
			}

			var foundMethod bool
			for _, entry := range entries {
				if m, ok := entry["method"]; ok && m == method {
					foundMethod = true
					break
				}
			}

			if !foundMethod {
				t.Errorf("Log should contain method %s", method)
			}
		})
	}
}

func TestLogging_DurationIsPositive(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &testLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Small delay to ensure measurable duration
		w.WriteHeader(http.StatusOK)
	})

	middleware := NewLoggingMiddleware(logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if len(entries) == 0 {
		t.Fatal("Expected at least one log entry")
	}

	var foundPositiveDuration bool
	for _, entry := range entries {
		// Check for duration_ms (actual field name in implementation)
		if dur, ok := entry["duration_ms"]; ok {
			switch d := dur.(type) {
			case time.Duration:
				if d > 0 {
					foundPositiveDuration = true
				}
			case string:
				// Duration might be formatted as string
				if d != "" && d != "0" && d != "0s" {
					foundPositiveDuration = true
				}
			case float64:
				if d > 0 {
					foundPositiveDuration = true
				}
			case int64:
				if d > 0 {
					foundPositiveDuration = true
				}
			}
		}
	}

	if !foundPositiveDuration {
		t.Error("Log should contain positive duration for request")
	}
}

func TestLogging_PassesThroughResponse(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	expectedBody := "response body content"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(expectedBody))
	})

	middleware := NewLoggingMiddleware(logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodPost, "/create", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Verify response is passed through correctly
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	if w.Body.String() != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, w.Body.String())
	}

	if w.Header().Get("X-Custom-Header") != "custom-value" {
		t.Error("Custom header should be passed through")
	}
}

func TestLogging_LogsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{"simple path", "/api/test"},
		{"root path", "/"},
		{"nested path", "/api/v1/resources/123"},
		{"path with query", "/search?q=test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entries := make([]map[string]any, 0)
			logHandler := &testLogHandler{entries: &entries}
			logger := slog.New(logHandler)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := NewLoggingMiddleware(logger)
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if len(entries) == 0 {
				t.Fatal("Expected at least one log entry")
			}

			// The path should be logged (with or without query string depending on implementation)
			var foundPath bool
			for _, entry := range entries {
				if path, ok := entry["path"]; ok {
					pathStr := path.(string)
					// Check if path contains the expected path prefix
					if strings.HasPrefix(tt.path, pathStr) || strings.HasPrefix(pathStr, strings.Split(tt.path, "?")[0]) {
						foundPath = true
						break
					}
				}
			}

			if !foundPath {
				t.Errorf("Log should contain path for %q", tt.path)
			}
		})
	}
}
