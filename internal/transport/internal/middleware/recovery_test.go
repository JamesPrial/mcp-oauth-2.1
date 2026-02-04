// Package middleware provides HTTP middleware for the MCP server.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// panicLogHandler captures log entries for panic recovery testing.
type panicLogHandler struct {
	mu      sync.Mutex
	entries *[]map[string]any
}

func (h *panicLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *panicLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	entry := map[string]any{
		"level":   r.Level.String(),
		"message": r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		entry[a.Key] = a.Value.Any()
		return true
	})
	*h.entries = append(*h.entries, entry)
	return nil
}

func (h *panicLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *panicLogHandler) WithGroup(name string) slog.Handler {
	return h
}

func TestRecovery_PanicInHandler(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("intentional test panic")
	})

	middleware := NewRecoveryMiddleware(responder, logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	// The middleware should recover from the panic
	// This should NOT panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	// Should return 500 Internal Server Error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() status = %v, want 500", w.Code)
	}

	// Should have logged the error
	if len(*logHandler.entries) == 0 {
		t.Error("Recovery() should log panic")
	}
}

func TestRecovery_PanicWithError(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	responder := &mockErrorResponder{}

	testErr := http.ErrAbortHandler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(testErr)
	})

	middleware := NewRecoveryMiddleware(responder, logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/panic-error", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from error panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() status = %v, want 500", w.Code)
	}
}

func TestRecovery_PanicWithNil(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	logger := slog.New(logHandler)

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(nil)
	})

	middleware := NewRecoveryMiddleware(responder, logger)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/panic-nil", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from nil panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	// Even nil panic should result in 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() with nil panic status = %v, want 500", w.Code)
	}
}

func TestRecovery_NoPanic(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	expectedBody := "normal response"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/normal", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Recovery() normal request status = %v, want 200", w.Code)
	}

	if w.Body.String() != expectedBody {
		t.Errorf("Recovery() body = %q, want %q", w.Body.String(), expectedBody)
	}
}

func TestRecovery_PreservesHeaders(t *testing.T) {
	t.Parallel()

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(http.StatusOK)
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/headers", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Custom") != "value" {
		t.Error("Recovery() should preserve headers on normal request")
	}
}

func TestRecovery_PanicWithStruct(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	type customPanic struct {
		Code    int
		Message string
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(customPanic{Code: 123, Message: "custom panic"})
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/panic-struct", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from struct panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() with struct panic status = %v, want 500", w.Code)
	}
}

func TestRecovery_PanicWithInt(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(42)
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/panic-int", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from int panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() with int panic status = %v, want 500", w.Code)
	}
}

func TestRecovery_LogsError(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("logged panic message")
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/logged-panic", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Verify error was logged
	if len(*logHandler.entries) == 0 {
		t.Fatal("Expected at least one log entry for panic")
	}

	// Check that an error-level log was created
	var foundErrorLog bool
	for _, entry := range *logHandler.entries {
		if level, ok := entry["level"]; ok {
			if level == "ERROR" || level == slog.LevelError.String() {
				foundErrorLog = true
				break
			}
		}
	}

	if !foundErrorLog {
		t.Error("Panic should be logged at ERROR level")
	}
}

func TestRecovery_ResponseBodyOnPanic(t *testing.T) {
	t.Parallel()

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("response body test")
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/body-on-panic", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Response body should contain some error indication
	// (implementation may vary - could be JSON, plain text, or empty)
	// At minimum, status should be 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 status, got %d", w.Code)
	}
}

func TestRecovery_NestedPanic(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		func() {
			func() {
				panic("deeply nested panic")
			}()
		}()
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/nested-panic", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovery middleware did not recover from nested panic: %v", r)
			}
		}()
		handler.ServeHTTP(w, req)
	}()

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() with nested panic status = %v, want 500", w.Code)
	}
}

func TestRecovery_MultiplePanicsSequential(t *testing.T) {
	t.Parallel()

	entries := make([]map[string]any, 0)
	logHandler := &panicLogHandler{entries: &entries}
	slog.SetDefault(slog.New(logHandler))

	responder := &mockErrorResponder{}

	panicCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panicCount++
		panic("sequential panic " + string(rune('0'+panicCount)))
	})

	middleware := NewRecoveryMiddleware(responder, nil)
	handler := middleware(next)

	// First request
	req1 := httptest.NewRequest(http.MethodGet, "/first", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusInternalServerError {
		t.Errorf("First panic: status = %v, want 500", w1.Code)
	}

	// Second request - middleware should still work
	req2 := httptest.NewRequest(http.MethodGet, "/second", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusInternalServerError {
		t.Errorf("Second panic: status = %v, want 500", w2.Code)
	}

	// Both panics should have been recovered
	if panicCount != 2 {
		t.Errorf("Expected 2 panics, got %d", panicCount)
	}
}
