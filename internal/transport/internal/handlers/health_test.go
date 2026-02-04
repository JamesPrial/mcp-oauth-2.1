// Package handlers provides HTTP handlers for the MCP server.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/mocks"
)

func TestHealthHandler_GET(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HealthHandler GET status = %v, want 200", resp.StatusCode)
	}

	// Response should be JSON
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("HealthHandler Content-Type = %v, want application/json", contentType)
	}

	// Response should contain status field
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check for status field (common pattern: {"status": "ok"} or {"status": "healthy"})
	if status, ok := body["status"]; ok {
		statusStr, isString := status.(string)
		if !isString {
			t.Error("status field should be a string")
		}
		if statusStr != "ok" && statusStr != "healthy" && statusStr != "up" {
			t.Logf("Note: status = %v (custom status value)", statusStr)
		}
	}
}

func TestHealthHandler_POST(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HealthHandler POST status = %v, want 405", w.Code)
	}
}

func TestHealthHandler_OtherMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/health", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("HealthHandler %s status = %v, want 405", method, w.Code)
			}
		})
	}
}

func TestHealthHandler_HEAD(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	req := httptest.NewRequest(http.MethodHead, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// HEAD might return 200 (same as GET without body) or 405
	if w.Code != http.StatusOK && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HealthHandler HEAD status = %v, want 200 or 405", w.Code)
	}

	// If 200, body should be empty for HEAD
	if w.Code == http.StatusOK && w.Body.Len() > 0 {
		t.Log("Note: HEAD response has body (some servers do this)")
	}
}

func TestHealthHandler_ResponseFormat(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Verify response is valid JSON
	var body interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Errorf("HealthHandler response is not valid JSON: %v", err)
	}

	// Body should be an object (map), not array or primitive
	if _, ok := body.(map[string]interface{}); !ok {
		t.Error("HealthHandler response should be a JSON object")
	}
}

func TestHealthHandler_MultipleRequests(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	// Health endpoint should be idempotent and stateless
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: HealthHandler status = %v, want 200", i+1, w.Code)
		}
	}
}

func TestHealthHandler_NoAuthRequired(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	// Health endpoint should work without Authorization header
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	// Explicitly no Authorization header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HealthHandler without auth status = %v, want 200", w.Code)
	}
}

func TestHealthHandler_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewHealthHandler(responder)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Concurrent request: status = %v, want 200", w.Code)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
