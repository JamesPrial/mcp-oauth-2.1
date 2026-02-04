// Package handlers provides HTTP handlers for the MCP server.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/mocks"
)

// mockMetadataService implements oauth.MetadataService for testing.
type mockMetadataService struct {
	getMetadataFunc    func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error)
	getMetadataURLFunc func() string
}

func (m *mockMetadataService) GetMetadata(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
	if m.getMetadataFunc != nil {
		return m.getMetadataFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockMetadataService) GetMetadataURL() string {
	if m.getMetadataURLFunc != nil {
		return m.getMetadataURLFunc()
	}
	return "https://example.com/.well-known/oauth-protected-resource"
}

func TestMetadataHandler_GET(t *testing.T) {
	t.Parallel()

	expectedMetadata := &oauth.ProtectedResourceMetadata{
		Resource:               "https://api.example.com/mcp",
		AuthorizationServers:   []string{"https://auth.example.com"},
		ScopesSupported:        []string{"mcp:read", "mcp:write", "mcp:admin"},
		BearerMethodsSupported: []string{"header"},
	}

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return expectedMetadata, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("MetadataHandler GET status = %v, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("MetadataHandler Content-Type = %v, want application/json", contentType)
	}

	var gotMetadata oauth.ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&gotMetadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if gotMetadata.Resource != expectedMetadata.Resource {
		t.Errorf("Resource = %v, want %v", gotMetadata.Resource, expectedMetadata.Resource)
	}

	if len(gotMetadata.AuthorizationServers) != len(expectedMetadata.AuthorizationServers) {
		t.Errorf("AuthorizationServers length = %v, want %v",
			len(gotMetadata.AuthorizationServers), len(expectedMetadata.AuthorizationServers))
	}

	if len(gotMetadata.ScopesSupported) != len(expectedMetadata.ScopesSupported) {
		t.Errorf("ScopesSupported length = %v, want %v",
			len(gotMetadata.ScopesSupported), len(expectedMetadata.ScopesSupported))
	}
}

func TestMetadataHandler_POST(t *testing.T) {
	t.Parallel()

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return &oauth.ProtectedResourceMetadata{}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("MetadataHandler POST status = %v, want 405", w.Code)
	}
}

func TestMetadataHandler_OtherMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
	}

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return &oauth.ProtectedResourceMetadata{}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/.well-known/oauth-protected-resource", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// HEAD might return 200, others should return 405
			if method != http.MethodHead && w.Code != http.StatusMethodNotAllowed {
				t.Errorf("MetadataHandler %s status = %v, want 405", method, w.Code)
			}
		})
	}
}

func TestMetadataHandler_ServiceError(t *testing.T) {
	t.Parallel()

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return nil, errors.New("internal service error")
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("MetadataHandler with error status = %v, want 500", w.Code)
	}
}

func TestMetadataHandler_MinimalMetadata(t *testing.T) {
	t.Parallel()

	// Minimal valid metadata per RFC 9728
	minimalMetadata := &oauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
	}

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return minimalMetadata, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MetadataHandler minimal metadata status = %v, want 200", w.Code)
	}

	var gotMetadata oauth.ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&gotMetadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if gotMetadata.Resource != minimalMetadata.Resource {
		t.Errorf("Resource = %v, want %v", gotMetadata.Resource, minimalMetadata.Resource)
	}
}

func TestMetadataHandler_MultipleAuthServers(t *testing.T) {
	t.Parallel()

	metadata := &oauth.ProtectedResourceMetadata{
		Resource: "https://api.example.com",
		AuthorizationServers: []string{
			"https://auth1.example.com",
			"https://auth2.example.com",
			"https://auth3.example.com",
		},
	}

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return metadata, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MetadataHandler status = %v, want 200", w.Code)
	}

	var gotMetadata oauth.ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&gotMetadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(gotMetadata.AuthorizationServers) != 3 {
		t.Errorf("AuthorizationServers length = %v, want 3", len(gotMetadata.AuthorizationServers))
	}
}

func TestMetadataHandler_ContextPassed(t *testing.T) {
	t.Parallel()

	var receivedCtx context.Context

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			receivedCtx = ctx
			return &oauth.ProtectedResourceMetadata{
				Resource:             "https://api.example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if receivedCtx == nil {
		t.Error("Context was not passed to service")
	}
}

func TestMetadataHandler_JSONContentType(t *testing.T) {
	t.Parallel()

	service := &mockMetadataService{
		getMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return &oauth.ProtectedResourceMetadata{
				Resource:             "https://api.example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	handler := NewMetadataHandler(service, responder)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	contentType := w.Header().Get("Content-Type")

	// Content-Type should be application/json
	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %v, want application/json", contentType)
	}
}
