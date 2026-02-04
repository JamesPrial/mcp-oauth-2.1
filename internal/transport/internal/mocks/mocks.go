// Package mocks provides mock implementations for testing the transport layer.
package mocks

import (
	"context"
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
)

// TokenValidator is a mock implementation of oauth.TokenValidator.
type TokenValidator struct {
	ValidateFunc func(ctx context.Context, token string) (*oauth.TokenClaims, error)
}

// ValidateToken calls the mock ValidateFunc.
func (m *TokenValidator) ValidateToken(ctx context.Context, token string) (*oauth.TokenClaims, error) {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(ctx, token)
	}
	return nil, nil
}

// MetadataService is a mock implementation of oauth.MetadataService.
type MetadataService struct {
	GetMetadataFunc    func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error)
	GetMetadataURLFunc func() string
}

// GetMetadata calls the mock GetMetadataFunc.
func (m *MetadataService) GetMetadata(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
	if m.GetMetadataFunc != nil {
		return m.GetMetadataFunc(ctx)
	}
	return &oauth.ProtectedResourceMetadata{}, nil
}

// GetMetadataURL calls the mock GetMetadataURLFunc.
func (m *MetadataService) GetMetadataURL() string {
	if m.GetMetadataURLFunc != nil {
		return m.GetMetadataURLFunc()
	}
	return "https://example.com/.well-known/oauth-protected-resource"
}

// MCPHandler is a mock implementation of mcp.Handler.
type MCPHandler struct {
	HandleFunc func(ctx context.Context, req *mcp.Request) (*mcp.Response, error)
}

// HandleRequest calls the mock HandleFunc.
func (m *MCPHandler) HandleRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(ctx, req)
	}
	return &mcp.Response{
		JSONRPC: "2.0",
		ID:      req.ID,
	}, nil
}

// ErrorResponder is a mock implementation for error response handling.
type ErrorResponder struct {
	MetadataURL        string
	UnauthorizedCalled bool
	UnauthorizedScope  string
	UnauthorizedErr    error
	ForbiddenCalled    bool
	ForbiddenScopes    []string
	ForbiddenErr       error
	InternalCalled     bool
	InternalErr        error
	BadRequestCalled   bool
	BadRequestErr      error
}

// Unauthorized records the call and writes a 401 response.
func (m *ErrorResponder) Unauthorized(w http.ResponseWriter, scope string, err error) {
	m.UnauthorizedCalled = true
	m.UnauthorizedScope = scope
	m.UnauthorizedErr = err
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+m.MetadataURL+`"`)
	if scope != "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+m.MetadataURL+`", scope="`+scope+`"`)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// Forbidden records the call and writes a 403 response.
func (m *ErrorResponder) Forbidden(w http.ResponseWriter, requiredScopes []string, err error) {
	m.ForbiddenCalled = true
	m.ForbiddenScopes = requiredScopes
	m.ForbiddenErr = err

	scopeStr := ""
	for i, s := range requiredScopes {
		if i > 0 {
			scopeStr += " "
		}
		scopeStr += s
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scopeStr+`", resource_metadata="`+m.MetadataURL+`"`)
	w.WriteHeader(http.StatusForbidden)
}

// InternalError records the call and writes a 500 response.
func (m *ErrorResponder) InternalError(w http.ResponseWriter, err error) {
	m.InternalCalled = true
	m.InternalErr = err
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"internal server error"}`))
}

// BadRequest records the call and writes a 400 response.
func (m *ErrorResponder) BadRequest(w http.ResponseWriter, err error) {
	m.BadRequestCalled = true
	m.BadRequestErr = err
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"error":"bad request"}`))
}

// Reset clears all recorded state.
func (m *ErrorResponder) Reset() {
	m.UnauthorizedCalled = false
	m.UnauthorizedScope = ""
	m.UnauthorizedErr = nil
	m.ForbiddenCalled = false
	m.ForbiddenScopes = nil
	m.ForbiddenErr = nil
	m.InternalCalled = false
	m.InternalErr = nil
	m.BadRequestCalled = false
	m.BadRequestErr = nil
}
