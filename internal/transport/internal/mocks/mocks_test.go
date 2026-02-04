// Package mocks provides mock implementations for testing the transport layer.
package mocks

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
)

func TestTokenValidator_ValidateToken(t *testing.T) {
	t.Parallel()

	expectedClaims := &oauth.TokenClaims{
		Subject:   "test-user",
		Issuer:    "https://auth.example.com",
		Scopes:    []string{"mcp:read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	validator := &TokenValidator{
		ValidateFunc: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
			if token == "valid-token" {
				return expectedClaims, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	// Test valid token
	claims, err := validator.ValidateToken(context.Background(), "valid-token")
	if err != nil {
		t.Errorf("ValidateToken with valid token error: %v", err)
	}
	if claims.Subject != expectedClaims.Subject {
		t.Errorf("Subject = %v, want %v", claims.Subject, expectedClaims.Subject)
	}

	// Test invalid token
	_, err = validator.ValidateToken(context.Background(), "invalid-token")
	if err == nil {
		t.Error("ValidateToken with invalid token should return error")
	}
}

func TestTokenValidator_NilFunc(t *testing.T) {
	t.Parallel()

	validator := &TokenValidator{}

	claims, err := validator.ValidateToken(context.Background(), "any-token")
	if err != nil {
		t.Errorf("ValidateToken with nil func error: %v", err)
	}
	if claims != nil {
		t.Errorf("ValidateToken with nil func claims: %v, want nil", claims)
	}
}

func TestMetadataService_GetMetadata(t *testing.T) {
	t.Parallel()

	expectedMetadata := &oauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
	}

	service := &MetadataService{
		GetMetadataFunc: func(ctx context.Context) (*oauth.ProtectedResourceMetadata, error) {
			return expectedMetadata, nil
		},
	}

	metadata, err := service.GetMetadata(context.Background())
	if err != nil {
		t.Errorf("GetMetadata error: %v", err)
	}
	if metadata.Resource != expectedMetadata.Resource {
		t.Errorf("Resource = %v, want %v", metadata.Resource, expectedMetadata.Resource)
	}
}

func TestMetadataService_GetMetadataURL(t *testing.T) {
	t.Parallel()

	expectedURL := "https://custom.example.com/.well-known/oauth-protected-resource"

	service := &MetadataService{
		GetMetadataURLFunc: func() string {
			return expectedURL
		},
	}

	url := service.GetMetadataURL()
	if url != expectedURL {
		t.Errorf("GetMetadataURL = %v, want %v", url, expectedURL)
	}
}

func TestMetadataService_DefaultURL(t *testing.T) {
	t.Parallel()

	service := &MetadataService{}

	url := service.GetMetadataURL()
	if url == "" {
		t.Error("GetMetadataURL with nil func should return default URL")
	}
}

func TestMCPHandler_HandleRequest(t *testing.T) {
	t.Parallel()

	expectedResult := map[string]any{"success": true}

	handler := &MCPHandler{
		HandleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  expectedResult,
			}, nil
		},
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	resp, err := handler.HandleRequest(context.Background(), req)
	if err != nil {
		t.Errorf("HandleRequest error: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %v, want 2.0", resp.JSONRPC)
	}
}

func TestErrorResponder_Unauthorized(t *testing.T) {
	t.Parallel()

	responder := &ErrorResponder{
		MetadataURL: "https://example.com/.well-known/oauth-protected-resource",
	}

	w := httptest.NewRecorder()
	responder.Unauthorized(w, "mcp:read", errors.New("test error"))

	if !responder.UnauthorizedCalled {
		t.Error("UnauthorizedCalled should be true")
	}
	if responder.UnauthorizedScope != "mcp:read" {
		t.Errorf("UnauthorizedScope = %v, want mcp:read", responder.UnauthorizedScope)
	}
	if w.Code != 401 {
		t.Errorf("Status = %v, want 401", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Error("WWW-Authenticate header should contain Bearer")
	}
}

func TestErrorResponder_Forbidden(t *testing.T) {
	t.Parallel()

	responder := &ErrorResponder{
		MetadataURL: "https://example.com/.well-known/oauth-protected-resource",
	}

	w := httptest.NewRecorder()
	responder.Forbidden(w, []string{"mcp:read", "mcp:write"}, errors.New("test error"))

	if !responder.ForbiddenCalled {
		t.Error("ForbiddenCalled should be true")
	}
	if len(responder.ForbiddenScopes) != 2 {
		t.Errorf("ForbiddenScopes length = %v, want 2", len(responder.ForbiddenScopes))
	}
	if w.Code != 403 {
		t.Errorf("Status = %v, want 403", w.Code)
	}
	authHeader := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(authHeader, "insufficient_scope") {
		t.Error("WWW-Authenticate header should contain insufficient_scope")
	}
}

func TestErrorResponder_InternalError(t *testing.T) {
	t.Parallel()

	responder := &ErrorResponder{}

	w := httptest.NewRecorder()
	responder.InternalError(w, errors.New("test error"))

	if !responder.InternalCalled {
		t.Error("InternalCalled should be true")
	}
	if w.Code != 500 {
		t.Errorf("Status = %v, want 500", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Error("Content-Type should be application/json")
	}
}

func TestErrorResponder_BadRequest(t *testing.T) {
	t.Parallel()

	responder := &ErrorResponder{}

	w := httptest.NewRecorder()
	responder.BadRequest(w, errors.New("test error"))

	if !responder.BadRequestCalled {
		t.Error("BadRequestCalled should be true")
	}
	if w.Code != 400 {
		t.Errorf("Status = %v, want 400", w.Code)
	}
}

func TestErrorResponder_Reset(t *testing.T) {
	t.Parallel()

	responder := &ErrorResponder{
		MetadataURL: "https://example.com/.well-known/oauth-protected-resource",
	}

	w := httptest.NewRecorder()
	responder.Unauthorized(w, "mcp:read", errors.New("test"))

	if !responder.UnauthorizedCalled {
		t.Fatal("Setup failed: UnauthorizedCalled should be true")
	}

	responder.Reset()

	if responder.UnauthorizedCalled {
		t.Error("After Reset, UnauthorizedCalled should be false")
	}
	if responder.UnauthorizedScope != "" {
		t.Error("After Reset, UnauthorizedScope should be empty")
	}
}
