// Package middleware provides HTTP middleware for the MCP server.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// mockTokenValidator implements oauth.TokenValidator for testing.
type mockTokenValidator struct {
	validateFunc func(ctx context.Context, token string) (*oauth.TokenClaims, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (*oauth.TokenClaims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, errors.New("not implemented")
}

// mockErrorResponder captures error responses for testing.
type mockErrorResponder struct {
	unauthorizedCalled bool
	unauthorizedScope  string
	forbiddenCalled    bool
	forbiddenScopes    []string
	metadataURL        string
}

func (m *mockErrorResponder) Unauthorized(w http.ResponseWriter, scope string, err error) {
	m.unauthorizedCalled = true
	m.unauthorizedScope = scope
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+m.metadataURL+`"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockErrorResponder) Forbidden(w http.ResponseWriter, requiredScopes []string, err error) {
	m.forbiddenCalled = true
	m.forbiddenScopes = requiredScopes
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+strings.Join(requiredScopes, " ")+`"`)
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockErrorResponder) InternalError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
}

func (m *mockErrorResponder) BadRequest(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusBadRequest)
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	validClaims := &oauth.TokenClaims{
		Subject:   "user123",
		Issuer:    "https://auth.example.com",
		Audience:  []string{"https://api.example.com"},
		Scopes:    []string{"mcp:read", "mcp:write"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		JTI:       "token-123",
	}

	tests := []struct {
		name              string
		authHeader        string
		validatorBehavior func(ctx context.Context, token string) (*oauth.TokenClaims, error)
		wantStatus        int
		wantNextCalled    bool
		wantClaimsInCtx   bool
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer valid-token-123",
			validatorBehavior: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
				if token == "valid-token-123" {
					return validClaims, nil
				}
				return nil, errors.New("invalid token")
			},
			wantStatus:      http.StatusOK,
			wantNextCalled:  true,
			wantClaimsInCtx: true,
		},
		{
			name:              "missing authorization header",
			authHeader:        "",
			validatorBehavior: nil,
			wantStatus:        http.StatusUnauthorized,
			wantNextCalled:    false,
			wantClaimsInCtx:   false,
		},
		{
			name:              "wrong auth scheme - Basic",
			authHeader:        "Basic dXNlcjpwYXNz",
			validatorBehavior: nil,
			wantStatus:        http.StatusUnauthorized,
			wantNextCalled:    false,
			wantClaimsInCtx:   false,
		},
		{
			name:              "wrong auth scheme - Digest",
			authHeader:        "Digest username=user",
			validatorBehavior: nil,
			wantStatus:        http.StatusUnauthorized,
			wantNextCalled:    false,
			wantClaimsInCtx:   false,
		},
		{
			name:       "invalid token",
			authHeader: "Bearer invalid-token",
			validatorBehavior: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
				return nil, errors.New("token signature verification failed")
			},
			wantStatus:      http.StatusUnauthorized,
			wantNextCalled:  false,
			wantClaimsInCtx: false,
		},
		{
			name:       "expired token",
			authHeader: "Bearer expired-token",
			validatorBehavior: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
				return nil, errors.New("token has expired")
			},
			wantStatus:      http.StatusUnauthorized,
			wantNextCalled:  false,
			wantClaimsInCtx: false,
		},
		{
			name:              "bearer with no token",
			authHeader:        "Bearer ",
			validatorBehavior: nil,
			wantStatus:        http.StatusUnauthorized,
			wantNextCalled:    false,
			wantClaimsInCtx:   false,
		},
		{
			name:              "bearer lowercase",
			authHeader:        "bearer valid-token",
			validatorBehavior: nil,
			// Implementation may or may not accept lowercase
			// Testing that it handles the case consistently
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name:       "token with wrong audience",
			authHeader: "Bearer wrong-audience-token",
			validatorBehavior: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
				return nil, errors.New("token audience does not match")
			},
			wantStatus:      http.StatusUnauthorized,
			wantNextCalled:  false,
			wantClaimsInCtx: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validator := &mockTokenValidator{validateFunc: tt.validatorBehavior}
			responder := &mockErrorResponder{metadataURL: "https://example.com/.well-known/oauth-protected-resource"}

			nextCalled := false
			var ctxFromNext context.Context

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				ctxFromNext = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			authMw := NewAuthMiddleware(validator, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
			handler := authMw.Authenticate()(next)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Authenticate() status = %v, want %v", w.Code, tt.wantStatus)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("Authenticate() next called = %v, want %v", nextCalled, tt.wantNextCalled)
			}

			if tt.wantClaimsInCtx && nextCalled {
				claims, ok := transportcore.ClaimsFromContext(ctxFromNext)
				if !ok {
					t.Error("Authenticate() claims not found in context")
				}
				if claims == nil {
					t.Error("Authenticate() claims in context are nil")
				}
			}

			// Verify 401 responses have WWW-Authenticate header
			if w.Code == http.StatusUnauthorized {
				if w.Header().Get("WWW-Authenticate") == "" {
					t.Error("Authenticate() 401 response missing WWW-Authenticate header")
				}
			}
		})
	}
}

func TestAuthenticate_ClaimsPassedToHandler(t *testing.T) {
	t.Parallel()

	expectedClaims := &oauth.TokenClaims{
		Subject:   "specific-user",
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"https://resource.example.com"},
		Scopes:    []string{"scope1", "scope2"},
		ExpiresAt: time.Now().Add(time.Hour),
		JTI:       "specific-jti",
	}

	validator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
			return expectedClaims, nil
		},
	}
	responder := &mockErrorResponder{}

	var receivedClaims *oauth.TokenClaims

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := transportcore.ClaimsFromContext(r.Context())
		if ok {
			receivedClaims = claims
		}
		w.WriteHeader(http.StatusOK)
	})

	authMw := NewAuthMiddleware(validator, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
	handler := authMw.Authenticate()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedClaims == nil {
		t.Fatal("Handler did not receive claims in context")
	}

	if receivedClaims.Subject != expectedClaims.Subject {
		t.Errorf("Claims Subject = %v, want %v", receivedClaims.Subject, expectedClaims.Subject)
	}
	if receivedClaims.JTI != expectedClaims.JTI {
		t.Errorf("Claims JTI = %v, want %v", receivedClaims.JTI, expectedClaims.JTI)
	}
}

func TestRequireScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tokenScopes    []string
		requiredScopes []string
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "has required scope",
			tokenScopes:    []string{"mcp:read"},
			requiredScopes: []string{"mcp:read"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "missing required scope",
			tokenScopes:    []string{"mcp:read"},
			requiredScopes: []string{"mcp:write"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "has all required scopes",
			tokenScopes:    []string{"mcp:read", "mcp:write"},
			requiredScopes: []string{"mcp:read", "mcp:write"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "missing one of multiple required",
			tokenScopes:    []string{"mcp:read"},
			requiredScopes: []string{"mcp:read", "mcp:write"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "has more scopes than required",
			tokenScopes:    []string{"mcp:read", "mcp:write", "mcp:admin"},
			requiredScopes: []string{"mcp:read"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "no scopes required",
			tokenScopes:    []string{},
			requiredScopes: []string{},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "no scopes required but has some",
			tokenScopes:    []string{"mcp:read"},
			requiredScopes: []string{},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "no token scopes but scope required",
			tokenScopes:    []string{},
			requiredScopes: []string{"mcp:read"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "three scopes required has all",
			tokenScopes:    []string{"mcp:read", "mcp:write", "mcp:admin"},
			requiredScopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "three scopes required missing last",
			tokenScopes:    []string{"mcp:read", "mcp:write"},
			requiredScopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			responder := &mockErrorResponder{metadataURL: "https://example.com/.well-known/oauth-protected-resource"}

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			authMw := NewAuthMiddleware(&mockTokenValidator{}, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
			handler := authMw.RequireScopes(tt.requiredScopes...)(next)

			// Create request with claims in context
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			claims := &oauth.TokenClaims{
				Subject: "test-user",
				Scopes:  tt.tokenScopes,
			}
			ctx := transportcore.ContextWithClaims(req.Context(), claims)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("RequireScopes() status = %v, want %v", w.Code, tt.wantStatus)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("RequireScopes() next called = %v, want %v", nextCalled, tt.wantNextCalled)
			}

			// Verify 403 responses have WWW-Authenticate with insufficient_scope
			if w.Code == http.StatusForbidden {
				authHeader := w.Header().Get("WWW-Authenticate")
				if authHeader == "" {
					t.Error("RequireScopes() 403 response missing WWW-Authenticate header")
				}
				if !strings.Contains(authHeader, "insufficient_scope") {
					t.Errorf("RequireScopes() WWW-Authenticate should contain insufficient_scope, got %s", authHeader)
				}
			}
		})
	}
}

func TestRequireScopes_NoClaims(t *testing.T) {
	t.Parallel()

	responder := &mockErrorResponder{}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	authMw := NewAuthMiddleware(&mockTokenValidator{}, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
	handler := authMw.RequireScopes("mcp:read")(next)

	// Request without claims in context
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Without claims, should return 401 (authentication required)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("RequireScopes() without claims status = %v, want 401", w.Code)
	}

	if nextCalled {
		t.Error("RequireScopes() should not call next handler when no claims present")
	}
}

func TestRequireScopes_NilClaims(t *testing.T) {
	t.Parallel()

	responder := &mockErrorResponder{}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	authMw := NewAuthMiddleware(&mockTokenValidator{}, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
	handler := authMw.RequireScopes("mcp:read")(next)

	// Request with nil claims explicitly set (edge case)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := transportcore.ContextWithClaims(req.Context(), nil)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// With nil claims, should return 401 (authentication required)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("RequireScopes() with nil claims status = %v, want 401", w.Code)
	}

	if nextCalled {
		t.Error("RequireScopes() should not call next handler when claims are nil")
	}
}

func TestMiddlewareChain_AuthThenScopes(t *testing.T) {
	t.Parallel()

	validClaims := &oauth.TokenClaims{
		Subject: "chain-user",
		Scopes:  []string{"mcp:read", "mcp:write"},
	}

	validator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
			if token == "valid-chain-token" {
				return validClaims, nil
			}
			return nil, errors.New("invalid")
		},
	}
	responder := &mockErrorResponder{metadataURL: "https://example.com/.well-known/oauth-protected-resource"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Chain: Authenticate -> RequireScopes -> handler
	authMw := NewAuthMiddleware(validator, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
	handler := authMw.Authenticate()(authMw.RequireScopes("mcp:read")(next))

	// Test with valid token and sufficient scopes
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-chain-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Chained middleware status = %v, want 200", w.Code)
	}
	if !nextCalled {
		t.Error("Chained middleware should call next handler")
	}
}

func TestMiddlewareChain_AuthFailsFirst(t *testing.T) {
	t.Parallel()

	validator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*oauth.TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}
	responder := &mockErrorResponder{metadataURL: "https://example.com/.well-known/oauth-protected-resource"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	authMw := NewAuthMiddleware(validator, responder, "https://example.com/.well-known/oauth-protected-resource", []string{"mcp:read"})
	handler := authMw.Authenticate()(authMw.RequireScopes("mcp:read")(next))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Auth fail should return 401, got %v", w.Code)
	}
	if nextCalled {
		t.Error("Next handler should not be called when auth fails")
	}
}
