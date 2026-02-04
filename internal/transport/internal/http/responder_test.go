// Package http provides HTTP response utilities for the MCP server.
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// newTestResponder creates a responder for testing.
// Uses the actual NewErrorResponder constructor.
func newTestResponder(metadataURL string) transportcore.ErrorResponder {
	return NewErrorResponder(metadataURL)
}

func TestResponder_Unauthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		metadataURL           string
		scope                 string
		err                   error
		wantStatus            int
		wantAuthHeaderContain []string
		wantAuthHeaderExclude []string
	}{
		{
			name:        "with scope",
			metadataURL: "https://example.com/.well-known/oauth-protected-resource",
			scope:       "mcp:read",
			err:         errors.New("token expired"),
			wantStatus:  http.StatusUnauthorized,
			wantAuthHeaderContain: []string{
				"Bearer",
				`resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
				`scope="mcp:read"`,
			},
		},
		{
			name:        "empty scope",
			metadataURL: "https://example.com/.well-known/oauth-protected-resource",
			scope:       "",
			err:         errors.New("missing token"),
			wantStatus:  http.StatusUnauthorized,
			wantAuthHeaderContain: []string{
				"Bearer",
				`resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			},
			wantAuthHeaderExclude: []string{
				"scope=",
			},
		},
		{
			name:        "with multiple scopes space-separated",
			metadataURL: "https://api.example.com/.well-known/oauth-protected-resource",
			scope:       "mcp:read mcp:write",
			err:         errors.New("invalid token"),
			wantStatus:  http.StatusUnauthorized,
			wantAuthHeaderContain: []string{
				"Bearer",
				`scope="mcp:read mcp:write"`,
			},
		},
		{
			name:        "nil error",
			metadataURL: "https://example.com/.well-known/oauth-protected-resource",
			scope:       "mcp:read",
			err:         nil,
			wantStatus:  http.StatusUnauthorized,
			wantAuthHeaderContain: []string{
				"Bearer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newTestResponder(tt.metadataURL)
			w := httptest.NewRecorder()

			r.Unauthorized(w, tt.scope, tt.err)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Unauthorized() status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader == "" {
				t.Error("Unauthorized() missing WWW-Authenticate header")
				return
			}

			for _, contain := range tt.wantAuthHeaderContain {
				if !strings.Contains(authHeader, contain) {
					t.Errorf("Unauthorized() WWW-Authenticate = %q, want to contain %q", authHeader, contain)
				}
			}

			for _, exclude := range tt.wantAuthHeaderExclude {
				if strings.Contains(authHeader, exclude) {
					t.Errorf("Unauthorized() WWW-Authenticate = %q, should not contain %q", authHeader, exclude)
				}
			}
		})
	}
}

func TestResponder_Forbidden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		metadataURL           string
		requiredScopes        []string
		err                   error
		wantStatus            int
		wantAuthHeaderContain []string
	}{
		{
			name:           "single scope",
			metadataURL:    "https://example.com/.well-known/oauth-protected-resource",
			requiredScopes: []string{"mcp:read"},
			err:            errors.New("insufficient scope"),
			wantStatus:     http.StatusForbidden,
			wantAuthHeaderContain: []string{
				"Bearer",
				`error="insufficient_scope"`,
				`scope="mcp:read"`,
				`resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			},
		},
		{
			name:           "multiple scopes",
			metadataURL:    "https://api.example.com/.well-known/oauth-protected-resource",
			requiredScopes: []string{"mcp:read", "mcp:write"},
			err:            errors.New("missing write scope"),
			wantStatus:     http.StatusForbidden,
			wantAuthHeaderContain: []string{
				"Bearer",
				`error="insufficient_scope"`,
				"mcp:read",
				"mcp:write",
				`resource_metadata=`,
			},
		},
		{
			name:           "three scopes",
			metadataURL:    "https://example.com/.well-known/oauth-protected-resource",
			requiredScopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			err:            errors.New("admin required"),
			wantStatus:     http.StatusForbidden,
			wantAuthHeaderContain: []string{
				"Bearer",
				`error="insufficient_scope"`,
			},
		},
		{
			name:           "empty scopes slice",
			metadataURL:    "https://example.com/.well-known/oauth-protected-resource",
			requiredScopes: []string{},
			err:            errors.New("forbidden"),
			wantStatus:     http.StatusForbidden,
			wantAuthHeaderContain: []string{
				"Bearer",
				`error="insufficient_scope"`,
			},
		},
		{
			name:           "nil error",
			metadataURL:    "https://example.com/.well-known/oauth-protected-resource",
			requiredScopes: []string{"mcp:read"},
			err:            nil,
			wantStatus:     http.StatusForbidden,
			wantAuthHeaderContain: []string{
				"Bearer",
				`error="insufficient_scope"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newTestResponder(tt.metadataURL)
			w := httptest.NewRecorder()

			r.Forbidden(w, tt.requiredScopes, tt.err)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Forbidden() status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader == "" {
				t.Error("Forbidden() missing WWW-Authenticate header")
				return
			}

			for _, contain := range tt.wantAuthHeaderContain {
				if !strings.Contains(authHeader, contain) {
					t.Errorf("Forbidden() WWW-Authenticate = %q, want to contain %q", authHeader, contain)
				}
			}
		})
	}
}

func TestResponder_Forbidden_ScopesSpaceSeparated(t *testing.T) {
	t.Parallel()

	r := newTestResponder("https://example.com/.well-known/oauth-protected-resource")
	w := httptest.NewRecorder()

	r.Forbidden(w, []string{"mcp:read", "mcp:write"}, errors.New("test"))

	authHeader := w.Header().Get("WWW-Authenticate")

	// The scopes should be space-separated in the scope parameter
	// Either "mcp:read mcp:write" or "mcp:write mcp:read" order
	if !strings.Contains(authHeader, "mcp:read") || !strings.Contains(authHeader, "mcp:write") {
		t.Errorf("Forbidden() scope should contain both scopes, got: %s", authHeader)
	}
}

func TestResponder_InternalError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantBodyFields []string
	}{
		{
			name:       "standard error",
			err:        errors.New("database connection failed"),
			wantStatus: http.StatusInternalServerError,
			wantBodyFields: []string{
				"error",
			},
		},
		{
			name:           "nil error",
			err:            nil,
			wantStatus:     http.StatusInternalServerError,
			wantBodyFields: []string{},
		},
		{
			name:       "wrapped error",
			err:        errors.New("outer: inner error"),
			wantStatus: http.StatusInternalServerError,
			wantBodyFields: []string{
				"error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newTestResponder("https://example.com/.well-known/oauth-protected-resource")
			w := httptest.NewRecorder()

			r.InternalError(w, tt.err)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("InternalError() status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				t.Errorf("InternalError() Content-Type = %v, want application/json", contentType)
			}

			// Verify response body is valid JSON
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Errorf("InternalError() body is not valid JSON: %v", err)
			}

			for _, field := range tt.wantBodyFields {
				if _, ok := body[field]; !ok {
					t.Errorf("InternalError() body missing field %q", field)
				}
			}
		})
	}
}

func TestResponder_BadRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantBodyFields []string
	}{
		{
			name:       "validation error",
			err:        errors.New("missing required field: name"),
			wantStatus: http.StatusBadRequest,
			wantBodyFields: []string{
				"error",
			},
		},
		{
			name:       "parse error",
			err:        errors.New("invalid JSON syntax"),
			wantStatus: http.StatusBadRequest,
			wantBodyFields: []string{
				"error",
			},
		},
		{
			name:           "nil error",
			err:            nil,
			wantStatus:     http.StatusBadRequest,
			wantBodyFields: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newTestResponder("https://example.com/.well-known/oauth-protected-resource")
			w := httptest.NewRecorder()

			r.BadRequest(w, tt.err)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("BadRequest() status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				t.Errorf("BadRequest() Content-Type = %v, want application/json", contentType)
			}

			// Verify response body is valid JSON
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Errorf("BadRequest() body is not valid JSON: %v", err)
			}

			for _, field := range tt.wantBodyFields {
				if _, ok := body[field]; !ok {
					t.Errorf("BadRequest() body missing field %q", field)
				}
			}
		})
	}
}

func TestResponder_ErrorResponseFormat(t *testing.T) {
	t.Parallel()

	// Test that error responses follow a consistent JSON format
	r := newTestResponder("https://example.com/.well-known/oauth-protected-resource")

	testCases := []struct {
		name   string
		call   func(w http.ResponseWriter)
		status int
	}{
		{
			name: "InternalError",
			call: func(w http.ResponseWriter) {
				r.InternalError(w, errors.New("test error"))
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "BadRequest",
			call: func(w http.ResponseWriter) {
				r.BadRequest(w, errors.New("test error"))
			},
			status: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			tc.call(w)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			// All error responses should be JSON
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("%s should return application/json, got %s", tc.name, ct)
			}

			// All error responses should be parseable
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Errorf("%s returned invalid JSON: %v", tc.name, err)
			}

			if resp.StatusCode != tc.status {
				t.Errorf("%s status = %d, want %d", tc.name, resp.StatusCode, tc.status)
			}
		})
	}
}
