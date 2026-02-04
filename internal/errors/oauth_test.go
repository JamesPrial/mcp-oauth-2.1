package errors

import (
	"strings"
	"testing"
)

// OAuthError represents an OAuth 2.0/2.1 specific error that can generate
// a WWW-Authenticate header value for 401/403 responses.
// This test file tests the expected interface for OAuthError.

func TestOAuthError_WWWAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		error_           string
		scope            string
		resourceMetadata string
		wantContains     []string
		wantPrefix       string
	}{
		{
			name:         "basic invalid_token error",
			error_:       "invalid_token",
			scope:        "",
			wantPrefix:   "Bearer",
			wantContains: []string{`error="invalid_token"`},
		},
		{
			name:         "with scope",
			error_:       "invalid_token",
			scope:        "mcp:read mcp:write",
			wantPrefix:   "Bearer",
			wantContains: []string{`error="invalid_token"`, `scope="mcp:read mcp:write"`},
		},
		{
			name:             "with resource_metadata",
			error_:           "invalid_token",
			resourceMetadata: "https://example.com/.well-known/oauth-protected-resource",
			wantPrefix:       "Bearer",
			wantContains:     []string{`error="invalid_token"`, `resource_metadata="https://example.com/.well-known/oauth-protected-resource"`},
		},
		{
			name:             "insufficient_scope error with all fields",
			error_:           "insufficient_scope",
			scope:            "mcp:admin",
			resourceMetadata: "https://example.com/.well-known/oauth-protected-resource",
			wantPrefix:       "Bearer",
			wantContains:     []string{`error="insufficient_scope"`, `scope="mcp:admin"`, `resource_metadata=`},
		},
		{
			name:         "invalid_request error",
			error_:       "invalid_request",
			wantPrefix:   "Bearer",
			wantContains: []string{`error="invalid_request"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oauthErr := &OAuthError{
				ErrorCode:        tt.error_,
				Scope:            tt.scope,
				ResourceMetadata: tt.resourceMetadata,
			}

			got := oauthErr.WWWAuthenticate()

			// Check prefix
			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("WWWAuthenticate() = %q, want prefix %q", got, tt.wantPrefix)
			}

			// Check all expected substrings
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("WWWAuthenticate() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

func TestOAuthError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		oauthErr     *OAuthError
		wantContains string
	}{
		{
			name: "contains error code",
			oauthErr: &OAuthError{
				ErrorCode: "invalid_token",
			},
			wantContains: "invalid_token",
		},
		{
			name: "contains description if present",
			oauthErr: &OAuthError{
				ErrorCode:        "invalid_token",
				ErrorDescription: "The access token expired",
			},
			wantContains: "The access token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.oauthErr.Error()
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("OAuthError.Error() = %q, want to contain %q", got, tt.wantContains)
			}
		})
	}
}

func TestOAuthError_WWWAuthenticate_EmptyError(t *testing.T) {
	t.Parallel()

	// When no error code is set, should still produce valid Bearer header
	oauthErr := &OAuthError{}
	got := oauthErr.WWWAuthenticate()

	if !strings.HasPrefix(got, "Bearer") {
		t.Errorf("WWWAuthenticate() with empty error should start with 'Bearer', got %q", got)
	}
}

func TestOAuthError_WWWAuthenticate_RealmIncluded(t *testing.T) {
	t.Parallel()

	oauthErr := &OAuthError{
		ErrorCode: "invalid_token",
		Realm:     "mcp-server",
	}

	got := oauthErr.WWWAuthenticate()

	if !strings.Contains(got, `realm="mcp-server"`) {
		t.Errorf("WWWAuthenticate() = %q, want to contain realm", got)
	}
}

func TestNewOAuthError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		errorCode        string
		errorDescription string
		wantCode         string
		wantDesc         string
	}{
		{
			name:             "creates with error code only",
			errorCode:        "invalid_token",
			errorDescription: "",
			wantCode:         "invalid_token",
			wantDesc:         "",
		},
		{
			name:             "creates with error code and description",
			errorCode:        "invalid_token",
			errorDescription: "Token has expired",
			wantCode:         "invalid_token",
			wantDesc:         "Token has expired",
		},
		{
			name:             "creates insufficient_scope error",
			errorCode:        "insufficient_scope",
			errorDescription: "The request requires higher privileges",
			wantCode:         "insufficient_scope",
			wantDesc:         "The request requires higher privileges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewOAuthError(tt.errorCode, tt.errorDescription)

			if got == nil {
				t.Fatal("NewOAuthError() returned nil")
			}
			if got.ErrorCode != tt.wantCode {
				t.Errorf("NewOAuthError() ErrorCode = %q, want %q", got.ErrorCode, tt.wantCode)
			}
			if got.ErrorDescription != tt.wantDesc {
				t.Errorf("NewOAuthError() ErrorDescription = %q, want %q", got.ErrorDescription, tt.wantDesc)
			}
		})
	}
}

func TestOAuthError_WithScope(t *testing.T) {
	t.Parallel()

	err := NewOAuthError("insufficient_scope", "")
	result := err.WithScope("mcp:read mcp:write")

	if result != err {
		t.Error("WithScope() should return same error for chaining")
	}
	if err.Scope != "mcp:read mcp:write" {
		t.Errorf("WithScope() Scope = %q, want %q", err.Scope, "mcp:read mcp:write")
	}
}

func TestOAuthError_WithResourceMetadata(t *testing.T) {
	t.Parallel()

	err := NewOAuthError("invalid_token", "")
	url := "https://example.com/.well-known/oauth-protected-resource"
	result := err.WithResourceMetadata(url)

	if result != err {
		t.Error("WithResourceMetadata() should return same error for chaining")
	}
	if err.ResourceMetadata != url {
		t.Errorf("WithResourceMetadata() ResourceMetadata = %q, want %q", err.ResourceMetadata, url)
	}
}

func TestOAuthError_Chaining(t *testing.T) {
	t.Parallel()

	err := NewOAuthError("insufficient_scope", "Needs more permissions").
		WithScope("mcp:admin").
		WithResourceMetadata("https://example.com/.well-known/oauth-protected-resource")

	if err.ErrorCode != "insufficient_scope" {
		t.Errorf("Chaining broke ErrorCode, got %q", err.ErrorCode)
	}
	if err.ErrorDescription != "Needs more permissions" {
		t.Errorf("Chaining broke ErrorDescription, got %q", err.ErrorDescription)
	}
	if err.Scope != "mcp:admin" {
		t.Errorf("Chaining did not set Scope, got %q", err.Scope)
	}
	if err.ResourceMetadata != "https://example.com/.well-known/oauth-protected-resource" {
		t.Errorf("Chaining did not set ResourceMetadata, got %q", err.ResourceMetadata)
	}
}

// OAuthErrorCode constants that should be defined
func TestOAuthErrorCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     string
		wantCode string
	}{
		{
			name:     "InvalidToken",
			code:     OAuthErrorInvalidToken,
			wantCode: "invalid_token",
		},
		{
			name:     "InsufficientScope",
			code:     OAuthErrorInsufficientScope,
			wantCode: "insufficient_scope",
		},
		{
			name:     "InvalidRequest",
			code:     OAuthErrorInvalidRequest,
			wantCode: "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.code != tt.wantCode {
				t.Errorf("OAuth error code %s = %q, want %q", tt.name, tt.code, tt.wantCode)
			}
		})
	}
}
