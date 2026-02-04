package oauth

import (
	"testing"
)

func TestScopeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "ScopeRead value",
			got:      ScopeRead,
			want:     "mcp:read",
			constant: "ScopeRead",
		},
		{
			name:     "ScopeWrite value",
			got:      ScopeWrite,
			want:     "mcp:write",
			constant: "ScopeWrite",
		},
		{
			name:     "ScopeAdmin value",
			got:      ScopeAdmin,
			want:     "mcp:admin",
			constant: "ScopeAdmin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestBearerTokenConstant(t *testing.T) {
	t.Parallel()

	if BearerToken != "Bearer" {
		t.Errorf("BearerToken = %q, want %q", BearerToken, "Bearer")
	}
}

func TestTokenTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "TokenTypeBearer",
			got:      TokenTypeBearer,
			want:     "Bearer",
			constant: "TokenTypeBearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestGrantTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "GrantTypeAuthorizationCode",
			got:      GrantTypeAuthorizationCode,
			want:     "authorization_code",
			constant: "GrantTypeAuthorizationCode",
		},
		{
			name:     "GrantTypeRefreshToken",
			got:      GrantTypeRefreshToken,
			want:     "refresh_token",
			constant: "GrantTypeRefreshToken",
		},
		{
			name:     "GrantTypeClientCredentials",
			got:      GrantTypeClientCredentials,
			want:     "client_credentials",
			constant: "GrantTypeClientCredentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestResponseTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "ResponseTypeCode",
			got:      ResponseTypeCode,
			want:     "code",
			constant: "ResponseTypeCode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestCodeChallengeMethodConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "CodeChallengeMethodS256",
			got:      CodeChallengeMethodS256,
			want:     "S256",
			constant: "CodeChallengeMethodS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestOAuth21ProhibitsPlainPKCE(t *testing.T) {
	t.Parallel()

	// OAuth 2.1 requires S256 only - plain method is prohibited
	// This test documents the expected behavior
	if CodeChallengeMethodS256 != "S256" {
		t.Error("OAuth 2.1 requires S256 code challenge method")
	}
}

func TestScopeValues_MCPPrefix(t *testing.T) {
	t.Parallel()

	// All MCP scopes should have the mcp: prefix
	scopes := []string{ScopeRead, ScopeWrite, ScopeAdmin}
	prefix := "mcp:"

	for _, scope := range scopes {
		if len(scope) < len(prefix) || scope[:len(prefix)] != prefix {
			t.Errorf("Scope %q should have prefix %q", scope, prefix)
		}
	}
}

func TestHeaderConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "HeaderAuthorization",
			got:      HeaderAuthorization,
			want:     "Authorization",
			constant: "HeaderAuthorization",
		},
		{
			name:     "HeaderWWWAuthenticate",
			got:      HeaderWWWAuthenticate,
			want:     "WWW-Authenticate",
			constant: "HeaderWWWAuthenticate",
		},
		{
			name:     "HeaderContentType",
			got:      HeaderContentType,
			want:     "Content-Type",
			constant: "HeaderContentType",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}

func TestContentTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		want     string
		constant string
	}{
		{
			name:     "ContentTypeJSON",
			got:      ContentTypeJSON,
			want:     "application/json",
			constant: "ContentTypeJSON",
		},
		{
			name:     "ContentTypeFormURLEncoded",
			got:      ContentTypeFormURLEncoded,
			want:     "application/x-www-form-urlencoded",
			constant: "ContentTypeFormURLEncoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.constant, tt.got, tt.want)
			}
		})
	}
}
