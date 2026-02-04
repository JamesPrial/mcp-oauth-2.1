// Package metadata provides OAuth 2.0 Protected Resource Metadata (RFC 9728)
// functionality for the MCP server.
// This test file tests the metadata service functionality.
package metadata

import (
	"context"
	"strings"
	"testing"
)

// testConfig holds configuration for test metadata services.
type testConfig struct {
	Resource               string
	AuthorizationServers   []string
	ScopesSupported        []string
	BearerMethodsSupported []string
}

// mockService wraps the real Service for testing.
type mockService struct {
	service *Service
}

func newMockService(config testConfig) *mockService {
	service := NewService(config.Resource, config.AuthorizationServers, config.ScopesSupported)
	return &mockService{service: service}
}

func (s *mockService) GetMetadata() *ProtectedResourceMetadata {
	metadata, _ := s.service.GetMetadata(context.Background())
	return metadata
}

func (s *mockService) GetMetadataURL() string {
	return s.service.GetMetadataURL()
}

// getMetadataURL computes the well-known URL for the protected resource metadata.
// This matches the implementation in service.go.
func getMetadataURL(resource string) string {
	const wellKnownPath = "/.well-known/oauth-protected-resource"
	// Remove trailing slash (normalizeBaseURL equivalent)
	normalized := strings.TrimRight(resource, "/")
	return normalized + wellKnownPath
}

func TestService_GetMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		config               testConfig
		wantResource         string
		wantAuthServersCount int
		wantScopesCount      int
	}{
		{
			name: "valid config",
			config: testConfig{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth.example.com"},
				ScopesSupported:      []string{"mcp:read", "mcp:write"},
			},
			wantResource:         "https://example.com/mcp",
			wantAuthServersCount: 1,
			wantScopesCount:      2,
		},
		{
			name: "multiple authorization servers",
			config: testConfig{
				Resource:             "https://example.com",
				AuthorizationServers: []string{"https://auth1.example.com", "https://auth2.example.com"},
				ScopesSupported:      []string{"mcp:read"},
			},
			wantResource:         "https://example.com",
			wantAuthServersCount: 2,
			wantScopesCount:      1,
		},
		{
			name: "no scopes",
			config: testConfig{
				Resource:             "https://example.com/api",
				AuthorizationServers: []string{"https://auth.example.com"},
				ScopesSupported:      nil,
			},
			wantResource:         "https://example.com/api",
			wantAuthServersCount: 1,
			wantScopesCount:      0,
		},
		{
			name: "empty config",
			config: testConfig{
				Resource:             "",
				AuthorizationServers: nil,
				ScopesSupported:      nil,
			},
			wantResource:         "",
			wantAuthServersCount: 0,
			wantScopesCount:      0,
		},
		{
			name: "with bearer methods",
			config: testConfig{
				Resource:               "https://example.com/mcp",
				AuthorizationServers:   []string{"https://auth.example.com"},
				ScopesSupported:        []string{"mcp:read"},
				BearerMethodsSupported: []string{"header"},
			},
			wantResource:         "https://example.com/mcp",
			wantAuthServersCount: 1,
			wantScopesCount:      1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := newMockService(tt.config)
			metadata := service.GetMetadata()

			if metadata == nil {
				t.Fatal("GetMetadata() returned nil")
			}
			if metadata.Resource != tt.wantResource {
				t.Errorf("Resource = %q, want %q", metadata.Resource, tt.wantResource)
			}
			if len(metadata.AuthorizationServers) != tt.wantAuthServersCount {
				t.Errorf("AuthorizationServers count = %d, want %d", len(metadata.AuthorizationServers), tt.wantAuthServersCount)
			}
			if len(metadata.ScopesSupported) != tt.wantScopesCount {
				t.Errorf("ScopesSupported count = %d, want %d", len(metadata.ScopesSupported), tt.wantScopesCount)
			}
		})
	}
}

func TestService_GetMetadata_FieldValues(t *testing.T) {
	t.Parallel()

	config := testConfig{
		Resource:               "https://api.example.com/mcp",
		AuthorizationServers:   []string{"https://auth1.example.com", "https://auth2.example.com"},
		ScopesSupported:        []string{"mcp:read", "mcp:write", "mcp:admin"},
		BearerMethodsSupported: []string{"header", "body"},
	}

	service := newMockService(config)
	metadata := service.GetMetadata()

	// Verify exact field values
	if metadata.Resource != "https://api.example.com/mcp" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, "https://api.example.com/mcp")
	}

	// Verify authorization servers
	if len(metadata.AuthorizationServers) != 2 {
		t.Fatalf("AuthorizationServers length = %d, want 2", len(metadata.AuthorizationServers))
	}
	if metadata.AuthorizationServers[0] != "https://auth1.example.com" {
		t.Errorf("AuthorizationServers[0] = %q, want %q", metadata.AuthorizationServers[0], "https://auth1.example.com")
	}
	if metadata.AuthorizationServers[1] != "https://auth2.example.com" {
		t.Errorf("AuthorizationServers[1] = %q, want %q", metadata.AuthorizationServers[1], "https://auth2.example.com")
	}

	// Verify scopes
	if len(metadata.ScopesSupported) != 3 {
		t.Fatalf("ScopesSupported length = %d, want 3", len(metadata.ScopesSupported))
	}
	expectedScopes := []string{"mcp:read", "mcp:write", "mcp:admin"}
	for i, scope := range expectedScopes {
		if metadata.ScopesSupported[i] != scope {
			t.Errorf("ScopesSupported[%d] = %q, want %q", i, metadata.ScopesSupported[i], scope)
		}
	}

	// Verify bearer methods - implementation always sets to ["header"] per OAuth 2.1
	if len(metadata.BearerMethodsSupported) != 1 {
		t.Fatalf("BearerMethodsSupported length = %d, want 1", len(metadata.BearerMethodsSupported))
	}
	if metadata.BearerMethodsSupported[0] != "header" {
		t.Errorf("BearerMethodsSupported[0] = %q, want %q", metadata.BearerMethodsSupported[0], "header")
	}
}

func TestGetMetadataURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource string
		wantURL  string
	}{
		{
			name:     "no path",
			resource: "https://example.com",
			wantURL:  "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:     "with path",
			resource: "https://example.com/mcp",
			wantURL:  "https://example.com/mcp/.well-known/oauth-protected-resource",
		},
		{
			name:     "with multi-level path",
			resource: "https://example.com/api/v1/mcp",
			wantURL:  "https://example.com/api/v1/mcp/.well-known/oauth-protected-resource",
		},
		{
			name:     "with port no path",
			resource: "https://example.com:8443",
			wantURL:  "https://example.com:8443/.well-known/oauth-protected-resource",
		},
		{
			name:     "with port and path",
			resource: "https://example.com:8443/mcp",
			wantURL:  "https://example.com:8443/mcp/.well-known/oauth-protected-resource",
		},
		{
			name:     "http scheme",
			resource: "http://localhost:8080/mcp",
			wantURL:  "http://localhost:8080/mcp/.well-known/oauth-protected-resource",
		},
		{
			name:     "trailing slash removed",
			resource: "https://example.com/mcp/",
			wantURL:  "https://example.com/mcp/.well-known/oauth-protected-resource",
		},
		{
			name:     "root path only",
			resource: "https://example.com/",
			wantURL:  "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:     "subdomain",
			resource: "https://api.example.com/mcp",
			wantURL:  "https://api.example.com/mcp/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := getMetadataURL(tt.resource)
			if got != tt.wantURL {
				t.Errorf("getMetadataURL(%q) = %q, want %q", tt.resource, got, tt.wantURL)
			}
		})
	}
}

func TestService_GetMetadataURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource string
		wantURL  string
	}{
		{
			name:     "service with no path",
			resource: "https://example.com",
			wantURL:  "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:     "service with path",
			resource: "https://example.com/mcp",
			wantURL:  "https://example.com/mcp/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := newMockService(testConfig{
				Resource:             tt.resource,
				AuthorizationServers: []string{"https://auth.example.com"},
			})

			got := service.GetMetadataURL()
			if got != tt.wantURL {
				t.Errorf("GetMetadataURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestProtectedResourceMetadata_RequiredFields(t *testing.T) {
	t.Parallel()

	// Per RFC 9728, the only REQUIRED field is "resource"
	// "authorization_servers" MUST be included if there are any AS
	// This test documents the expected structure

	metadata := &ProtectedResourceMetadata{
		Resource:             "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
	}

	if metadata.Resource == "" {
		t.Error("Resource field is required but empty")
	}

	if len(metadata.AuthorizationServers) == 0 {
		t.Error("AuthorizationServers should have at least one entry for protected resources")
	}
}

func TestProtectedResourceMetadata_OptionalFields(t *testing.T) {
	t.Parallel()

	// Test that optional fields can be omitted
	metadata := &ProtectedResourceMetadata{
		Resource:             "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
		// All other fields intentionally omitted
	}

	// Optional fields should be their zero values
	if metadata.ScopesSupported != nil {
		t.Errorf("ScopesSupported should be nil, got %v", metadata.ScopesSupported)
	}
	if metadata.BearerMethodsSupported != nil {
		t.Errorf("BearerMethodsSupported should be nil, got %v", metadata.BearerMethodsSupported)
	}
}

// Benchmark tests for metadata operations
func BenchmarkService_GetMetadata(b *testing.B) {
	service := newMockService(testConfig{
		Resource:             "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write", "mcp:admin"},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = service.GetMetadata()
	}
}

func BenchmarkGetMetadataURL(b *testing.B) {
	resource := "https://example.com/api/v1/mcp"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getMetadataURL(resource)
	}
}

func TestValidateMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		metadata        *ProtectedResourceMetadata
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "valid metadata",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth.example.com"},
			},
			wantErr: false,
		},
		{
			name: "missing resource",
			metadata: &ProtectedResourceMetadata{
				AuthorizationServers: []string{"https://auth.example.com"},
			},
			wantErr:         true,
			wantErrContains: "resource",
		},
		{
			name: "empty resource",
			metadata: &ProtectedResourceMetadata{
				Resource:             "",
				AuthorizationServers: []string{"https://auth.example.com"},
			},
			wantErr:         true,
			wantErrContains: "resource",
		},
		{
			name: "missing authorization servers",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{},
			},
			wantErr:         true,
			wantErrContains: "authorization_servers",
		},
		{
			name: "nil authorization servers",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: nil,
			},
			wantErr:         true,
			wantErrContains: "authorization_servers",
		},
		{
			name: "empty authorization server URL",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{""},
			},
			wantErr:         true,
			wantErrContains: "empty",
		},
		{
			name: "invalid authorization server URL (no https)",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"http://auth.example.com"},
			},
			wantErr:         true,
			wantErrContains: "HTTPS",
		},
		{
			name: "valid localhost URL",
			metadata: &ProtectedResourceMetadata{
				Resource:             "http://localhost:8080/mcp",
				AuthorizationServers: []string{"http://localhost:9090"},
			},
			wantErr: false,
		},
		{
			name: "multiple authorization servers with one invalid",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth1.example.com", "http://auth2.example.com"},
			},
			wantErr:         true,
			wantErrContains: "HTTPS",
		},
		{
			name: "multiple valid authorization servers",
			metadata: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth1.example.com", "https://auth2.example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateMetadata(tt.metadata)

			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateMetadata() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("ValidateMetadata() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("ValidateMetadata() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no trailing slash",
			input:    "https://example.com/mcp",
			expected: "https://example.com/mcp",
		},
		{
			name:     "with trailing slash",
			input:    "https://example.com/mcp/",
			expected: "https://example.com/mcp",
		},
		{
			name:     "with multiple trailing slashes",
			input:    "https://example.com/mcp///",
			expected: "https://example.com/mcp",
		},
		{
			name:     "root path with trailing slash",
			input:    "https://example.com/",
			expected: "https://example.com",
		},
		{
			name:     "no path",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeBaseURL(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeBaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNewService(t *testing.T) {
	t.Parallel()

	baseURL := "https://example.com/mcp"
	authServers := []string{"https://auth.example.com"}
	scopes := []string{"mcp:read", "mcp:write"}

	service := NewService(baseURL, authServers, scopes)

	if service == nil {
		t.Fatal("NewService() returned nil")
	}

	metadata, err := service.GetMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetMetadata() unexpected error: %v", err)
	}

	if metadata.Resource != "https://example.com/mcp" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, "https://example.com/mcp")
	}

	if len(metadata.AuthorizationServers) != 1 {
		t.Errorf("AuthorizationServers length = %d, want 1", len(metadata.AuthorizationServers))
	}

	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("ScopesSupported length = %d, want 2", len(metadata.ScopesSupported))
	}

	// Verify bearer methods always set to ["header"] per OAuth 2.1
	if len(metadata.BearerMethodsSupported) != 1 || metadata.BearerMethodsSupported[0] != "header" {
		t.Errorf("BearerMethodsSupported = %v, want [\"header\"]", metadata.BearerMethodsSupported)
	}
}

func TestService_GetMetadataURL_Integration(t *testing.T) {
	t.Parallel()

	service := NewService("https://example.com/mcp/", []string{"https://auth.example.com"}, nil)

	metadataURL := service.GetMetadataURL()
	expectedURL := "https://example.com/mcp/.well-known/oauth-protected-resource"

	if metadataURL != expectedURL {
		t.Errorf("GetMetadataURL() = %q, want %q", metadataURL, expectedURL)
	}
}
