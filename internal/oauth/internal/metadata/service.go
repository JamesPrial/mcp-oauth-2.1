package metadata

import (
	"context"
	"fmt"
	"strings"
)

// ProtectedResourceMetadata represents the OAuth 2.0 Protected Resource
// Metadata as defined in RFC 9728.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// Service provides Protected Resource Metadata per RFC 9728.
type Service struct {
	resource               string
	authorizationServers   []string
	scopesSupported        []string
	bearerMethodsSupported []string
	metadataURL            string
}

// NewService creates a new metadata service.
//
// Parameters:
//   - baseURL: the canonical base URL for this protected resource (e.g., "https://example.com/mcp")
//   - authorizationServers: array of authorization server URLs
//   - scopesSupported: array of supported OAuth scopes (optional)
func NewService(baseURL string, authorizationServers []string, scopesSupported []string) *Service {
	// RFC 9728 requires Authorization header only for OAuth 2.1
	bearerMethods := []string{"header"}

	// Construct metadata URL: {baseURL}/.well-known/oauth-protected-resource
	metadataURL := normalizeBaseURL(baseURL) + "/.well-known/oauth-protected-resource"

	return &Service{
		resource:               normalizeBaseURL(baseURL),
		authorizationServers:   authorizationServers,
		scopesSupported:        scopesSupported,
		bearerMethodsSupported: bearerMethods,
		metadataURL:            metadataURL,
	}
}

// GetMetadata returns the protected resource metadata document.
func (s *Service) GetMetadata(ctx context.Context) (*ProtectedResourceMetadata, error) {
	return &ProtectedResourceMetadata{
		Resource:               s.resource,
		AuthorizationServers:   s.authorizationServers,
		ScopesSupported:        s.scopesSupported,
		BearerMethodsSupported: s.bearerMethodsSupported,
	}, nil
}

// GetMetadataURL returns the canonical URL where this metadata is served.
func (s *Service) GetMetadataURL() string {
	return s.metadataURL
}

// normalizeBaseURL ensures the base URL has no trailing slash unless semantically significant.
// Per RFC 8707, resource identifiers should not have trailing slashes unless they are
// semantically meaningful (e.g., representing a collection vs. a specific resource).
func normalizeBaseURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/")
}

// ValidateMetadata validates the metadata configuration per RFC 9728.
func ValidateMetadata(metadata *ProtectedResourceMetadata) error {
	if metadata.Resource == "" {
		return fmt.Errorf("resource field is required")
	}

	if len(metadata.AuthorizationServers) == 0 {
		return fmt.Errorf("authorization_servers field must contain at least one server")
	}

	// Validate each authorization server URL is well-formed
	for _, server := range metadata.AuthorizationServers {
		if server == "" {
			return fmt.Errorf("authorization server URL cannot be empty")
		}
		if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://localhost") {
			return fmt.Errorf("authorization server URL must use HTTPS (or http://localhost for testing): %s", server)
		}
	}

	return nil
}
