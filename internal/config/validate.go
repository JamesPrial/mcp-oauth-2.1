package config

import (
	"fmt"
	"net/url"
)

// Validate checks that the configuration is valid and complete.
// It returns an error if required fields are missing or values are invalid.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate server configuration
	if err := validateServer(cfg); err != nil {
		return fmt.Errorf("invalid server config: %w", err)
	}

	// Validate OAuth configuration
	if err := validateOAuth(cfg); err != nil {
		return fmt.Errorf("invalid oauth config: %w", err)
	}

	// Validate MCP configuration
	if err := validateMCP(cfg); err != nil {
		return fmt.Errorf("invalid mcp config: %w", err)
	}

	return nil
}

// isLocalhost returns true if the host is localhost or a loopback address.
// It handles bare hostnames and host:port combinations.
func isLocalhost(host string) bool {
	// Check exact matches for bare hostnames
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}

	// Check if host starts with localhost: or 127.0.0.1: (with port)
	if len(host) > len("localhost:") && host[:len("localhost:")] == "localhost:" {
		return true
	}
	if len(host) > len("127.0.0.1:") && host[:len("127.0.0.1:")] == "127.0.0.1:" {
		return true
	}

	return false
}

// validateServer validates the server-related fields.
func validateServer(cfg *Config) error {
	// Addr is required
	if cfg.Addr == "" {
		return fmt.Errorf("SERVER_ADDR is required")
	}

	// BaseURL is required
	if cfg.BaseURL == "" {
		return fmt.Errorf("SERVER_BASE_URL is required")
	}

	// Validate BaseURL format
	parsedURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid SERVER_BASE_URL: %w", err)
	}

	// BaseURL must be absolute
	if !parsedURL.IsAbs() {
		return fmt.Errorf("SERVER_BASE_URL must be an absolute URL")
	}

	// BaseURL scheme must be https (or http for localhost only)
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("SERVER_BASE_URL must use http or https scheme")
	}

	// If using HTTP, must be localhost
	if parsedURL.Scheme == "http" && !isLocalhost(parsedURL.Host) {
		return fmt.Errorf("SERVER_BASE_URL must use https scheme for non-localhost hosts")
	}

	// Validate timeouts are positive
	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("SERVER_READ_TIMEOUT must be positive")
	}

	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("SERVER_WRITE_TIMEOUT must be positive")
	}

	// Validate IdleTimeout is non-negative (0 is allowed meaning no timeout)
	if cfg.IdleTimeout < 0 {
		return fmt.Errorf("SERVER_IDLE_TIMEOUT must be non-negative")
	}

	return nil
}

// validateOAuth validates the OAuth-related fields.
func validateOAuth(cfg *Config) error {
	// AuthorizationServers is required and must have at least one entry
	if len(cfg.AuthorizationServers) == 0 {
		return fmt.Errorf("OAUTH_AUTHORIZATION_SERVERS is required (at least one server)")
	}

	// Validate each authorization server URL
	for i, serverURL := range cfg.AuthorizationServers {
		parsedURL, err := url.Parse(serverURL)
		if err != nil {
			return fmt.Errorf("invalid OAUTH_AUTHORIZATION_SERVERS[%d]: %w", i, err)
		}

		if !parsedURL.IsAbs() {
			return fmt.Errorf("OAUTH_AUTHORIZATION_SERVERS[%d] must be an absolute URL", i)
		}

		if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
			return fmt.Errorf("OAUTH_AUTHORIZATION_SERVERS[%d] must use http or https scheme", i)
		}

		// If using HTTP, must be localhost
		if parsedURL.Scheme == "http" && !isLocalhost(parsedURL.Host) {
			return fmt.Errorf("OAUTH_AUTHORIZATION_SERVERS[%d] must use https scheme for non-localhost hosts", i)
		}
	}

	// Audience is required
	if cfg.Audience == "" {
		return fmt.Errorf("OAUTH_AUDIENCE is required")
	}

	// Validate Audience format
	parsedAudience, err := url.Parse(cfg.Audience)
	if err != nil {
		return fmt.Errorf("invalid OAUTH_AUDIENCE: %w", err)
	}

	if !parsedAudience.IsAbs() {
		return fmt.Errorf("OAUTH_AUDIENCE must be an absolute URL")
	}

	if parsedAudience.Scheme != "https" && parsedAudience.Scheme != "http" {
		return fmt.Errorf("OAUTH_AUDIENCE must use http or https scheme")
	}

	// Validate JWKSCacheTTL is positive
	if cfg.JWKSCacheTTL <= 0 {
		return fmt.Errorf("OAUTH_JWKS_CACHE_TTL must be positive")
	}

	// Validate ClockSkew is positive
	if cfg.ClockSkew <= 0 {
		return fmt.Errorf("OAUTH_CLOCK_SKEW must be positive")
	}

	return nil
}

// validateMCP validates the MCP-related fields.
func validateMCP(cfg *Config) error {
	// Validate SessionTTL is positive
	if cfg.SessionTTL <= 0 {
		return fmt.Errorf("MCP_SESSION_TTL must be positive")
	}

	return nil
}
