// Package config provides configuration management for the OAuth 2.1 MCP server.
// Configuration is loaded from environment variables with sensible defaults.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds the complete server configuration in a flat structure.
type Config struct {
	// Server settings
	// Addr is the address to bind the HTTP server (e.g., ":8080").
	Addr string

	// BaseURL is the canonical base URL for this server (e.g., "https://example.com/mcp").
	// This is used for OAuth audience validation and resource metadata.
	BaseURL string

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum duration to wait for the next request when keep-alives are enabled.
	IdleTimeout time.Duration

	// OAuth settings
	// AuthorizationServers is a list of trusted authorization server URLs.
	// These servers are listed in the protected resource metadata.
	AuthorizationServers []string

	// Audience is the expected audience (aud) claim in access tokens.
	// This should match the server's canonical URI.
	Audience string

	// ScopesSupported is a list of OAuth scopes this server supports.
	ScopesSupported []string

	// JWKSCacheTTL is how long to cache JWKS keys from authorization servers.
	JWKSCacheTTL time.Duration

	// ClockSkew is the allowed clock skew for token expiration validation.
	ClockSkew time.Duration

	// MCP settings
	// SessionTTL is the duration before an MCP session expires.
	SessionTTL time.Duration
}

// Load reads configuration from environment variables and returns a Config.
// It sets default values for optional fields and validates the configuration.
func Load() (*Config, error) {
	// Parse durations with error handling
	readTimeout, err := parseDurationWithDefault("SERVER_READ_TIMEOUT", "30s")
	if err != nil {
		return nil, fmt.Errorf("invalid SERVER_READ_TIMEOUT: %w", err)
	}

	writeTimeout, err := parseDurationWithDefault("SERVER_WRITE_TIMEOUT", "30s")
	if err != nil {
		return nil, fmt.Errorf("invalid SERVER_WRITE_TIMEOUT: %w", err)
	}

	idleTimeout, err := parseDurationWithDefault("SERVER_IDLE_TIMEOUT", "120s")
	if err != nil {
		return nil, fmt.Errorf("invalid SERVER_IDLE_TIMEOUT: %w", err)
	}

	jwksCacheTTL, err := parseDurationWithDefault("OAUTH_JWKS_CACHE_TTL", "1h")
	if err != nil {
		return nil, fmt.Errorf("invalid OAUTH_JWKS_CACHE_TTL: %w", err)
	}

	clockSkew, err := parseDurationWithDefault("OAUTH_CLOCK_SKEW", "1m")
	if err != nil {
		return nil, fmt.Errorf("invalid OAUTH_CLOCK_SKEW: %w", err)
	}

	sessionTTL, err := parseDurationWithDefault("MCP_SESSION_TTL", "1h")
	if err != nil {
		return nil, fmt.Errorf("invalid MCP_SESSION_TTL: %w", err)
	}

	cfg := &Config{
		// Server settings
		Addr:         getEnvWithDefault("SERVER_ADDR", ":8080"),
		BaseURL:      os.Getenv("SERVER_BASE_URL"),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,

		// OAuth settings
		AuthorizationServers: parseCommaSeparated("OAUTH_AUTHORIZATION_SERVERS"),
		Audience:             os.Getenv("OAUTH_AUDIENCE"),
		ScopesSupported:      parseCommaSeparated("OAUTH_SCOPES_SUPPORTED"),
		JWKSCacheTTL:         jwksCacheTTL,
		ClockSkew:            clockSkew,

		// MCP settings
		SessionTTL: sessionTTL,
	}

	// Validate configuration
	if err := Validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// getEnvWithDefault returns the environment variable value or the default if not set.
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseCommaSeparated parses a comma-separated environment variable into a string slice.
// Empty values are filtered out. Returns nil if the environment variable is not set.
func parseCommaSeparated(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// parseDurationWithDefault parses a duration from an environment variable.
// If the variable is not set, it uses the default value.
// Returns an error if the value is set but cannot be parsed.
func parseDurationWithDefault(key, defaultValue string) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		// Use default if not set
		duration, err := time.ParseDuration(defaultValue)
		if err != nil {
			return 0, fmt.Errorf("invalid default duration %q: %w", defaultValue, err)
		}
		return duration, nil
	}

	// Parse the provided value
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("cannot parse duration %q: %w", value, err)
	}

	return duration, nil
}

// String returns a string representation of the configuration (for debugging).
// Sensitive values are redacted.
func (c *Config) String() string {
	return fmt.Sprintf("Config{Addr: %s, BaseURL: %s, ReadTimeout: %v, WriteTimeout: %v, IdleTimeout: %v, AuthorizationServers: %v, Audience: %s, ScopesSupported: %v, JWKSCacheTTL: %v, ClockSkew: %v, SessionTTL: %v}",
		c.Addr, c.BaseURL, c.ReadTimeout, c.WriteTimeout, c.IdleTimeout,
		c.AuthorizationServers, c.Audience, c.ScopesSupported,
		c.JWKSCacheTTL, c.ClockSkew, c.SessionTTL)
}
