package config

import (
	"strings"
	"testing"
	"time"
)

// validConfig returns a valid configuration for testing.
// Tests can override specific fields as needed.
func validConfig() *Config {
	return &Config{
		BaseURL:              "https://example.com",
		Addr:                 ":8080",
		AuthorizationServers: []string{"https://auth.example.com"},
		Audience:             "https://example.com/mcp",
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		IdleTimeout:          120 * time.Second,
		JWKSCacheTTL:         1 * time.Hour,
		ClockSkew:            1 * time.Minute,
		SessionTTL:           1 * time.Hour,
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid config with all required fields",
			config:  validConfig(),
			wantErr: false,
		},
		{
			name: "empty BaseURL",
			config: func() *Config {
				c := validConfig()
				c.BaseURL = ""
				return c
			}(),
			wantErr:     true,
			errContains: "BASE_URL",
		},
		{
			name: "empty AuthorizationServers",
			config: func() *Config {
				c := validConfig()
				c.AuthorizationServers = nil
				return c
			}(),
			wantErr:     true,
			errContains: "AUTHORIZATION_SERVERS",
		},
		{
			name: "empty AuthorizationServers slice",
			config: func() *Config {
				c := validConfig()
				c.AuthorizationServers = []string{}
				return c
			}(),
			wantErr:     true,
			errContains: "AUTHORIZATION_SERVERS",
		},
		{
			name: "empty Audience",
			config: func() *Config {
				c := validConfig()
				c.Audience = ""
				return c
			}(),
			wantErr:     true,
			errContains: "AUDIENCE",
		},
		{
			name: "invalid BaseURL format - not a URL",
			config: func() *Config {
				c := validConfig()
				c.BaseURL = "not-a-url"
				return c
			}(),
			wantErr:     true,
			errContains: "BASE_URL",
		},
		{
			name: "invalid BaseURL format - missing scheme",
			config: func() *Config {
				c := validConfig()
				c.BaseURL = "example.com"
				return c
			}(),
			wantErr:     true,
			errContains: "BASE_URL",
		},
		{
			name: "negative read timeout",
			config: func() *Config {
				c := validConfig()
				c.ReadTimeout = -1 * time.Second
				return c
			}(),
			wantErr:     true,
			errContains: "READ_TIMEOUT",
		},
		{
			name: "negative write timeout",
			config: func() *Config {
				c := validConfig()
				c.WriteTimeout = -1 * time.Second
				return c
			}(),
			wantErr:     true,
			errContains: "WRITE_TIMEOUT",
		},
		{
			name: "negative idle timeout",
			config: func() *Config {
				c := validConfig()
				c.IdleTimeout = -1 * time.Second
				return c
			}(),
			wantErr:     true,
			errContains: "IDLE_TIMEOUT",
		},
		{
			name: "zero idle timeout is valid",
			config: func() *Config {
				c := validConfig()
				c.IdleTimeout = 0
				return c
			}(),
			wantErr: false,
		},
		{
			name: "zero read timeout is invalid",
			config: func() *Config {
				c := validConfig()
				c.ReadTimeout = 0
				return c
			}(),
			wantErr:     true,
			errContains: "READ_TIMEOUT",
		},
		{
			name: "zero write timeout is invalid",
			config: func() *Config {
				c := validConfig()
				c.WriteTimeout = 0
				return c
			}(),
			wantErr:     true,
			errContains: "WRITE_TIMEOUT",
		},
		{
			name: "valid config with multiple authorization servers",
			config: func() *Config {
				c := validConfig()
				c.AuthorizationServers = []string{"https://auth1.example.com", "https://auth2.example.com"}
				return c
			}(),
			wantErr: false,
		},
		{
			name: "invalid authorization server URL",
			config: func() *Config {
				c := validConfig()
				c.AuthorizationServers = []string{"not-a-url"}
				return c
			}(),
			wantErr:     true,
			errContains: "AUTHORIZATION_SERVERS",
		},
		{
			name: "valid config with http scheme for localhost",
			config: func() *Config {
				c := validConfig()
				c.BaseURL = "http://localhost:8080"
				c.Audience = "http://localhost:8080/mcp"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "zero JWKSCacheTTL is invalid",
			config: func() *Config {
				c := validConfig()
				c.JWKSCacheTTL = 0
				return c
			}(),
			wantErr:     true,
			errContains: "JWKS_CACHE_TTL",
		},
		{
			name: "zero ClockSkew is invalid",
			config: func() *Config {
				c := validConfig()
				c.ClockSkew = 0
				return c
			}(),
			wantErr:     true,
			errContains: "CLOCK_SKEW",
		},
		{
			name: "zero SessionTTL is invalid",
			config: func() *Config {
				c := validConfig()
				c.SessionTTL = 0
				return c
			}(),
			wantErr:     true,
			errContains: "SESSION_TTL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Validate(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if tt.errContains != "" && !strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(tt.errContains)) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_NilConfig(t *testing.T) {
	t.Parallel()

	err := Validate(nil)
	if err == nil {
		t.Error("Validate(nil) should return error")
	}
}

func TestValidate_EmptyAddr(t *testing.T) {
	t.Parallel()

	config := validConfig()
	config.Addr = ""

	err := Validate(config)
	if err == nil {
		t.Error("Validate() with empty Addr should return error")
	}
	if !strings.Contains(strings.ToUpper(err.Error()), "ADDR") {
		t.Errorf("Validate() error = %q, want to mention ADDR", err.Error())
	}
}

func TestValidate_AuthorizationServerURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers []string
		wantErr bool
	}{
		{
			name:    "valid https URL",
			servers: []string{"https://auth.example.com"},
			wantErr: false,
		},
		{
			name:    "valid https URL with path",
			servers: []string{"https://auth.example.com/oauth"},
			wantErr: false,
		},
		{
			name:    "http URL should be invalid for non-localhost",
			servers: []string{"http://auth.example.com"},
			wantErr: true,
		},
		{
			name:    "http localhost is valid",
			servers: []string{"http://localhost"},
			wantErr: false,
		},
		{
			name:    "http 127.0.0.1 is valid",
			servers: []string{"http://127.0.0.1"},
			wantErr: false,
		},
		{
			name:    "empty string in list",
			servers: []string{"https://auth.example.com", ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := validConfig()
			config.AuthorizationServers = tt.servers

			err := Validate(config)

			if tt.wantErr && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_AudienceFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		audience string
		wantErr  bool
	}{
		{
			name:     "valid https URL",
			audience: "https://example.com/mcp",
			wantErr:  false,
		},
		{
			name:     "valid https URL without path",
			audience: "https://example.com",
			wantErr:  false,
		},
		{
			name:     "invalid - not a URL",
			audience: "not-a-url",
			wantErr:  true,
		},
		{
			name:     "invalid - missing scheme",
			audience: "example.com/mcp",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := validConfig()
			config.Audience = tt.audience

			err := Validate(config)

			if tt.wantErr && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}
