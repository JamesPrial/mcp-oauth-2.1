package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Note: Cannot use t.Parallel() with t.Setenv as it modifies process env
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "all required env vars set",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.BaseURL != "https://example.com" {
					t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "https://example.com")
				}
				if len(cfg.AuthorizationServers) != 1 || cfg.AuthorizationServers[0] != "https://auth.example.com" {
					t.Errorf("AuthorizationServers = %v, want [https://auth.example.com]", cfg.AuthorizationServers)
				}
				if cfg.Audience != "https://example.com/mcp" {
					t.Errorf("Audience = %q, want %q", cfg.Audience, "https://example.com/mcp")
				}
			},
		},
		{
			name: "missing SERVER_BASE_URL",
			envVars: map[string]string{
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
			},
			wantErr:     true,
			errContains: "SERVER_BASE_URL",
		},
		{
			name: "missing OAUTH_AUTHORIZATION_SERVERS",
			envVars: map[string]string{
				"SERVER_BASE_URL": "https://example.com",
				"OAUTH_AUDIENCE":  "https://example.com/mcp",
			},
			wantErr:     true,
			errContains: "OAUTH_AUTHORIZATION_SERVERS",
		},
		{
			name: "missing OAUTH_AUDIENCE",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
			},
			wantErr:     true,
			errContains: "OAUTH_AUDIENCE",
		},
		{
			name: "default values applied",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Addr != ":8080" {
					t.Errorf("default Addr = %q, want %q", cfg.Addr, ":8080")
				}
				if cfg.ReadTimeout != 30*time.Second {
					t.Errorf("default ReadTimeout = %v, want %v", cfg.ReadTimeout, 30*time.Second)
				}
				if cfg.WriteTimeout != 30*time.Second {
					t.Errorf("default WriteTimeout = %v, want %v", cfg.WriteTimeout, 30*time.Second)
				}
				if cfg.IdleTimeout != 120*time.Second {
					t.Errorf("default IdleTimeout = %v, want %v", cfg.IdleTimeout, 120*time.Second)
				}
			},
		},
		{
			name: "custom timeout",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
				"SERVER_READ_TIMEOUT":         "60s",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ReadTimeout != 60*time.Second {
					t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, 60*time.Second)
				}
			},
		},
		{
			name: "custom write timeout",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
				"SERVER_WRITE_TIMEOUT":        "45s",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.WriteTimeout != 45*time.Second {
					t.Errorf("WriteTimeout = %v, want %v", cfg.WriteTimeout, 45*time.Second)
				}
			},
		},
		{
			name: "custom idle timeout",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
				"SERVER_IDLE_TIMEOUT":         "180s",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.IdleTimeout != 180*time.Second {
					t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, 180*time.Second)
				}
			},
		},
		{
			name: "custom address",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
				"SERVER_ADDR":                 ":9000",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Addr != ":9000" {
					t.Errorf("Addr = %q, want %q", cfg.Addr, ":9000")
				}
			},
		},
		{
			name: "invalid duration format",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://auth.example.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
				"SERVER_READ_TIMEOUT":         "invalid",
			},
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name: "comma-separated auth servers",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://as1.com,https://as2.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.AuthorizationServers) != 2 {
					t.Errorf("AuthorizationServers length = %d, want 2", len(cfg.AuthorizationServers))
				}
				if cfg.AuthorizationServers[0] != "https://as1.com" {
					t.Errorf("AuthorizationServers[0] = %q, want %q", cfg.AuthorizationServers[0], "https://as1.com")
				}
				if cfg.AuthorizationServers[1] != "https://as2.com" {
					t.Errorf("AuthorizationServers[1] = %q, want %q", cfg.AuthorizationServers[1], "https://as2.com")
				}
			},
		},
		{
			name: "comma-separated auth servers with spaces",
			envVars: map[string]string{
				"SERVER_BASE_URL":             "https://example.com",
				"OAUTH_AUTHORIZATION_SERVERS": "https://as1.com, https://as2.com, https://as3.com",
				"OAUTH_AUDIENCE":              "https://example.com/mcp",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.AuthorizationServers) != 3 {
					t.Errorf("AuthorizationServers length = %d, want 3", len(cfg.AuthorizationServers))
				}
				// After trimming spaces
				if cfg.AuthorizationServers[1] != "https://as2.com" {
					t.Errorf("AuthorizationServers[1] = %q, want %q (spaces should be trimmed)", cfg.AuthorizationServers[1], "https://as2.com")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear relevant env vars and set test values
			// Note: Cannot use t.Parallel() with t.Setenv as it modifies process env
			clearConfigEnvVars(t)
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg, err := Load()

			if tt.wantErr {
				if err == nil {
					t.Fatal("Load() error = nil, want error")
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("Load() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("Load() returned nil config")
			}

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestLoad_EmptyEnvVars(t *testing.T) {
	// Test behavior when env vars are set but empty
	clearConfigEnvVars(t)
	t.Setenv("SERVER_BASE_URL", "")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com")
	t.Setenv("OAUTH_AUDIENCE", "https://example.com/mcp")

	_, err := Load()
	if err == nil {
		t.Error("Load() with empty SERVER_BASE_URL should return error")
	}
}

func TestLoad_AllTimeouts(t *testing.T) {
	clearConfigEnvVars(t)
	t.Setenv("SERVER_BASE_URL", "https://example.com")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com")
	t.Setenv("OAUTH_AUDIENCE", "https://example.com/mcp")
	t.Setenv("SERVER_READ_TIMEOUT", "15s")
	t.Setenv("SERVER_WRITE_TIMEOUT", "20s")
	t.Setenv("SERVER_IDLE_TIMEOUT", "60s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, 15*time.Second)
	}
	if cfg.WriteTimeout != 20*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", cfg.WriteTimeout, 20*time.Second)
	}
	if cfg.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, 60*time.Second)
	}
}

// clearConfigEnvVars clears all config-related environment variables
func clearConfigEnvVars(t *testing.T) {
	t.Helper()
	envVars := []string{
		"SERVER_BASE_URL",
		"SERVER_ADDR",
		"SERVER_READ_TIMEOUT",
		"SERVER_WRITE_TIMEOUT",
		"SERVER_IDLE_TIMEOUT",
		"OAUTH_AUTHORIZATION_SERVERS",
		"OAUTH_AUDIENCE",
	}
	for _, env := range envVars {
		t.Setenv(env, "")
	}
}

// containsString checks if s contains substr
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
