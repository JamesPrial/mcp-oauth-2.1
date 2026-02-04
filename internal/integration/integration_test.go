// Package integration provides integration tests for the OAuth 2.1 MCP Server.
// These tests verify the full stack works correctly when all components are wired together.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jamesprial/mcp-oauth-2.1/internal/config"
	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// testKeyID is the key ID used for test tokens.
const testKeyID = "test-key-1"

// testServerInfo contains test server configuration.
var testServerInfo = struct {
	Name    string
	Version string
}{
	Name:    "test-mcp-server",
	Version: "1.0.0",
}

// testFixture contains all dependencies for integration tests.
type testFixture struct {
	server      *httptest.Server
	router      transport.Router
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	baseURL     string
	metadataURL string
	audience    string
	issuer      string
}

// mockJWKSClient is a mock implementation of oauth.JWKSClient for testing.
type mockJWKSClient struct {
	publicKey *rsa.PublicKey
}

func (m *mockJWKSClient) GetKey(_ context.Context, keyID string) (any, error) {
	if keyID != testKeyID {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return m.publicKey, nil
}

func (m *mockJWKSClient) RefreshKeys(_ context.Context) error {
	return nil
}

// setupTestFixture creates a test fixture with all components wired together.
func setupTestFixture(t *testing.T) *testFixture {
	t.Helper()

	// Generate RSA key pair for signing tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create mock JWKS client
	jwksClient := &mockJWKSClient{publicKey: &privateKey.PublicKey}

	// Create test configuration
	audience := "https://test.example.com/mcp"
	issuer := "https://auth.example.com"
	baseURL := "https://test.example.com"

	// Create OAuth configuration
	oauthCfg := &oauth.Config{
		BaseURL:              baseURL,
		AuthorizationServers: []string{issuer},
		Audience:             audience,
		ScopesSupported:      []string{pkgoauth.ScopeRead, pkgoauth.ScopeWrite, pkgoauth.ScopeAdmin},
		JWKSCacheTTL:         time.Hour,
		ClockSkew:            time.Minute,
	}

	// Create OAuth services with mock JWKS client
	tokenValidator := oauth.NewTokenValidator(oauthCfg, jwksClient)
	metadataService := oauth.NewMetadataService(oauthCfg)

	// Create MCP configuration and services
	mcpCfg := &mcp.Config{
		ServerName:    testServerInfo.Name,
		ServerVersion: testServerInfo.Version,
	}
	mcpHandler, _, _ := mcp.NewMCPServices(mcpCfg)

	// Create server configuration
	serverCfg := &config.Config{
		Addr:         ":0",
		BaseURL:      baseURL,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create transport configuration
	transportCfg := &transport.Config{
		ServerConfig:    serverCfg,
		OAuthValidator:  tokenValidator,
		MetadataService: metadataService,
		MCPHandler:      mcpHandler,
	}

	// Wire transport services
	_, router, err := transport.NewTransportServices(transportCfg)
	if err != nil {
		t.Fatalf("failed to create transport services: %v", err)
	}

	// Create test server
	server := httptest.NewServer(router)

	return &testFixture{
		server:      server,
		router:      router,
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		baseURL:     server.URL,
		metadataURL: baseURL + "/.well-known/oauth-protected-resource",
		audience:    audience,
		issuer:      issuer,
	}
}

// teardown cleans up the test fixture.
func (f *testFixture) teardown() {
	if f.server != nil {
		f.server.Close()
	}
}

// createToken creates a signed JWT token for testing.
func (f *testFixture) createToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	// Set default claims if not provided
	if claims == nil {
		claims = jwt.MapClaims{}
	}

	now := time.Now()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = f.issuer
	}
	if _, ok := claims["sub"]; !ok {
		claims["sub"] = "test-user"
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = f.audience
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["scope"]; !ok {
		claims["scope"] = pkgoauth.ScopeRead
	}
	if _, ok := claims["jti"]; !ok {
		claims["jti"] = "test-token-id"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKeyID

	tokenString, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

// createExpiredToken creates an expired JWT token for testing.
func (f *testFixture) createExpiredToken(t *testing.T) string {
	t.Helper()

	claims := jwt.MapClaims{
		"exp": time.Now().Add(-time.Hour).Unix(), // expired 1 hour ago
	}
	return f.createToken(t, claims)
}

// createTokenWithWrongAudience creates a token with an incorrect audience.
func (f *testFixture) createTokenWithWrongAudience(t *testing.T) string {
	t.Helper()

	claims := jwt.MapClaims{
		"aud": "https://wrong-audience.example.com",
	}
	return f.createToken(t, claims)
}

// ============================================================================
// Protected Resource Metadata Endpoint Tests
// ============================================================================

func TestIntegration_MetadataEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		wantStatusCode int
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name:           "GET returns 200 with valid metadata",
			method:         http.MethodGet,
			wantStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var metadata oauth.ProtectedResourceMetadata
				if err := json.Unmarshal(body, &metadata); err != nil {
					t.Fatalf("failed to unmarshal metadata: %v", err)
				}

				// Verify required fields
				if metadata.Resource == "" {
					t.Error("metadata.Resource should not be empty")
				}

				if len(metadata.AuthorizationServers) == 0 {
					t.Error("metadata.AuthorizationServers should not be empty")
				}

				// Verify authorization_servers contains expected server
				found := false
				for _, server := range metadata.AuthorizationServers {
					if server == "https://auth.example.com" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("authorization_servers should contain expected server, got: %v", metadata.AuthorizationServers)
				}
			},
		},
		{
			name:           "POST returns 405 Method Not Allowed",
			method:         http.MethodPost,
			wantStatusCode: http.StatusMethodNotAllowed,
			checkResponse:  nil,
		},
		{
			name:           "PUT returns 405 Method Not Allowed",
			method:         http.MethodPut,
			wantStatusCode: http.StatusMethodNotAllowed,
			checkResponse:  nil,
		},
		{
			name:           "DELETE returns 405 Method Not Allowed",
			method:         http.MethodDelete,
			wantStatusCode: http.StatusMethodNotAllowed,
			checkResponse:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupTestFixture(t)
			defer fixture.teardown()

			req, err := http.NewRequest(tt.method, fixture.baseURL+"/.well-known/oauth-protected-resource", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("got status %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantStatusCode == http.StatusOK {
				// Verify Content-Type header
				contentType := resp.Header.Get("Content-Type")
				if !strings.Contains(contentType, "application/json") {
					t.Errorf("Content-Type should be application/json, got: %s", contentType)
				}
			}

			if tt.checkResponse != nil {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				tt.checkResponse(t, body)
			}
		})
	}
}

func TestIntegration_MetadataEndpoint_ContainsRequiredFields(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	req, err := http.NewRequest(http.MethodGet, fixture.baseURL+"/.well-known/oauth-protected-resource", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// Parse as raw map to check field presence
	var rawMetadata map[string]any
	if err := json.Unmarshal(body, &rawMetadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Check required field: resource (RFC 9728)
	if _, ok := rawMetadata["resource"]; !ok {
		t.Error("metadata must contain 'resource' field per RFC 9728")
	}

	// Check required field: authorization_servers (RFC 9728)
	if _, ok := rawMetadata["authorization_servers"]; !ok {
		t.Error("metadata must contain 'authorization_servers' field per RFC 9728")
	}
}

// ============================================================================
// Health Check Endpoint Tests
// ============================================================================

func TestIntegration_HealthEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		wantStatusCode int
		wantStatus     string
	}{
		{
			name:           "GET returns 200 with ok status",
			method:         http.MethodGet,
			wantStatusCode: http.StatusOK,
			wantStatus:     "ok",
		},
		{
			name:           "POST returns 405 Method Not Allowed",
			method:         http.MethodPost,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
		},
		{
			name:           "PUT returns 405 Method Not Allowed",
			method:         http.MethodPut,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupTestFixture(t)
			defer fixture.teardown()

			req, err := http.NewRequest(tt.method, fixture.baseURL+"/health", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("got status %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantStatus != "" {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}

				var healthResp struct {
					Status string `json:"status"`
				}
				if err := json.Unmarshal(body, &healthResp); err != nil {
					t.Fatalf("failed to unmarshal health response: %v", err)
				}

				if healthResp.Status != tt.wantStatus {
					t.Errorf("got status %q, want %q", healthResp.Status, tt.wantStatus)
				}
			}
		})
	}
}

func TestIntegration_HealthEndpoint_ContentType(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	req, err := http.NewRequest(http.MethodGet, fixture.baseURL+"/health", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type should be application/json, got: %s", contentType)
	}
}

// ============================================================================
// MCP Endpoint Tests - No Authentication
// ============================================================================

func TestIntegration_MCPEndpoint_NoAuth(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	// Create a valid JSON-RPC request
	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Intentionally NOT setting Authorization header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should return 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Verify WWW-Authenticate header is present
	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" {
		t.Error("WWW-Authenticate header should be present")
	}

	// Verify WWW-Authenticate starts with Bearer
	if !strings.HasPrefix(authHeader, "Bearer") {
		t.Errorf("WWW-Authenticate should start with 'Bearer', got: %s", authHeader)
	}

	// Verify resource_metadata is included per RFC 9728
	if !strings.Contains(authHeader, "resource_metadata=") {
		t.Errorf("WWW-Authenticate should contain resource_metadata parameter, got: %s", authHeader)
	}
}

func TestIntegration_MCPEndpoint_NoAuth_ContainsScope(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Verify WWW-Authenticate contains scope parameter
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(authHeader, "scope=") {
		t.Errorf("WWW-Authenticate should contain scope parameter, got: %s", authHeader)
	}
}

// ============================================================================
// MCP Endpoint Tests - Invalid Token
// ============================================================================

func TestIntegration_MCPEndpoint_InvalidToken(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		wantStatusCode int
	}{
		{
			name:           "malformed token returns 401",
			authHeader:     "Bearer not-a-valid-jwt",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "empty bearer token returns 401",
			authHeader:     "Bearer ",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "wrong auth scheme returns 401",
			authHeader:     "Basic dXNlcjpwYXNz",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "no bearer prefix returns 401",
			authHeader:     "some-token",
			wantStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupTestFixture(t)
			defer fixture.teardown()

			jsonRPCReq := map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "initialize",
			}

			body, err := json.Marshal(jsonRPCReq)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", tt.authHeader)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("got status %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			// Verify WWW-Authenticate header is present
			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader == "" {
				t.Error("WWW-Authenticate header should be present")
			}
		})
	}
}

func TestIntegration_MCPEndpoint_ExpiredToken(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	// Create an expired token
	token := fixture.createExpiredToken(t)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Expired token should return 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestIntegration_MCPEndpoint_WrongAudience(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	// Create a token with wrong audience
	token := fixture.createTokenWithWrongAudience(t)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Wrong audience should return 401 (token not valid for this resource server)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// ============================================================================
// MCP Endpoint Tests - Valid Token
// ============================================================================

func TestIntegration_MCPEndpoint_WithValidToken(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	// Create a valid token
	token := fixture.createToken(t, nil)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should return 200 OK
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("got status %d, want %d. Response: %s", resp.StatusCode, http.StatusOK, string(respBody))
	}

	// Verify Content-Type is JSON
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type should be application/json, got: %s", contentType)
	}

	// Parse JSON-RPC response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Result  map[string]any `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify JSON-RPC version
	if jsonRPCResp.JSONRPC != "2.0" {
		t.Errorf("got jsonrpc %q, want %q", jsonRPCResp.JSONRPC, "2.0")
	}

	// Verify no error
	if jsonRPCResp.Error != nil {
		t.Errorf("unexpected error: code=%d, message=%s", jsonRPCResp.Error.Code, jsonRPCResp.Error.Message)
	}

	// Verify result contains expected fields
	if jsonRPCResp.Result == nil {
		t.Fatal("result should not be nil")
	}

	// Verify protocol version in result
	if protocolVersion, ok := jsonRPCResp.Result["protocolVersion"].(string); !ok || protocolVersion == "" {
		t.Error("result should contain protocolVersion")
	}

	// Verify serverInfo in result
	if serverInfo, ok := jsonRPCResp.Result["serverInfo"].(map[string]any); !ok || serverInfo == nil {
		t.Error("result should contain serverInfo")
	}
}

func TestIntegration_MCPEndpoint_ToolsList(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Tools []any `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if jsonRPCResp.Error != nil {
		t.Errorf("unexpected error: code=%d, message=%s", jsonRPCResp.Error.Code, jsonRPCResp.Error.Message)
	}

	// tools should be an array (may be empty)
	if jsonRPCResp.Result.Tools == nil {
		t.Error("result.tools should not be nil")
	}
}

func TestIntegration_MCPEndpoint_ResourcesList(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/list",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Resources []any `json:"resources"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if jsonRPCResp.Error != nil {
		t.Errorf("unexpected error: code=%d, message=%s", jsonRPCResp.Error.Code, jsonRPCResp.Error.Message)
	}

	// resources should be an array (may be empty)
	if jsonRPCResp.Result.Resources == nil {
		t.Error("result.resources should not be nil")
	}
}

func TestIntegration_MCPEndpoint_MethodNotFound(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "unknown/method",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// JSON-RPC errors still return 200 OK at HTTP level
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Should have error
	if jsonRPCResp.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown method")
	}

	// Error code should be -32601 (Method not found)
	if jsonRPCResp.Error.Code != -32601 {
		t.Errorf("got error code %d, want %d", jsonRPCResp.Error.Code, -32601)
	}
}

// ============================================================================
// MCP Endpoint Tests - HTTP Method
// ============================================================================

func TestIntegration_MCPEndpoint_OnlyAllowsPost(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method+" returns 405", func(t *testing.T) {
			fixture := setupTestFixture(t)
			defer fixture.teardown()

			token := fixture.createToken(t, nil)

			req, err := http.NewRequest(method, fixture.baseURL+"/mcp", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

// ============================================================================
// JSON-RPC Protocol Tests
// ============================================================================

func TestIntegration_MCPEndpoint_InvalidJSON(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	// Send invalid JSON
	body := []byte(`{invalid json}`)

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// JSON-RPC parse errors return 200 with error in body
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		JSONRPC string `json:"jsonrpc"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if jsonRPCResp.Error == nil {
		t.Fatal("expected JSON-RPC error for invalid JSON")
	}

	// Error code should be -32700 (Parse error)
	if jsonRPCResp.Error.Code != -32700 {
		t.Errorf("got error code %d, want %d", jsonRPCResp.Error.Code, -32700)
	}
}

func TestIntegration_MCPEndpoint_InvalidJSONRPCVersion(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	// Send request with wrong JSON-RPC version
	jsonRPCReq := map[string]any{
		"jsonrpc": "1.0", // Wrong version
		"id":      1,
		"method":  "initialize",
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if jsonRPCResp.Error == nil {
		t.Fatal("expected JSON-RPC error for invalid version")
	}

	// Error code should be -32600 (Invalid Request)
	if jsonRPCResp.Error.Code != -32600 {
		t.Errorf("got error code %d, want %d", jsonRPCResp.Error.Code, -32600)
	}
}

func TestIntegration_MCPEndpoint_MissingMethod(t *testing.T) {
	fixture := setupTestFixture(t)
	defer fixture.teardown()

	token := fixture.createToken(t, nil)

	// Send request without method
	jsonRPCReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		// "method" is missing
	}

	body, err := json.Marshal(jsonRPCReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var jsonRPCResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &jsonRPCResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if jsonRPCResp.Error == nil {
		t.Fatal("expected JSON-RPC error for missing method")
	}

	// Error code should be -32600 (Invalid Request)
	if jsonRPCResp.Error.Code != -32600 {
		t.Errorf("got error code %d, want %d", jsonRPCResp.Error.Code, -32600)
	}
}

// ============================================================================
// Build Verification Test
// ============================================================================

func TestBuild(t *testing.T) {
	// Skip if go command is not available
	_, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found, skipping build test")
	}

	// Note: This test would verify cmd/server builds, but since it doesn't exist yet,
	// we verify the main packages build correctly
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = "/Users/jamesprial/code/mcp-oauth-2.1"
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, output)
	}
}
