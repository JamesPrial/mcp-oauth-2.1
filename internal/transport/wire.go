package transport

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/config"
	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/handlers"
	transporthttp "github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/http"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/middleware"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// NewServer creates a configured HTTP server.
// The server is configured with timeouts from the config and uses the provided router.
func NewServer(cfg *config.Config, router Router) Server {
	return transporthttp.NewServer(cfg, router)
}

// NewRouter creates a new HTTP router backed by http.ServeMux.
func NewRouter() Router {
	return transporthttp.NewRouter()
}

// NewAuthMiddleware creates OAuth authentication middleware.
// It validates Bearer tokens and enforces scope requirements.
// The metadataURL is included in WWW-Authenticate headers for client discovery.
func NewAuthMiddleware(
	validator oauth.TokenValidator,
	responder ErrorResponder,
	metadataURL string,
) AuthMiddleware {
	// Use default scopes for authentication
	defaultScopes := []string{pkgoauth.ScopeRead}
	return middleware.NewAuthMiddleware(validator, responder, metadataURL, defaultScopes)
}

// NewErrorResponder creates an error responder with the given metadata URL.
// The responder formats HTTP error responses according to OAuth 2.1 and RFC 9728.
func NewErrorResponder(metadataURL string) ErrorResponder {
	return transporthttp.NewErrorResponder(metadataURL)
}

// NewMetadataHandler creates the OAuth protected resource metadata handler.
// It serves metadata at /.well-known/oauth-protected-resource per RFC 9728.
func NewMetadataHandler(service oauth.MetadataService, responder ErrorResponder) http.Handler {
	return handlers.NewMetadataHandler(service, responder)
}

// NewMCPHandler creates the MCP protocol handler.
// It handles JSON-RPC requests at the configured MCP endpoint.
func NewMCPHandler(handler mcp.Handler, responder ErrorResponder) http.Handler {
	return handlers.NewMCPHandler(handler, responder)
}

// NewHealthHandler creates the health check handler.
// It provides a simple health status endpoint.
func NewHealthHandler(responder ErrorResponder) http.Handler {
	return handlers.NewHealthHandler(responder)
}

// NewLoggingMiddleware creates request logging middleware.
// It logs HTTP request details using structured logging.
// If logger is nil, it uses the default slog logger.
func NewLoggingMiddleware(logger *slog.Logger) Middleware {
	return middleware.NewLoggingMiddleware(logger)
}

// NewRecoveryMiddleware creates panic recovery middleware.
// It recovers from panics and returns a 500 error to the client.
// If logger is nil, it uses the default slog logger.
func NewRecoveryMiddleware(responder ErrorResponder, logger *slog.Logger) Middleware {
	return middleware.NewRecoveryMiddleware(responder, logger)
}

// Config holds the configuration needed for the transport layer.
type Config struct {
	// ServerConfig is the server configuration.
	ServerConfig *config.Config

	// OAuthValidator validates access tokens.
	OAuthValidator oauth.TokenValidator

	// MetadataService provides protected resource metadata.
	MetadataService oauth.MetadataService

	// MCPHandler processes MCP protocol requests.
	MCPHandler mcp.Handler
}

// NewTransportServices creates all transport layer services from the configuration.
// This is a convenience function for dependency injection that wires up the complete
// HTTP transport layer with routing, middleware, and handlers.
func NewTransportServices(cfg *Config) (Server, Router, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config cannot be nil")
	}
	if cfg.ServerConfig == nil {
		return nil, nil, fmt.Errorf("server config cannot be nil")
	}
	if cfg.OAuthValidator == nil {
		return nil, nil, fmt.Errorf("oauth validator cannot be nil")
	}
	if cfg.MetadataService == nil {
		return nil, nil, fmt.Errorf("metadata service cannot be nil")
	}
	if cfg.MCPHandler == nil {
		return nil, nil, fmt.Errorf("mcp handler cannot be nil")
	}

	// Get metadata URL from service
	metadataURL := cfg.MetadataService.GetMetadataURL()

	// Create error responder
	responder := NewErrorResponder(metadataURL)

	// Create middleware
	recoveryMiddleware := NewRecoveryMiddleware(responder, nil)
	loggingMiddleware := NewLoggingMiddleware(nil)
	authMiddleware := NewAuthMiddleware(cfg.OAuthValidator, responder, metadataURL)

	// Create handlers
	metadataHandler := NewMetadataHandler(cfg.MetadataService, responder)
	mcpHandler := NewMCPHandler(cfg.MCPHandler, responder)
	healthHandler := NewHealthHandler(responder)

	// Create router
	router := NewRouter()

	// Apply global middleware
	router.Use(recoveryMiddleware, loggingMiddleware)

	// Register routes
	// Public endpoints (no auth required)
	router.Handle("GET /.well-known/oauth-protected-resource", metadataHandler)
	router.Handle("GET /health", healthHandler)

	// Protected endpoints (auth required)
	// Apply authentication middleware for MCP endpoint
	authenticatedMCP := authMiddleware.Authenticate()(mcpHandler)
	router.Handle("POST /mcp", authenticatedMCP)

	// Create server
	server := NewServer(cfg.ServerConfig, router)

	return server, router, nil
}
