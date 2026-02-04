// Package transport provides HTTP transport layer for the OAuth 2.1 MCP server.
//
// # Architecture
//
// The transport package implements the HTTP layer that connects OAuth 2.1 token
// validation with MCP protocol handling. It follows the adapter pattern to bridge
// the internal OAuth and MCP verticals with HTTP.
//
// Package structure:
//
//	internal/transport/
//	├── transport.go              # Public interfaces
//	├── errors.go                 # Transport domain errors
//	├── context.go                # Context keys and helpers
//	├── wire.go                   # Factory functions
//	├── internal/
//	│   ├── http/
//	│   │   ├── server.go         # HTTP server with graceful shutdown
//	│   │   ├── router.go         # HTTP routing
//	│   │   └── response.go       # Error responder with WWW-Authenticate
//	│   ├── middleware/
//	│   │   ├── auth.go           # Authentication middleware
//	│   │   ├── logging.go        # Request logging
//	│   │   └── recovery.go       # Panic recovery
//	│   └── handlers/
//	│       ├── metadata.go       # /.well-known/oauth-protected-resource
//	│       ├── mcp.go            # MCP protocol endpoint
//	│       └── health.go         # Health check endpoint
//
// # OAuth 2.1 Compliance
//
// The transport layer enforces OAuth 2.1 requirements:
//
//   - Bearer tokens MUST be in Authorization header only (not query strings)
//   - 401 responses include WWW-Authenticate header with resource_metadata parameter
//   - 403 responses use error="insufficient_scope" with required scopes
//   - Protected Resource Metadata is served at /.well-known/oauth-protected-resource
//
// # Middleware Chain
//
// The middleware chain is applied in this order:
//
//  1. Recovery - catches panics and returns 500 errors
//  2. Logging - logs request details
//  3. Authentication - validates Bearer token (protected routes only)
//  4. Scope checking - validates required scopes (if needed)
//
// # Error Handling
//
// Error responses follow RFC 6750 (Bearer Token Usage) and RFC 9728:
//
// 401 Unauthorized:
//
//	HTTP/1.1 401 Unauthorized
//	WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="mcp:read"
//	Content-Type: application/json
//
//	{"error": "unauthorized", "message": "Authentication required"}
//
// 403 Forbidden (insufficient scope):
//
//	HTTP/1.1 403 Forbidden
//	WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp:read mcp:write", resource_metadata="https://example.com/.well-known/oauth-protected-resource"
//	Content-Type: application/json
//
//	{"error": "insufficient_scope", "message": "Required scopes: mcp:read mcp:write"}
//
// # Usage Example
//
//	// Create transport services
//	cfg := &transport.Config{
//		ServerConfig:    serverConfig,
//		OAuthValidator:  tokenValidator,
//		MetadataService: metadataService,
//		MCPHandler:      mcpHandler,
//	}
//
//	server, router, err := transport.NewTransportServices(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Start server
//	if err := server.Start(); err != nil {
//		log.Fatal(err)
//	}
//
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := server.Shutdown(ctx); err != nil {
//		log.Printf("shutdown error: %v", err)
//	}
//
// # Endpoints
//
// Public endpoints (no authentication):
//   - GET /.well-known/oauth-protected-resource - Protected Resource Metadata (RFC 9728)
//   - GET /health - Health check
//
// Protected endpoints (authentication required):
//   - POST /mcp - MCP protocol (JSON-RPC 2.0)
//
// # Context Values
//
// The authentication middleware stores validated OAuth claims in the request context:
//
//	claims, ok := transport.ClaimsFromContext(r.Context())
//	if !ok {
//		// Not authenticated
//	}
//
//	// Access token claims
//	subject := claims.Subject
//	scopes := claims.Scopes
package transport
