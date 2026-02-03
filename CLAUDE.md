# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OAuth 2.1 compliant MCP (Model Context Protocol) server implementation in Go. The MCP server acts as an OAuth 2.1 Resource Server that accepts and responds to protected resource requests using access tokens.

## OAuth 2.1 Compliance Requirements

### Core Standards

This implementation must comply with:
- OAuth 2.1 (draft-ietf-oauth-v2-1-13)
- OAuth 2.0 Protected Resource Metadata (RFC 9728)
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
- OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00)
- Resource Indicators for OAuth 2.0 (RFC 8707)

### OAuth 2.1 Key Differences from OAuth 2.0

**Mandatory requirements:**
- PKCE is required for ALL OAuth clients using authorization code flow
- MUST use S256 code challenge method (not plain)
- Redirect URIs MUST use exact string matching
- Refresh tokens for public clients MUST be sender-constrained or one-time use
- Access tokens MUST NOT be included in URI query strings
- Bearer tokens MUST use Authorization header only

**Removed/prohibited:**
- Implicit grant (`response_type=token`) - NOT allowed
- Resource Owner Password Credentials grant - NOT allowed
- Bearer tokens in query strings - NOT allowed

### MCP Server Requirements (Resource Server Role)

**Protected Resource Metadata (RFC 9728):**
- MUST serve metadata at `/.well-known/oauth-protected-resource` or `/.well-known/oauth-protected-resource/{path}`
- MUST include `authorization_servers` field with at least one authorization server
- SHOULD include `scopes_supported` field

**401 Response Requirements:**
- MUST include `WWW-Authenticate: Bearer` header
- SHOULD include `resource_metadata` URL parameter
- SHOULD include `scope` parameter indicating required scopes

**403 Response for Insufficient Scope:**
- Use `WWW-Authenticate: Bearer error="insufficient_scope", scope="required_scopes"`
- Include `resource_metadata` parameter

**Token Validation:**
- MUST validate tokens were issued specifically for this server (audience validation)
- MUST validate tokens per OAuth 2.1 Section 5.2
- MUST reject tokens not intended for this server
- MUST NOT accept or pass through tokens meant for other services

### Client Registration Support

Support these mechanisms in priority order:
1. Pre-registered client credentials
2. Client ID Metadata Documents (if AS supports `client_id_metadata_document_supported`)
3. Dynamic Client Registration (RFC 7591) as fallback

### Resource Indicators (RFC 8707)

- Clients MUST include `resource` parameter in authorization and token requests
- Server MUST validate token audience matches its canonical URI
- Canonical URI format: `https://example.com/mcp` (no trailing slash unless semantically significant)

## Architecture Guidelines

### Recommended Go Project Structure

```
├── cmd/
│   └── server/          # Main application entry point
├── internal/
│   ├── oauth/           # OAuth 2.1 implementation
│   │   ├── metadata/    # Protected Resource Metadata (RFC 9728)
│   │   ├── token/       # Token validation
│   │   └── pkce/        # PKCE verification
│   ├── mcp/             # MCP protocol implementation
│   │   ├── transport/   # HTTP transport layer
│   │   └── handlers/    # MCP request handlers
│   └── middleware/      # HTTP middleware (auth, logging)
├── pkg/                 # Public packages (if any)
└── api/                 # OpenAPI/Protocol definitions
```

### Key Implementation Patterns

**Token Validation Middleware:**
```go
// Every request must validate the Bearer token
// Authorization header is required on EVERY request, even within same session
func ValidateToken(next http.Handler) http.Handler
```

**Protected Resource Metadata Endpoint:**
```go
// GET /.well-known/oauth-protected-resource
// Response must include authorization_servers array
```

**401 Response Format:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="mcp:read"
```

**403 Insufficient Scope Response:**
```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp:read mcp:write", resource_metadata="https://example.com/.well-known/oauth-protected-resource"
```

## Security Requirements

### MUST Implement
- HTTPS for all endpoints (except localhost redirects)
- Exact redirect URI matching
- Token audience validation (reject tokens not meant for this server)
- PKCE support verification before accepting auth flows
- Secure token storage

### MUST NOT Do
- Accept tokens in query strings
- Pass through tokens to upstream APIs (confused deputy prevention)
- Accept tokens issued for other services
- Use implicit grant or ROPC grant

## Development Commands

```bash
# Build (once go.mod exists)
go build -o bin/server ./cmd/server

# Run tests
go test ./...

# Run single test
go test -run TestName ./path/to/package

# Run with race detector
go test -race ./...

# Generate coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Testing Considerations

- Test PKCE flow with S256 challenge method
- Test token validation rejects wrong audience
- Test 401 responses include proper WWW-Authenticate header
- Test 403 responses for insufficient scope
- Test Protected Resource Metadata endpoint
- Test exact redirect URI matching (no substring/pattern matching)
