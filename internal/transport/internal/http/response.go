package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
	"github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// errorResponse represents a JSON error response body.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// errorResponder implements transport.ErrorResponder.
type errorResponder struct {
	metadataURL string
}

// NewErrorResponder creates a new error responder with the given metadata URL.
// The metadata URL is included in WWW-Authenticate headers per RFC 9728.
func NewErrorResponder(metadataURL string) transportcore.ErrorResponder {
	return &errorResponder{
		metadataURL: metadataURL,
	}
}

// Unauthorized sends a 401 Unauthorized response with WWW-Authenticate header.
// The header follows RFC 6750 Section 3 and includes the resource_metadata parameter
// per RFC 9728 for client discovery.
//
// Format: WWW-Authenticate: Bearer resource_metadata="<url>", scope="<scope>"
func (e *errorResponder) Unauthorized(w http.ResponseWriter, scope string, err error) {
	// Build WWW-Authenticate header value
	authHeader := e.buildAuthHeader("", scope)

	w.Header().Set(oauth.HeaderWWWAuthenticate, authHeader)
	w.Header().Set(oauth.HeaderContentType, oauth.ContentTypeJSON)
	w.WriteHeader(http.StatusUnauthorized)

	// Log the error for debugging
	slog.Warn("unauthorized request",
		"error", err,
		"scope", scope,
	)

	// Write JSON error response
	resp := errorResponse{
		Error:   "unauthorized",
		Message: "Authentication required",
	}
	if encodeErr := json.NewEncoder(w).Encode(resp); encodeErr != nil {
		slog.Error("failed to encode error response", "error", encodeErr)
	}
}

// Forbidden sends a 403 Forbidden response with WWW-Authenticate header
// for insufficient scope errors per RFC 6750 Section 3.1.
//
// Format: WWW-Authenticate: Bearer error="insufficient_scope", scope="<scopes>", resource_metadata="<url>"
func (e *errorResponder) Forbidden(w http.ResponseWriter, requiredScopes []string, err error) {
	// Join scopes with space separator per OAuth 2.1 spec
	scopeStr := strings.Join(requiredScopes, " ")

	// Build WWW-Authenticate header with insufficient_scope error
	authHeader := e.buildAuthHeader("insufficient_scope", scopeStr)

	w.Header().Set(oauth.HeaderWWWAuthenticate, authHeader)
	w.Header().Set(oauth.HeaderContentType, oauth.ContentTypeJSON)
	w.WriteHeader(http.StatusForbidden)

	// Log the error for debugging
	slog.Warn("forbidden request - insufficient scope",
		"error", err,
		"required_scopes", requiredScopes,
	)

	// Write JSON error response
	resp := errorResponse{
		Error:   "insufficient_scope",
		Message: fmt.Sprintf("Required scopes: %s", scopeStr),
	}
	if encodeErr := json.NewEncoder(w).Encode(resp); encodeErr != nil {
		slog.Error("failed to encode error response", "error", encodeErr)
	}
}

// InternalError sends a 500 Internal Server Error response.
// The response body contains a JSON error message.
func (e *errorResponder) InternalError(w http.ResponseWriter, err error) {
	w.Header().Set(oauth.HeaderContentType, oauth.ContentTypeJSON)
	w.WriteHeader(http.StatusInternalServerError)

	// Log the error for debugging
	slog.Error("internal server error", "error", err)

	// Write JSON error response
	resp := errorResponse{
		Error:   "internal_error",
		Message: "An internal server error occurred",
	}
	if encodeErr := json.NewEncoder(w).Encode(resp); encodeErr != nil {
		slog.Error("failed to encode error response", "error", encodeErr)
	}
}

// BadRequest sends a 400 Bad Request response.
// The response body contains a JSON error message.
func (e *errorResponder) BadRequest(w http.ResponseWriter, err error) {
	w.Header().Set(oauth.HeaderContentType, oauth.ContentTypeJSON)
	w.WriteHeader(http.StatusBadRequest)

	// Log the error for debugging
	slog.Warn("bad request", "error", err)

	// Determine error message
	message := "Invalid request"
	if err != nil {
		message = err.Error()
	}

	// Write JSON error response
	resp := errorResponse{
		Error:   "bad_request",
		Message: message,
	}
	if encodeErr := json.NewEncoder(w).Encode(resp); encodeErr != nil {
		slog.Error("failed to encode error response", "error", encodeErr)
	}
}

// buildAuthHeader builds the WWW-Authenticate header value per RFC 6750.
// If errorCode is non-empty, it includes the error parameter.
// Scope and resource_metadata parameters are always included if available.
func (e *errorResponder) buildAuthHeader(errorCode, scope string) string {
	parts := []string{"Bearer"}

	// Add error parameter if present
	if errorCode != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, errorCode))
	}

	// Add scope parameter if present
	if scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, scope))
	}

	// Add resource_metadata parameter per RFC 9728
	if e.metadataURL != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata="%s"`, e.metadataURL))
	}

	return strings.Join(parts, " ")
}
