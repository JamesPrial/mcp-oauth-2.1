// Package handlers provides HTTP handlers for the transport layer.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// metadataHandler serves OAuth 2.0 Protected Resource Metadata per RFC 9728.
type metadataHandler struct {
	service   oauth.MetadataService
	responder transportcore.ErrorResponder
}

// NewMetadataHandler creates a handler for the /.well-known/oauth-protected-resource endpoint.
// It serves Protected Resource Metadata to aid client discovery per RFC 9728.
func NewMetadataHandler(service oauth.MetadataService, responder transportcore.ErrorResponder) http.Handler {
	if service == nil {
		panic("service cannot be nil")
	}
	if responder == nil {
		panic("responder cannot be nil")
	}

	return &metadataHandler{
		service:   service,
		responder: responder,
	}
}

// ServeHTTP handles GET requests for protected resource metadata.
// Only GET method is allowed per RFC 9728.
func (h *metadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET method
	if r.Method != http.MethodGet {
		// Method not allowed - return 405
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get metadata from service
	metadata, err := h.service.GetMetadata(r.Context())
	if err != nil {
		slog.Error("failed to get metadata", "error", err)
		h.responder.InternalError(w, err)
		return
	}

	// Set response headers
	w.Header().Set(pkgoauth.HeaderContentType, pkgoauth.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	// Encode metadata as JSON
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		slog.Error("failed to encode metadata", "error", err)
		// Can't send error response here since headers are already written
		return
	}
}
