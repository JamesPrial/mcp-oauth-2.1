package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// healthResponse represents the JSON response for health checks.
type healthResponse struct {
	Status string `json:"status"`
}

// healthHandler provides a simple health check endpoint.
type healthHandler struct {
	responder transportcore.ErrorResponder
}

// NewHealthHandler creates a handler for the /health endpoint.
// It returns a simple JSON response indicating the server is healthy.
func NewHealthHandler(responder transportcore.ErrorResponder) http.Handler {
	if responder == nil {
		panic("responder cannot be nil")
	}

	return &healthHandler{
		responder: responder,
	}
}

// ServeHTTP handles GET requests for health checks.
// Only GET method is allowed.
func (h *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET method
	if r.Method != http.MethodGet {
		// Method not allowed - return 405
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Set response headers
	w.Header().Set(pkgoauth.HeaderContentType, pkgoauth.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	// Send health response
	resp := healthResponse{Status: "ok"}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode health response", "error", err)
		// Can't send error response here since headers are already written
	}
}
