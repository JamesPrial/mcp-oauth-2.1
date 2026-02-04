package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// NewRecoveryMiddleware creates middleware that recovers from panics.
// It logs the panic with a stack trace and returns a 500 Internal Server Error
// to the client to prevent connection termination.
// If logger is nil, it uses the default slog logger.
func NewRecoveryMiddleware(responder transportcore.ErrorResponder, logger *slog.Logger) transportcore.Middleware {
	if responder == nil {
		panic("responder cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					// Capture stack trace
					stack := debug.Stack()

					// Log the panic with stack trace
					logger.Error("panic recovered",
						"panic", recovered,
						"method", r.Method,
						"path", r.URL.Path,
						"stack", string(stack),
					)

					// Return 500 error to client
					err := fmt.Errorf("panic: %v", recovered)
					responder.InternalError(w, err)
				}
			}()

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}
