package http

import (
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// router implements transportcore.Router using http.ServeMux.
type router struct {
	mux         *http.ServeMux
	middlewares []transportcore.Middleware
}

// NewRouter creates a new HTTP router backed by http.ServeMux.
func NewRouter() transportcore.Router {
	return &router{
		mux:         http.NewServeMux(),
		middlewares: make([]transportcore.Middleware, 0),
	}
}

// Handle registers a handler for the given pattern.
// The handler is wrapped with all currently registered middleware.
func (r *router) Handle(pattern string, handler http.Handler) {
	// Apply all middleware in order
	wrapped := r.applyMiddleware(handler)
	r.mux.Handle(pattern, wrapped)
}

// HandleFunc registers a handler function for the given pattern.
// The handler is wrapped with all currently registered middleware.
func (r *router) HandleFunc(pattern string, handler http.HandlerFunc) {
	r.Handle(pattern, handler)
}

// Use applies middleware to all subsequent route registrations.
// Middleware is applied in the order registered.
func (r *router) Use(middlewares ...transportcore.Middleware) {
	r.middlewares = append(r.middlewares, middlewares...)
}

// ServeHTTP implements http.Handler by delegating to the underlying ServeMux.
func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// applyMiddleware wraps the handler with all registered middleware.
// Middleware is applied in order, so the first middleware in the list
// is the outermost layer (executes first).
func (r *router) applyMiddleware(handler http.Handler) http.Handler {
	// Apply middleware in reverse order so the first middleware
	// registered is the outermost layer
	wrapped := handler
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		wrapped = r.middlewares[i](wrapped)
	}
	return wrapped
}
