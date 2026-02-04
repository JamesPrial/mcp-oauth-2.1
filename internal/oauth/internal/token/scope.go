package token

import (
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/oautherr"
)

// ScopeChecker validates token scopes against required scopes.
type ScopeChecker struct{}

// NewScopeChecker creates a new scope checker.
func NewScopeChecker() *ScopeChecker {
	return &ScopeChecker{}
}

// RequireScopes checks that the token has all of the specified scopes.
func (s *ScopeChecker) RequireScopes(claims *TokenClaims, required ...string) error {
	if claims == nil {
		return oautherr.NewInsufficientScopeError("RequireScopes", required)
	}

	if !claims.HasAllScopes(required...) {
		return oautherr.NewInsufficientScopeError("RequireScopes", required)
	}

	return nil
}

// RequireAnyScope checks that the token has at least one of the specified scopes.
func (s *ScopeChecker) RequireAnyScope(claims *TokenClaims, scopes ...string) error {
	if claims == nil {
		return oautherr.NewInsufficientScopeError("RequireAnyScope", scopes)
	}

	if !claims.HasAnyScope(scopes...) {
		return oautherr.NewInsufficientScopeError("RequireAnyScope", scopes)
	}

	return nil
}
