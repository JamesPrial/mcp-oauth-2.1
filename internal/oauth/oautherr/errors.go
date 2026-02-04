// Package oautherr provides OAuth 2.1 error constructors.
// This package is separate from internal/oauth to avoid import cycles
// when internal packages need to create OAuth errors.
package oautherr

import (
	"fmt"

	ierrors "github.com/jamesprial/mcp-oauth-2.1/internal/errors"
)

// Domain identifier for OAuth errors.
const domainOAuth = "oauth"

// NewInvalidTokenError creates a DomainError for invalid token with context.
func NewInvalidTokenError(op string, err error) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, err).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken)
}

// NewInsufficientScopeError creates a DomainError for insufficient scope.
func NewInsufficientScopeError(op string, required []string) *ierrors.DomainError {
	// Import the sentinel error from the parent package
	return ierrors.New(domainOAuth, op, ierrors.ErrForbidden, fmt.Errorf("insufficient_scope")).
		WithContext("oauth_error", ierrors.ErrorCodeInsufficientScope).
		WithContext("required_scopes", required)
}

// NewInvalidAudienceError creates a DomainError for invalid audience.
func NewInvalidAudienceError(op string, expected string, actual []string) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, fmt.Errorf("invalid audience")).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("expected_audience", expected).
		WithContext("actual_audience", actual)
}

// NewTokenExpiredError creates a DomainError for expired token.
func NewTokenExpiredError(op string, err error) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, err).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("reason", "token_expired")
}

// NewInvalidSignatureError creates a DomainError for signature verification failure.
func NewInvalidSignatureError(op string, err error) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, err).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("reason", "invalid_signature")
}

// NewUnsupportedAlgorithmError creates a DomainError for unsupported signing algorithm.
func NewUnsupportedAlgorithmError(op string, algorithm string) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, fmt.Errorf("unsupported algorithm")).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("algorithm", algorithm)
}

// NewMissingClaimError creates a DomainError for missing JWT claim.
func NewMissingClaimError(op string, claim string) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, fmt.Errorf("missing claim: %s", claim)).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("missing_claim", claim)
}

// NewKeyNotFoundError creates a DomainError for JWKS key not found.
func NewKeyNotFoundError(op string, keyID string) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrUnauthorized, fmt.Errorf("key not found")).
		WithContext("oauth_error", ierrors.ErrorCodeInvalidToken).
		WithContext("key_id", keyID)
}

// NewJWKSFetchError creates a DomainError for JWKS fetch failure.
func NewJWKSFetchError(op string, serverURL string, err error) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrInternal, fmt.Errorf("jwks fetch failed: %v", err)).
		WithContext("authorization_server", serverURL)
}

// NewInvalidMetadataError creates a DomainError for invalid authorization server metadata.
func NewInvalidMetadataError(op string, serverURL string, err error) *ierrors.DomainError {
	return ierrors.New(domainOAuth, op, ierrors.ErrInternal, fmt.Errorf("invalid metadata: %v", err)).
		WithContext("authorization_server", serverURL)
}
