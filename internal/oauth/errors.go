package oauth

import (
	"errors"
)

// Sentinel errors for OAuth operations.
// These are used for error identification and testing.
// For creating domain errors with context, use the oautherr package.
var (
	// ErrInvalidToken indicates the access token is invalid, expired, malformed, or revoked.
	ErrInvalidToken = errors.New("invalid token")

	// ErrInsufficientScope indicates the token lacks required scope(s).
	ErrInsufficientScope = errors.New("insufficient_scope")

	// ErrInvalidAudience indicates the token audience does not match this resource server.
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidSignature indicates the token signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrUnsupportedAlgorithm indicates the token uses an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrMissingClaim indicates a required JWT claim is missing.
	ErrMissingClaim = errors.New("missing claim")

	// ErrKeyNotFound indicates the signing key (kid) was not found in JWKS.
	ErrKeyNotFound = errors.New("key not found")

	// ErrJWKSFetchFailed indicates fetching JWKS from the authorization server failed.
	ErrJWKSFetchFailed = errors.New("jwks fetch failed")

	// ErrInvalidMetadata indicates the authorization server metadata is invalid.
	ErrInvalidMetadata = errors.New("invalid metadata")
)
