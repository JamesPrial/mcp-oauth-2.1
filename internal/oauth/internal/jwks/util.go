package jwks

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"
)

// base64URLDecode decodes a base64url-encoded string.
// It handles both padded and unpadded inputs.
func base64URLDecode(s string) ([]byte, error) {
	// base64url uses - and _ instead of + and /
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// getCurve maps a JWK curve name to a crypto/elliptic curve.
func getCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}
}
