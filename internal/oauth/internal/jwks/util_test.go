package jwks

import (
	"crypto/elliptic"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBase64URLDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "standard encoding",
			input:    base64.StdEncoding.EncodeToString([]byte("hello world")),
			expected: []byte("hello world"),
			wantErr:  false,
		},
		{
			name:     "url encoding without padding",
			input:    "aGVsbG8gd29ybGQ",
			expected: []byte("hello world"),
			wantErr:  false,
		},
		{
			name:     "url encoding with url-safe chars",
			input:    strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("test>>??")), "="),
			expected: []byte("test>>??"),
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "single character",
			input:    base64.StdEncoding.EncodeToString([]byte("a")),
			expected: []byte("a"),
			wantErr:  false,
		},
		{
			name:     "padding case 1",
			input:    "YWI",
			expected: []byte("ab"),
			wantErr:  false,
		},
		{
			name:     "padding case 2",
			input:    "YQ",
			expected: []byte("a"),
			wantErr:  false,
		},
		{
			name:     "with explicit padding",
			input:    "aGVsbG8gd29ybGQ=",
			expected: []byte("hello world"),
			wantErr:  false,
		},
		{
			name:    "invalid base64",
			input:   "invalid!@#$%",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := base64URLDecode(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("base64URLDecode() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("base64URLDecode() unexpected error: %v", err)
				}

				if string(result) != string(tt.expected) {
					t.Errorf("base64URLDecode() = %q, want %q", result, tt.expected)
				}
			}
		})
	}
}

func TestBase64URLDecode_URLSafeChars(t *testing.T) {
	t.Parallel()

	// Test that URL-safe characters (- and _) are properly handled
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "contains minus",
			input: "SGVsbG8tV29ybGQ",
		},
		{
			name:  "contains underscore",
			input: "SGVsbG9fV29ybGQ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := base64URLDecode(tt.input)
			if err != nil {
				t.Fatalf("base64URLDecode() should handle URL-safe chars: %v", err)
			}
		})
	}
}

func TestGetCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		curveName    string
		expectedName string
		wantErr      bool
	}{
		{
			name:         "P-256",
			curveName:    "P-256",
			expectedName: "P-256",
			wantErr:      false,
		},
		{
			name:         "P-384",
			curveName:    "P-384",
			expectedName: "P-384",
			wantErr:      false,
		},
		{
			name:         "P-521",
			curveName:    "P-521",
			expectedName: "P-521",
			wantErr:      false,
		},
		{
			name:      "unsupported curve",
			curveName: "P-224",
			wantErr:   true,
		},
		{
			name:      "invalid curve",
			curveName: "invalid-curve",
			wantErr:   true,
		},
		{
			name:      "empty curve name",
			curveName: "",
			wantErr:   true,
		},
		{
			name:      "secp256k1 not supported",
			curveName: "secp256k1",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			curve, err := getCurve(tt.curveName)

			if tt.wantErr {
				if err == nil {
					t.Fatal("getCurve() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
					t.Errorf("getCurve() error = %q, want error about unsupported curve", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("getCurve() unexpected error: %v", err)
				}

				if curve == nil {
					t.Fatal("getCurve() returned nil curve")
				}

				// Verify the curve parameters match expected curve
				var expectedCurve elliptic.Curve
				switch tt.expectedName {
				case "P-256":
					expectedCurve = elliptic.P256()
				case "P-384":
					expectedCurve = elliptic.P384()
				case "P-521":
					expectedCurve = elliptic.P521()
				}

				if curve.Params().Name != expectedCurve.Params().Name {
					t.Errorf("getCurve() curve name = %q, want %q",
						curve.Params().Name, expectedCurve.Params().Name)
				}
			}
		})
	}
}

func TestGetCurve_CurveProperties(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		curveName string
		checkFunc func(*testing.T, elliptic.Curve)
	}{
		{
			name:      "P-256 has correct bit size",
			curveName: "P-256",
			checkFunc: func(t *testing.T, curve elliptic.Curve) {
				if curve.Params().BitSize != 256 {
					t.Errorf("P-256 bit size = %d, want 256", curve.Params().BitSize)
				}
			},
		},
		{
			name:      "P-384 has correct bit size",
			curveName: "P-384",
			checkFunc: func(t *testing.T, curve elliptic.Curve) {
				if curve.Params().BitSize != 384 {
					t.Errorf("P-384 bit size = %d, want 384", curve.Params().BitSize)
				}
			},
		},
		{
			name:      "P-521 has correct bit size",
			curveName: "P-521",
			checkFunc: func(t *testing.T, curve elliptic.Curve) {
				if curve.Params().BitSize != 521 {
					t.Errorf("P-521 bit size = %d, want 521", curve.Params().BitSize)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			curve, err := getCurve(tt.curveName)
			if err != nil {
				t.Fatalf("getCurve() unexpected error: %v", err)
			}

			tt.checkFunc(t, curve)
		})
	}
}

func TestBase64URLDecode_RoundTrip(t *testing.T) {
	t.Parallel()

	testData := [][]byte{
		[]byte("hello world"),
		[]byte("test data"),
		[]byte(""),
		[]byte("a"),
		[]byte("ab"),
		[]byte("abc"),
		[]byte("abcd"),
		make([]byte, 256), // All possible byte values
	}

	// Fill the last test case with all possible byte values
	for i := range testData[len(testData)-1] {
		testData[len(testData)-1][i] = byte(i)
	}

	for i, data := range testData {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			t.Parallel()

			// Encode
			encoded := strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")

			// Decode
			decoded, err := base64URLDecode(encoded)
			if err != nil {
				t.Fatalf("base64URLDecode() unexpected error: %v", err)
			}

			// Verify round trip
			if string(decoded) != string(data) {
				t.Errorf("Round trip failed: got %q, want %q", decoded, data)
			}
		})
	}
}

func BenchmarkBase64URLDecode(b *testing.B) {
	input := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("hello world test data for benchmark")), "=")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = base64URLDecode(input)
	}
}

func BenchmarkGetCurve(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = getCurve("P-256")
	}
}
