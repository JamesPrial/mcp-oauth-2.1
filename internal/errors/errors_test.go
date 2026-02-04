package errors

import (
	"errors"
	"testing"
)

func TestDomainError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *DomainError
		contains string
	}{
		{
			name: "formats correctly with wrapped error",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
				Err:    errors.New("token expired"),
			},
			contains: "oauth.ValidateToken:",
		},
		{
			name: "formats correctly with Kind only",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
			},
			contains: "oauth.ValidateToken: unauthorized",
		},
		{
			name: "includes wrapped error message",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
				Err:    errors.New("token expired"),
			},
			contains: "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !containsString(got, tt.contains) {
				t.Errorf("DomainError.Error() = %q, want to contain %q", got, tt.contains)
			}
		})
	}
}

func TestDomainError_Unwrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       *DomainError
		wantInner error
	}{
		{
			name: "returns wrapped error",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Err:    ErrNotFound,
			},
			wantInner: ErrNotFound,
		},
		{
			name: "returns nil when no wrapped error",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
			},
			wantInner: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Unwrap()
			if got != tt.wantInner {
				t.Errorf("DomainError.Unwrap() = %v, want %v", got, tt.wantInner)
			}
		})
	}
}

func TestDomainError_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    *DomainError
		target error
		want   bool
	}{
		{
			name: "matches Kind",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
			},
			target: ErrUnauthorized,
			want:   true,
		},
		{
			name: "matches wrapped error",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrBadRequest,
				Err:    ErrNotFound,
			},
			target: ErrNotFound,
			want:   true,
		},
		{
			name: "does not match different error",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
			},
			target: ErrForbidden,
			want:   false,
		},
		{
			name: "matches Kind via errors.Is",
			err: &DomainError{
				Domain: "oauth",
				Op:     "ValidateToken",
				Kind:   ErrUnauthorized,
			},
			target: ErrUnauthorized,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Test direct Is method
			if got := tt.err.Is(tt.target); got != tt.want {
				t.Errorf("DomainError.Is() = %v, want %v", got, tt.want)
			}
			// Also verify errors.Is works correctly
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is(DomainError, target) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainError_WithContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		initial    *DomainError
		addPairs   [][2]interface{}
		checkKey   string
		checkValue interface{}
	}{
		{
			name: "adds single context value",
			initial: &DomainError{
				Domain:  "oauth",
				Op:      "ValidateToken",
				Context: nil,
			},
			addPairs:   [][2]interface{}{{"key", "value"}},
			checkKey:   "key",
			checkValue: "value",
		},
		{
			name: "adds multiple context values",
			initial: &DomainError{
				Domain:  "oauth",
				Op:      "ValidateToken",
				Context: nil,
			},
			addPairs:   [][2]interface{}{{"key1", "value1"}, {"key2", 42}},
			checkKey:   "key2",
			checkValue: 42,
		},
		{
			name: "adds to existing context",
			initial: &DomainError{
				Domain:  "oauth",
				Op:      "ValidateToken",
				Context: map[string]interface{}{"existing": "data"},
			},
			addPairs:   [][2]interface{}{{"new", "value"}},
			checkKey:   "new",
			checkValue: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.initial
			for _, pair := range tt.addPairs {
				err = err.WithContext(pair[0].(string), pair[1])
			}
			if err.Context == nil {
				t.Fatal("WithContext() did not initialize Context map")
			}
			if got, ok := err.Context[tt.checkKey]; !ok {
				t.Errorf("WithContext() did not add key %q", tt.checkKey)
			} else if got != tt.checkValue {
				t.Errorf("WithContext() Context[%q] = %v, want %v", tt.checkKey, got, tt.checkValue)
			}
		})
	}
}

func TestDomainError_WithContext_Chaining(t *testing.T) {
	t.Parallel()

	err := &DomainError{
		Domain: "oauth",
		Op:     "ValidateToken",
	}

	result := err.WithContext("key1", "value1").WithContext("key2", "value2").WithContext("key3", "value3")

	if result != err {
		t.Error("WithContext() should return same error for chaining")
	}

	expectedKeys := []string{"key1", "key2", "key3"}
	for _, key := range expectedKeys {
		if _, ok := err.Context[key]; !ok {
			t.Errorf("WithContext() chaining did not add key %q", key)
		}
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		domain     string
		op         string
		kind       error
		err        error
		wantDomain string
		wantOp     string
		wantKind   error
		wantErr    error
	}{
		{
			name:       "creates DomainError with all fields",
			domain:     "oauth",
			op:         "Validate",
			kind:       ErrUnauthorized,
			err:        nil,
			wantDomain: "oauth",
			wantOp:     "Validate",
			wantKind:   ErrUnauthorized,
			wantErr:    nil,
		},
		{
			name:       "creates DomainError with wrapped error",
			domain:     "oauth",
			op:         "Validate",
			kind:       ErrUnauthorized,
			err:        errors.New("inner error"),
			wantDomain: "oauth",
			wantOp:     "Validate",
			wantKind:   ErrUnauthorized,
		},
		{
			name:       "creates DomainError with different domain",
			domain:     "mcp",
			op:         "HandleRequest",
			kind:       ErrBadRequest,
			err:        nil,
			wantDomain: "mcp",
			wantOp:     "HandleRequest",
			wantKind:   ErrBadRequest,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := New(tt.domain, tt.op, tt.kind, tt.err)

			if got == nil {
				t.Fatal("New() returned nil")
			}
			if got.Domain != tt.wantDomain {
				t.Errorf("New() Domain = %q, want %q", got.Domain, tt.wantDomain)
			}
			if got.Op != tt.wantOp {
				t.Errorf("New() Op = %q, want %q", got.Op, tt.wantOp)
			}
			if got.Kind != tt.wantKind {
				t.Errorf("New() Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if tt.err != nil && got.Err == nil {
				t.Error("New() Err is nil, want non-nil")
			}
			if got.Context == nil {
				t.Error("New() Context is nil, want initialized map")
			}
		})
	}
}

func TestNew_InitializesContext(t *testing.T) {
	t.Parallel()

	err := New("oauth", "Test", ErrUnauthorized, nil)

	if err.Context == nil {
		t.Fatal("New() should initialize Context map")
	}

	// Should be able to add to context without panic
	err.Context["test"] = "value"
	if err.Context["test"] != "value" {
		t.Error("Context map should be usable after New()")
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "ErrNotFound",
			err:     ErrNotFound,
			wantMsg: "not found",
		},
		{
			name:    "ErrUnauthorized",
			err:     ErrUnauthorized,
			wantMsg: "unauthorized",
		},
		{
			name:    "ErrForbidden",
			err:     ErrForbidden,
			wantMsg: "forbidden",
		},
		{
			name:    "ErrBadRequest",
			err:     ErrBadRequest,
			wantMsg: "bad request",
		},
		{
			name:    "ErrInternal",
			err:     ErrInternal,
			wantMsg: "internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.wantMsg)
			}
		})
	}
}

// containsString is a helper function to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
