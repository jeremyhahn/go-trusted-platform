package disklessroot

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestCov964ValidateSalt checks that ValidateSalt accepts the salt DeriveSalt
// produces and rejects anything that is not 64 lowercase hex characters with a
// FieldError naming the verity salt parameter.
func TestCov964ValidateSalt(t *testing.T) {
	derived := DeriveSalt(1700000000, "v1.2.3")
	tests := []struct {
		name    string
		salt    string
		wantErr bool
	}{
		{name: "derived salt", salt: derived, wantErr: false},
		{name: "uppercase", salt: strings.ToUpper(derived), wantErr: true},
		{name: "short", salt: derived[:63], wantErr: true},
		{name: "long", salt: derived + "0", wantErr: true},
		{name: "non-hex", salt: "g" + derived[1:], wantErr: true},
		{name: "empty", salt: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSalt(tc.salt)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("ValidateSalt(%q) = %v, want nil", tc.salt, err)
				}
				return
			}
			var fieldErr *FieldError
			if !errors.As(err, &fieldErr) {
				t.Fatalf("ValidateSalt(%q) = %v, want *FieldError", tc.salt, err)
			}
			if fieldErr.Field != ParamVeritySalt {
				t.Errorf("Field = %q, want %q", fieldErr.Field, ParamVeritySalt)
			}
		})
	}
}

// TestCov964ErrorMessages checks each typed error's message and that the
// wrapped cause is reachable through errors.Is.
func TestCov964ErrorMessages(t *testing.T) {
	cause := fs.ErrNotExist
	tests := []struct {
		name      string
		err       error
		wantMsg   string
		wantCause error
	}{
		{
			name:    "field error",
			err:     &FieldError{Field: "verity.salt", Reason: "bad"},
			wantMsg: "disklessroot: verity.salt: bad",
		},
		{
			name:      "manifest error",
			err:       &ManifestError{Path: "/m.json", Err: cause},
			wantMsg:   "disklessroot: manifest /m.json: " + cause.Error(),
			wantCause: cause,
		},
		{
			name:    "signature error without cause",
			err:     &SignatureError{Reason: "mismatch"},
			wantMsg: "disklessroot: signature: mismatch",
		},
		{
			name:      "signature error with cause",
			err:       &SignatureError{Reason: "sign", Err: cause},
			wantMsg:   "disklessroot: signature: sign: " + cause.Error(),
			wantCause: cause,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tc.wantMsg)
			}
			if tc.wantCause != nil && !errors.Is(tc.err, tc.wantCause) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tc.err, tc.wantCause)
			}
		})
	}
}

// TestCov964UnwrapNilCause checks that a SignatureError without a cause
// unwraps to nil rather than a non-nil sentinel.
func TestCov964UnwrapNilCause(t *testing.T) {
	err := &SignatureError{Reason: "mismatch"}
	if got := err.Unwrap(); got != nil {
		t.Fatalf("Unwrap() = %v, want nil", got)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatal("errors.Is matched a cause the error does not carry")
	}
}
