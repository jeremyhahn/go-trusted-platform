// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"errors"
	"strings"
	"testing"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// Error strings land in audit trails, so what they say is part of the
// contract: each must name the package, the condition, and the values a
// reader needs to act on.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{
			name: "invalid config",
			err:  ErrInvalidConfig{Field: "RequestTimeout", Reason: "must not be negative"},
			want: []string{"RequestTimeout", "must not be negative"},
		},
		{
			name: "nil config",
			err:  ErrNilConfig{},
			want: []string{"nil config"},
		},
		{
			name: "nil device",
			err:  ErrNilDevice{},
			want: []string{"nil device"},
		},
		{
			name: "nil policy",
			err:  ErrNilPolicy{},
			want: []string{"nil policy"},
		},
		{
			name: "invalid tenant with a cause",
			err:  ErrInvalidTenant{TenantID: "a/b", Cause: errors.New("bad segment")},
			want: []string{`"a/b"`, "bad segment"},
		},
		{
			name: "invalid tenant with no cause",
			err:  ErrInvalidTenant{TenantID: ""},
			want: []string{`""`},
		},
		{
			name: "tenant mismatch names both sides",
			err:  ErrTenantMismatch{Want: "acme", Got: "globex"},
			want: []string{`"globex"`, `"acme"`},
		},
		{
			name: "tenant mismatch with no tenant at all",
			err:  ErrTenantMismatch{Want: "acme"},
			want: []string{"(none)", `"acme"`},
		},
		{
			name: "attestation not compiled in",
			err:  ErrAttestationNotCompiledIn{BoardID: 3, CryptoTier: "software"},
			want: []string{"board 3", "software", "no attestation feature bit"},
		},
		{
			name: "nonce length names the flow and both widths",
			err:  ErrNonceLength{Flow: "enrolment", Got: 16, Want: 32},
			want: []string{"enrolment", "32", "16"},
		},
		{
			name: "evidence length",
			err:  ErrEvidenceLength{Got: 100, Want: 164},
			want: []string{"164", "100"},
		},
		{
			name: "evidence version",
			err:  ErrEvidenceVersion{Got: 9, Want: 1},
			want: []string{"9", "1"},
		},
		{
			name: "unsupported action",
			err:  ErrUnsupportedAction{Action: bmcattestation.ActionList},
			want: []string{`"list"`},
		},
		{
			name: "unsupported compare names both actions",
			err:  ErrUnsupportedCompare{Live: ActionAttestCert, Ref: ActionDump},
			want: []string{`"attestcert"`, `"dump"`, "golden-build"},
		},
		{
			name: "max age unset",
			err:  ErrPolicyMaxAgeUnset{},
			want: []string{"MaxAgeSeconds", "explicitly"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, "avr attestation: ") {
				t.Errorf("message does not name the package: %q", msg)
			}
			for _, want := range tc.want {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

func TestErrInvalidTenant_Unwraps(t *testing.T) {
	cause := errors.New("bad segment")
	err := ErrInvalidTenant{TenantID: "a/b", Cause: cause}

	if !errors.Is(err, cause) {
		t.Fatal("ErrInvalidTenant does not unwrap to its cause")
	}
	if got := (ErrInvalidTenant{}).Unwrap(); got != nil {
		t.Fatalf("Unwrap with no cause = %v, want nil", got)
	}
}
