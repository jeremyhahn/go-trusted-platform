// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package orchestration

import (
	"errors"
	"testing"

	quicbaasorch "github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// wrappedError carries an error one level down, the way a platform service
// layer wraps an upstream failure in its own typed error.
type wrappedError struct{ err error }

func (e *wrappedError) Error() string { return "platform: " + e.err.Error() }
func (e *wrappedError) Unwrap() error { return e.err }

func policyPtr(p TrustPolicy) *TrustPolicy { return &p }

// fullCaps is a host that can prove every tier.
var fullCaps = TrustCapabilities{DigestPinning: true, HostTPM: true, MeasuredLaunch: true}

func TestResolveTrustLevel_Resolves(t *testing.T) {
	tests := []struct {
		name           string
		requested      TrustLevel
		serverPolicy   TrustPolicy
		tenantOverride *TrustPolicy
		caps           TrustCapabilities
		want           TrustLevel
	}{
		{
			name:         "default under opt-in needs nothing from the host",
			requested:    TrustLevelDefault,
			serverPolicy: TrustPolicyOptIn,
			want:         TrustLevelNone,
		},
		{
			name:         "default resolves to the policy floor",
			requested:    TrustLevelDefault,
			serverPolicy: TrustPolicyPinned,
			caps:         TrustCapabilities{DigestPinning: true},
			want:         TrustLevelPinned,
		},
		{
			name:           "tenant override tightens the server policy",
			requested:      TrustLevelDefault,
			serverPolicy:   TrustPolicyOptIn,
			tenantOverride: policyPtr(TrustPolicyAttested),
			caps:           fullCaps,
			want:           TrustLevelAttested,
		},
		{
			name:         "explicit level above the floor is kept",
			requested:    TrustLevelMeasured,
			serverPolicy: TrustPolicyPinned,
			caps:         fullCaps,
			want:         TrustLevelMeasured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveTrustLevel(tt.requested, tt.serverPolicy, tt.tenantOverride, tt.caps)
			if err != nil {
				t.Fatalf("ResolveTrustLevel() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ResolveTrustLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveTrustLevel_Violation(t *testing.T) {
	tests := []struct {
		name           string
		requested      TrustLevel
		serverPolicy   TrustPolicy
		tenantOverride *TrustPolicy
		caps           TrustCapabilities
		wantPolicy     TrustPolicy
	}{
		{
			name:         "explicit level below the policy floor",
			requested:    TrustLevelNone,
			serverPolicy: TrustPolicyAttested,
			caps:         fullCaps,
			wantPolicy:   TrustPolicyAttested,
		},
		{
			name:         "host cannot prove the requested tier",
			requested:    TrustLevelAttested,
			serverPolicy: TrustPolicyOptIn,
			caps:         TrustCapabilities{DigestPinning: true},
			wantPolicy:   TrustPolicyOptIn,
		},
		{
			name:           "tenant override cannot loosen the server policy",
			requested:      TrustLevelNone,
			serverPolicy:   TrustPolicyPinned,
			tenantOverride: policyPtr(TrustPolicyOptIn),
			caps:           fullCaps,
			wantPolicy:     TrustPolicyPinned,
		},
		{
			name:         "unknown trust level",
			requested:    TrustLevel(99),
			serverPolicy: TrustPolicyOptIn,
			caps:         fullCaps,
			wantPolicy:   TrustPolicyOptIn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveTrustLevel(tt.requested, tt.serverPolicy, tt.tenantOverride, tt.caps)
			if err == nil {
				t.Fatal("ResolveTrustLevel() error = nil, want a trust-level violation")
			}

			// Matched through the platform alias, one wrap down.
			var violation *TrustLevelViolationError
			if !errors.As(&wrappedError{err: err}, &violation) {
				t.Fatalf("errors.As(%T) through the alias = false, want true", err)
			}
			if violation.Requested != tt.requested {
				t.Errorf("violation.Requested = %v, want %v", violation.Requested, tt.requested)
			}
			if violation.Policy != tt.wantPolicy {
				t.Errorf("violation.Policy = %v, want %v", violation.Policy, tt.wantPolicy)
			}

			// The alias is the upstream type, not a copy of it.
			var upstream *quicbaasorch.TrustLevelViolationError
			if !errors.As(err, &upstream) || upstream != violation {
				t.Error("errors.As with the upstream type did not yield the same error value")
			}
		})
	}
}

func TestParseTrustLevel_RoundTrip(t *testing.T) {
	levels := []TrustLevel{
		TrustLevelDefault, TrustLevelNone, TrustLevelPinned, TrustLevelAttested, TrustLevelMeasured,
	}
	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			got, err := ParseTrustLevel(level.String())
			if err != nil {
				t.Fatalf("ParseTrustLevel(%q) error = %v", level.String(), err)
			}
			if got != level {
				t.Errorf("ParseTrustLevel(%q) = %v, want %v", level.String(), got, level)
			}
		})
	}
}

func TestParseTrustLevel_InvalidName(t *testing.T) {
	_, err := ParseTrustLevel("bogus")
	assertInputValidationError(t, err, "trust_level")
}

func TestParseTrustPolicy_RoundTrip(t *testing.T) {
	policies := []TrustPolicy{
		TrustPolicyOptIn, TrustPolicyPinned, TrustPolicyAttested, TrustPolicyMeasured,
	}
	for _, policy := range policies {
		t.Run(policy.String(), func(t *testing.T) {
			got, err := ParseTrustPolicy(policy.String())
			if err != nil {
				t.Fatalf("ParseTrustPolicy(%q) error = %v", policy.String(), err)
			}
			if got != policy {
				t.Errorf("ParseTrustPolicy(%q) = %v, want %v", policy.String(), got, policy)
			}
		})
	}
}

func TestParseTrustPolicy_InvalidName(t *testing.T) {
	_, err := ParseTrustPolicy("bogus")
	assertInputValidationError(t, err, "trust_policy")
}

// assertInputValidationError checks err is the re-exported validation error
// for field, matchable by type and by the re-exported sentinel.
func assertInputValidationError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want an input validation error")
	}
	var invalid *InputValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("errors.As(%T, *InputValidationError) = false, want true", err)
	}
	if invalid.Field != field {
		t.Errorf("InputValidationError.Field = %q, want %q", invalid.Field, field)
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Error("errors.Is(err, ErrInvalidInput) = false, want true")
	}
}
