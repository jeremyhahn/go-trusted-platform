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

package network

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrAuthFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAuthFailed
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrAuthFailed{},
			contains: []string{"network: authentication failed"},
		},
		{
			name:     "with port ID",
			err:      ErrAuthFailed{PortID: "eth0"},
			contains: []string{"network: authentication failed", "eth0"},
		},
		{
			name:     "with reason",
			err:      ErrAuthFailed{Reason: "certificate expired"},
			contains: []string{"network: authentication failed", "certificate expired"},
		},
		{
			name:     "with cause",
			err:      ErrAuthFailed{Cause: errors.New("underlying error")},
			contains: []string{"network: authentication failed", "underlying error"},
		},
		{
			name: "full error",
			err: ErrAuthFailed{
				PortID: "eth0",
				Reason: "validation failed",
				Cause:  errors.New("cert chain invalid"),
			},
			contains: []string{"eth0", "validation failed", "cert chain invalid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrAuthFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrAuthFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrCertInvalid(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertInvalid
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrCertInvalid{},
			contains: []string{"network: certificate invalid"},
		},
		{
			name:     "with subject",
			err:      ErrCertInvalid{Subject: "CN=test"},
			contains: []string{"CN=test"},
		},
		{
			name:     "with reason",
			err:      ErrCertInvalid{Reason: "expired"},
			contains: []string{"expired"},
		},
		{
			name:     "with cause",
			err:      ErrCertInvalid{Cause: errors.New("chain error")},
			contains: []string{"chain error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrCertInvalid_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrCertInvalid{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
}

func TestErrPolicyViolation(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrPolicyViolation
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrPolicyViolation{},
			contains: []string{"network: policy violation"},
		},
		{
			name:     "with port ID",
			err:      ErrPolicyViolation{PortID: "eth0"},
			contains: []string{"eth0"},
		},
		{
			name:     "with policy ID",
			err:      ErrPolicyViolation{PolicyID: "policy-123"},
			contains: []string{"policy-123"},
		},
		{
			name:     "with reason",
			err:      ErrPolicyViolation{Reason: "access denied"},
			contains: []string{"access denied"},
		},
		{
			name: "full error",
			err: ErrPolicyViolation{
				PortID:   "eth0",
				PolicyID: "policy-123",
				Reason:   "missing required claim",
				Details:  []string{"claim: role"},
			},
			contains: []string{"eth0", "policy-123", "missing required claim"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrAttestFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAttestFailed
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrAttestFailed{},
			contains: []string{"network: attestation failed"},
		},
		{
			name:     "with device ID",
			err:      ErrAttestFailed{DeviceID: "device-123"},
			contains: []string{"device-123"},
		},
		{
			name:     "with reason",
			err:      ErrAttestFailed{Reason: "PCR mismatch"},
			contains: []string{"PCR mismatch"},
		},
		{
			name:     "with cause",
			err:      ErrAttestFailed{Cause: errors.New("TPM error")},
			contains: []string{"TPM error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrAttestFailed_Unwrap(t *testing.T) {
	cause := errors.New("TPM error")
	err := ErrAttestFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
}

func TestErrVLANFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrVLANFailed
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrVLANFailed{},
			contains: []string{"network: VLAN operation failed"},
		},
		{
			name:     "with port ID",
			err:      ErrVLANFailed{PortID: "eth0"},
			contains: []string{"eth0"},
		},
		{
			name:     "with VLANs",
			err:      ErrVLANFailed{FromVLAN: 1, ToVLAN: 100},
			contains: []string{"from=1", "to=100"},
		},
		{
			name:     "with reason",
			err:      ErrVLANFailed{Reason: "switch error"},
			contains: []string{"switch error"},
		},
		{
			name:     "with cause",
			err:      ErrVLANFailed{Cause: errors.New("OVS error")},
			contains: []string{"OVS error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrVLANFailed_Unwrap(t *testing.T) {
	cause := errors.New("OVS error")
	err := ErrVLANFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
}

func TestErrOPAEvaluation(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrOPAEvaluation
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrOPAEvaluation{},
			contains: []string{"network: OPA evaluation failed"},
		},
		{
			name:     "with endpoint",
			err:      ErrOPAEvaluation{Endpoint: "http://localhost:8181"},
			contains: []string{"OPA evaluation failed"},
		},
		{
			name:     "with policy path",
			err:      ErrOPAEvaluation{PolicyPath: "network/auth"},
			contains: []string{"network/auth"},
		},
		{
			name:     "with reason",
			err:      ErrOPAEvaluation{Reason: "connection refused"},
			contains: []string{"connection refused"},
		},
		{
			name:     "with cause",
			err:      ErrOPAEvaluation{Cause: errors.New("timeout")},
			contains: []string{"timeout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrOPAEvaluation_Unwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrOPAEvaluation{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
}

func TestErrFlowRule(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrFlowRule
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrFlowRule{},
			contains: []string{"network: OpenFlow rule error"},
		},
		{
			name:     "with port ID",
			err:      ErrFlowRule{PortID: "eth0"},
			contains: []string{"eth0"},
		},
		{
			name:     "with rule ID",
			err:      ErrFlowRule{RuleID: "rule-123"},
			contains: []string{"rule-123"},
		},
		{
			name:     "with operation",
			err:      ErrFlowRule{Operation: "install"},
			contains: []string{"install"},
		},
		{
			name:     "with reason",
			err:      ErrFlowRule{Reason: "priority conflict"},
			contains: []string{"priority conflict"},
		},
		{
			name:     "with cause",
			err:      ErrFlowRule{Cause: errors.New("OVS error")},
			contains: []string{"OVS error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrFlowRule_Unwrap(t *testing.T) {
	cause := errors.New("OVS error")
	err := ErrFlowRule{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
}

func TestErrInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidConfig
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrInvalidConfig{Reason: "missing required field"},
			contains: []string{"network: invalid config", "missing required field"},
		},
		{
			name:     "with field",
			err:      ErrInvalidConfig{Field: "BridgeName", Reason: "cannot be empty"},
			contains: []string{"BridgeName", "cannot be empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrContextCanceled(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrContextCanceled
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrContextCanceled{},
			contains: []string{"network: operation canceled"},
		},
		{
			name:     "with operation",
			err:      ErrContextCanceled{Operation: "Authenticate"},
			contains: []string{"Authenticate canceled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrServiceNotInitialized(t *testing.T) {
	err := ErrServiceNotInitialized{}
	assert.Equal(t, "network: service not initialized", err.Error())
}

func TestErrPortNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrPortNotFound
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrPortNotFound{},
			contains: []string{"network: port not found"},
		},
		{
			name:     "with port ID",
			err:      ErrPortNotFound{PortID: "eth0"},
			contains: []string{"eth0", "not found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrSessionExpired(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrSessionExpired
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrSessionExpired{},
			contains: []string{"network: session expired"},
		},
		{
			name:     "with session ID",
			err:      ErrSessionExpired{SessionID: "sess-123"},
			contains: []string{"sess-123"},
		},
		{
			name:     "with port ID",
			err:      ErrSessionExpired{PortID: "eth0"},
			contains: []string{"eth0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrStateTransition(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrStateTransition
		contains []string
	}{
		{
			name: "basic error",
			err: ErrStateTransition{
				FromState: AuthStateQuarantine,
				ToState:   AuthStateEnrolling,
			},
			contains: []string{"quarantine", "enrolling"},
		},
		{
			name: "with port ID",
			err: ErrStateTransition{
				PortID:    "eth0",
				FromState: AuthStateQuarantine,
				ToState:   AuthStateAuthorized,
			},
			contains: []string{"eth0"},
		},
		{
			name: "with reason",
			err: ErrStateTransition{
				FromState: AuthStateRevoked,
				ToState:   AuthStateAuthorized,
				Reason:    "cannot transition from revoked",
			},
			contains: []string{"cannot transition from revoked"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrOIDMissing(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrOIDMissing
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrOIDMissing{OID: "1.2.3.4"},
			contains: []string{"1.2.3.4", "missing"},
		},
		{
			name:     "with subject",
			err:      ErrOIDMissing{OID: "1.2.3.4", Subject: "CN=test"},
			contains: []string{"1.2.3.4", "CN=test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrReattestRequired(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrReattestRequired
		contains []string
	}{
		{
			name:     "basic error",
			err:      ErrReattestRequired{},
			contains: []string{"re-attestation required"},
		},
		{
			name:     "with port ID",
			err:      ErrReattestRequired{PortID: "eth0"},
			contains: []string{"eth0"},
		},
		{
			name:     "with last time",
			err:      ErrReattestRequired{LastTime: "2025-01-01T00:00:00Z"},
			contains: []string{"2025-01-01"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

func TestErrorTypeAssertions(t *testing.T) {
	// Test that errors can be properly type-asserted
	var err error

	err = ErrAuthFailed{PortID: "eth0"}
	_, ok := err.(ErrAuthFailed)
	assert.True(t, ok)

	err = ErrCertInvalid{Subject: "CN=test"}
	_, ok = err.(ErrCertInvalid)
	assert.True(t, ok)

	err = ErrPolicyViolation{PolicyID: "policy-123"}
	_, ok = err.(ErrPolicyViolation)
	assert.True(t, ok)

	err = ErrAttestFailed{DeviceID: "device-123"}
	_, ok = err.(ErrAttestFailed)
	assert.True(t, ok)

	err = ErrVLANFailed{PortID: "eth0"}
	_, ok = err.(ErrVLANFailed)
	assert.True(t, ok)
}
