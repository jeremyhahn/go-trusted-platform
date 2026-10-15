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

package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrPortNotFound",
			err:      ErrPortNotFound,
			expected: "port not found",
		},
		{
			name:     "ErrPortExists",
			err:      ErrPortExists,
			expected: "port already exists",
		},
		{
			name:     "ErrInvalidPortID",
			err:      ErrInvalidPortID,
			expected: "invalid port ID",
		},
		{
			name:     "ErrInvalidState",
			err:      ErrInvalidState,
			expected: "invalid state transition",
		},
		{
			name:     "ErrPolicyNotFound",
			err:      ErrPolicyNotFound,
			expected: "policy not found",
		},
		{
			name:     "ErrInvalidPolicy",
			err:      ErrInvalidPolicy,
			expected: "invalid policy specification",
		},
		{
			name:     "ErrInvalidCertificate",
			err:      ErrInvalidCertificate,
			expected: "invalid certificate",
		},
		{
			name:     "ErrCertificateExpired",
			err:      ErrCertificateExpired,
			expected: "certificate expired",
		},
		{
			name:     "ErrCertificateRevoked",
			err:      ErrCertificateRevoked,
			expected: "certificate revoked",
		},
		{
			name:     "ErrMissingTenantID",
			err:      ErrMissingTenantID,
			expected: "missing tenant ID in certificate",
		},
		{
			name:     "ErrMissingVLAN",
			err:      ErrMissingVLAN,
			expected: "missing VLAN in certificate",
		},
		{
			name:     "ErrInvalidVLAN",
			err:      ErrInvalidVLAN,
			expected: "invalid VLAN ID",
		},
		{
			name:     "ErrInvalidACL",
			err:      ErrInvalidACL,
			expected: "invalid ACL rule",
		},
		{
			name:     "ErrFlowInstallFailed",
			err:      ErrFlowInstallFailed,
			expected: "failed to install flow rule",
		},
		{
			name:     "ErrFlowDeleteFailed",
			err:      ErrFlowDeleteFailed,
			expected: "failed to delete flow rule",
		},
		{
			name:     "ErrEngineNotRunning",
			err:      ErrEngineNotRunning,
			expected: "policy engine not running",
		},
		{
			name:     "ErrEngineAlreadyRunning",
			err:      ErrEngineAlreadyRunning,
			expected: "policy engine already running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.err)
			assert.Equal(t, tt.expected, tt.err.Error())
			assert.True(t, errors.Is(tt.err, tt.err))
		})
	}
}

// Every transport classifies the port-auth refusal through GRPCStatus, so the
// class must be FailedPrecondition and the message must name the operation.
func TestErrPortAuthNotEnforced(t *testing.T) {
	err := error(ErrPortAuthNotEnforced{Operation: "AuthenticatePort"})

	assert.Equal(t, "sdn/policy: AuthenticatePort is refused: port authentication is not enforced on the switch", err.Error())
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, err.Error(), status.Convert(err).Message())

	wrapped := errors.Join(errors.New("context"), err)
	var refusal ErrPortAuthNotEnforced
	assert.ErrorAs(t, wrapped, &refusal)
	assert.Equal(t, "AuthenticatePort", refusal.Operation)
}
