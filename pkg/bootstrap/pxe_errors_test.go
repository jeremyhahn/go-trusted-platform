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

package bootstrap

import (
	"errors"
	"strings"
	"testing"
)

func TestPXEErrors_ErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrInvalidBootstrapConfig",
			err:      ErrInvalidBootstrapConfig{Reason: "test reason"},
			contains: "test reason",
		},
		{
			name:     "ErrNodeDiscoveryFailed",
			err:      ErrNodeDiscoveryFailed{Hostname: "cp-0", Cause: errors.New("timeout")},
			contains: "cp-0",
		},
		{
			name:     "ErrNodeDiscoveryFailed_NilCause",
			err:      ErrNodeDiscoveryFailed{Hostname: "cp-0"},
			contains: "cp-0",
		},
		{
			name:     "ErrMACDiscoveryFailed",
			err:      ErrMACDiscoveryFailed{BMCAddress: "10.0.0.1", Cause: errors.New("conn refused")},
			contains: "10.0.0.1",
		},
		{
			name:     "ErrMACDiscoveryFailed_NilCause",
			err:      ErrMACDiscoveryFailed{BMCAddress: "10.0.0.1"},
			contains: "10.0.0.1",
		},
		{
			name:     "ErrDuplicateMAC",
			err:      ErrDuplicateMAC{MAC: "AA:BB:CC:DD:EE:FF", Hostnames: []string{"cp-0", "w-0"}},
			contains: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "ErrInvalidControlPlaneCount",
			err:      ErrInvalidControlPlaneCount{Count: 2},
			contains: "2",
		},
		{
			name:     "ErrMissingRequiredField",
			err:      ErrMissingRequiredField{Field: "deployer.host"},
			contains: "deployer.host",
		},
		{
			name:     "ErrInvalidNodeRole",
			err:      ErrInvalidNodeRole{Hostname: "bad-node", Role: "database"},
			contains: "database",
		},
		{
			name:     "ErrNodeMissingIdentity",
			err:      ErrNodeMissingIdentity{Hostname: "orphan"},
			contains: "orphan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !strings.Contains(msg, tt.contains) {
				t.Errorf("error message %q does not contain %q", msg, tt.contains)
			}
		})
	}
}

func TestPXEErrors_Unwrap(t *testing.T) {
	cause := errors.New("root cause")

	t.Run("ErrNodeDiscoveryFailed", func(t *testing.T) {
		err := ErrNodeDiscoveryFailed{Hostname: "cp-0", Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return cause")
		}
	})

	t.Run("ErrMACDiscoveryFailed", func(t *testing.T) {
		err := ErrMACDiscoveryFailed{BMCAddress: "10.0.0.1", Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return cause")
		}
	})
}
