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

func TestErrForbiddenOverrideKey_Error(t *testing.T) {
	tests := []struct {
		name string
		err  ErrForbiddenOverrideKey
		want string
	}{
		{
			name: "with source and line",
			err: ErrForbiddenOverrideKey{
				Source:   "/deploy/overrides/cp-0.yaml",
				Line:     5,
				Hostname: "cp-0",
				KeyPath:  "network.interfaces",
				UseField: "nodes[].interfaces",
			},
			want: `bootstrap: /deploy/overrides/cp-0.yaml:5: node cp-0: override key "network.interfaces" duplicates authoritative field nodes[].interfaces; delete it — the bootstrap injects this value automatically`,
		},
		{
			name: "with source, no line",
			err: ErrForbiddenOverrideKey{
				Source:   "/deploy/bootstrap.yaml",
				Hostname: "cp-0",
				KeyPath:  "os.hostname",
				UseField: "nodes[].hostname",
			},
			want: `bootstrap: /deploy/bootstrap.yaml: node cp-0: override key "os.hostname" duplicates authoritative field nodes[].hostname; delete it — the bootstrap injects this value automatically`,
		},
		{
			name: "no source, no line",
			err: ErrForbiddenOverrideKey{
				Hostname: "gw-1",
				KeyPath:  "bmc.address",
				UseField: "nodes[].bmc_address",
			},
			want: `bootstrap: node gw-1: override key "bmc.address" duplicates authoritative field nodes[].bmc_address; delete it — the bootstrap injects this value automatically`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrNilConfigMap_Error(t *testing.T) {
	err := ErrNilConfigMap{}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error message %q should mention the nil map", err.Error())
	}
}

func TestErrConfigKeyNotMap_Error(t *testing.T) {
	err := ErrConfigKeyNotMap{Hostname: "cp-0", Key: "os"}
	msg := err.Error()
	if !strings.Contains(msg, "cp-0") || !strings.Contains(msg, `"os"`) {
		t.Errorf("error message %q should name the host and key", msg)
	}
}

func TestErrInterfaceConvertFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("marshal boom")
	err := ErrInterfaceConvertFailed{Hostname: "cp-0", Cause: cause}
	if !strings.Contains(err.Error(), "cp-0") || !strings.Contains(err.Error(), "marshal boom") {
		t.Errorf("error message %q should name the host and cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return cause")
	}
}
