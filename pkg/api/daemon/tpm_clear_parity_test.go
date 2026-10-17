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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// clearTPM is an owned TPM: its config holds the SO PIN as the owner and
// endorsement hierarchy auth, as the daemon leaves it after taking
// ownership. Any call other than Clear or Config panics.
type clearTPM struct {
	xkmssdk.TrustedPlatformModule
	cfg      *xkmssdk.TPMConfig
	clearErr error
}

func newClearTPM(clearErr error) *clearTPM {
	return &clearTPM{
		cfg: &xkmssdk.TPMConfig{
			SSRK: &xkmssdk.SRKConfig{HierarchyAuth: "so-pin"},
			EK:   &xkmssdk.EKConfig{HierarchyAuth: "so-pin"},
		},
		clearErr: clearErr,
	}
}

func (c *clearTPM) Config() *xkmssdk.TPMConfig     { return c.cfg }
func (c *clearTPM) Clear(lockoutAuth []byte) error { return c.clearErr }

// After a Clear the TPM's owner and endorsement auth are empty, so the
// daemon's must be too, or the next CreateSRK or Provision is refused
// with TPM_RC_BAD_AUTH. Every transport goes through the same path.
func TestTPMClearParity_ResetsHierarchyAuth(t *testing.T) {
	grpcTPM := newClearTPM(nil)
	mcpTPM := newClearTPM(nil)

	_, err := newTPMGRPCServiceWith(grpcTPM).Clear(context.Background(), &platformv1.TPMClearRequest{})
	require.NoError(t, err)
	_, err = newMCPProviderWithTPM(mcpTPM).TPMClear(context.Background(), "")
	require.NoError(t, err)

	for name, tpm := range map[string]*clearTPM{"gRPC": grpcTPM, "MCP": mcpTPM} {
		assert.Empty(t, tpm.cfg.SSRK.HierarchyAuth, "%s: owner hierarchy auth after Clear", name)
		assert.Empty(t, tpm.cfg.EK.HierarchyAuth, "%s: endorsement hierarchy auth after Clear", name)
	}
}

func TestTPMClearParity_RefusedClearKeepsHierarchyAuth(t *testing.T) {
	refused := errors.New("TPM_RC_LOCKOUT")
	grpcTPM := newClearTPM(refused)
	mcpTPM := newClearTPM(refused)

	_, err := newTPMGRPCServiceWith(grpcTPM).Clear(context.Background(), &platformv1.TPMClearRequest{OwnerPassword: "wrong"})
	require.Error(t, err)
	_, err = newMCPProviderWithTPM(mcpTPM).TPMClear(context.Background(), "wrong")
	require.Error(t, err)

	for name, tpm := range map[string]*clearTPM{"gRPC": grpcTPM, "MCP": mcpTPM} {
		assert.Equal(t, "so-pin", tpm.cfg.SSRK.HierarchyAuth, "%s: a refused Clear left the TPM owned", name)
		assert.Equal(t, "so-pin", tpm.cfg.EK.HierarchyAuth, "%s: a refused Clear left the TPM owned", name)
	}
}
