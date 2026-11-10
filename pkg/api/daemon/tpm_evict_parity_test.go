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

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	evictEKHandle   = tpm2.TPMHandle(0x81010001)
	evictSSRKHandle = tpm2.TPMHandle(0x81000001)
)

// evictTPM answers the reads and the eviction that tpmek.Delete and
// tpmsrk.Delete make, and records every handle it evicts.
type evictTPM struct {
	xkmssdk.TrustedPlatformModule
	persisted bool
	deleteErr error
	evicted   []*xkmssdk.KeyAttributes
}

func (t *evictTPM) Config() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		EK:   &xkmssdk.EKConfig{Handle: uint32(evictEKHandle)},
		SSRK: &xkmssdk.SRKConfig{Handle: uint32(evictSSRKHandle)},
	}
}

func (t *evictTPM) ReadHandle(tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if t.persisted {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
	}
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, tpm2.TPMRCHandle
}

func (t *evictTPM) DeleteKey(keyAttrs *xkmssdk.KeyAttributes, _ xkmssdk.TPMKeyBackend) error {
	t.evicted = append(t.evicted, keyAttrs)
	return t.deleteErr
}

// deleteBoth runs one delete on gRPC (and so Unix, embedded and daemon
// REST) and on MCP.
func deleteBoth(t *testing.T, tpm *evictTPM, ek bool) (grpcErr, mcpErr error) {
	t.Helper()
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)
	if ek {
		resp, err := grpcSvc.DeleteEK(context.Background(), &platformv1.DeleteEKRequest{Handle: uint32(evictEKHandle)})
		if err == nil {
			assert.Equal(t, "EK evicted", resp.GetStatus().GetMessage())
		}
		_, mcpErr = mcp.TPMDeleteEK(context.Background(), uint32(evictEKHandle))
		return err, mcpErr
	}
	resp, err := grpcSvc.DeleteSRK(context.Background(), &platformv1.DeleteSRKRequest{Handle: uint32(evictSSRKHandle)})
	if err == nil {
		assert.Equal(t, "SRK evicted", resp.GetStatus().GetMessage())
	}
	_, mcpErr = mcp.TPMDeleteSRK(context.Background(), uint32(evictSSRKHandle))
	return err, mcpErr
}

// TestTPMDeleteParity_Evicts: DeleteEK and DeleteSRK evict the configured
// persistent key with TPM2_EvictControl on gRPC and MCP, rather than
// flushing a handle a persistent object never occupies.
func TestTPMDeleteParity_Evicts(t *testing.T) {
	cases := map[string]struct {
		ek     bool
		handle tpm2.TPMHandle
	}{
		"DeleteEK":  {ek: true, handle: evictEKHandle},
		"DeleteSRK": {ek: false, handle: evictSSRKHandle},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := &evictTPM{persisted: true}

			grpcErr, mcpErr := deleteBoth(t, tpm, tc.ek)

			require.NoError(t, grpcErr)
			require.NoError(t, mcpErr)
			require.Len(t, tpm.evicted, 2, "one eviction per transport")
			for _, attrs := range tpm.evicted {
				assert.Equal(t, tc.handle, attrs.TPMAttributes.Handle)
				assert.Equal(t, tpm2.TPMHTPersistent, attrs.TPMAttributes.HandleType)
			}
		})
	}
}

// TestTPMDeleteParity_Refusals: an empty handle is NotFound and a failed
// eviction is an error on both transports.
func TestTPMDeleteParity_Refusals(t *testing.T) {
	for name, ek := range map[string]bool{"DeleteEK": true, "DeleteSRK": false} {
		t.Run(name+" empty handle", func(t *testing.T) {
			tpm := &evictTPM{}

			grpcErr, mcpErr := deleteBoth(t, tpm, ek)

			assert.Equal(t, codes.NotFound, status.Code(grpcErr), "gRPC")
			assert.Equal(t, codes.NotFound, status.Code(mcpErr), "MCP")
			assert.Empty(t, tpm.evicted)
		})
		t.Run(name+" eviction fails", func(t *testing.T) {
			tpm := &evictTPM{persisted: true, deleteErr: errors.New("TPM_RC_BAD_AUTH")}

			grpcErr, mcpErr := deleteBoth(t, tpm, ek)

			assert.Error(t, grpcErr, "gRPC")
			assert.Error(t, mcpErr, "MCP")
		})
	}
}

// TestTPMDeleteSRK_RefusesMismatchedHandle (Codex 8183): a DeleteSRK naming
// any handle but the configured SSRK, a missing one included, is
// InvalidArgument on gRPC and MCP and evicts nothing.
func TestTPMDeleteSRK_RefusesMismatchedHandle(t *testing.T) {
	for name, handle := range map[string]uint32{"PlatformSRK": 0x81000002, "missing": 0} {
		t.Run(name, func(t *testing.T) {
			tpm := &evictTPM{persisted: true}

			_, grpcErr := newTPMGRPCServiceWith(tpm).DeleteSRK(context.Background(),
				&platformv1.DeleteSRKRequest{Handle: handle})
			_, mcpErr := newMCPProviderWithTPM(tpm).TPMDeleteSRK(context.Background(), handle)

			assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "gRPC")
			assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr), "MCP")
			assert.Empty(t, tpm.evicted, "a mismatched handle must not evict the SSRK")
		})
	}
}

// TestTPMDeleteEK_RefusesMismatchedHandle (Codex 8200): DeleteEK evicts only
// the configured EK. Another handle, or none, is InvalidArgument on gRPC and
// MCP and the configured EK stays persisted; the matching handle evicts it.
func TestTPMDeleteEK_RefusesMismatchedHandle(t *testing.T) {
	for name, handle := range map[string]uint32{"SSRK": uint32(evictSSRKHandle), "other": 0x81000002, "missing": 0} {
		t.Run(name, func(t *testing.T) {
			tpm := &evictTPM{persisted: true}

			_, grpcErr := newTPMGRPCServiceWith(tpm).DeleteEK(context.Background(),
				&platformv1.DeleteEKRequest{Handle: handle})
			_, mcpErr := newMCPProviderWithTPM(tpm).TPMDeleteEK(context.Background(), handle)

			assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "gRPC")
			assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr), "MCP")
			assert.Empty(t, tpm.evicted, "a mismatched handle must not evict the configured EK")
		})
	}
	t.Run("matching", func(t *testing.T) {
		tpm := &evictTPM{persisted: true}

		resp, err := newTPMGRPCServiceWith(tpm).DeleteEK(context.Background(),
			&platformv1.DeleteEKRequest{Handle: uint32(evictEKHandle)})

		require.NoError(t, err)
		assert.Equal(t, "EK evicted", resp.GetStatus().GetMessage())
		require.Len(t, tpm.evicted, 1)
		assert.Equal(t, evictEKHandle, tpm.evicted[0].TPMAttributes.Handle)
	})
}
