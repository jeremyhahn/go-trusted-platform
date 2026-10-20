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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// handlesTPM is a TrustedPlatformModule whose config carries the SRK
// handles under test. Only the methods the Info and GetSRK paths call are
// implemented; the embedded nil interface panics on anything else.
type handlesTPM struct {
	xkmssdk.TrustedPlatformModule
	cfg  *xkmssdk.TPMConfig
	psrk *xkmssdk.KeyAttributes
}

func (h *handlesTPM) Info() (string, error)                              { return "handles-tpm", nil }
func (h *handlesTPM) Config() *xkmssdk.TPMConfig                         { return h.cfg }
func (h *handlesTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) { return nil, nil }
func (h *handlesTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return h.psrk, nil
}

// ReadPCRs refuses, so Info must still answer without PCR banks.
func (h *handlesTPM) ReadPCRs(_ []uint) ([]xkmssdk.PCRBank, error) {
	return nil, errors.New("PCR read refused")
}

func tpmWithHandles(platform, ssrk uint32) *handlesTPM {
	return &handlesTPM{
		cfg: &xkmssdk.TPMConfig{
			PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: platform},
			SSRK:        &xkmssdk.SRKConfig{Handle: ssrk},
		},
		psrk: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{Handle: xkmssdk.TPMHandle(platform)},
		},
	}
}

func TestTPMGRPCService_Info_PublishesConfiguredSRKHandles(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(tpmWithHandles(0x81000005, 0x81000007))

	resp, err := svc.Info(context.Background(), &platformv1.TPMInfoRequest{})
	require.NoError(t, err)

	assert.Equal(t, "0x81000005", resp.Properties["platform_srk_handle"])
	assert.Equal(t, "0x81000007", resp.Properties["ssrk_handle"])
	assert.Equal(t, "handles-tpm", resp.Properties["info"], "the text report must survive")
	assert.Empty(t, resp.PcrBanks, "a refused PCR read leaves the banks empty and fails nothing")
}

func TestTPMGRPCService_Info_PublishesDefaultSRKHandlesWithoutConfig(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(&infoOnlyTPM{info: "mock-tpm-info"})

	resp, err := svc.Info(context.Background(), &platformv1.TPMInfoRequest{})
	require.NoError(t, err)

	assert.Equal(t, "0x81000002", resp.Properties["platform_srk_handle"])
	assert.Equal(t, "0x81000001", resp.Properties["ssrk_handle"])
}

func TestTPMGRPCService_GetSRK_AcceptsConfiguredPlatformHandle(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(tpmWithHandles(0x81000005, 0x81000007))

	resp, err := svc.GetSRK(context.Background(), &platformv1.GetSRKRequest{Handle: 0x81000005})
	require.NoError(t, err)
	assert.Equal(t, uint32(0x81000005), resp.Handle)
}

func TestTPMGRPCService_GetSRK_RejectsUnconfiguredHandle(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(tpmWithHandles(0x81000005, 0x81000007))

	_, err := svc.GetSRK(context.Background(), &platformv1.GetSRKRequest{Handle: 0x81000006})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMCPServiceProvider_TPMInfo_PublishesConfiguredSRKHandles(t *testing.T) {
	p := &MCPServiceProvider{tpm2Service: tpmWithHandles(0x81000005, 0x81000007)}

	got, err := p.TPMInfo(context.Background())
	require.NoError(t, err)

	result, ok := got.(map[string]interface{})
	require.True(t, ok, "TPMInfo returns a map, got %T", got)
	assert.Equal(t, "0x81000005", result["platform_srk_handle"])
	assert.Equal(t, "0x81000007", result["ssrk_handle"])
	assert.Equal(t, "handles-tpm", result["info"])
	assert.Equal(t, "2.0", result["version"])
	assert.Empty(t, result["pcr_banks"], "a refused PCR read leaves the banks empty and fails nothing")
}

func TestMCPServiceProvider_TPMInfo_ReportsActivePCRBanks(t *testing.T) {
	p := &MCPServiceProvider{tpm2Service: &infoOnlyTPM{info: "mock-tpm-info"}}

	got, err := p.TPMInfo(context.Background())
	require.NoError(t, err)

	result, ok := got.(map[string]interface{})
	require.True(t, ok, "TPMInfo returns a map, got %T", got)
	assert.Equal(t, []string{"sha1", "sha256"}, result["pcr_banks"])
	assert.Equal(t, "2.0", result["version"])
}

func TestMCPServiceProvider_TPMInfo_UnavailableWithoutService(t *testing.T) {
	p := &MCPServiceProvider{}

	got, err := p.TPMInfo(context.Background())

	require.Error(t, err)
	assert.Nil(t, got)
}
