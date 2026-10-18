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
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// go-xkms seals a PCR selection without a policy digest as a password-only
// object. The TPM and vTPM seal paths that bound PCRs before go-quicbaas
// v0.14 must refuse them instead (go-quicbaas #1171), and a seal without
// PCRs must keep working.

// Every CLI transport that serves `platformctl tpm seal` (gRPC, Unix, and
// REST through the webservice proxy) reaches TPMGRPCService.Seal.
func TestTPMGRPCService_Seal_RefusesPCRBoundSeal(t *testing.T) {
	svc := NewTPMGRPCService(logging.DefaultLogger())
	tpm := &sealOnlyTPM{sealed: &xkmssdk.SealedData{KeyID: "pcr-bound"}}
	svc.SetTPM2Service(tpm)

	resp, err := svc.Seal(context.Background(), &platformv1.SealRequest{
		Cn:         "pcr-bound",
		Data:       []byte("secret"),
		Password:   "auth",
		PcrIndices: []uint32{0, 7},
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "go-quicbaas #1171", "the refusal names the missing upstream capability")
	assert.Nil(t, tpm.gotOpts, "a refused PCR-bound seal must never reach the TPM")
}

func TestTPMGRPCService_Seal_PasswordOnlySealCarriesNoPCRSelection(t *testing.T) {
	svc := NewTPMGRPCService(logging.DefaultLogger())
	tpm := &sealOnlyTPM{sealed: &xkmssdk.SealedData{KeyID: "password-only"}}
	svc.SetTPM2Service(tpm)

	_, err := svc.Seal(context.Background(), &platformv1.SealRequest{Cn: "password-only", Data: []byte("secret"), Password: "auth"})

	require.NoError(t, err)
	require.NotNil(t, tpm.gotOpts)
	assert.Nil(t, tpm.gotOpts.KeyAttributes.TPMAttributes, "no PCR selection")
	assert.NotNil(t, tpm.gotOpts.KeyAttributes.Password)
}

// pcrRefusingSeal mirrors vtpm.Service.Seal: a PCR-bound seal is refused.
func pcrRefusingSeal(_ context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	if opts != nil && len(opts.PCRs) > 0 {
		return nil, vtpm.ErrTPMSealFailed{BundleID: bundleID, Cause: common.ErrPCRBoundSealUnavailable{}}
	}
	return append([]byte("sealed-"), data...), nil
}

func TestVTPMServiceServer_SealVTPM_RefusesPCRBoundSeal(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{sealFunc: pcrRefusingSeal}, vtpmTestLogger())

	resp, err := server.SealVTPM(context.Background(), &platformv1.SealVTPMRequest{
		BundleId:  "vm1",
		Data:      []byte("secret"),
		Pcrs:      []int32{7},
		AuthValue: "auth",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "go-quicbaas #1171")
}

func TestVTPMServiceServer_SealVTPM_PasswordOnlySeal(t *testing.T) {
	var got *vtpm.SealOptions
	mock := &mockVTPMService{sealFunc: func(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
		got = opts
		return pcrRefusingSeal(ctx, bundleID, data, opts)
	}}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	resp, err := server.SealVTPM(context.Background(), &platformv1.SealVTPMRequest{BundleId: "vm1", Data: []byte("secret"), AuthValue: "auth"})

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, []byte("sealed-secret"), resp.GetSealedData())
	require.NotNil(t, got)
	assert.Empty(t, got.PCRs)
	assert.Equal(t, "auth", got.AuthValue)
}

func TestMCPServiceProvider_VTPMSeal_PropagatesPCRBoundRefusal(t *testing.T) {
	mock := &mockVTPMService{
		getBundleFunc: func(context.Context, string) (*vtpm.Bundle, error) { return &vtpm.Bundle{ID: "vm1"}, nil },
		sealFunc:      pcrRefusingSeal,
	}
	p := newMCPProviderWithVTPM(mock)

	_, err := p.VTPMSeal(context.Background(), "vm1", []byte("secret"), []int{7}, "")
	assert.True(t, errors.As(err, &common.ErrPCRBoundSealUnavailable{}), "got %v", err)

	sealed, err := p.VTPMSeal(context.Background(), "vm1", []byte("secret"), nil, "")
	require.NoError(t, err)
	assert.Equal(t, []byte("sealed-secret"), sealed)
}
