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

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealOnlyTPM supports the two calls the Seal handler makes.
type sealOnlyTPM struct {
	xkmssdk.TrustedPlatformModule
	sealed  *xkmssdk.SealedData
	sealErr error
	gotOpts *xkmssdk.SealOptions
}

func (t *sealOnlyTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{CN: "ssrk"}, nil
}

func (t *sealOnlyTPM) Seal(_ context.Context, _ []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	t.gotOpts = opts
	return t.sealed, t.sealErr
}

// TestTPMGRPCService_Seal_ReportsSuccessStatus pins the contract the SDK
// and `platformctl tpm seal` judge the call by: a successful seal carries
// Status.Success. Without it the CLI reported "unknown error" after every
// seal the daemon had in fact completed (found by the aarch64 userspace
// suite, 2026-09-21).
func TestTPMGRPCService_Seal_ReportsSuccessStatus(t *testing.T) {
	svc := NewTPMGRPCService(logging.DefaultLogger())
	tpm := &sealOnlyTPM{sealed: &xkmssdk.SealedData{KeyID: "userspace-suite", TPMPublic: []byte{1, 2}, TPMPrivate: []byte{3}}}
	svc.SetTPM2Service(tpm)

	resp, err := svc.Seal(context.Background(), &platformv1.SealRequest{Cn: "userspace-suite", Data: []byte("secret"), Password: "auth"})

	require.NoError(t, err)
	require.NotNil(t, resp.GetStatus(), "the SDK's SealResponse is built from Status")
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Contains(t, resp.GetStatus().GetMessage(), "userspace-suite")
	assert.Equal(t, encodeSealedData(tpm.sealed), resp.GetSealedData())
	require.NotNil(t, tpm.gotOpts)
	assert.Equal(t, "userspace-suite", tpm.gotOpts.KeyAttributes.CN)
	assert.Equal(t, "ssrk", tpm.gotOpts.KeyAttributes.Parent.CN, "operator seals parent on the Storage SRK")
	assert.NotNil(t, tpm.gotOpts.KeyAttributes.Password, "the request password becomes the object's auth")
}

func TestTPMGRPCService_Seal_BackendErrorHasNoStatus(t *testing.T) {
	svc := NewTPMGRPCService(logging.DefaultLogger())
	svc.SetTPM2Service(&sealOnlyTPM{sealErr: errors.New("tpm: sealing failed")})

	resp, err := svc.Seal(context.Background(), &platformv1.SealRequest{Cn: "x", Data: []byte("secret")})

	require.Error(t, err)
	assert.Nil(t, resp)
}
