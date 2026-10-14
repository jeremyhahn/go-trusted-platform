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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmsrk"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// iakTPM is a TrustedPlatformModule holding an IAK (or not) and a random
// source. Only the methods the GetAK / Random paths call are implemented.
type iakTPM struct {
	xkmssdk.TrustedPlatformModule
	attrs *xkmssdk.KeyAttributes
	pub   crypto.PublicKey
}

func (t *iakTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) { return t.attrs, nil }
func (t *iakTPM) IAK() (crypto.PublicKey, error)                 { return t.pub, nil }
func (t *iakTPM) RandomBytes(n int) ([]byte, error)              { return make([]byte, n), nil }

func newIAKTPM(t *testing.T, withIAK bool) *iakTPM {
	t.Helper()
	tpm := &iakTPM{attrs: &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:         xkmssdk.TPMHandle(0x81010002),
			PublicKeyBytes: []byte("iak-public"),
		},
	}}
	if withIAK {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tpm.pub = key.Public()
	}
	return tpm
}

// TestTPMParity_SRK: the MCP tool and gRPC GetSRK give the same key for a
// known handle and NotFound for an unknown one. MCP used to return the raw
// tpmsrk error, which the MCP server classed as InternalError.
func TestTPMParity_SRK(t *testing.T) {
	ctx := context.Background()
	tpm := &handlesTPM{psrk: &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:         xkmssdk.TPMHandle(tpmsrk.PlatformSRKHandle),
			PublicKeyBytes: []byte("srk-public"),
		},
	}}
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	t.Run("known handle", func(t *testing.T) {
		resp, err := grpcSvc.GetSRK(ctx, &platformv1.GetSRKRequest{Handle: tpmsrk.PlatformSRKHandle})
		require.NoError(t, err)
		got, err := mcp.TPMGetSRK(ctx, tpmsrk.PlatformSRKHandle)
		require.NoError(t, err)

		answer := got.(map[string]interface{})
		assert.Equal(t, resp.GetHandle(), answer["handle"])
		assert.Equal(t, base64.StdEncoding.EncodeToString(resp.GetPublicKey()), answer["public_key"])
	})

	t.Run("unknown handle", func(t *testing.T) {
		_, grpcErr := grpcSvc.GetSRK(ctx, &platformv1.GetSRKRequest{Handle: 0x81000999})
		_, mcpErr := mcp.TPMGetSRK(ctx, 0x81000999)
		assert.Equal(t, codes.NotFound, status.Code(grpcErr))
		assert.Equal(t, codes.NotFound, status.Code(mcpErr))
	})
}

// TestTPMParity_IAK: the same IAK on both transports, and NotFound on both
// when the TPM has none. MCP used to answer success with a nil key.
func TestTPMParity_IAK(t *testing.T) {
	ctx := context.Background()

	t.Run("present", func(t *testing.T) {
		tpm := newIAKTPM(t, true)
		resp, err := newTPMGRPCServiceWith(tpm).GetAK(ctx, &platformv1.GetAKRequest{})
		require.NoError(t, err)
		got, err := newMCPProviderWithTPM(tpm).TPMGetIAK(ctx)
		require.NoError(t, err)

		answer := got.(map[string]interface{})
		assert.Equal(t, resp.GetHandle(), answer["handle"])
		assert.Equal(t, base64.StdEncoding.EncodeToString(resp.GetPublicKey()), answer["public_key"])
	})

	t.Run("absent", func(t *testing.T) {
		tpm := newIAKTPM(t, false)
		_, grpcErr := newTPMGRPCServiceWith(tpm).GetAK(ctx, &platformv1.GetAKRequest{})
		_, mcpErr := newMCPProviderWithTPM(tpm).TPMGetIAK(ctx)
		assert.Equal(t, codes.NotFound, status.Code(grpcErr))
		assert.Equal(t, codes.NotFound, status.Code(mcpErr))
	})
}

// TestTPMParity_Random: the same byte count on both transports, and
// InvalidArgument on both for a request over the 1024-byte limit. MCP's
// ErrTPMInvalidSize carried no class and surfaced as InternalError.
func TestTPMParity_Random(t *testing.T) {
	ctx := context.Background()
	tpm := newIAKTPM(t, false)
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	resp, err := grpcSvc.GetRandom(ctx, &platformv1.GetRandomRequest{NumBytes: 48})
	require.NoError(t, err)
	got, err := mcp.TPMRandom(ctx, 48)
	require.NoError(t, err)
	assert.Len(t, got, len(resp.GetRandomBytes()))

	_, grpcErr := grpcSvc.GetRandom(ctx, &platformv1.GetRandomRequest{NumBytes: 2000})
	_, mcpErr := mcp.TPMRandom(ctx, 2000)
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))
}

// sealFakeError is an error the in-memory sealing TPM returns.
type sealFakeError string

func (e sealFakeError) Error() string { return string(e) }

const (
	errFakeBackendMismatch = sealFakeError("sealed data backend mismatch")
	errFakeSealedKeyAbsent = sealFakeError("sealed key not found")
)

// sealStoreTPM seals in memory, keyed by CN, and refuses SealedData that does
// not name the TPM2 backend, as the SDK's TPM2 Unseal does.
type sealStoreTPM struct {
	xkmssdk.TrustedPlatformModule
	blobs      map[string][]byte
	lastPolicy *xkmssdk.TPMSealPolicy
}

func newSealStoreTPM() *sealStoreTPM {
	return &sealStoreTPM{blobs: map[string][]byte{}}
}

func (t *sealStoreTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{CN: "ssrk"}, nil
}

func (t *sealStoreTPM) Seal(_ context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	cn := opts.KeyAttributes.CN
	t.blobs[cn] = append([]byte(nil), data...)
	t.lastPolicy = opts.TPMPolicy
	return &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		KeyID:      cn,
		TPMPublic:  []byte("public:" + cn),
		TPMPrivate: []byte("private:" + cn),
	}, nil
}

func (t *sealStoreTPM) Unseal(_ context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	if sealed.Backend != xkmssdk.BackendTypeTPM2 {
		return nil, errFakeBackendMismatch
	}
	data, ok := t.blobs[opts.KeyAttributes.CN]
	if !ok {
		return nil, errFakeSealedKeyAbsent
	}
	return data, nil
}

// TestTPMParity_Seal: MCP seal returns the payload gRPC Seal returns and binds
// the PCRs it is given. It used to answer success with empty sealed_data and
// drop the PCR policy.
func TestTPMParity_Seal(t *testing.T) {
	ctx := context.Background()
	tpm := newSealStoreTPM()
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	resp, err := grpcSvc.Seal(ctx, &platformv1.SealRequest{Data: []byte("secret"), PcrIndices: []uint32{0, 7}, Cn: "app-key"})
	require.NoError(t, err)

	tpm.lastPolicy = nil
	got, err := mcp.TPMSeal(ctx, []byte("secret"), []uint32{0, 7}, "app-key", "")
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	assert.Equal(t, resp.GetSealedData(), got)
	assert.NotNil(t, tpm.lastPolicy, "MCP seal dropped the PCR policy")

	_, grpcErr := grpcSvc.Seal(ctx, &platformv1.SealRequest{})
	_, mcpErr := mcp.TPMSeal(ctx, nil, nil, "", "")
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))
}

// TestTPMParity_Unseal: MCP unseal returns what was sealed, as gRPC Unseal
// does, and fails with the same class for an absent or empty CN. It used to
// send SealedData with no backend, which the SDK refuses, so it never
// unsealed anything.
func TestTPMParity_Unseal(t *testing.T) {
	ctx := context.Background()
	tpm := newSealStoreTPM()
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	_, err := mcp.TPMSeal(ctx, []byte("secret"), nil, "app-key", "")
	require.NoError(t, err)

	resp, err := grpcSvc.Unseal(ctx, &platformv1.UnsealRequest{Cn: "app-key"})
	require.NoError(t, err)
	got, err := mcp.TPMUnseal(ctx, "app-key", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), got)
	assert.Equal(t, resp.GetData(), got)

	_, grpcErr := grpcSvc.Unseal(ctx, &platformv1.UnsealRequest{Cn: "absent"})
	_, mcpErr := mcp.TPMUnseal(ctx, "absent", "")
	assert.Equal(t, codes.NotFound, status.Code(grpcErr))
	assert.Equal(t, codes.NotFound, status.Code(mcpErr))

	_, grpcErr = grpcSvc.Unseal(ctx, &platformv1.UnsealRequest{})
	_, mcpErr = mcp.TPMUnseal(ctx, "", "")
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))
}
