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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmpcr"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var errCapabilityRefused = errors.New("TPM_RC_VALUE")

// attrsTPM answers the capability and platform-attribute reads that
// GetCapabilities, GetPlatformAttributes and their MCP twins make.
type attrsTPM struct {
	xkmssdk.TrustedPlatformModule
	cmdErr  error
	iakErr  error
	extends []tpmExtend
}

func (t *attrsTPM) SupportedAlgorithms() ([]string, error) { return []string{"RSA", "ECC"}, nil }
func (t *attrsTPM) SupportedCommands() ([]string, error) {
	return []string{"TPM2_Quote"}, t.cmdErr
}
func (t *attrsTPM) SupportedECCCurves() ([]string, error) { return []string{"NIST_P256"}, nil }
func (t *attrsTPM) Device() string                        { return "/dev/tpmrm0" }
func (t *attrsTPM) IsFIPS140_2() (bool, error)            { return true, nil }
func (t *attrsTPM) IsPlatformPCRExtended() (bool, error)  { return true, nil }
func (t *attrsTPM) CanSeal() bool                         { return true }
func (t *attrsTPM) Config() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{UseSimulator: true}
}
func (t *attrsTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return &xkmssdk.PropertiesFixed{Manufacturer: "IFX"}, nil
}
func (t *attrsTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return attrsKey(0x81010001, x509.RSA), nil
}
func (t *attrsTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return attrsKey(0x81000001, x509.RSA), nil
}
func (t *attrsTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	if t.iakErr != nil {
		return nil, t.iakErr
	}
	return attrsKey(0x81010002, x509.ECDSA), nil
}
func (t *attrsTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	t.extends = append(t.extends, tpmExtend{index: pcrIndex, hashAlg: hashAlg, data: data})
	return nil
}

func attrsKey(handle uint32, alg x509.PublicKeyAlgorithm) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:  alg,
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: xkmssdk.TPMHandle(handle)},
	}
}

// TestTPMAttrsParity_Capabilities: gRPC (and so Unix, embedded and daemon
// REST) and MCP return the same three lists.
func TestTPMAttrsParity_Capabilities(t *testing.T) {
	tpm := &attrsTPM{}

	grpcResp, err := newTPMGRPCServiceWith(tpm).GetCapabilities(context.Background(), &platformv1.TPMCapabilitiesRequest{})
	require.NoError(t, err)
	mcpResp, err := newMCPProviderWithTPM(tpm).TPMCapabilities(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"RSA", "ECC"}, grpcResp.GetAlgorithms())
	assert.Equal(t, []string{"TPM2_Quote"}, grpcResp.GetCommands())
	assert.Equal(t, []string{"NIST_P256"}, grpcResp.GetEccCurves())
	assert.Equal(t, map[string]interface{}{
		"algorithms": grpcResp.GetAlgorithms(),
		"commands":   grpcResp.GetCommands(),
		"ecc_curves": grpcResp.GetEccCurves(),
	}, mcpResp)
}

// TestTPMAttrsParity_CapabilitiesRefused: a list the TPM refuses fails the
// read as FailedPrecondition on both, naming the list.
func TestTPMAttrsParity_CapabilitiesRefused(t *testing.T) {
	tpm := &attrsTPM{cmdErr: errCapabilityRefused}

	_, grpcErr := newTPMGRPCServiceWith(tpm).GetCapabilities(context.Background(), &platformv1.TPMCapabilitiesRequest{})
	_, mcpErr := newMCPProviderWithTPM(tpm).TPMCapabilities(context.Background())

	for name, err := range map[string]error{"gRPC": grpcErr, "MCP": mcpErr} {
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
		assert.Contains(t, err.Error(), "commands", name)
	}
}

// TestTPMAttrsParity_Platform: gRPC and MCP describe the same device and
// keys, and an IAK that is not provisioned is absent on both.
func TestTPMAttrsParity_Platform(t *testing.T) {
	tpm := &attrsTPM{iakErr: errors.New("IAK not provisioned")}

	grpcResp, err := newTPMGRPCServiceWith(tpm).GetPlatformAttributes(context.Background(), &platformv1.TPMPlatformAttributesRequest{})
	require.NoError(t, err)
	mcpResp, err := newMCPProviderWithTPM(tpm).TPMPlatform(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "/dev/tpmrm0", grpcResp.GetDevice())
	assert.True(t, grpcResp.GetIsFips())
	assert.True(t, grpcResp.GetPcrExtended())
	assert.True(t, grpcResp.GetCanSeal())
	assert.True(t, grpcResp.GetIsSimulator())
	assert.Equal(t, "IFX", grpcResp.GetManufacturer())
	assert.Equal(t, uint32(0x81010001), grpcResp.GetEk().GetHandle())
	assert.Equal(t, "RSA", grpcResp.GetEk().GetAlgorithm())
	assert.Equal(t, uint32(0x81000001), grpcResp.GetSrk().GetHandle())
	assert.Nil(t, grpcResp.GetIak())

	assert.Equal(t, map[string]interface{}{
		"available":     true,
		"device":        grpcResp.GetDevice(),
		"is_fips":       grpcResp.GetIsFips(),
		"pcr_extended":  grpcResp.GetPcrExtended(),
		"can_seal":      grpcResp.GetCanSeal(),
		"is_simulator":  grpcResp.GetIsSimulator(),
		"manufacturer":  grpcResp.GetManufacturer(),
		"ek_handle":     grpcResp.GetEk().GetHandle(),
		"ek_algorithm":  grpcResp.GetEk().GetAlgorithm(),
		"srk_handle":    grpcResp.GetSrk().GetHandle(),
		"srk_algorithm": grpcResp.GetSrk().GetAlgorithm(),
	}, mcpResp)
}

// TestTPMParity_ExtendPCR: the gRPC method extends exactly what the MCP
// tool does, with the same default bank, and reports the same success.
func TestTPMParity_ExtendPCR(t *testing.T) {
	grpcTPM := &attrsTPM{}
	mcpTPM := &attrsTPM{}

	reply, err := newTPMGRPCServiceWith(grpcTPM).ExtendPCR(context.Background(),
		&platformv1.ExtendPCRRequest{Index: 16, Data: []byte("measurement")})
	require.NoError(t, err)
	mcpResult, err := newMCPProviderWithTPM(mcpTPM).TPMExtendPCR(context.Background(), 16, "", []byte("measurement"))
	require.NoError(t, err)

	require.NotNil(t, reply.GetStatus(), "a successful extend returns a status")
	assert.True(t, reply.GetStatus().GetSuccess())
	assert.Equal(t, "PCR 16 extended", reply.GetStatus().GetMessage())
	assert.Equal(t, map[string]interface{}{
		"success": reply.GetStatus().GetSuccess(),
		"message": reply.GetStatus().GetMessage(),
	}, mcpResult)

	want := []tpmExtend{{index: 16, hashAlg: tpmpcr.DefaultHashAlg, data: []byte("measurement")}}
	assert.Equal(t, want, grpcTPM.extends)
	assert.Equal(t, want, mcpTPM.extends)
}

func TestTPMGRPCService_ExtendPCR_ErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		tpm  xkmssdk.TrustedPlatformModule
		req  *platformv1.ExtendPCRRequest
		want codes.Code
	}{
		{"index past 23", &attrsTPM{}, &platformv1.ExtendPCRRequest{Index: 24, Data: []byte("x")}, codes.InvalidArgument},
		{"no data", &attrsTPM{}, &platformv1.ExtendPCRRequest{Index: 16}, codes.InvalidArgument},
		{"TPM failure", &nvPCRTPM{extendErr: errExtendFailed}, &platformv1.ExtendPCRRequest{Index: 16, Data: []byte("x")}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply, err := newTPMGRPCServiceWith(tt.tpm).ExtendPCR(context.Background(), tt.req)
			assert.Equal(t, tt.want, status.Code(err))
			assert.Nil(t, reply, "a refused extend returns no status")
		})
	}
}

// TestTPMGRPCService_AttrsWithoutTPM: every new method answers
// Unavailable, not a nil-TPM panic, before a TPM is wired.
func TestTPMGRPCService_AttrsWithoutTPM(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	ctx := context.Background()

	_, capsErr := svc.GetCapabilities(ctx, &platformv1.TPMCapabilitiesRequest{})
	_, platformErr := svc.GetPlatformAttributes(ctx, &platformv1.TPMPlatformAttributesRequest{})
	_, extendErr := svc.ExtendPCR(ctx, &platformv1.ExtendPCRRequest{Index: 16, Data: []byte("x")})

	for name, err := range map[string]error{"GetCapabilities": capsErr, "GetPlatformAttributes": platformErr, "ExtendPCR": extendErr} {
		assert.Equal(t, codes.Unavailable, status.Code(err), name)
	}
}
