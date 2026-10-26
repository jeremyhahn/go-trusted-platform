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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// simulatedPCR is the PCR the simulator tests extend; the platform PCR of
// the simulated TPM's config.
const simulatedPCR = 16

// newSimulatedTPM provisions the EK, SSRK and IAK on an in-memory TPM 2.0
// simulator, so the TPM service methods run against real TPM commands.
func newSimulatedTPM(t *testing.T) xkmssdk.TrustedPlatformModule {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })

	rsa2048 := func() *xkmssdk.RSAConfig { return &xkmssdk.RSAConfig{KeySize: 2048} }
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Config: &xkmssdk.TPMConfig{
			Hash: "SHA-256",
			EK: &xkmssdk.EKConfig{
				CertHandle:    0x01C00002,
				Handle:        0x81010001,
				HierarchyAuth: xkmssdk.DEFAULT_PASSWORD,
				RSAConfig:     rsa2048(),
			},
			IAK: &xkmssdk.IAKConfig{
				CN:                 "simulated-iak",
				Hash:               crypto.SHA256.String(),
				Handle:             0x81010002,
				KeyAlgorithm:       x509.RSA.String(),
				RSAConfig:          rsa2048(),
				SignatureAlgorithm: x509.SHA256WithRSA.String(),
			},
			PlatformPCR:     simulatedPCR,
			PlatformPCRBank: "sha256",
			SSRK: &xkmssdk.SRKConfig{
				Handle:        0x81000001,
				HierarchyAuth: xkmssdk.DEFAULT_PASSWORD,
				KeyAlgorithm:  x509.RSA.String(),
				RSAConfig:     rsa2048(),
			},
		},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Transport: transport.FromReadWriter(sim),
	})
	if err == xkmssdk.ErrTPMNotInitialized {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, tpm.Close()) })
	return tpm
}

// simulatedPCRValue reads the SHA-256 bank of simulatedPCR through GetPCRs.
func simulatedPCRValue(t *testing.T, svc *TPMGRPCService) []byte {
	t.Helper()
	resp, err := svc.GetPCRs(context.Background(), &platformv1.GetPCRsRequest{
		Indices: []uint32{simulatedPCR},
		Bank:    platformv1.PCRBank_PCR_BANK_SHA256,
	})
	require.NoError(t, err)
	for _, value := range resp.GetPcrValues() {
		if value.GetIndex() == simulatedPCR {
			return value.GetValue()
		}
	}
	require.FailNow(t, "GetPCRs did not return the PCR", "PCR %d", simulatedPCR)
	return nil
}

// simulatedAKName is the TPM2B name of a key this TPM does not hold: a
// SHA-256 name algorithm followed by the digest of label.
func simulatedAKName(label string) []byte {
	digest := sha256.Sum256([]byte(label))
	return append([]byte{0x00, 0x0B}, digest[:]...)
}

// TestTPMSimulator_Attrs: the capability, platform-attribute, PCR-extend and
// credential methods of the gRPC service (behind gRPC, Unix, daemon REST and
// embedded) and of the MCP provider read and drive a real TPM the same way.
func TestTPMSimulator_Attrs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	svc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)
	ctx := context.Background()

	t.Run("Capabilities", func(t *testing.T) {
		got, err := svc.GetCapabilities(ctx, &platformv1.TPMCapabilitiesRequest{})
		require.NoError(t, err)
		mcpGot, err := mcp.TPMCapabilities(ctx)
		require.NoError(t, err)

		assert.NotEmpty(t, got.GetAlgorithms(), "a TPM implements at least one algorithm")
		assert.NotEmpty(t, got.GetCommands(), "a TPM implements at least one command")
		assert.Equal(t, map[string]interface{}{
			"algorithms": got.GetAlgorithms(),
			"commands":   got.GetCommands(),
			"ecc_curves": got.GetEccCurves(),
		}, mcpGot, "every transport reads the same capability lists")
	})

	t.Run("PlatformAttributes", func(t *testing.T) {
		got, err := svc.GetPlatformAttributes(ctx, &platformv1.TPMPlatformAttributesRequest{})
		require.NoError(t, err)
		mcpGot, err := mcp.TPMPlatform(ctx)
		require.NoError(t, err)

		assert.NotEmpty(t, got.GetManufacturer(), "the TPM reports its manufacturer")
		require.NotNil(t, got.GetEk(), "the provisioned EK is described")
		require.NotNil(t, got.GetSrk(), "the provisioned SRK is described")
		attrs, ok := mcpGot.(map[string]interface{})
		require.True(t, ok, "the MCP result is a map, got %T", mcpGot)
		assert.Equal(t, got.GetManufacturer(), attrs["manufacturer"], "every transport describes the same TPM")
		assert.Equal(t, got.GetEk().GetHandle(), attrs["ek_handle"])
		assert.Equal(t, got.GetSrk().GetHandle(), attrs["srk_handle"])
	})

	t.Run("ExtendPCRChangesTheValue", func(t *testing.T) {
		for name, extend := range map[string]func() error{
			"gRPC": func() error {
				_, err := svc.ExtendPCR(ctx, &platformv1.ExtendPCRRequest{Index: simulatedPCR, HashAlg: "sha256", Data: []byte("attrs-grpc")})
				return err
			},
			"MCP": func() error {
				_, err := mcp.TPMExtendPCR(ctx, simulatedPCR, "sha256", []byte("attrs-mcp"))
				return err
			},
		} {
			before := simulatedPCRValue(t, svc)
			require.NoError(t, extend(), name)
			assert.NotEqual(t, before, simulatedPCRValue(t, svc), "%s: the extend must change PCR %d", name, simulatedPCR)
		}
	})

	t.Run("ExtendPCRRefusesAnIndexPast23", func(t *testing.T) {
		_, err := svc.ExtendPCR(ctx, &platformv1.ExtendPCRRequest{Index: 24, HashAlg: "sha256", Data: []byte("out-of-range")})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "PCR 24 does not exist")
		_, err = mcp.TPMExtendPCR(ctx, 24, "sha256", []byte("out-of-range"))
		assert.Error(t, err, "PCR 24 does not exist")
	})

	t.Run("ExtendPCRRefusesEmptyData", func(t *testing.T) {
		before := simulatedPCRValue(t, svc)

		_, grpcErr := svc.ExtendPCR(ctx, &platformv1.ExtendPCRRequest{Index: simulatedPCR, HashAlg: "sha256"})
		_, mcpErr := mcp.TPMExtendPCR(ctx, simulatedPCR, "sha256", nil)

		assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "an extend needs data")
		assert.Error(t, mcpErr, "an extend needs data")
		assert.Equal(t, before, simulatedPCRValue(t, svc), "a refused extend must leave the PCR alone")
	})

	t.Run("MakeCredentialWrapsTheSecret", func(t *testing.T) {
		secret := sha256.Sum256([]byte("credential-secret"))

		got, err := svc.MakeCredential(ctx, &platformv1.MakeCredentialRequest{AkName: simulatedAKName("make"), Secret: secret[:]})
		require.NoError(t, err)
		mcpGot, err := mcp.TPMMakeCredential(ctx, simulatedAKName("make"), secret[:], nil, nil)
		require.NoError(t, err)

		assert.NotEmpty(t, got.GetCredentialBlob())
		assert.NotEmpty(t, got.GetEncryptedSecret())
		assert.Equal(t, secret[:], got.GetSecret(), "the challenge carries the caller's secret")
		assert.NotContains(t, string(got.GetCredentialBlob()), string(secret[:]),
			"the blob must not carry the secret in the clear")
		challenge, ok := mcpGot.(map[string]interface{})
		require.True(t, ok, "the MCP result is a map, got %T", mcpGot)
		assert.Equal(t, base64.StdEncoding.EncodeToString(secret[:]), challenge["secret"])
		assert.NotEmpty(t, challenge["credential_blob"])
		assert.NotEmpty(t, challenge["encrypted_secret"])
	})

	t.Run("ActivateCredentialRefusesAMissingBlob", func(t *testing.T) {
		_, err := svc.ActivateCredential(ctx, &platformv1.TPMActivateCredentialRequest{EncryptedSecret: []byte("encrypted-secret")})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "an activation needs a credential blob")
		_, err = mcp.TPMActivateCredential(ctx, nil, []byte("encrypted-secret"))
		assert.Error(t, err, "an activation needs a credential blob")
	})

	t.Run("ActivateCredentialRefusesAForeignCredential", func(t *testing.T) {
		secret := sha256.Sum256([]byte("foreign-secret"))
		challenge, err := svc.MakeCredential(ctx, &platformv1.MakeCredentialRequest{AkName: simulatedAKName("foreign"), Secret: secret[:]})
		require.NoError(t, err)

		recovered, err := svc.ActivateCredential(ctx, &platformv1.TPMActivateCredentialRequest{
			CredentialBlob:  challenge.GetCredentialBlob(),
			EncryptedSecret: challenge.GetEncryptedSecret(),
		})
		assert.Error(t, err, "a credential made for another key's name must not activate")
		assert.NotEqual(t, secret[:], recovered.GetSecret(), "the secret must not be released")

		mcpRecovered, err := mcp.TPMActivateCredential(ctx, challenge.GetCredentialBlob(), challenge.GetEncryptedSecret())
		assert.Error(t, err, "a credential made for another key's name must not activate over MCP")
		assert.Nil(t, mcpRecovered, "the secret must not be released over MCP")
	})
}
