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

//go:build integration

package tpm

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// attrsPCR is the debug PCR the extend checks measure into.
const attrsPCR = 16

// TestTPMAttrMultiProtocol drives the capability, platform-attribute,
// PCR-extend and credential surface over every network transport and checks
// each one against the gRPC reference reading of the same TPM.
func TestTPMAttrMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	reference := NewGRPCAdapter()
	require.NoError(t, reference.Setup(ctx), "the gRPC reference adapter must connect")
	defer func() {
		if err := reference.Teardown(); err != nil {
			t.Logf("Warning: teardown error for the reference adapter: %v", err)
		}
	}()
	// The daemon provisioned its TPM at start and owns it with the SO PIN
	// (docs/tpm/engineering.md). A Provision here would present the empty owner
	// auth to that owned hierarchy and be refused with TPM_RC_BAD_AUTH.

	adapters := []TPMAttrCommands{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "tpm-attrs", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testTPMAttrs(t, ctx, reference, adapter)
		})
	}
}

func testTPMAttrs(t *testing.T, ctx context.Context, reference *GRPCAdapter, cmd TPMAttrCommands) {
	t.Run("Capabilities", func(t *testing.T) {
		want, err := reference.Capabilities(ctx)
		require.NoError(t, err)

		got, err := cmd.Capabilities(ctx)

		require.NoError(t, err)
		assert.NotEmpty(t, got.Algorithms, "a TPM implements at least one algorithm")
		assert.NotEmpty(t, got.Commands, "a TPM implements at least one command")
		assert.Equal(t, want, got, "every transport reads the same capability lists")
	})

	t.Run("PlatformAttributes", func(t *testing.T) {
		want, err := reference.PlatformAttributes(ctx)
		require.NoError(t, err)

		got, err := cmd.PlatformAttributes(ctx)

		require.NoError(t, err)
		assert.NotEmpty(t, got.Manufacturer, "the TPM reports its manufacturer")
		require.NotNil(t, got.EK, "the provisioned EK is described")
		require.NotNil(t, got.SRK, "the provisioned SRK is described")
		assert.Equal(t, want, got, "every transport describes the same TPM")
	})

	t.Run("ExtendPCRChangesTheValue", func(t *testing.T) {
		before, err := reference.PCRValue(ctx, attrsPCR)
		require.NoError(t, err)

		err = cmd.ExtendPCR(ctx, attrsPCR, "sha256", []byte("attrs-"+cmd.Name()))

		require.NoError(t, err)
		after, err := reference.PCRValue(ctx, attrsPCR)
		require.NoError(t, err)
		assert.NotEqual(t, before, after, "the extend must change PCR %d", attrsPCR)
	})

	t.Run("ExtendPCRRefusesAnIndexPast23", func(t *testing.T) {
		err := cmd.ExtendPCR(ctx, 24, "sha256", []byte("out-of-range"))

		assert.Error(t, err, "PCR 24 does not exist")
	})

	t.Run("ExtendPCRRefusesEmptyData", func(t *testing.T) {
		before, err := reference.PCRValue(ctx, attrsPCR)
		require.NoError(t, err)

		err = cmd.ExtendPCR(ctx, attrsPCR, "sha256", nil)

		assert.Error(t, err, "an extend needs data")
		after, err := reference.PCRValue(ctx, attrsPCR)
		require.NoError(t, err)
		assert.Equal(t, before, after, "a refused extend must leave the PCR alone")
	})

	t.Run("MakeCredentialWrapsTheSecret", func(t *testing.T) {
		secret := sha256.Sum256([]byte("credential-secret-" + cmd.Name()))

		challenge, err := cmd.MakeCredential(ctx, foreignAKName("make-"+cmd.Name()), secret[:])

		require.NoError(t, err)
		assert.NotEmpty(t, challenge.CredentialBlob)
		assert.NotEmpty(t, challenge.EncryptedSecret)
		assert.Equal(t, secret[:], challenge.Secret, "the challenge carries the caller's secret")
		assert.NotContains(t, string(challenge.CredentialBlob), string(secret[:]),
			"the blob must not carry the secret in the clear")
	})

	t.Run("ActivateCredentialRefusesAMissingBlob", func(t *testing.T) {
		_, err := cmd.ActivateCredential(ctx, nil, []byte("encrypted-secret"))

		assert.Error(t, err, "an activation needs a credential blob")
	})

	t.Run("ActivateCredentialRefusesAForeignCredential", func(t *testing.T) {
		secret := sha256.Sum256([]byte("foreign-secret-" + cmd.Name()))
		challenge, err := cmd.MakeCredential(ctx, foreignAKName("foreign-"+cmd.Name()), secret[:])
		require.NoError(t, err)

		recovered, err := cmd.ActivateCredential(ctx, challenge.CredentialBlob, challenge.EncryptedSecret)

		assert.Error(t, err, "a credential made for another key's name must not activate")
		assert.NotEqual(t, secret[:], recovered, "the secret must not be released")
	})
}

// foreignAKName is a well-formed sha256 TPM name (TPM_ALG_SHA256 then the
// digest) of no key the TPM holds.
func foreignAKName(label string) []byte {
	digest := sha256.Sum256([]byte(label))
	return append([]byte{0x00, 0x0B}, digest[:]...)
}
