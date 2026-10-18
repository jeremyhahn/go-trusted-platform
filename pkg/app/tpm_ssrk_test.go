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

package app

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// harnessSSRKHandle is tpm.ssrk.handle in test/integration/config.yaml.
const harnessSSRKHandle = tpm2.TPMHandle(0x81000001)

// ssrkName reads the object Name the TPM holds at the SSRK handle.
func ssrkName(t *testing.T, tpm transport.TPM) []byte {
	t.Helper()
	pub, err := tpm2.ReadPublic{ObjectHandle: harnessSSRKHandle}.Execute(tpm)
	require.NoError(t, err, "the SSRK is persisted at its configured handle")
	return pub.Name.Buffer
}

// The integration daemon's TPM holds its EK from swtpm_setup, so InitTPM
// never runs a full Provision. Its first start must still leave the SSRK
// every seal, SRK info and vTPM call reads.
func TestEnsureSSRK_FreshTPMCreatesSSRK(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	_, err := tpm2.ReadPublic{ObjectHandle: harnessSSRKHandle}.Execute(sim)
	require.ErrorIs(t, err, tpm2.TPMRCHandle, "the harness TPM starts without an SSRK")

	a, err := harnessStart(t, sim, t.TempDir(), harnessSOPIN)
	require.NoError(t, err)

	ssrkName(t, sim)
	attrs, err := a.TPM.SSRKAttributes()
	require.NoError(t, err)
	require.Equal(t, harnessSSRKHandle, attrs.TPMAttributes.Handle)
	require.True(t, hierarchyAuthState(t, sim).ownerAuthSet, "ownership is still taken after the SSRK exists")
	require.NoError(t, ownerAuthorizes(t, sim, harnessSOPIN))
}

// A restart on a provisioned TPM keeps the SSRK it created: same Name, no
// second persist.
func TestEnsureSSRK_ProvisionedTPMKeepsSSRK(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	dir := t.TempDir()
	_, err := harnessStart(t, sim, dir, harnessSOPIN)
	require.NoError(t, err)
	before := ssrkName(t, sim)

	counting := newCountingTPM(sim)
	a, err := harnessStart(t, counting, dir, harnessSOPIN)
	require.NoError(t, err)
	require.Zero(t, counting.counts[tpm2.TPMCCEvictControl], "nothing is persisted on a restart")
	require.Equal(t, before, ssrkName(t, sim))
	_, err = a.TPM.SSRKAttributes()
	require.NoError(t, err)
}

// An SSRK that cannot be created stops the start with SSRKCreateError, and
// ownership is not taken.
func TestEnsureSSRK_CreateFault(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	counting := newCountingTPM(sim)
	counting.failCC = tpm2.TPMCCCreatePrimary

	_, err := harnessStart(t, counting, t.TempDir(), harnessSOPIN)
	var createErr *SSRKCreateError
	require.ErrorAs(t, err, &createErr)
	require.Equal(t, uint32(harnessSSRKHandle), createErr.Handle)
	require.ErrorIs(t, err, errInjectedTPMFault)
	require.False(t, hierarchyAuthState(t, sim).ownerAuthSet)
}

// A read failure other than an empty handle is reported, not taken for a
// missing SSRK.
func TestEnsureSSRK_ProbeFault(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	counting := newCountingTPM(sim)
	a, err := harnessStart(t, counting, t.TempDir(), harnessSOPIN)
	require.NoError(t, err)
	before := ssrkName(t, sim)

	counting.failCC = tpm2.TPMCCReadPublic
	err = a.ensureSSRK()
	var probeErr *SSRKProbeError
	require.ErrorAs(t, err, &probeErr)
	require.ErrorIs(t, err, errInjectedTPMFault)
	counting.failCC = 0
	require.Equal(t, before, ssrkName(t, sim))
}

func TestEnsureSSRK_NoSSRKConfigured(t *testing.T) {
	a := &App{}
	require.NoError(t, a.ensureSSRK(), "no tpm.ssrk means nothing to create")
	a.TPMConfig.SSRK = &xkmssdk.SRKConfig{}
	require.NoError(t, a.ensureSSRK(), "a zero handle means nothing to create")
}

func TestSSRKKeyAttributes(t *testing.T) {
	rsa, err := ssrkKeyAttributes(&xkmssdk.SRKConfig{
		Handle:        uint32(harnessSSRKHandle),
		RSAConfig:     &xkmssdk.RSAConfig{KeySize: 2048},
		HierarchyAuth: harnessSOPIN,
	})
	require.NoError(t, err)
	require.Equal(t, x509.RSA, rsa.KeyAlgorithm)
	require.Equal(t, "shared-srk", rsa.CN)
	require.Equal(t, tpm2.TPMAlgRSA, rsa.TPMAttributes.Template.Type)
	require.Equal(t, harnessSSRKHandle, rsa.TPMAttributes.Handle)
	require.Equal(t, tpm2.TPMHTPersistent, rsa.TPMAttributes.HandleType)
	require.Equal(t, tpm2.TPMHandle(tpm2.TPMRHOwner), rsa.TPMAttributes.Hierarchy)
	require.Equal(t, harnessSOPIN, string(rsa.TPMAttributes.HierarchyAuth.Bytes()))
	require.Nil(t, rsa.Password, "an empty password stays nil")
	require.Empty(t, rsa.TPMAttributes.Template.AuthPolicy.Buffer, "the SSRK carries no platform policy")

	ecc, err := ssrkKeyAttributes(&xkmssdk.SRKConfig{
		CN:        "ssrk",
		Handle:    uint32(harnessSSRKHandle),
		ECCConfig: &xkmssdk.ECCConfig{Curve: "P-256"},
		Password:  "srk-pin",
	})
	require.NoError(t, err)
	require.Equal(t, x509.ECDSA, ecc.KeyAlgorithm)
	require.Equal(t, "ssrk", ecc.CN)
	require.Equal(t, tpm2.TPMAlgECC, ecc.TPMAttributes.Template.Type)
	require.Equal(t, "srk-pin", string(ecc.Password.Bytes()))
	require.Nil(t, ecc.TPMAttributes.HierarchyAuth, "an empty hierarchy auth stays nil")
}

func TestSSRKKeyAttributes_BadAlgorithm(t *testing.T) {
	_, err := ssrkKeyAttributes(&xkmssdk.SRKConfig{KeyAlgorithm: "not-an-algorithm"})
	require.Error(t, err)

	_, err = ssrkKeyAttributes(&xkmssdk.SRKConfig{KeyAlgorithm: "Ed25519"})
	var algErr *SSRKAlgorithmError
	require.ErrorAs(t, err, &algErr)
	require.Equal(t, "Ed25519", algErr.Algorithm)
}
