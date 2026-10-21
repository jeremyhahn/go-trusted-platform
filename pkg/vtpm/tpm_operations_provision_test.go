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

package vtpm

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A bundle's first Start finds a vTPM with no persistent EK. ProvisionIfNew
// provisions it, so Quote works; without it Quote fails "tpm: not initialized".
func TestTPMOperations_ProvisionIfNew_ProvisionsAFreshTPM(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	ops, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.False(t, ops.provisioned, "a fresh vTPM opens unprovisioned")

	require.NoError(t, ops.ProvisionIfNew())

	quote, err := ops.Quote([]byte("0123456789abcdef"), []int{0, 7})
	require.NoError(t, err)
	assert.NotEmpty(t, quote.Signature)
}

// A restart opens the vTPM with its persistent EK: ProvisionIfNew leaves it as
// it is, so the EK the first Start created survives.
func TestTPMOperations_ProvisionIfNew_KeepsAProvisionedTPM(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	first, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.NoError(t, first.ProvisionIfNew())
	firstEK, err := first.GetEKPublicKey()
	require.NoError(t, err)

	restarted, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.True(t, restarted.provisioned, "a vTPM with a persistent EK opens provisioned")
	require.NoError(t, restarted.ProvisionIfNew())

	restartedEK, err := restarted.GetEKPublicKey()
	require.NoError(t, err)
	assert.Equal(t, firstEK, restartedEK, "a restart must not re-provision the EK")
}

// A bundle created with EK-certificate injection is provisioned at create, so
// its Start opens a vTPM that already holds the IAK. ProvisionIfNew loads that
// IAK, so Quote signs with it; without it Quote fails "tpm: not initialized".
func TestTPMOperations_ProvisionIfNew_LoadsTheIAKOfAProvisionedTPM(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	created, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.NoError(t, created.Provision(""))

	started, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.NoError(t, started.ProvisionIfNew())

	quote, err := started.Quote([]byte("0123456789abcdef"), []int{0, 7})
	require.NoError(t, err)
	assert.NotEmpty(t, quote.Signature)
}

// A vTPM whose EK is persistent but whose IAK is gone cannot quote: Start
// refuses it with a typed error instead of starting an instance whose every
// Quote fails.
func TestTPMOperations_ProvisionIfNew_RefusesAProvisionedTPMWithoutAnIAK(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	created, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.NoError(t, created.Provision(""))
	_, err = tpm2.EvictControl{
		Auth:             tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		ObjectHandle:     &tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x81020001), Name: iakName(t, tpmTransport)},
		PersistentHandle: tpm2.TPMHandle(0x81020001),
	}.Execute(tpmTransport)
	require.NoError(t, err)

	started, err := newTPMOperations(tpmTransport, "", t.TempDir(), EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)

	err = started.ProvisionIfNew()
	var notProvisioned ErrVTPMAttestationKeyMissing
	require.ErrorAs(t, err, &notProvisioned)
}

func iakName(t *testing.T, tpmTransport transport.TPM) tpm2.TPM2BName {
	t.Helper()
	pub, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(0x81020001)}.Execute(tpmTransport)
	require.NoError(t, err)
	return pub.Name
}

// Seal keeps the sealed object's blobs in the bundle's sealed-data store, so a
// later TPMOperations on the same bundle unseals what an earlier one sealed.
func TestTPMOperations_SealUnseal_AcrossInstancesOfOneBundle(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	sealedDir := sealedDataDir(t.TempDir())
	ops, err := newTPMOperations(tpmTransport, "", sealedDir, EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	require.NoError(t, ops.ProvisionIfNew())

	sealed, err := ops.Seal(context.Background(), []byte("disk-key"), nil, "")
	require.NoError(t, err, "Seal needs the bundle's sealed-data store")

	restarted, err := newTPMOperations(tpmTransport, "", sealedDir, EKAlgorithmRSA, "vm-01", nil)
	require.NoError(t, err)
	plaintext, err := restarted.Unseal(context.Background(), sealed, "")
	require.NoError(t, err)
	assert.Equal(t, []byte("disk-key"), plaintext)
}

func TestNewTPMOperations_RefusesAnEmptySealedDataDir(t *testing.T) {
	_, err := newTPMOperations(newSimulatorTransport(t), "/run/swtpm.sock", "", EKAlgorithmRSA, "vm-01", nil)

	var connErr ErrTPMConnectionFailed
	require.True(t, errors.As(err, &connErr), "got %v", err)
	assert.Equal(t, "/run/swtpm.sock", connErr.SocketPath)
}

func TestSealedDataDir_IsInsideTheTPMStateDir(t *testing.T) {
	stateDir := filepath.Join(string(filepath.Separator), "bundles", "b1", "tpm")
	assert.Equal(t, filepath.Join(stateDir, "sealed"), sealedDataDir(stateDir))
}
