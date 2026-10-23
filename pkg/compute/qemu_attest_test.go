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

package compute

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sort"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVTPMDevice is an in-memory vm.VTPMDevice seam that produces real,
// verifiable quotes signed with an RSA test key.
type fakeVTPMDevice struct {
	key       *rsa.PrivateKey
	pcrValues map[int][]byte

	quoteErr  error
	aikErr    error
	sigAlgErr error
	closed    bool
	lastPCRs  []int
}

func newFakeVTPMDevice(t *testing.T) *fakeVTPMDevice {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pcrValues := make(map[int][]byte)
	for i := 0; i < 24; i++ {
		value := make([]byte, 32)
		value[0] = byte(i)
		value[31] = 0x5A // ensure no PCR value equals the zero digest
		pcrValues[i] = value
	}
	return &fakeVTPMDevice{key: key, pcrValues: pcrValues}
}

// buildQuote marshals a TPMS_ATTEST quote over the device's PCR values.
func (f *fakeVTPMDevice) buildQuote(nonce []byte, pcrIndices []int) []byte {
	indices := append([]int(nil), pcrIndices...)
	sort.Ints(indices)

	hasher := sha256.New()
	pcrs := make([]uint, 0, len(indices))
	for _, idx := range indices {
		hasher.Write(f.pcrValues[idx])
		pcrs = append(pcrs, uint(idx))
	}

	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
					},
				},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: hasher.Sum(nil)},
		}),
	}
	return tpm2.Marshal(attest)
}

func (f *fakeVTPMDevice) GenerateQuote(ctx context.Context, nonce []byte, pcrIndices []int, algorithm vm.HashAlgorithm) ([]byte, []byte, error) {
	if f.quoteErr != nil {
		return nil, nil, f.quoteErr
	}
	f.lastPCRs = append([]int(nil), pcrIndices...)

	quote := f.buildQuote(nonce, pcrIndices)
	hashed := sha256.Sum256(quote)
	// The fake AK is an RSA-PSS IAK, so a verifier that inferred PKCS#1 v1.5
	// from the RSA key would refuse every quote it makes.
	signature, err := rsa.SignPSS(rand.Reader, f.key, crypto.SHA256, hashed[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, err
	}
	return quote, signature, nil
}

func (f *fakeVTPMDevice) GetAIKSignatureAlgorithm(ctx context.Context) (string, error) {
	if f.sigAlgErr != nil {
		return "", f.sigAlgErr
	}
	return x509.SHA256WithRSAPSS.String(), nil
}

func (f *fakeVTPMDevice) ReadPCR(ctx context.Context, pcr int, algorithm vm.HashAlgorithm) ([]byte, error) {
	value, ok := f.pcrValues[pcr]
	if !ok {
		return nil, errors.New("pcr not found")
	}
	return value, nil
}

func (f *fakeVTPMDevice) GetAIKPublicKey(ctx context.Context) ([]byte, error) {
	if f.aikErr != nil {
		return nil, f.aikErr
	}
	return x509.MarshalPKIXPublicKey(&f.key.PublicKey)
}

func (f *fakeVTPMDevice) GetEKCertificate(ctx context.Context) ([]byte, error) {
	return nil, errors.New("no EK certificate in fake")
}

func (f *fakeVTPMDevice) Close() error {
	f.closed = true
	return nil
}

// newAttestTestOrchestrator builds a QEMU orchestrator with a fake vTPM
// device seam.
func newAttestTestOrchestrator(t *testing.T) (*QEMUOrchestrator, *fakeVTPMDevice) {
	t.Helper()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()

	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)

	device := newFakeVTPMDevice(t)
	orch.vtpmDeviceFor = func(socketPath string) (vm.VTPMDevice, error) {
		return device, nil
	}

	t.Cleanup(func() {
		orch.mu.Lock()
		orch.instances = make(map[string]*qemuInstance)
		orch.mu.Unlock()
		require.NoError(t, orch.Close())
	})

	return orch, device
}

func TestQEMUOrchestrator_AttestVM(t *testing.T) {
	orch, device := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")

	nonce := []byte("caller-supplied-nonce")
	report, err := orch.AttestVM(context.Background(), "vm1", nonce, []int{0, 7})
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "vm1", report.VMID)
	assert.Equal(t, "test-vm", report.VMName)
	assert.Equal(t, nonce, report.Nonce)
	assert.False(t, report.Verified) // generation does not verify
	assert.NotEmpty(t, report.Quote)
	assert.NotEmpty(t, report.Signature)
	assert.NotEmpty(t, report.AKPublicKey)
	assert.Len(t, report.PCRValues, 2)
	assert.Equal(t, []int{0, 7}, device.lastPCRs)

	// The generated quote must verify against the fake device's AK under the
	// scheme the report declares.
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), report.SignatureAlgorithm)
	require.NoError(t, vm.VerifyQuoteSignatureWithAlgorithm(report.AKPublicKey, report.Quote, report.Signature, report.SignatureAlgorithm))
	require.NoError(t, vm.VerifyQuoteNonce(report.Quote, nonce))
	assert.True(t, device.closed, "AttestVM must release the per-call vTPM session")
}

func TestQEMUOrchestrator_AttestVM_Defaults(t *testing.T) {
	orch, device := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")

	report, err := orch.AttestVM(context.Background(), "vm1", nil, nil)
	require.NoError(t, err)

	// Platform generates a 32-byte nonce and defaults to PCRs 0-7.
	assert.Len(t, report.Nonce, attestNonceSize)
	assert.Equal(t, defaultAttestPCRs, device.lastPCRs)
	assert.Len(t, report.PCRValues, len(defaultAttestPCRs))
}

func TestQEMUOrchestrator_AttestVM_Errors(t *testing.T) {
	orch, device := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")
	addFakeVMInstance(t, orch, "no-tpm", true, "/vms/n/disk.qcow2", "")
	addFakeVMInstance(t, orch, "stopped-vm", false, "/vms/s/disk.qcow2", "/tmp/swtpm2.sock")

	ctx := context.Background()

	t.Run("empty instance ID", func(t *testing.T) {
		_, err := orch.AttestVM(ctx, "", nil, nil)
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("instance not found", func(t *testing.T) {
		_, err := orch.AttestVM(ctx, "missing", nil, nil)
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("TPM-less instance", func(t *testing.T) {
		_, err := orch.AttestVM(ctx, "no-tpm", nil, nil)
		assert.ErrorIs(t, err, ErrVTPMNotAvailable)
	})

	t.Run("stopped VM", func(t *testing.T) {
		_, err := orch.AttestVM(ctx, "stopped-vm", nil, nil)
		assert.ErrorIs(t, err, ErrInstanceNotRunning)
	})

	t.Run("unreachable vTPM", func(t *testing.T) {
		device.aikErr = errors.New("connection refused")
		defer func() { device.aikErr = nil }()

		_, err := orch.AttestVM(ctx, "vm1", nil, nil)
		assert.ErrorIs(t, err, ErrVTPMNotAvailable)
	})

	t.Run("AK scheme unavailable", func(t *testing.T) {
		device.sigAlgErr = errors.New("IAK attributes unavailable")
		defer func() { device.sigAlgErr = nil }()

		_, err := orch.AttestVM(ctx, "vm1", nil, nil)
		var quoteErr vm.ErrQuoteGenerationFailed
		assert.ErrorAs(t, err, &quoteErr)
	})

	t.Run("device factory failure", func(t *testing.T) {
		orig := orch.vtpmDeviceFor
		defer func() { orch.vtpmDeviceFor = orig }()
		factoryErr := &SentinelCauseError{Sentinel: ErrVTPMNotAvailable, Cause: errors.New("socket gone")}
		orch.vtpmDeviceFor = func(socketPath string) (vm.VTPMDevice, error) {
			return nil, factoryErr
		}

		_, err := orch.AttestVM(ctx, "vm1", nil, nil)
		assert.ErrorIs(t, err, ErrVTPMNotAvailable)
	})
}

func TestQEMUOrchestrator_VerifyVMAttestation(t *testing.T) {
	orch, device := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")

	ctx := context.Background()
	nonce := []byte("verification-nonce")

	report, err := orch.AttestVM(ctx, "vm1", nonce, []int{0, 7})
	require.NoError(t, err)

	t.Run("full verification passes", func(t *testing.T) {
		result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote:              report.Quote,
			Signature:          report.Signature,
			SignatureAlgorithm: report.SignatureAlgorithm,
			Nonce:              nonce,
			ExpectedPCRs: map[int][]byte{
				0: device.pcrValues[0],
				7: device.pcrValues[7],
			},
		})
		require.NoError(t, err)
		assert.True(t, result.Verified)
		assert.True(t, result.SignatureValid)
		assert.True(t, result.NonceValid)
		assert.True(t, result.PCRsValid)
		assert.Equal(t, "attestation verified", result.Message)
		assert.Len(t, result.ActualPCRs, 2)
	})

	t.Run("tampered signature fails", func(t *testing.T) {
		tampered := append([]byte(nil), report.Signature...)
		tampered[0] ^= 0xFF

		result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote:              report.Quote,
			Signature:          tampered,
			SignatureAlgorithm: report.SignatureAlgorithm,
			Nonce:              nonce,
		})
		require.NoError(t, err)
		assert.False(t, result.Verified)
		assert.False(t, result.SignatureValid)
		assert.True(t, result.NonceValid)
		assert.NotEmpty(t, result.Message)
	})

	t.Run("wrong nonce fails", func(t *testing.T) {
		result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote:              report.Quote,
			Signature:          report.Signature,
			SignatureAlgorithm: report.SignatureAlgorithm,
			Nonce:              []byte("wrong-nonce"),
		})
		require.NoError(t, err)
		assert.False(t, result.Verified)
		assert.True(t, result.SignatureValid)
		assert.False(t, result.NonceValid)
	})

	t.Run("wrong expected PCRs fail", func(t *testing.T) {
		result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote:     report.Quote,
			Signature: report.Signature,
			Nonce:     nonce,
			ExpectedPCRs: map[int][]byte{
				0: make([]byte, 32), // wrong value
				7: device.pcrValues[7],
			},
		})
		require.NoError(t, err)
		assert.False(t, result.Verified)
		assert.False(t, result.PCRsValid)
	})

	t.Run("undeclared or mismatched scheme fails", func(t *testing.T) {
		for name, scheme := range map[string]string{
			"undeclared":                      "",
			"PKCS#1 v1.5 for a PSS signature": x509.SHA256WithRSA.String(),
			"ECDSA for an RSA AK":             x509.ECDSAWithSHA256.String(),
		} {
			t.Run(name, func(t *testing.T) {
				result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
					Quote:              report.Quote,
					Signature:          report.Signature,
					SignatureAlgorithm: scheme,
					Nonce:              nonce,
				})
				require.NoError(t, err)
				assert.False(t, result.Verified)
				assert.False(t, result.SignatureValid)
				assert.True(t, result.NonceValid)
			})
		}
	})
}

func TestQEMUOrchestrator_VerifyVMAttestation_InvalidEvidence(t *testing.T) {
	orch, _ := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")

	ctx := context.Background()

	tests := []struct {
		name     string
		evidence *VMAttestationEvidence
	}{
		{"nil evidence", nil},
		{"missing quote", &VMAttestationEvidence{Signature: []byte("s"), Nonce: []byte("n")}},
		{"missing signature", &VMAttestationEvidence{Quote: []byte("q"), Nonce: []byte("n")}},
		{"missing nonce", &VMAttestationEvidence{Quote: []byte("q"), Signature: []byte("s")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := orch.VerifyVMAttestation(ctx, "vm1", tt.evidence)
			assert.ErrorIs(t, err, ErrInvalidAttestationEvidence)
		})
	}

	t.Run("instance not found", func(t *testing.T) {
		_, err := orch.VerifyVMAttestation(ctx, "missing", &VMAttestationEvidence{
			Quote: []byte("q"), Signature: []byte("s"), Nonce: []byte("n"),
		})
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})
}
