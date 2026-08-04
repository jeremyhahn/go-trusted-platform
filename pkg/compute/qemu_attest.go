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
	"crypto/rand"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// Compile-time proof that QEMUOrchestrator provides the VM attestation
// capability.
var _ VMAttester = (*QEMUOrchestrator)(nil)

// attestNonceSize is the size in bytes of platform-generated attestation
// nonces when the caller does not supply one.
const attestNonceSize = 32

// defaultAttestPCRs is the default PCR selection for VM quotes: the
// firmware/boot PCRs 0-7.
var defaultAttestPCRs = []int{0, 1, 2, 3, 4, 5, 6, 7}

// defaultVTPMDevice opens a go-xkms TPM connection to the instance's swtpm
// socket (cached by the orchestrator's TPM provider) and wraps it in the VM
// attestor device adapter. Closing the device releases the cached
// connection.
func (o *QEMUOrchestrator) defaultVTPMDevice(socketPath string) (vm.VTPMDevice, error) {
	tpm, err := o.tpmProvider.GetTPM(socketPath)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVTPMNotAvailable, Cause: err}
	}
	device, err := vtpm.NewVMAttestorDevice(tpm, func() error {
		return o.tpmProvider.CloseTPM(socketPath)
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVTPMNotAvailable, Cause: err}
	}
	return device, nil
}

// attestSession validates the instance and returns it together with a vTPM
// attestor device bound to its swtpm socket. The caller owns closing the
// returned device.
func (o *QEMUOrchestrator) attestSession(instanceID string) (*qemuInstance, vm.VTPMDevice, error) {
	if instanceID == "" {
		return nil, nil, ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return nil, nil, ErrInstanceNotFound
	}

	socketPath := qemuInst.instance.Metadata["tpm_socket"]
	if socketPath == "" {
		return nil, nil, &SentinelCauseError{
			Sentinel: ErrVTPMNotAvailable,
			Cause:    &MessageError{Msg: "instance has no vTPM socket (TPM disabled at creation)"},
		}
	}

	// The per-instance swtpm daemon only runs while the VM runs.
	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, nil, err
	}
	if state != StateRunning {
		return nil, nil, &SentinelCauseError{
			Sentinel: ErrInstanceNotRunning,
			Cause:    &MessageError{Msg: "vTPM attestation requires a running VM (swtpm runs with the VM)"},
		}
	}

	device, err := o.vtpmDeviceFor(socketPath)
	if err != nil {
		return nil, nil, err
	}

	return qemuInst, device, nil
}

// AttestVM generates a TPM quote from the instance's vTPM. A nil nonce is
// replaced with a platform-generated random nonce and an empty PCR selection
// defaults to PCRs 0-7 (SHA-256 bank).
func (o *QEMUOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*VMAttestationReport, error) {
	qemuInst, device, err := o.attestSession(instanceID)
	if err != nil {
		return nil, err
	}

	if len(nonce) == 0 {
		nonce = make([]byte, attestNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			if closeErr := device.Close(); closeErr != nil {
				o.logger.Warnf("Failed to close vTPM device: %v", closeErr)
			}
			return nil, &WrappedError{Msg: "failed to generate attestation nonce", Err: err}
		}
	}

	if len(pcrIndices) == 0 {
		pcrIndices = append([]int(nil), defaultAttestPCRs...)
	}

	// The attestor takes ownership of the device and closes it.
	attestor := vm.NewVMAttestor(
		vm.WithVTPMDevice(device),
		vm.WithAttestorLogger(o.logger.Slog()),
	)
	defer func() {
		if err := attestor.Close(); err != nil {
			o.logger.Warnf("Failed to close VM attestor: %v", err)
		}
	}()

	socketPath := qemuInst.instance.Metadata["tpm_socket"]
	if err := attestor.Initialize(ctx, &vm.AttestorConfig{
		VTPMDevicePath:       socketPath,
		DefaultHashAlgorithm: vm.HashAlgorithmSHA256,
		DefaultPCRIndices:    defaultAttestPCRs,
	}); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVTPMNotAvailable, Cause: err}
	}

	quote, err := attestor.GenerateQuote(ctx, &vm.QuoteRequest{
		Nonce:         nonce,
		PCRIndices:    pcrIndices,
		HashAlgorithm: vm.HashAlgorithmSHA256,
	})
	if err != nil {
		return nil, err
	}

	pcrValues := make(map[int][]byte, len(quote.PCRs))
	for _, pcr := range quote.PCRs {
		pcrValues[pcr.Index] = pcr.Value
	}

	report := &VMAttestationReport{
		VMID:        instanceID,
		VMName:      qemuInst.instance.Name,
		Timestamp:   quote.Timestamp,
		Verified:    false,
		Nonce:       nonce,
		PCRValues:   pcrValues,
		Quote:       quote.QuoteData,
		Signature:   quote.Signature,
		AKPublicKey: quote.AIKPublicKey,
	}

	o.logger.Infof("Generated vTPM quote for VM instance %s (%d PCRs)", instanceID, len(pcrValues))

	return report, nil
}

// VerifyVMAttestation verifies quote evidence against the instance's live
// vTPM attestation key: the AK signature over the quote, the embedded
// anti-replay nonce, and — when expected PCR values are supplied — the
// quote's PCR digest computed from the expected values.
func (o *QEMUOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *VMAttestationEvidence) (*VMVerificationResult, error) {
	if evidence == nil {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidAttestationEvidence,
			Cause:    &MessageError{Msg: "evidence is required"},
		}
	}
	if len(evidence.Quote) == 0 {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidAttestationEvidence,
			Cause:    &MessageError{Msg: "quote is required"},
		}
	}
	if len(evidence.Signature) == 0 {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidAttestationEvidence,
			Cause:    &MessageError{Msg: "signature is required"},
		}
	}
	if len(evidence.Nonce) == 0 {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidAttestationEvidence,
			Cause:    &MessageError{Msg: "nonce is required"},
		}
	}

	_, device, err := o.attestSession(instanceID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := device.Close(); err != nil {
			o.logger.Warnf("Failed to close vTPM device: %v", err)
		}
	}()

	akPublicKey, err := device.GetAIKPublicKey(ctx)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVTPMNotAvailable, Cause: err}
	}

	result := &VMVerificationResult{}
	var failures []string

	if err := vm.VerifyQuoteSignature(akPublicKey, evidence.Quote, evidence.Signature); err != nil {
		failures = append(failures, err.Error())
	} else {
		result.SignatureValid = true
	}

	if err := vm.VerifyQuoteNonce(evidence.Quote, evidence.Nonce); err != nil {
		failures = append(failures, err.Error())
	} else {
		result.NonceValid = true
	}

	if len(evidence.ExpectedPCRs) > 0 {
		if err := vm.VerifyQuotePCRDigest(evidence.Quote, evidence.ExpectedPCRs); err != nil {
			failures = append(failures, err.Error())
		} else {
			result.PCRsValid = true
		}

		// Read the live PCR values for the expected indices as
		// diagnostics for the verifier.
		result.ActualPCRs = make(map[int][]byte, len(evidence.ExpectedPCRs))
		for idx := range evidence.ExpectedPCRs {
			value, readErr := device.ReadPCR(ctx, idx, vm.HashAlgorithmSHA256)
			if readErr != nil {
				o.logger.Warnf("Failed to read live PCR %d for verification diagnostics: %v", idx, readErr)
				continue
			}
			result.ActualPCRs[idx] = value
		}
	} else {
		result.PCRsValid = true
	}

	result.Verified = result.SignatureValid && result.NonceValid && result.PCRsValid
	if result.Verified {
		result.Message = "attestation verified"
	} else {
		result.Message = strings.Join(failures, "; ")
	}

	o.logger.Infof("Verified vTPM attestation for VM instance %s (verified=%v)", instanceID, result.Verified)

	return result, nil
}
