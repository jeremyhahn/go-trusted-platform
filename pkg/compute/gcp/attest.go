//go:build gcpcompute

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

package gcp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"time"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// attestNonceSize is the size of a platform-generated attestation nonce when
// the caller supplies none.
const attestNonceSize = 32

// AttestVM performs Shielded VM endorsement-key identity attestation from the
// control plane. Unlike an in-guest QEMU vTPM quote, the GCE control plane
// cannot read the guest's PCRs or drive its attestation key; what it can do —
// cryptographically and without any in-guest agent — is retrieve the
// instance's Shielded VM vTPM endorsement key (EK) via
// GetShieldedInstanceIdentity and prove which hardware root of trust backs the
// instance.
//
// The returned report carries the DER-encoded EK public key in AKPublicKey and
// echoes the caller's nonce (a fresh random nonce is generated when none is
// supplied). PCRValues is empty and Verified is false: a full PCR quote
// requires the in-guest platform agent, which uses vtpm.ResolveTPMTarget on
// /dev/tpmrm0 and submits its quote to the platform VM attestation verifier.
// See docs/compute/cloud-providers.md.
func (o *GCPOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*compute.VMAttestationReport, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}

	gi, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	if gi.GetStatus() != statusRunning {
		return nil, &compute.SentinelCauseError{
			Sentinel: compute.ErrVTPMNotAvailable,
			Cause:    &compute.MessageError{Msg: "Shielded VM endorsement key requires a running instance"},
		}
	}

	if len(nonce) == 0 {
		nonce = make([]byte, attestNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, &compute.WrappedError{Msg: "failed to generate attestation nonce", Err: err}
		}
	}

	ekDER, err := o.endorsementKeyDER(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	report := &compute.VMAttestationReport{
		VMID:        instanceID,
		VMName:      labelValue(gi.GetLabels(), nameLabelKey),
		Timestamp:   time.Now().UTC(),
		Verified:    false,
		Nonce:       nonce,
		AKPublicKey: ekDER,
	}
	o.logger.Infof("Retrieved Shielded VM EK identity for instance %s (%d-byte EK)", instanceID, len(ekDER))
	return report, nil
}

// endorsementKeyDER retrieves and validates the instance's Shielded VM
// endorsement public key in DER form. GCE returns the EK as a PEM-encoded
// public key; it is decoded to DER and validated as a PKIX public key, reusing
// the same crypto the platform VM verifier relies on.
func (o *GCPOrchestrator) endorsementKeyDER(ctx context.Context, instanceID string) ([]byte, error) {
	identity, err := o.client.ShieldedIdentity(ctx, instanceID)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: &APIError{Op: "GetShieldedInstanceIdentity", Err: err}}
	}
	ekPEM := endorsementKeyPEM(identity)
	if ekPEM == "" {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: &compute.MessageError{Msg: "empty EK public key"}}
	}

	block, _ := pem.Decode([]byte(ekPEM))
	if block == nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: &compute.MessageError{Msg: "EK public key is not valid PEM"}}
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: err}
	}
	return block.Bytes, nil
}

// endorsementKeyPEM returns the RSA endorsement-key PEM, falling back to the
// ECC endorsement key when RSA is absent.
func endorsementKeyPEM(identity *computepb.ShieldedInstanceIdentity) string {
	if identity == nil {
		return ""
	}
	if ek := identity.GetEncryptionKey(); ek != nil && ek.GetEkPub() != "" {
		return ek.GetEkPub()
	}
	if ek := identity.GetEccP256EncryptionKey(); ek != nil && ek.GetEkPub() != "" {
		return ek.GetEkPub()
	}
	return ""
}

// VerifyVMAttestation is not supported by the GCE control plane. Verifying a
// PCR quote requires the guest's attestation key, which is only reachable from
// inside the instance. The honest GCP flow is: the in-guest platform agent
// generates a quote via vtpm.ResolveTPMTarget(/dev/tpmrm0) and submits it to
// the platform VM attestation verifier (pkg/attestation/vm); the control-plane
// orchestrator provides EK identity via AttestVM. See
// docs/compute/cloud-providers.md.
func (o *GCPOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	return nil, &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "control-plane PCR-quote verification is unavailable; verify in-guest quotes with pkg/attestation/vm"},
	}
}
