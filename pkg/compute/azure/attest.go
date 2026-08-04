//go:build azurecompute

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

package azure

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// AttestVM is not supported from the Azure control plane. Unlike AWS NitroTPM
// (GetInstanceTpmEkPub) and GCP Shielded VM (GetShieldedInstanceIdentity),
// Azure exposes no Resource Manager API to retrieve a Trusted Launch VM's vTPM
// endorsement key or drive its attestation key. Azure Trusted Launch
// attestation is fundamentally guest-driven: the in-guest agent reads the vTPM
// via vtpm.ResolveTPMTarget(/dev/tpmrm0), obtains a quote, and submits it to
// Microsoft Azure Attestation and/or the platform VM attestation verifier
// (pkg/attestation/vm). Rather than fabricate a hollow report, the control-plane
// orchestrator honestly rejects with a typed error. See
// docs/compute/cloud-providers.md.
func (o *AzureOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*compute.VMAttestationReport, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	return nil, &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "control-plane vTPM EK retrieval is unavailable on Azure; Trusted Launch attestation is guest-driven via Microsoft Azure Attestation + pkg/attestation/vm"},
	}
}

// VerifyVMAttestation is not supported by the Azure control plane. Verifying a
// PCR quote requires the guest's attestation key, which is only reachable from
// inside the instance. The honest Azure flow is: the in-guest platform agent
// generates a quote via vtpm.ResolveTPMTarget(/dev/tpmrm0) and submits it to
// Microsoft Azure Attestation and/or the platform VM attestation verifier
// (pkg/attestation/vm). See docs/compute/cloud-providers.md.
func (o *AzureOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	return nil, &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "control-plane PCR-quote verification is unavailable; verify in-guest quotes with pkg/attestation/vm"},
	}
}
