//go:build awscompute

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

package aws

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// attestNonceSize is the size of a platform-generated attestation nonce when
// the caller supplies none.
const attestNonceSize = 32

// AttestVM performs NitroTPM endorsement-key identity attestation from the
// control plane. Unlike an in-guest QEMU vTPM quote, the EC2 control plane
// cannot read the guest's PCRs or drive its attestation key; what it can do
// — cryptographically and without any in-guest agent — is retrieve the
// instance's NitroTPM endorsement key (EK) via GetInstanceTpmEkPub and prove
// which hardware root of trust backs the instance.
//
// The returned report carries the DER-encoded EK public key in AKPublicKey
// and echoes the caller's nonce (a fresh random nonce is generated when none
// is supplied). PCRValues is empty and Verified is false: a full PCR quote
// requires the in-guest platform agent, which uses vtpm.ResolveTPMTarget on
// /dev/tpmrm0 and submits its quote to the platform VM attestation verifier.
// See docs/compute/cloud-providers.md.
func (o *AWSOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*compute.VMAttestationReport, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}

	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	if ec2Inst.State == nil || ec2Inst.State.Name != ec2types.InstanceStateNameRunning {
		return nil, &compute.SentinelCauseError{
			Sentinel: compute.ErrVTPMNotAvailable,
			Cause:    &compute.MessageError{Msg: "NitroTPM endorsement key requires a running instance"},
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
		VMName:      tagValue(ec2Inst.Tags, nameTagKey),
		Timestamp:   time.Now().UTC(),
		Verified:    false,
		Nonce:       nonce,
		AKPublicKey: ekDER,
	}
	o.logger.Infof("Retrieved NitroTPM EK identity for instance %s (%d-byte EK)", instanceID, len(ekDER))
	return report, nil
}

// endorsementKeyDER retrieves and validates the instance's NitroTPM
// endorsement public key in DER form.
func (o *AWSOrchestrator) endorsementKeyDER(ctx context.Context, instanceID string) ([]byte, error) {
	out, err := o.client.GetInstanceTpmEkPub(ctx, &ec2.GetInstanceTpmEkPubInput{
		InstanceId: awssdk.String(instanceID),
		KeyType:    ec2types.EkPubKeyTypeRsa2048,
		KeyFormat:  ec2types.EkPubKeyFormatDer,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: &APIError{Op: "GetInstanceTpmEkPub", Err: err}}
	}
	if out.KeyValue == nil || *out.KeyValue == "" {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: &compute.MessageError{Msg: "empty EK public key"}}
	}

	der, err := base64.StdEncoding.DecodeString(*out.KeyValue)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: err}
	}
	// Validate the EK material parses as a public key, reusing the same
	// crypto the platform VM verifier relies on. A malformed EK is a
	// verification failure, not a silent pass.
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: err}
	}
	return der, nil
}

// VerifyVMAttestation is not supported by the AWS control plane. Verifying a
// PCR quote requires the guest's attestation key, which is only reachable
// from inside the instance. The honest AWS flow is: the in-guest platform
// agent generates a quote via vtpm.ResolveTPMTarget(/dev/tpmrm0) and submits
// it to the platform VM attestation verifier (pkg/attestation/vm); the
// control-plane orchestrator provides EK identity via AttestVM. See
// docs/compute/cloud-providers.md.
func (o *AWSOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	return nil, &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "control-plane PCR-quote verification is unavailable; verify in-guest quotes with pkg/attestation/vm"},
	}
}
