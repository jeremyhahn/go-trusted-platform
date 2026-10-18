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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkcompute "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// vmAttestSDKVerbs drive the VM attestation verbs through the Go SDK
// compute client.
var vmAttestSDKVerbs = []vmSnapshotSDKVerb{
	{
		name: "attest",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			_, err := c.AttestVM(ctx, vmID, []byte("nonce"), []uint32{0, 7}, platformv1.PCRBank_PCR_BANK_SHA256)
			return err
		},
		typed: typedAs[*sdkcompute.ErrAttestVMFailed],
		fail:  func(orch *computeParityOrchestrator, err error) { orch.attestErr = err },
	},
	{
		name: "verify",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			_, err := c.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{
				VmId:               vmID,
				Quote:              []byte("quote-bytes"),
				Signature:          []byte("signature-bytes"),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Nonce:              []byte("nonce"),
			})
			return err
		},
		typed: typedAs[*sdkcompute.ErrVerifyVMAttestationFailed],
		fail:  func(orch *computeParityOrchestrator, err error) { orch.verifyErr = err },
	},
}

func TestVMAttestSDKParity_AttestThenVerify(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, orch := seededVMPair()
			client := transport.dial(t, provider, svc)
			ctx := context.Background()

			quote, err := client.AttestVM(ctx, "vm-1", []byte("nonce"), []uint32{0, 7}, platformv1.PCRBank_PCR_BANK_SHA256)
			require.NoError(t, err)
			assert.Equal(t, []byte("quote-bytes"), quote.GetQuote())
			assert.Equal(t, x509.SHA256WithRSAPSS.String(), quote.GetSignatureAlgorithm())
			assert.Equal(t, []int{0, 7}, orch.lastAttestPCRs)

			verified, err := client.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{
				VmId:               "vm-1",
				Quote:              quote.GetQuote(),
				Signature:          quote.GetSignature(),
				SignatureAlgorithm: quote.GetSignatureAlgorithm(),
				Nonce:              []byte("nonce"),
				ExpectedPcrs:       quote.GetPcrValues(),
			})
			require.NoError(t, err)
			assert.True(t, verified.GetVerified())
			require.NotNil(t, orch.lastEvidence)
			assert.Equal(t, []byte("signature-bytes"), orch.lastEvidence.Signature)
			assert.Equal(t, []byte{0x07}, orch.lastEvidence.ExpectedPCRs[7])
		})
	}
}

func TestVMAttestSDKParity_UnknownVM(t *testing.T) {
	notFound := &compute.SentinelCauseError{Sentinel: compute.ErrInstanceNotFound, Cause: &compute.MessageError{Msg: "no such vm"}}
	for _, transport := range vmSDKTransports {
		for _, verb := range vmAttestSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				verb.fail(orch, notFound)
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "vm-missing")
				assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
				assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
			})
		}
	}
}

func TestVMAttestSDKParity_NoVTPM(t *testing.T) {
	noVTPM := &compute.SentinelCauseError{Sentinel: compute.ErrVTPMNotAvailable, Cause: &compute.MessageError{Msg: "vm has no vtpm"}}
	for _, transport := range vmSDKTransports {
		for _, verb := range vmAttestSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				verb.fail(orch, noVTPM)
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "vm-1")
				assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
				assert.Equal(t, transport.wrongState, status.Code(err), "err = %v", err)
			})
		}
	}
}
