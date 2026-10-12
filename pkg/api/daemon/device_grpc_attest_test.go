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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestDeviceGRPCService_AttestDevice_Success(t *testing.T) {
	f := newQuoteFixture(t)
	svc := f.grpcService(t)

	resp, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: f.evidence(t, []byte("fresh-nonce-000001"), goldenPCRs()),
	})
	require.NoError(t, err)

	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, f.device.ID, resp.GetDeviceId())
	assert.Equal(t, "SN-1", resp.GetSerial())
	assert.True(t, resp.GetVerified())
	assert.True(t, resp.GetAkCertificateVerified())
	assert.True(t, resp.GetSignatureValid())
	assert.True(t, resp.GetNonceValid())
	assert.True(t, resp.GetPcrsValid())
	assert.True(t, resp.GetPcrBaselineCaptured())
	assert.Equal(t, "tofu", resp.GetPcrBaselineSource())
	assert.Equal(t, f.now, resp.GetPcrBaselineRecordedAt().AsTime())
	assert.Equal(t, "verified", resp.GetAttestationStatus())
	assert.False(t, resp.GetAttestedAt().AsTime().IsZero())
}

func TestDeviceGRPCService_AttestDevice_FailedVerificationIsNotAnError(t *testing.T) {
	f := newQuoteFixture(t)
	svc := f.grpcService(t)
	otherKey, _ := newAttestTestKey(t)

	resp, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: signedEvidence(t, otherKey, []byte("fresh-nonce-000002"), goldenPCRs(), goldenPCRs()),
	})
	require.NoError(t, err, "a failed verification must not be reported as a transport error")

	assert.False(t, resp.GetVerified())
	assert.True(t, resp.GetAkCertificateVerified(), "the certificate was fine")
	assert.False(t, resp.GetSignatureValid(), "the signature check is the one that failed")
	assert.Nil(t, resp.GetPcrBaselineRecordedAt(), "no baseline was evaluated, so none is reported")
	assert.Equal(t, "failed", resp.GetAttestationStatus())
	assert.NotEmpty(t, resp.GetMessage(), "a negative verdict must say why")
}

func TestDeviceGRPCService_AttestDevice_NoCertificateFailsClosed(t *testing.T) {
	f := newQuoteFixture(t)
	f.device.AttestCert = ""
	svc := f.grpcService(t)

	resp, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: f.evidence(t, []byte("fresh-nonce-000005"), goldenPCRs()),
	})
	require.NoError(t, err)
	assert.False(t, resp.GetVerified())
	assert.False(t, resp.GetAkCertificateVerified())
}

func TestDeviceGRPCService_AttestDevice_RejectsIncompleteRequests(t *testing.T) {
	f := newQuoteFixture(t)
	svc := f.grpcService(t)

	tests := []struct {
		name string
		req  *platformv1.AttestDeviceRequest
	}{
		{"no device id", &platformv1.AttestDeviceRequest{Evidence: []byte(`{"quote":"x"}`)}},
		{"no evidence", &platformv1.AttestDeviceRequest{DeviceId: itoa(f.device.ID)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.AttestDevice(context.Background(), tt.req)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestDeviceGRPCService_AttestDevice_MatchesTheProviderVerdict(t *testing.T) {
	f := newQuoteFixture(t)
	evidence := f.evidence(t, []byte("fresh-nonce-000003"), goldenPCRs())

	grpcSvc := f.grpcService(t)
	provider, providerID := enrolledDeviceProvider(t, f)

	grpcResp, err := grpcSvc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: evidence,
	})
	require.NoError(t, err)

	raw, err := provider.DeviceAttest(context.Background(), itoa(providerID), evidence)
	require.NoError(t, err)
	providerResult, ok := raw.(*DeviceAttestationResult)
	require.True(t, ok)

	assert.Equal(t, providerResult.Verified, grpcResp.GetVerified())
	assert.Equal(t, providerResult.AKCertificateVerified, grpcResp.GetAkCertificateVerified())
	assert.Equal(t, providerResult.SignatureValid, grpcResp.GetSignatureValid())
	assert.Equal(t, providerResult.NonceValid, grpcResp.GetNonceValid())
	assert.Equal(t, providerResult.PCRsValid, grpcResp.GetPcrsValid())
	assert.Equal(t, providerResult.PCRBaselineSource, grpcResp.GetPcrBaselineSource())
	assert.Equal(t, providerResult.Status, grpcResp.GetAttestationStatus())
}

func TestQUICDeviceAttest_IsNoLongerNotImplemented(t *testing.T) {
	f := newQuoteFixture(t)

	h := &QUICServiceHandler{
		deviceService:  f.devices,
		profileService: f.profiles,
		logger:         logging.DefaultLogger(),
	}
	h.SetDeviceAKTrust(f.trust)
	h.SetDeviceVerdictSink(f.sink)
	h.deviceGRPC.verifier.now = func() time.Time { return f.now }

	payload, err := quicwire.EncodePayload(&platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: f.evidence(t, []byte("fresh-nonce-000004"), goldenPCRs()),
	})
	require.NoError(t, err)

	resp := h.handleDeviceOperation(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpDeviceAttest,
		Payload: payload,
	})

	require.NotNil(t, resp)
	assert.NotEqual(t, quicwire.StatusNotImplemented, resp.Status,
		"OpDeviceAttest must not answer StatusNotImplemented on the live dispatcher")
	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var decoded platformv1.AttestDeviceResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &decoded))
	assert.True(t, decoded.GetVerified(), "QUIC must reach the same verdict as gRPC over the same verifier")
	assert.True(t, decoded.GetAkCertificateVerified())
}
