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

// Evidence the verifier cannot use is the caller's fault, so it is
// InvalidArgument -- not Internal, which tells the caller to retry a
// request that can never succeed (#949). The last case is the forged
// shape the integration suite sends: a quote, signature and nonce but no
// PCR values.
func TestDeviceGRPCService_AttestDevice_UnusableEvidenceIsInvalidArgument(t *testing.T) {
	f := newQuoteFixture(t)
	svc := f.grpcService(t)

	tests := []struct {
		name     string
		evidence string
		reason   string
	}{
		{"not json", `not json`, "JSON-encoded"},
		{"no quote", `{"signature":"eA==","nonce":"eA=="}`, "quote is required"},
		{"no signature", `{"quote":"eA==","nonce":"eA=="}`, "signature is required"},
		{"no nonce", `{"quote":"eA==","signature":"eA=="}`, "nonce is required"},
		{"no pcrs", `{"quote":"eA==","signature":"eA==","nonce":"eA=="}`, "pcrs are required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
				DeviceId: itoa(f.device.ID),
				Evidence: []byte(tt.evidence),
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), tt.reason)
		})
	}
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

// TestQUICDeviceDispatcher_RetiredOpcodesAreUnknown pins #317: the device
// dispatcher has no stub for Deactivate (0x3C) or GetMetrics (0x3E), which
// no transport ever implemented and which are retired, nor for 0x6D, which
// the IDevID handler owns. Each answers the generic unknown-opcode error.
func TestQUICDeviceDispatcher_RetiredOpcodesAreUnknown(t *testing.T) {
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}

	for _, opcode := range []byte{0x3C, 0x3E, quicwire.OpDeviceAttributes} {
		resp := h.handleDeviceOperation(context.Background(), &quicwire.Request{Opcode: opcode})

		require.NotNil(t, resp)
		assert.Equal(t, quicwire.StatusNotImplemented, resp.Status, "opcode 0x%02X", opcode)
		assert.Equal(t, ErrQUICUnknownOpcode{Opcode: opcode}.Error(), string(resp.Payload), "opcode 0x%02X", opcode)
	}
}

// TestQUICDeviceDispatcher_LiveOpcodeReachesItsHandler is the counterpart:
// OpDeviceGetState, the device range's last opcode, still reaches its
// handler, which refuses a request without a device id.
func TestQUICDeviceDispatcher_LiveOpcodeReachesItsHandler(t *testing.T) {
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}

	payload, err := quicwire.EncodePayload(&deviceGetWireRequest{})
	require.NoError(t, err)

	resp := h.handleDeviceOperation(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpDeviceGetState,
		Payload: payload,
	})

	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	assert.Equal(t, ErrQUICMissingField{Field: "id"}.Error(), string(resp.Payload))
}
