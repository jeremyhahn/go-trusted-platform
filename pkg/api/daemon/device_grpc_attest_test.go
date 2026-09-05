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
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// enrolledDeviceGRPCService returns a DeviceGRPCService backed by the same
// mock device service the provider tests use, with one enrolled device.
func enrolledDeviceGRPCService(t *testing.T, akPubPEM string) (*DeviceGRPCService, uint64) {
	t.Helper()
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "test-model", Serial: "SN-1", AttestPub: akPubPEM}
	require.NoError(t, devSvc.Save(context.Background(), dev))
	return NewDeviceGRPCService(devSvc, nil, nil), dev.ID
}

// validAttestEvidence builds evidence that verifies against akPubPEM's key.
func validAttestEvidence(t *testing.T, key *rsa.PrivateKey, nonce []byte) []byte {
	t.Helper()
	pcrs := map[int][]byte{0: make([]byte, 32)}
	quote := buildAttestTestQuote(t, nonce, pcrs)
	sig := signAttestQuote(t, key, quote)
	evidence, err := json.Marshal(DeviceQuoteEvidence{
		Quote:        quote,
		Signature:    sig,
		Nonce:        nonce,
		ExpectedPCRs: pcrs,
	})
	require.NoError(t, err)
	return evidence
}

// TestDeviceGRPCService_AttestDevice_Success covers the happy path over the
// gRPC transport, which is also the Unix transport: the device service is
// registered on both the TCP and the UDS gRPC server from one construction
// (daemon.go), so this method serves both.
func TestDeviceGRPCService_AttestDevice_Success(t *testing.T) {
	key, pubPEM := newAttestTestKey(t)
	svc, id := enrolledDeviceGRPCService(t, pubPEM)

	resp, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(id),
		Evidence: validAttestEvidence(t, key, []byte("fresh-nonce-000001")),
	})
	require.NoError(t, err)

	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, id, resp.GetDeviceId())
	assert.Equal(t, "SN-1", resp.GetSerial())
	assert.True(t, resp.GetVerified())
	assert.True(t, resp.GetSignatureValid())
	assert.True(t, resp.GetNonceValid())
	assert.True(t, resp.GetPcrsValid())
	assert.Equal(t, "verified", resp.GetAttestationStatus())
	assert.False(t, resp.GetAttestedAt().AsTime().IsZero())
}

// TestDeviceGRPCService_AttestDevice_FailedVerificationIsNotAnError is the
// contract that matters most for a console.
//
// A device that fails to attest is a successful answer to the question the
// caller asked, carrying a negative verdict — not a transport error. If it
// were an error, the caller could not tell WHICH check failed without
// parsing a status message, and a UI would have to render "attestation
// errored" for a device that simply did not attest.
func TestDeviceGRPCService_AttestDevice_FailedVerificationIsNotAnError(t *testing.T) {
	_, pubPEM := newAttestTestKey(t)
	svc, id := enrolledDeviceGRPCService(t, pubPEM)

	// A different key signs the quote, so the signature cannot verify
	// against the device's enrolled attestation key.
	otherKey, _ := newAttestTestKey(t)

	resp, err := svc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(id),
		Evidence: validAttestEvidence(t, otherKey, []byte("fresh-nonce-000002")),
	})
	require.NoError(t, err, "a failed verification must not be reported as a transport error")

	assert.False(t, resp.GetVerified())
	assert.False(t, resp.GetSignatureValid(), "the signature check is the one that failed")
	assert.Equal(t, "failed", resp.GetAttestationStatus())
	assert.NotEmpty(t, resp.GetMessage(), "a negative verdict must say why")
}

// TestDeviceGRPCService_AttestDevice_RejectsIncompleteRequests covers the
// error direction: a request that cannot be evaluated at all is an error,
// and specifically InvalidArgument rather than Internal, so a caller is not
// told the server broke when the request was incomplete.
func TestDeviceGRPCService_AttestDevice_RejectsIncompleteRequests(t *testing.T) {
	_, pubPEM := newAttestTestKey(t)
	svc, id := enrolledDeviceGRPCService(t, pubPEM)

	tests := []struct {
		name string
		req  *platformv1.AttestDeviceRequest
	}{
		{"no device id", &platformv1.AttestDeviceRequest{Evidence: []byte(`{"quote":"x"}`)}},
		{"no evidence", &platformv1.AttestDeviceRequest{DeviceId: itoa(id)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.AttestDevice(context.Background(), tt.req)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestDeviceGRPCService_AttestDevice_MatchesTheProviderVerdict is the
// anti-divergence test.
//
// gRPC/Unix, QUIC and MCP must not be able to disagree about whether a
// device attested. They share verifyDeviceQuote today; this asserts the
// gRPC surface reports exactly what the provider reports for identical
// evidence, so a future change that gives one transport its own verifier
// fails here rather than in production on one protocol only.
func TestDeviceGRPCService_AttestDevice_MatchesTheProviderVerdict(t *testing.T) {
	key, pubPEM := newAttestTestKey(t)
	evidence := validAttestEvidence(t, key, []byte("fresh-nonce-000003"))

	grpcSvc, grpcID := enrolledDeviceGRPCService(t, pubPEM)
	provider, providerID := enrolledDeviceProvider(t, pubPEM)

	grpcResp, err := grpcSvc.AttestDevice(context.Background(), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(grpcID),
		Evidence: evidence,
	})
	require.NoError(t, err)

	raw, err := provider.DeviceAttest(context.Background(), itoa(providerID), evidence)
	require.NoError(t, err)
	providerResult, ok := raw.(*DeviceAttestationResult)
	require.True(t, ok)

	assert.Equal(t, providerResult.Verified, grpcResp.GetVerified())
	assert.Equal(t, providerResult.SignatureValid, grpcResp.GetSignatureValid())
	assert.Equal(t, providerResult.NonceValid, grpcResp.GetNonceValid())
	assert.Equal(t, providerResult.PCRsValid, grpcResp.GetPcrsValid())
	assert.Equal(t, providerResult.Status, grpcResp.GetAttestationStatus())
}

// TestQUICDeviceAttest_IsNoLongerNotImplemented is the regression guard for
// the stub this change removed.
//
// OpDeviceAttest answered StatusNotImplemented on the LIVE dispatcher while a
// complete handler existed in pkg/api/quic — a package with no non-test
// caller (#291). The operation therefore read as implemented to anyone
// grepping for it, and was a stub to anyone calling it. Asserting the live
// dispatcher does not answer StatusNotImplemented is the check that would
// have caught that, and the one that catches it coming back.
func TestQUICDeviceAttest_IsNoLongerNotImplemented(t *testing.T) {
	key, pubPEM := newAttestTestKey(t)
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "test-model", Serial: "SN-1", AttestPub: pubPEM}
	require.NoError(t, devSvc.Save(context.Background(), dev))

	h := &QUICServiceHandler{
		deviceService: devSvc,
		deviceGRPC:    NewDeviceGRPCService(devSvc, nil, nil),
		logger:        logging.DefaultLogger(),
	}

	payload, err := quic.EncodePayload(&platformv1.AttestDeviceRequest{
		DeviceId: itoa(dev.ID),
		Evidence: validAttestEvidence(t, key, []byte("fresh-nonce-000004")),
	})
	require.NoError(t, err)

	resp := h.handleDeviceOperation(context.Background(), &quic.Request{
		Opcode:  quic.OpDeviceAttest,
		Payload: payload,
	})

	require.NotNil(t, resp)
	assert.NotEqual(t, quic.StatusNotImplemented, resp.Status,
		"OpDeviceAttest must not answer StatusNotImplemented on the live dispatcher")
	assert.Equal(t, quic.StatusOK, resp.Status)
}
