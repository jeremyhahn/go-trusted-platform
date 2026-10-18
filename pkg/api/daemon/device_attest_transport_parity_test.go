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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// These tests exercise the REST and QUIC device-attest surfaces against the
// REAL DeviceQuoteVerifier rather than a stub, because the defect they pin
// (#403) was a verifier that could not fail: both transports carried a
// handler-local verifyTPMAttestation that logged the evidence lengths and
// returned true, so any request with a non-empty nonce, quote and signature
// reported the device attested.
//
// A test asserting only that the verifier is called would have passed
// against that stub too. So each transport is driven with a quote signed by
// a key the device did not enroll, and must answer verified=false.

// restAttestRouter mounts the device REST routes over the fixture's real
// DeviceGRPCService. Device and profile services are nil: the attest route
// reaches the verifier through the gRPC service and touches neither.
func restAttestRouter(t *testing.T, f *quoteFixture) *mux.Router {
	t.Helper()
	handlers := restapi.NewDeviceHandlers(nil, nil, slog.Default(),
		restapi.WithDeviceAttestService(f.grpcService(t)))
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router
}

// postRESTAttest posts evidence to the REST attest route and decodes the
// verdict.
func postRESTAttest(t *testing.T, router *mux.Router, deviceID uint64, evidence []byte) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string][]byte{"evidence": evidence})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+itoa(deviceID)+"/attest",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var decoded map[string]any
	if w.Body.Len() > 0 {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
	}
	return w.Result().StatusCode, decoded
}

func TestRESTDeviceAttest_RefusesForgedQuote(t *testing.T) {
	f := newQuoteFixture(t)
	router := restAttestRouter(t, f)

	// A quote signed by a key the device never enrolled. The AK certificate
	// on the device record is the trust anchor, so this must not verify.
	forger, _ := newAttestTestKey(t)
	forged := signedEvidence(t, forger, []byte("forged-nonce-0001"), goldenPCRs(), goldenPCRs())

	code, verdict := postRESTAttest(t, router, f.device.ID, forged)

	require.Equal(t, http.StatusOK, code,
		"an evaluated quote is a successful call; the verdict carries the failure")
	assert.Equal(t, false, verdict["verified"],
		"REST must refuse a quote signed by a key the device did not enroll")
	assert.Equal(t, false, verdict["signature_valid"])
	assert.Equal(t, "failed", verdict["attestation_status"])
	assert.NotEmpty(t, verdict["message"], "the verdict must say why it failed")
}

func TestRESTDeviceAttest_AcceptsGenuineQuote(t *testing.T) {
	f := newQuoteFixture(t)
	router := restAttestRouter(t, f)

	evidence := f.evidence(t, []byte("genuine-nonce-001"), goldenPCRs())

	code, verdict := postRESTAttest(t, router, f.device.ID, evidence)

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, verdict["verified"])
	assert.Equal(t, true, verdict["signature_valid"])
	assert.Equal(t, true, verdict["ak_certificate_verified"])
	assert.Equal(t, "verified", verdict["attestation_status"])
}

func TestRESTDeviceAttest_UnknownDeviceIsNotAVerdict(t *testing.T) {
	f := newQuoteFixture(t)
	router := restAttestRouter(t, f)

	code, _ := postRESTAttest(t, router, f.device.ID+9999,
		f.evidence(t, []byte("nonce-for-nobody1"), goldenPCRs()))

	assert.Equal(t, http.StatusNotFound, code,
		"a device that does not exist cannot be evaluated, so it is an error, not verified=false")
}

// Evidence with no PCR values cannot be evaluated; that is a 400 the
// caller can correct, not a 500 (#949). The body is the integration
// suite's forged shape.
func TestRESTDeviceAttest_UnusableEvidenceIsBadRequest(t *testing.T) {
	f := newQuoteFixture(t)
	router := restAttestRouter(t, f)

	code, body := postRESTAttest(t, router, f.device.ID,
		[]byte(`{"quote":"eA==","signature":"eA==","nonce":"eA=="}`))

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, fmt.Sprint(body), "pcrs are required")
}

// quicAttestHandler builds the live QUIC dispatcher's device handler over
// the fixture's real DeviceGRPCService.
func quicAttestHandler(t *testing.T, f *quoteFixture) *QUICServiceHandler {
	t.Helper()
	return &QUICServiceHandler{
		deviceService:  f.devices,
		profileService: f.profiles,
		logger:         logging.DefaultLogger(),
		deviceGRPC:     f.grpcService(t),
	}
}

func quicAttest(t *testing.T, h *QUICServiceHandler, deviceID uint64, evidence []byte) *platformv1.AttestDeviceResponse {
	t.Helper()
	payload, err := quicwire.EncodePayload(&platformv1.AttestDeviceRequest{DeviceId: itoa(deviceID), Evidence: evidence})
	require.NoError(t, err)
	resp := h.handleDeviceOperation(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpDeviceAttest,
		Payload: payload,
	})
	require.Equal(t, quicwire.StatusOK, resp.Status)
	var decoded platformv1.AttestDeviceResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &decoded))
	return &decoded
}

func TestQUICDeviceAttest_RefusesForgedQuote(t *testing.T) {
	f := newQuoteFixture(t)
	h := quicAttestHandler(t, f)

	forger, _ := newAttestTestKey(t)
	forged := signedEvidence(t, forger, []byte("forged-nonce-0002"), goldenPCRs(), goldenPCRs())

	decoded := quicAttest(t, h, f.device.ID, forged)

	assert.False(t, decoded.GetVerified(),
		"QUIC must refuse a quote signed by a key the device did not enroll")
	assert.False(t, decoded.GetSignatureValid())
	assert.Equal(t, "failed", decoded.GetAttestationStatus())
	assert.NotEmpty(t, decoded.GetMessage())
}

// QUIC answers evidence with no PCR values with StatusInvalidArgument, the
// status REST's 400 and gRPC's InvalidArgument carry (#949).
func TestQUICDeviceAttest_UnusableEvidenceIsInvalidArgument(t *testing.T) {
	f := newQuoteFixture(t)
	h := quicAttestHandler(t, f)

	payload, err := quicwire.EncodePayload(&platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: []byte(`{"quote":"eA==","signature":"eA==","nonce":"eA=="}`),
	})
	require.NoError(t, err)
	resp := h.handleDeviceOperation(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpDeviceAttest,
		Payload: payload,
	})

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// TestMCPDeviceAttest_UnusableEvidenceIsInvalidArgument pins the MCP class:
// the MCP provider hands back the verifier's typed error, and MCP classifies
// it through errclass, so the error itself must report InvalidArgument.
func TestMCPDeviceAttest_UnusableEvidenceIsInvalidArgument(t *testing.T) {
	err := fmt.Errorf("device_attest: %w", ErrInvalidAttestationEvidence{Reason: "pcrs are required"})
	if got := mcpErrorClass(err); got != codes.InvalidArgument {
		t.Fatalf("MCP class = %v, want InvalidArgument", got)
	}
	if got := mcpErrorClass(ErrDeviceOperationFailed{Operation: "attest", Cause: errors.New("store down")}); got == codes.InvalidArgument {
		t.Fatalf("an operation failure must not be classified InvalidArgument")
	}
}

func TestQUICDeviceAttest_AcceptsGenuineQuote(t *testing.T) {
	f := newQuoteFixture(t)
	h := quicAttestHandler(t, f)

	decoded := quicAttest(t, h, f.device.ID, f.evidence(t, []byte("genuine-nonce-002"), goldenPCRs()))

	assert.True(t, decoded.GetVerified())
	assert.True(t, decoded.GetAkCertificateVerified())
	assert.Equal(t, "verified", decoded.GetAttestationStatus())
}

// TestDeviceAttest_TransportsAgreeOnOneVerdict is the property the single
// verifier exists for: the same evidence answers identically on every
// transport. A per-transport verifier is how two of them come to disagree.
func TestDeviceAttest_TransportsAgreeOnOneVerdict(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, f *quoteFixture) []byte
	}{
		{
			name: "genuine quote",
			build: func(t *testing.T, f *quoteFixture) []byte {
				return f.evidence(t, []byte("agree-nonce-00001"), goldenPCRs())
			},
		},
		{
			name: "quote signed by an unenrolled key",
			build: func(t *testing.T, f *quoteFixture) []byte {
				forger, _ := newAttestTestKey(t)
				return signedEvidence(t, forger, []byte("agree-nonce-00002"), goldenPCRs(), goldenPCRs())
			},
		},
		{
			name: "reported PCRs disagree with the quote",
			build: func(t *testing.T, f *quoteFixture) []byte {
				reported := goldenPCRs()
				reported[0] = fillPCR(0xEE)
				return signedEvidence(t, f.key, []byte("agree-nonce-00003"), goldenPCRs(), reported)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One fixture, one device, one enrolled attestation key: the
			// same evidence is submitted on all three transports. A second
			// fixture would carry a different CA and a different AK, so a
			// genuine quote would fail there for a reason unrelated to the
			// property under test.
			f := newQuoteFixture(t)
			evidence := tc.build(t, f)

			grpcResp, err := f.grpcService(t).AttestDevice(context.Background(),
				&platformv1.AttestDeviceRequest{
					DeviceId: itoa(f.device.ID),
					Evidence: evidence,
				})
			require.NoError(t, err)

			_, restVerdict := postRESTAttest(t, restAttestRouter(t, f), f.device.ID, evidence)

			quicVerdict := quicAttest(t, quicAttestHandler(t, f), f.device.ID, evidence)

			assert.Equal(t, grpcResp.GetVerified(), restVerdict["verified"],
				"REST and gRPC must reach the same verdict")
			assert.Equal(t, grpcResp.GetVerified(), quicVerdict.GetVerified(),
				"QUIC and gRPC must reach the same verdict")
			assert.Equal(t, grpcResp.GetSignatureValid(), restVerdict["signature_valid"])
			assert.Equal(t, grpcResp.GetSignatureValid(), quicVerdict.GetSignatureValid())
			assert.Equal(t, grpcResp.GetAttestationStatus(), restVerdict["attestation_status"])
			assert.Equal(t, grpcResp.GetAttestationStatus(), quicVerdict.GetAttestationStatus())
		})
	}
}
