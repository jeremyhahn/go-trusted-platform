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

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// stubAttestDeviceService records what the handler passed down and returns a
// scripted answer, so the test exercises HTTP binding without standing up a
// verifier.
type stubAttestDeviceService struct {
	platformv1.UnimplementedDeviceServiceServer
	gotDeviceID string
	gotEvidence []byte
	resp        *platformv1.AttestDeviceResponse
	err         error
}

func (s *stubAttestDeviceService) AttestDevice(
	_ context.Context,
	req *platformv1.AttestDeviceRequest,
) (*platformv1.AttestDeviceResponse, error) {
	s.gotDeviceID = req.GetDeviceId()
	s.gotEvidence = req.GetEvidence()
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func attestPost(t *testing.T, h AttestHandler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/devices/"+id+"/attest", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": id})
	rr := httptest.NewRecorder()
	h.HandleAttestDevice(rr, req)
	return rr
}

// TestAttestHandler_PassesEvidenceThroughUnchanged proves the REST layer
// binds HTTP and nothing more: the device id comes from the path, the
// evidence bytes reach the service byte-for-byte, and the verdict is
// rendered as sent. Any transformation here would be a second opinion about
// evidence, which is exactly what having one verifier is meant to prevent.
func TestAttestHandler_PassesEvidenceThroughUnchanged(t *testing.T) {
	attestedAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	svc := &stubAttestDeviceService{resp: &platformv1.AttestDeviceResponse{
		DeviceId:          42,
		Serial:            "SN-42",
		Model:             "test-model",
		Verified:          true,
		SignatureValid:    true,
		NonceValid:        true,
		PcrsValid:         true,
		AttestationStatus: "verified",
		AttestedAt:        timestamppb.New(attestedAt),
	}}
	h := NewAttestHandler(logging.DefaultLogger(), &mockResponseWriter{}, svc)
	require.NotNil(t, h)

	evidence := []byte(`{"quote":"AAEC"}`)
	body, err := json.Marshal(AttestRequest{Evidence: evidence})
	require.NoError(t, err)

	rr := attestPost(t, h, "42", string(body))
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "42", svc.gotDeviceID)
	assert.Equal(t, evidence, svc.gotEvidence, "evidence must reach the verifier unaltered")

	var got AttestResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.True(t, got.Verified)
	assert.Equal(t, "verified", got.AttestationStatus)
	assert.Equal(t, uint64(42), got.DeviceID)
	assert.Equal(t, attestedAt, got.AttestedAt.UTC())
}

// TestAttestHandler_FailedVerdictIs200 mirrors the gRPC contract: a device
// that did not attest is a successful answer carrying a negative verdict,
// not an HTTP error. A console must be able to show WHICH check failed, and
// a 4xx/5xx would leave it saying only that something went wrong.
func TestAttestHandler_FailedVerdictIs200(t *testing.T) {
	svc := &stubAttestDeviceService{resp: &platformv1.AttestDeviceResponse{
		DeviceId:          7,
		Verified:          false,
		SignatureValid:    false,
		NonceValid:        true,
		PcrsValid:         true,
		AttestationStatus: "failed",
		Message:           "quote signature verification failed",
		AttestedAt:        timestamppb.Now(),
	}}
	h := NewAttestHandler(logging.DefaultLogger(), &mockResponseWriter{}, svc)

	rr := attestPost(t, h, "7", `{"evidence":"AAEC"}`)
	require.Equal(t, http.StatusOK, rr.Code, "a negative verdict is not an HTTP error")

	var got AttestResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.False(t, got.Verified)
	assert.False(t, got.SignatureValid)
	assert.True(t, got.NonceValid, "the checks that passed must still be reported")
	assert.NotEmpty(t, got.Message)
}

// TestAttestHandler_RejectsUnusableRequests covers the error direction. A
// request that cannot be evaluated fails closed with a client error — an
// absent or unreadable body is never treated as a device that attested.
func TestAttestHandler_RejectsUnusableRequests(t *testing.T) {
	tests := []struct {
		name string
		id   string
		body string
	}{
		{"no device id", "", `{"evidence":"AAEC"}`},
		{"no evidence field", "9", `{}`},
		{"empty evidence", "9", `{"evidence":""}`},
		{"body is not json", "9", `not json at all`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &stubAttestDeviceService{resp: &platformv1.AttestDeviceResponse{}}
			h := NewAttestHandler(logging.DefaultLogger(), &mockResponseWriter{}, svc)

			rr := attestPost(t, h, tt.id, tt.body)
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Empty(t, svc.gotEvidence, "an unusable request must not reach the verifier")
		})
	}
}

// TestAttestHandler_ServiceErrorIsNotAVerdict guards the distinction the
// whole design rests on: when the verifier could not evaluate the evidence,
// the response must not look like a device that failed attestation. Absence
// of evidence is not failed attestation — the same rule the design of record
// records for quarantine.
func TestAttestHandler_ServiceErrorIsNotAVerdict(t *testing.T) {
	svc := &stubAttestDeviceService{err: status.Error(codes.NotFound, "device not found")}
	h := NewAttestHandler(logging.DefaultLogger(), &mockResponseWriter{}, svc)

	rr := attestPost(t, h, "404", `{"evidence":"AAEC"}`)

	assert.NotEqual(t, http.StatusOK, rr.Code,
		"a verifier error must not be rendered as a 200 verdict")
	assert.False(t, strings.Contains(rr.Body.String(), `"verified":false`),
		"an unevaluated request must not produce a verdict field at all")
}

// TestNewAttestHandler_NilServiceYieldsNilHandler proves an unconfigured
// service produces no handler, so the route is never registered rather than
// registered and answering 503. An absent capability should not look like a
// broken one — that distinction is what #227 disabled the console control
// for.
func TestNewAttestHandler_NilServiceYieldsNilHandler(t *testing.T) {
	assert.Nil(t, NewAttestHandler(logging.DefaultLogger(), &mockResponseWriter{}, nil))
}
