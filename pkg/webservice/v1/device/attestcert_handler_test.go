// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

type stubRecordAttestCertService struct {
	platformv1.UnimplementedDeviceServiceServer
	gotDeviceID string
	gotReissue  bool
	gotClear    bool
	calls       int
	resp        *platformv1.RecordAttestationCertificateResponse
	err         error
}

func (s *stubRecordAttestCertService) RecordAttestationCertificate(
	_ context.Context,
	req *platformv1.RecordAttestationCertificateRequest,
) (*platformv1.RecordAttestationCertificateResponse, error) {
	s.calls++
	s.gotDeviceID = req.GetDeviceId()
	s.gotReissue = req.GetReissue()
	s.gotClear = req.GetClearOnRefusal()
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

var recordNotAfter = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

func recordedResponse() *platformv1.RecordAttestationCertificateResponse {
	return &platformv1.RecordAttestationCertificateResponse{
		Status:            &platformv1.Status{Success: true},
		DeviceId:          42,
		Serial:            "SN0042",
		Model:             "SuperMicro X10",
		Changed:           true,
		Source:            "ca",
		SourceDetail:      "SuperMicro X10-SN0042",
		Subject:           "CN=SuperMicro X10-SN0042",
		CertificateSerial: "777",
		NotAfter:          timestamppb.New(recordNotAfter),
		AttestCert:        "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
	}
}

func recordPost(t *testing.T, h AttestCertHandler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/devices/{id:[0-9]+}/attest-cert/record", h.HandleRecordAttestCert).Methods(http.MethodPost)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+id+"/attest-cert/record", strings.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func newRecordHandler(svc platformv1.DeviceServiceServer) AttestCertHandler {
	return NewAttestCertHandler(logging.DefaultLogger(), newTestResponseWriter(), svc)
}

func TestNewAttestCertHandler_NilServiceYieldsNilHandler(t *testing.T) {
	assert.Nil(t, NewAttestCertHandler(logging.DefaultLogger(), newTestResponseWriter(), nil))
}

func TestAttestCertHandler_RecordsAndMirrorsTheProtoShape(t *testing.T) {
	svc := &stubRecordAttestCertService{resp: recordedResponse()}
	rec := recordPost(t, newRecordHandler(svc), "42", `{"reissue": true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "42", svc.gotDeviceID)
	assert.True(t, svc.gotReissue)

	var envelope struct {
		Payload RecordAttestCertResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	got := envelope.Payload
	assert.Equal(t, uint64(42), got.DeviceID)
	assert.Equal(t, "SN0042", got.Serial)
	assert.True(t, got.Changed)
	assert.Equal(t, "ca", got.Source)
	assert.Equal(t, "SuperMicro X10-SN0042", got.SourceDetail)
	assert.Equal(t, "CN=SuperMicro X10-SN0042", got.Subject)
	assert.Equal(t, "777", got.CertificateSerial)
	require.NotNil(t, got.NotAfter)
	assert.True(t, recordNotAfter.Equal(*got.NotAfter))
	assert.Equal(t, recordedResponse().AttestCert, got.AttestCert)

	// The pb reply decodes from the same JSON: proto field names and the
	// uint64-as-string id are what the SDK's REST transport expects.
	raw := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, `"42"`, string(mustField(t, raw["payload"], "device_id")))
}

func mustField(t *testing.T, payload json.RawMessage, name string) json.RawMessage {
	t.Helper()
	fields := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(payload, &fields))
	v, ok := fields[name]
	require.True(t, ok, "field %q missing in %s", name, string(payload))
	return v
}

func TestAttestCertHandler_EmptyBodyMeansNoReissue(t *testing.T) {
	svc := &stubRecordAttestCertService{resp: recordedResponse()}
	rec := recordPost(t, newRecordHandler(svc), "42", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.False(t, svc.gotReissue)
	assert.False(t, svc.gotClear, "clearing is never on unless the body asks for it")
}

func TestAttestCertHandler_ClearOnRefusalReportsTheClear(t *testing.T) {
	svc := &stubRecordAttestCertService{resp: &platformv1.RecordAttestationCertificateResponse{
		Status:            &platformv1.Status{Success: true, Message: "refused attestation certificate cleared"},
		DeviceId:          42,
		Changed:           true,
		Cleared:           true,
		Subject:           "CN=node-09",
		CertificateSerial: "777",
		Refusal:           "device: attestation certificate refused for device 42; nothing recorded",
	}}
	rec := recordPost(t, newRecordHandler(svc), "42", `{"clear_on_refusal": true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, svc.gotClear)
	assert.False(t, svc.gotReissue)

	var envelope struct {
		Payload RecordAttestCertResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	got := envelope.Payload
	assert.True(t, got.Cleared)
	assert.True(t, got.Changed)
	assert.Equal(t, "CN=node-09", got.Subject)
	assert.Contains(t, got.Refusal, "nothing recorded")
	assert.Empty(t, got.AttestCert)
	assert.Empty(t, got.Source)
}

func TestAttestCertHandler_MalformedBodyIs400(t *testing.T) {
	svc := &stubRecordAttestCertService{resp: recordedResponse()}
	rec := recordPost(t, newRecordHandler(svc), "42", `{"reissue": "yes"`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Zero(t, svc.calls, "a malformed body never reaches the service")
}

func TestAttestCertHandler_StatusMapping(t *testing.T) {
	cases := map[codes.Code]int{
		codes.FailedPrecondition: http.StatusBadRequest,
		codes.InvalidArgument:    http.StatusBadRequest,
		codes.NotFound:           http.StatusNotFound,
		codes.Aborted:            http.StatusConflict,
		codes.PermissionDenied:   http.StatusForbidden,
		codes.Unauthenticated:    http.StatusUnauthorized,
		codes.Unavailable:        http.StatusInternalServerError,
		codes.Internal:           http.StatusInternalServerError,
	}
	for code, want := range cases {
		t.Run(code.String(), func(t *testing.T) {
			svc := &stubRecordAttestCertService{err: status.Error(code, "device: attestation certificate refused for device 42; nothing recorded: ca[node-03]: lacks tcg-cap-verifiedTPMRestricted")}
			rec := recordPost(t, newRecordHandler(svc), "42", "")
			assert.Equal(t, want, rec.Code)
			assert.Contains(t, rec.Body.String(), "nothing recorded", "the refusal reason reaches the caller")
		})
	}
}

func TestAttestCertHandler_NonStatusErrorIs500(t *testing.T) {
	svc := &stubRecordAttestCertService{err: assert.AnError}
	rec := recordPost(t, newRecordHandler(svc), "42", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
