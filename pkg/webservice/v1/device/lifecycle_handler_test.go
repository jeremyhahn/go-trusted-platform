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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type stubLifecycleService struct {
	platformv1.UnimplementedDeviceServiceServer
	disabled  []string
	enabled   []string
	gotReason string
	resp      *platformv1.DeviceLifecycleResponse
	err       error
}

func (s *stubLifecycleService) DisableDevice(_ context.Context, req *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.disabled = append(s.disabled, req.GetDeviceId())
	s.gotReason = req.GetReason()
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func (s *stubLifecycleService) EnableDevice(_ context.Context, req *platformv1.EnableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.enabled = append(s.enabled, req.GetDeviceId())
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func lifecyclePost(t *testing.T, svc platformv1.DeviceServiceServer, id, action, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewLifecycleHandler(logging.DefaultLogger(), newTestResponseWriter(), svc)
	require.NotNil(t, h)
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/devices/{id:[0-9]+}/disable", h.HandleDisable).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/{id:[0-9]+}/enable", h.HandleEnable).Methods(http.MethodPost)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+id+"/"+action, strings.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestNewLifecycleHandler_NilServiceYieldsNilHandler(t *testing.T) {
	assert.Nil(t, NewLifecycleHandler(logging.DefaultLogger(), newTestResponseWriter(), nil))
}

func TestLifecycleHandler_DisableMirrorsTheProtoShape(t *testing.T) {
	svc := &stubLifecycleService{resp: &platformv1.DeviceLifecycleResponse{
		Status:        &platformv1.Status{Success: true},
		DeviceId:      42,
		State:         "suspended",
		PreviousState: "activated",
		StateReason:   "operator: rma pending",
	}}

	rec := lifecyclePost(t, svc, "42", "disable", `{"reason": "rma pending"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"42"}, svc.disabled)
	assert.Equal(t, "rma pending", svc.gotReason)

	var envelope struct {
		Payload DeviceLifecycleResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, uint64(42), envelope.Payload.DeviceID)
	assert.Equal(t, "suspended", envelope.Payload.State)
	assert.Equal(t, "activated", envelope.Payload.PreviousState)
	assert.Equal(t, "operator: rma pending", envelope.Payload.StateReason)

	raw := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, `"42"`, string(mustField(t, raw["payload"], "device_id")),
		"the uint64 id travels as a string, as the SDK's REST transport expects")
}

func TestLifecycleHandler_DisableWithoutABody(t *testing.T) {
	svc := &stubLifecycleService{resp: &platformv1.DeviceLifecycleResponse{DeviceId: 42, State: "suspended"}}

	rec := lifecyclePost(t, svc, "42", "disable", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, svc.gotReason)
}

func TestLifecycleHandler_DisableRejectsAMalformedBody(t *testing.T) {
	svc := &stubLifecycleService{}

	rec := lifecyclePost(t, svc, "42", "disable", `{"reason": `)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, svc.disabled, "a malformed body never reaches the service")
}

func TestLifecycleHandler_EnableReportsTheReattestation(t *testing.T) {
	svc := &stubLifecycleService{resp: &platformv1.DeviceLifecycleResponse{
		DeviceId:               42,
		State:                  "quarantined",
		PreviousState:          "suspended",
		ReattestationRequested: true,
	}}

	rec := lifecyclePost(t, svc, "42", "enable", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"42"}, svc.enabled)

	var envelope struct {
		Payload DeviceLifecycleResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, "quarantined", envelope.Payload.State)
	assert.True(t, envelope.Payload.ReattestationRequested)
}

func TestLifecycleHandler_MapsServiceErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "reason too long"), http.StatusBadRequest},
		{"precondition", status.Error(codes.FailedPrecondition, "device is not on the fabric"), http.StatusBadRequest},
		{"not found", status.Error(codes.NotFound, "device not found"), http.StatusNotFound},
		{"internal", status.Error(codes.Internal, "store down"), http.StatusInternalServerError},
		{"non-status", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []string{"disable", "enable"} {
				rec := lifecyclePost(t, &stubLifecycleService{err: tc.err}, "42", action, "")
				assert.Equal(t, tc.want, rec.Code, "%s: %s", action, rec.Body.String())
			}
		})
	}
}
