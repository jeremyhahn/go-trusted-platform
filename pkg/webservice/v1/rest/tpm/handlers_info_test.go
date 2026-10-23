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

package tpm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// infoServer answers Info with a fixed response or error, so the tests pin
// the JSON the REST handler puts on the wire for it.
type infoServer struct {
	platformv1.UnimplementedTPMServiceServer

	resp *platformv1.TPMInfoResponse
	err  error
}

func (s *infoServer) Info(_ context.Context, _ *platformv1.TPMInfoRequest) (*platformv1.TPMInfoResponse, error) {
	return s.resp, s.err
}

func getInfo(t *testing.T, srv *infoServer) (*httptest.ResponseRecorder, map[string]json.RawMessage) {
	t.Helper()
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	parent := mux.NewRouter()
	NewTPMRouter(logging.NewLogger(slog.LevelError, io.Discard), srv, w).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)

	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	return rec, envelope
}

// The JavaScript SDK's TPMInfoResponse type (sdk/javascript/src/types/tpm.ts)
// is written against exactly this shape: a flat payload with camelCase keys,
// enums as their proto names, and an unset manufacturer as null. Changing any
// of these silently breaks every SDK caller, so they are pinned here (#325).
func TestInfo_WireShapeMatchesSDKType(t *testing.T) {
	srv := &infoServer{resp: &platformv1.TPMInfoResponse{
		Version:      platformv1.TPMVersion_TPM_VERSION_2_0,
		PcrBanks:     []platformv1.PCRBank{platformv1.PCRBank_PCR_BANK_SHA256},
		MaxNvramSize: 2048,
		IsSimulator:  true,
		Properties:   map[string]string{"info": "Manufacturer: IBM"},
		NvIndexes: []*platformv1.NVIndex{
			{Handle: 0x01c00002, Type: "ordinary", Size: 1024, AuthRead: true},
		},
	}}

	rec, envelope := getInfo(t, srv)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["payload"], &payload))

	assert.NotContains(t, payload, "tpm", "the payload is flat, not wrapped")
	assert.JSONEq(t, `"TPM_VERSION_2_0"`, string(payload["version"]))
	assert.JSONEq(t, `null`, string(payload["manufacturer"]))
	assert.JSONEq(t, `[]`, string(payload["capabilities"]))
	assert.JSONEq(t, `["PCR_BANK_SHA256"]`, string(payload["pcrBanks"]))
	assert.JSONEq(t, `2048`, string(payload["maxNvramSize"]))
	assert.JSONEq(t, `true`, string(payload["isSimulator"]))
	assert.JSONEq(t, `false`, string(payload["fipsMode"]))
	assert.JSONEq(t, `{"info":"Manufacturer: IBM"}`, string(payload["properties"]))
	assert.JSONEq(t,
		`[{"handle":29360130,"type":"ordinary","size":1024,"authRead":true,"authWrite":false}]`,
		string(payload["nvIndexes"]))
}

// A populated manufacturer serialises as an object with camelCase keys.
func TestInfo_ManufacturerIsAnObject(t *testing.T) {
	srv := &infoServer{resp: &platformv1.TPMInfoResponse{
		Manufacturer: &platformv1.TPMManufacturer{
			Name: "Infineon", Id: 0x49465800, Model: "SLB9670", FirmwareVersion: "7.85",
		},
	}}

	rec, envelope := getInfo(t, srv)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["payload"], &payload))
	assert.JSONEq(t,
		`{"name":"Infineon","id":1229346816,"model":"SLB9670","firmwareVersion":"7.85"}`,
		string(payload["manufacturer"]))
}

// A failing Info is an unsuccessful envelope with no payload: the SDK derives
// "TPM unavailable" from this, never from a field of a 200 response.
func TestInfo_ServiceErrorIsUnsuccessfulEnvelope(t *testing.T) {
	srv := &infoServer{err: status.Error(codes.Unavailable, "tpm device not open")}

	rec, envelope := getInfo(t, srv)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `false`, string(envelope["success"]))
	assert.Contains(t, string(envelope["error"]), "tpm device not open")
}
