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

package protorest_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
)

// errBodyRead is the failure a broken request body reports.
type errBodyRead struct{}

func (errBodyRead) Error() string { return "body read failed" }

// failingBody is a request body whose Read always fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errBodyRead{} }
func (failingBody) Close() error             { return nil }

// wrappedErr wraps another error, as service layers do around gRPC statuses.
type wrappedErr struct{ inner error }

func (e *wrappedErr) Error() string { return "wrapped: " + e.inner.Error() }
func (e *wrappedErr) Unwrap() error { return e.inner }

// okStatusErr is a non-nil error carrying a gRPC OK status.
type okStatusErr struct{}

func (okStatusErr) Error() string              { return "ok" }
func (okStatusErr) GRPCStatus() *status.Status { return status.New(codes.OK, "ok") }

func coverageWriter() response.HttpWriter {
	return response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
}

func coverageEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func TestDecodeRequest_ReadFailureIsTyped(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Body = failingBody{}

	err := protorest.DecodeRequest(req, &wrapperspb.StringValue{})

	var readErr *protorest.ErrReadBodyFailed
	require.ErrorAs(t, err, &readErr)
	assert.ErrorIs(t, err, errBodyRead{})
	assert.Contains(t, err.Error(), "body read failed")
}

func TestDecodeRequest_MalformedJSONUnwrapsCause(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"value":`))

	err := protorest.DecodeRequest(req, &wrapperspb.StringValue{})

	var jsonErr *protorest.ErrInvalidJSON
	require.ErrorAs(t, err, &jsonErr)
	require.NotNil(t, errors.Unwrap(err))
	assert.Equal(t, jsonErr.Cause, errors.Unwrap(err))
}

func TestWriteSuccessStatus_NilMessage(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   int
	}{
		{name: "created", status: http.StatusCreated, want: http.StatusCreated},
		{name: "ok", status: http.StatusOK, want: http.StatusOK},
		{name: "accepted falls back to ok", status: http.StatusAccepted, want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/x", nil)

			protorest.WriteSuccessStatus(w, req, coverageWriter(), tt.status, nil)

			assert.Equal(t, tt.want, w.Code)
			assert.Equal(t, true, coverageEnvelope(t, w)["success"])
		})
	}
}

func TestWriteSuccessStatus_MarshalFailureIs500(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	// protojson refuses a proto3 string field holding invalid UTF-8.
	protorest.WriteSuccessStatus(w, req, coverageWriter(), http.StatusOK, wrapperspb.String("\xff"))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, false, coverageEnvelope(t, w)["success"])
}

func TestWriteSuccessStatus_PayloadEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)

	protorest.WriteSuccessStatus(w, req, coverageWriter(), http.StatusCreated, wrapperspb.String("abc"))

	require.Equal(t, http.StatusCreated, w.Code)
	body := coverageEnvelope(t, w)
	assert.Equal(t, true, body["success"])
	assert.Equal(t, float64(http.StatusCreated), body["code"])
	assert.Equal(t, "abc", body["payload"])
}

func TestWriteError_StatusMapping(t *testing.T) {
	tests := []struct {
		code codes.Code
		want int
	}{
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.OutOfRange, http.StatusBadRequest},
		{codes.Unauthenticated, http.StatusUnauthorized},
		{codes.PermissionDenied, http.StatusForbidden},
		{codes.NotFound, http.StatusNotFound},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.Aborted, http.StatusConflict},
		{codes.FailedPrecondition, http.StatusConflict},
		{codes.ResourceExhausted, http.StatusTooManyRequests},
		{codes.Unimplemented, http.StatusNotImplemented},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.DeadlineExceeded, http.StatusGatewayTimeout},
		{codes.Internal, http.StatusInternalServerError},
		{codes.Unknown, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)

			protorest.WriteError(w, req, coverageWriter(), status.Error(tt.code, "boom"))

			assert.Equal(t, tt.want, w.Code)
		})
	}
}

func TestWriteError_OKStatusIs200(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	// status.Error(codes.OK, ...) is nil, so an OK status only reaches
	// WriteError through an error that reports it via GRPCStatus.
	protorest.WriteError(w, req, coverageWriter(), okStatusErr{})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, coverageEnvelope(t, w)["success"])
}

func TestWriteError_ConflictCarriesMessage(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	protorest.WriteError(w, req, coverageWriter(), status.Error(codes.FailedPrecondition, "sealed"))

	require.Equal(t, http.StatusConflict, w.Code)
	body := coverageEnvelope(t, w)
	assert.Equal(t, false, body["success"])
	assert.Equal(t, float64(http.StatusConflict), body["code"])
	assert.Contains(t, body["error"], "sealed")
}

func TestWriteError_WrappedStatusIsMapped(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	err := &wrappedErr{inner: status.Error(codes.NotFound, "missing")}
	protorest.WriteError(w, req, coverageWriter(), err)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWriteError_WrappedServiceUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	err := &wrappedErr{inner: &protorest.ErrServiceUnavailable{Service: "kms"}}
	protorest.WriteError(w, req, coverageWriter(), err)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "kms")
}

func TestQueryUint64(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    uint64
		wantErr bool
	}{
		{name: "absent", query: "", want: 0},
		{name: "max", query: "n=18446744073709551615", want: 18446744073709551615},
		{name: "zero", query: "n=0", want: 0},
		{name: "overflow", query: "n=18446744073709551616", wantErr: true},
		{name: "negative", query: "n=-1", wantErr: true},
		{name: "not a number", query: "n=abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x?"+tt.query, nil)

			got, err := protorest.QueryUint64(req, "n")

			if !tt.wantErr {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
				return
			}
			var queryErr *protorest.ErrInvalidQuery
			require.ErrorAs(t, err, &queryErr)
			assert.Equal(t, "n", queryErr.Name)
			assert.Zero(t, got)
			var numErr *strconv.NumError
			assert.ErrorAs(t, err, &numErr)
		})
	}
}

func TestQueryBool_InvalidIsTyped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x?flag=maybe", nil)

	got, err := protorest.QueryBool(req, "flag")

	assert.False(t, got)
	var queryErr *protorest.ErrInvalidQuery
	require.ErrorAs(t, err, &queryErr)
	assert.Equal(t, "maybe", queryErr.Value)
	assert.Equal(t, `invalid query parameter "flag" ("maybe"): `+queryErr.Cause.Error(), err.Error())
}

func TestIsProtoMessage(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want bool
	}{
		{name: "proto message", v: &emptypb.Empty{}, want: true},
		{name: "wrapper message", v: wrapperspb.Bool(true), want: true},
		{name: "plain struct", v: struct{}{}, want: false},
		{name: "string", v: "x", want: false},
		{name: "nil", v: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, protorest.IsProtoMessage(tt.v))
		})
	}
}

func TestErrorTypes_UnwrapAndNilCause(t *testing.T) {
	cause := errBodyRead{}
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{name: "read body", err: &protorest.ErrReadBodyFailed{Cause: cause}, wantMsg: "failed to read request body: body read failed"},
		{name: "invalid json", err: &protorest.ErrInvalidJSON{Cause: cause}, wantMsg: "invalid request body: body read failed"},
		{name: "marshal", err: &protorest.ErrMarshalFailed{Cause: cause}, wantMsg: "failed to encode response: body read failed"},
		{name: "query", err: &protorest.ErrInvalidQuery{Name: "a", Value: "b", Cause: cause}, wantMsg: `invalid query parameter "a" ("b"): body read failed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantMsg, tt.err.Error())
			assert.ErrorIs(t, tt.err, cause)
			assert.Equal(t, cause, errors.Unwrap(tt.err))
		})
	}

	assert.Equal(t, "failed to encode response", (&protorest.ErrMarshalFailed{}).Error())
	assert.NoError(t, errors.Unwrap(&protorest.ErrMarshalFailed{}))
}
