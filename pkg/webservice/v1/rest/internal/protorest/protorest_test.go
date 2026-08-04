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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

func newWriter() response.HttpWriter {
	return response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
}

func TestDecodeRequest_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	msg := &wrapperspb.StringValue{}
	require.NoError(t, protorest.DecodeRequest(req, msg))
	assert.Equal(t, "", msg.Value)
}

func TestDecodeRequest_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))
	msg := &wrapperspb.StringValue{}
	require.NoError(t, protorest.DecodeRequest(req, msg))
}

func TestDecodeRequest_ValidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`"hello"`))
	msg := &wrapperspb.StringValue{}
	require.NoError(t, protorest.DecodeRequest(req, msg))
	assert.Equal(t, "hello", msg.Value)
}

func TestDecodeRequest_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not-json"))
	msg := &wrapperspb.StringValue{}
	err := protorest.DecodeRequest(req, msg)
	require.Error(t, err)
	var typed *protorest.ErrInvalidJSON
	assert.ErrorAs(t, err, &typed)
}

func TestDecodeRequest_DiscardsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"page":3,"unknown":99}`))
	msg := &platformv1.PaginationRequest{}
	require.NoError(t, protorest.DecodeRequest(req, msg))
	assert.Equal(t, uint32(3), msg.Page)
}

func TestWriteSuccess_NilEmits200(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteSuccess(w, req, newWriter(), nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWriteSuccess_MarshalsProto(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteSuccess(w, req, newWriter(), &platformv1.PaginationRequest{Page: 7, PageSize: 25})
	assert.Equal(t, http.StatusOK, w.Code)
	var env response.WebServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	assert.True(t, env.Success)
	assert.Equal(t, http.StatusOK, env.Code)
	body, err := json.Marshal(env.Payload)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"page":7`)
}

func TestWriteSuccessStatus_201(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	protorest.WriteSuccessStatus(w, req, newWriter(), http.StatusCreated, &emptypb.Empty{})
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestWriteError_NilFallsBackTo500(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWriteError_GRPCCodeMapping(t *testing.T) {
	cases := []struct {
		code   codes.Code
		status int
	}{
		{codes.NotFound, http.StatusNotFound},
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.Unauthenticated, http.StatusUnauthorized},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.DeadlineExceeded, http.StatusGatewayTimeout},
		{codes.Unimplemented, http.StatusNotImplemented},
		{codes.ResourceExhausted, http.StatusTooManyRequests},
		{codes.Internal, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			protorest.WriteError(w, req, newWriter(), status.Error(tc.code, "boom"))
			assert.Equal(t, tc.status, w.Code)
		})
	}
}

func TestWriteError_PlainErrorIs500(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), errors.New("plain"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestQueryUint32(t *testing.T) {
	cases := []struct {
		raw    string
		want   uint32
		hasErr bool
	}{
		{"", 0, false},
		{"10", 10, false},
		{"abc", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x?n="+tc.raw, nil)
			got, err := protorest.QueryUint32(r, "n")
			if tc.hasErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestQueryBool(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?b=true", nil)
	got, err := protorest.QueryBool(r, "b")
	require.NoError(t, err)
	assert.True(t, got)

	r = httptest.NewRequest(http.MethodGet, "/x?b=junk", nil)
	_, err = protorest.QueryBool(r, "b")
	assert.Error(t, err)
}

func TestErrorTypes(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&protorest.ErrReadBodyFailed{Cause: errors.New("io")}, "failed to read request body: io"},
		{&protorest.ErrReadBodyFailed{}, "failed to read request body"},
		{&protorest.ErrInvalidJSON{Cause: errors.New("syntax")}, "invalid request body: syntax"},
		{&protorest.ErrInvalidJSON{}, "invalid request body"},
		{&protorest.ErrMarshalFailed{Cause: errors.New("oops")}, "failed to encode response: oops"},
		{&protorest.ErrUnknown{}, "unknown internal error"},
		{&protorest.ErrServiceUnavailable{Service: "svc"}, "svc service is not available"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.err.Error())
	}
}

// readBody is a helper for tests.
func readBody(b *bytes.Buffer) []byte {
	if b == nil {
		return nil
	}
	return b.Bytes()
}
