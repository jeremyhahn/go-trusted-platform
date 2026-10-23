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
	"strings"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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
	var env restwire.WebServiceResponse
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

// decodeEnvelope reads the JSON error body the writer produced.
func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// notConfiguredStatus builds the status a daemon gRPC service returns
// when its backend is absent on this node — codes.Unavailable carrying
// the ErrorInfo detail. It mirrors
// pkg/api/daemon/service_not_configured.go without importing it, so the
// REST layer's contract is pinned independently of the producer.
func notConfiguredStatus(t *testing.T, service, msg string) error {
	t.Helper()
	st, err := status.New(codes.Unavailable, msg).WithDetails(&errdetails.ErrorInfo{
		Reason:   response.ReasonServiceNotConfigured,
		Domain:   response.ErrorInfoDomain,
		Metadata: map[string]string{"service": service},
	})
	require.NoError(t, err)
	return st.Err()
}

func TestWriteError_ServiceUnavailableCarriesDiscriminator(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), &protorest.ErrServiceUnavailable{Service: "pxe"})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body := decodeEnvelope(t, w)
	assert.Equal(t, response.ReasonServiceNotConfigured, body["reason"])
	assert.Equal(t, "pxe", body["service"])
	assert.Equal(t, false, body["success"])
}

func TestWriteError_UnavailableWithErrorInfoCarriesDiscriminator(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(),
		notConfiguredStatus(t, "gateway", "gateway service is not configured on this node"))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body := decodeEnvelope(t, w)
	assert.Equal(t, response.ReasonServiceNotConfigured, body["reason"])
	assert.Equal(t, "gateway", body["service"])
}

func TestWriteError_UnavailableWithoutErrorInfoOmitsDiscriminator(t *testing.T) {
	// A configured service reporting a transient outage. It is still a
	// 503, but a client must NOT read it as "this node does not host
	// the service" — that distinction is the whole point of the
	// discriminator.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(),
		status.Error(codes.Unavailable, "gateway is not running"))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body := decodeEnvelope(t, w)
	_, hasReason := body["reason"]
	assert.False(t, hasReason, "transient 503 must not carry the not-configured discriminator")
}

func TestWriteError_UnavailableWithForeignErrorInfoOmitsDiscriminator(t *testing.T) {
	// An ErrorInfo from another API that happens to use the same reason
	// string is scoped out by the domain check, so it cannot be
	// mistaken for this platform's contract.
	st, err := status.New(codes.Unavailable, "upstream said so").WithDetails(&errdetails.ErrorInfo{
		Reason:   response.ReasonServiceNotConfigured,
		Domain:   "example.com",
		Metadata: map[string]string{"service": "gateway"},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), st.Err())

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body := decodeEnvelope(t, w)
	_, hasReason := body["reason"]
	assert.False(t, hasReason, "a foreign ErrorInfo domain must not satisfy the contract")
}

func TestWriteError_NonUnavailableIgnoresErrorInfo(t *testing.T) {
	// isServiceNotConfigured requires the 503 status too; the server
	// must not emit the discriminator under any other status.
	st, err := status.New(codes.Internal, "backend blew up").WithDetails(&errdetails.ErrorInfo{
		Reason:   response.ReasonServiceNotConfigured,
		Domain:   response.ErrorInfoDomain,
		Metadata: map[string]string{"service": "pxe"},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), st.Err())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	body := decodeEnvelope(t, w)
	_, hasReason := body["reason"]
	assert.False(t, hasReason)
}

func TestWriteError_UnavailableWithOtherReasonOmitsDiscriminator(t *testing.T) {
	// This platform's domain, but a different reason: the service is
	// present and reporting something else, so the not-configured
	// contract must not fire.
	st, err := status.New(codes.Unavailable, "gateway is draining").WithDetails(&errdetails.ErrorInfo{
		Reason:   "SERVICE_DRAINING",
		Domain:   response.ErrorInfoDomain,
		Metadata: map[string]string{"service": "gateway"},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	protorest.WriteError(w, req, newWriter(), st.Err())

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body := decodeEnvelope(t, w)
	_, hasReason := body["reason"]
	assert.False(t, hasReason, "a different reason must not satisfy the not-configured contract")
}
