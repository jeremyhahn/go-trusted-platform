package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func decodeProxyError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env proxyErrorEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	return env.Error
}

// Every proxy endpoint maps the backend's gRPC status to the HTTP status
// and returns the backend message in the error envelope.
func TestProxyAPIRest_ServiceErrorsMapToHTTPStatus(t *testing.T) {
	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/proxy/routes", `{"route":{"id":"r1"}}`},
		{http.MethodGet, "/api/v1/proxy/routes", ""},
		{http.MethodGet, "/api/v1/proxy/routes/r1", ""},
		{http.MethodPut, "/api/v1/proxy/routes/r1", `{}`},
		{http.MethodDelete, "/api/v1/proxy/routes/r1", ""},
		{http.MethodPost, "/api/v1/proxy/pools", `{}`},
		{http.MethodGet, "/api/v1/proxy/pools", ""},
		{http.MethodGet, "/api/v1/proxy/pools/p1", ""},
		{http.MethodPut, "/api/v1/proxy/pools/p1", `{}`},
		{http.MethodDelete, "/api/v1/proxy/pools/p1", ""},
		{http.MethodGet, "/api/v1/proxy/config", ""},
		{http.MethodPost, "/api/v1/proxy/reload", ""},
	}
	errorCases := []struct {
		code       codes.Code
		wantStatus int
	}{
		{codes.NotFound, http.StatusNotFound},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.PermissionDenied, http.StatusForbidden},
		{codes.Unknown, http.StatusInternalServerError},
	}

	for _, ep := range endpoints {
		for _, ec := range errorCases {
			t.Run(ep.method+" "+ep.path+" "+ec.code.String(), func(t *testing.T) {
				router := newProxyTestRouter(&fakeProxyBackend{err: status.Error(ec.code, "backend says no")})
				req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				require.Equal(t, ec.wantStatus, rec.Code)
				assert.Contains(t, decodeProxyError(t, rec), "backend says no")
			})
		}
	}
}

func TestProxyAPIRest_MissingPathID(t *testing.T) {
	h := NewProxyHandlers(&fakeProxyBackend{}, nil)
	handlers := map[string]http.HandlerFunc{
		"get route":    h.handleGetRoute,
		"update route": h.handleUpdateRoute,
		"delete route": h.handleDeleteRoute,
		"get pool":     h.handleGetPool,
		"update pool":  h.handleUpdatePool,
		"delete pool":  h.handleDeletePool,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{})
			rec := httptest.NewRecorder()
			handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrProxyMissingID{}.Error(), decodeProxyError(t, rec))
		})
	}
}

func TestProxyAPIRest_DecodeBody(t *testing.T) {
	h := NewProxyHandlers(&fakeProxyBackend{}, nil)

	t.Run("nil body is an empty request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = nil
		rec := httptest.NewRecorder()
		var msg platformv1.CreateProxyRouteRequest
		assert.True(t, h.decodeBody(rec, req, &msg))
		assert.Nil(t, msg.GetRoute())
	})

	t.Run("unknown fields are discarded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"route":{"id":"r9"},"extra":1}`))
		rec := httptest.NewRecorder()
		var msg platformv1.CreateProxyRouteRequest
		require.True(t, h.decodeBody(rec, req, &msg))
		assert.Equal(t, "r9", msg.GetRoute().GetId())
	})

	t.Run("body read failure", func(t *testing.T) {
		readErr := errors.New("connection reset")
		req := httptest.NewRequest(http.MethodPost, "/", iotest.ErrReader(readErr))
		rec := httptest.NewRecorder()
		var msg platformv1.CreateProxyRouteRequest
		assert.False(t, h.decodeBody(rec, req, &msg))
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "invalid proxy request body: connection reset", decodeProxyError(t, rec))
	})

	t.Run("invalid json on pool create", func(t *testing.T) {
		router := newProxyTestRouter(&fakeProxyBackend{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/pools", strings.NewReader(`{"pool":`))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, decodeProxyError(t, rec), "invalid proxy request body")
	})
}

func TestProxyAPIRest_InvalidBodyOnUpdate(t *testing.T) {
	for _, path := range []string{"/api/v1/proxy/routes/r1", "/api/v1/proxy/pools/p1"} {
		t.Run(path, func(t *testing.T) {
			router := newProxyTestRouter(&fakeProxyBackend{})
			req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`not json`))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, decodeProxyError(t, rec), "invalid proxy request body")
		})
	}
}

func TestErrProxyInvalidRequestBody_Unwrap(t *testing.T) {
	cause := errors.New("bad json")
	err := error(ErrProxyInvalidRequestBody{Cause: cause})

	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "invalid proxy request body: bad json", err.Error())
	var typed ErrProxyInvalidRequestBody
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, cause, typed.Cause)
}

// A backend response that protojson cannot encode (invalid UTF-8 in a
// string field) is reported as a 500, never a truncated 200.
func TestProxyAPIRest_WriteProtoMarshalFailure(t *testing.T) {
	backend := &fakeProxyBackend{
		getRouteResp: &platformv1.GetProxyRouteResponse{Route: &platformv1.ProxyRoute{Id: "\xff\xfe"}},
	}
	router := newProxyTestRouter(backend)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/proxy/routes/r1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, decodeProxyError(t, rec), "UTF-8")
}
