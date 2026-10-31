package rest

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatewayErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var errResp ErrorResponse
	decodeResponse(t, rec.Body, &errResp)
	return errResp.Error
}

func callGateway(handle http.HandlerFunc, vars map[string]string) *httptest.ResponseRecorder {
	req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), vars)
	rec := httptest.NewRecorder()
	handle(rec, req)
	return rec
}

// Path variables the router cannot produce (empty, or not valid percent
// encoding) are refused before the gateway service is reached.
func TestGatewayAPIRest_PathVariableRefusals(t *testing.T) {
	h := NewGatewayHandlers(newMockGatewayService(), slog.Default())
	cases := []struct {
		name   string
		handle http.HandlerFunc
		vars   map[string]string
		want   error
	}{
		{"withdraw empty prefix", h.handleWithdrawPrefix, map[string]string{"prefix": ""}, ErrInvalidPrefix{}},
		{"withdraw undecodable prefix", h.handleWithdrawPrefix, map[string]string{"prefix": "10.0.0.0%zz"}, ErrInvalidPrefix{Prefix: "10.0.0.0%zz"}},
		{"get pool empty id", h.handleGetIPAMPool, map[string]string{"id": ""}, ErrInvalidPoolID{}},
		{"update pool empty id", h.handleUpdateIPAMPool, map[string]string{"id": ""}, ErrInvalidPoolID{}},
		{"delete pool empty id", h.handleDeleteIPAMPool, map[string]string{"id": ""}, ErrInvalidPoolID{}},
		{"release empty ip", h.handleReleaseIP, map[string]string{"ip": ""}, ErrInvalidIPAddress{}},
		{"release undecodable ip", h.handleReleaseIP, map[string]string{"ip": "10.0.0.1%g"}, ErrInvalidIPAddress{IP: "10.0.0.1%g"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := callGateway(tc.handle, tc.vars)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want.Error(), gatewayErrorMessage(t, rec))
		})
	}
}

func TestGatewayAPIRest_AdmittedVTEPsWithoutService(t *testing.T) {
	h := NewGatewayHandlers(nil, slog.Default())
	handlers := map[string]http.HandlerFunc{
		"list": h.handleListAdmittedVTEPs,
		"get":  h.handleGetAdmittedVTEP,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := callGateway(handle, map[string]string{"vtep": "10.0.0.1"})
			require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Equal(t, ErrGatewayServiceNotAvailable{}.Error(), gatewayErrorMessage(t, rec))
		})
	}
}

func TestGatewayAPIRest_GetAdmittedVTEPInvalidIP(t *testing.T) {
	h := NewGatewayHandlers(newMockGatewayService(), slog.Default())

	rec := callGateway(h.handleGetAdmittedVTEP, map[string]string{"vtep": "not-an-ip"})

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, ErrGatewayOperationFailed{Operation: "get_admitted_vtep", Cause: ErrInvalidIPAddress{IP: "not-an-ip"}}.Error(),
		gatewayErrorMessage(t, rec))
}

func TestGatewayAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := NewGatewayHandlers(newMockGatewayService(), slog.Default())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestGatewayAPIRest_LBWithoutService(t *testing.T) {
	h := NewGatewayHandlers(nil, slog.Default())
	handlers := map[string]http.HandlerFunc{
		"list vips":    h.handleListVIPs,
		"get vip":      h.handleGetVIP,
		"remove vip":   h.handleRemoveVIP,
		"set backends": h.handleSetVIPBackends,
		"lb status":    h.handleGetLBStatus,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := callGateway(handle, map[string]string{"protocol": "tcp", "address": "10.0.0.1", "port": "80"})
			require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Equal(t, ErrGatewayServiceNotAvailable{}.Error(), gatewayErrorMessage(t, rec))
		})
	}
}

func TestGatewayAPIRest_LBVIPRefusals(t *testing.T) {
	h := NewGatewayHandlers(newMockGatewayService(), slog.Default())
	badPort := ErrLBInvalidVIP{Reason: "port must be 1-65535"}
	cases := []struct {
		name   string
		handle http.HandlerFunc
		port   string
		want   error
	}{
		{"remove with port zero", h.handleRemoveVIP, "0", ErrGatewayOperationFailed{Operation: "remove_vip", Cause: badPort}},
		{"set backends with port out of range", h.handleSetVIPBackends, "65536", ErrGatewayOperationFailed{Operation: "set_vip_backends", Cause: badPort}},
		{"set backends with malformed body", h.handleSetVIPBackends, "80", ErrInvalidRequestBody{Reason: "unexpected EOF"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"backends":`)),
				map[string]string{"protocol": "tcp", "address": "10.0.0.1", "port": tc.port})
			rec := httptest.NewRecorder()
			tc.handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want.Error(), gatewayErrorMessage(t, rec))
		})
	}
}
