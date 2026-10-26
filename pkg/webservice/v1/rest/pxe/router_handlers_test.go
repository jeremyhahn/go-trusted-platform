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

package pxe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// operatorPXE records the RPC and request each handler hands the service,
// and answers with resp, or with err when it is set.
type operatorPXE struct {
	platformv1.UnimplementedPXEServiceServer
	resp proto.Message
	err  error
	rpc  string
	req  proto.Message
}

func answer[T proto.Message](s *operatorPXE, rpc string, req proto.Message) (T, error) {
	s.rpc, s.req = rpc, req
	var none T
	if s.err != nil {
		return none, s.err
	}
	return s.resp.(T), nil
}

func (s *operatorPXE) GetStatus(_ context.Context, req *platformv1.GetPXEStatusRequest) (*platformv1.GetPXEStatusResponse, error) {
	return answer[*platformv1.GetPXEStatusResponse](s, "GetStatus", req)
}

func (s *operatorPXE) StartService(_ context.Context, req *platformv1.StartPXEServiceRequest) (*platformv1.StartPXEServiceResponse, error) {
	return answer[*platformv1.StartPXEServiceResponse](s, "StartService", req)
}

func (s *operatorPXE) StopService(_ context.Context, req *platformv1.StopPXEServiceRequest) (*platformv1.StopPXEServiceResponse, error) {
	return answer[*platformv1.StopPXEServiceResponse](s, "StopService", req)
}

func (s *operatorPXE) ListDevices(_ context.Context, req *platformv1.ListPXEDevicesRequest) (*platformv1.ListPXEDevicesResponse, error) {
	return answer[*platformv1.ListPXEDevicesResponse](s, "ListDevices", req)
}

func (s *operatorPXE) RegisterDevice(_ context.Context, req *platformv1.RegisterPXEDeviceRequest) (*platformv1.RegisterPXEDeviceResponse, error) {
	return answer[*platformv1.RegisterPXEDeviceResponse](s, "RegisterDevice", req)
}

func (s *operatorPXE) GetDevice(_ context.Context, req *platformv1.GetPXEDeviceRequest) (*platformv1.GetPXEDeviceResponse, error) {
	return answer[*platformv1.GetPXEDeviceResponse](s, "GetDevice", req)
}

func (s *operatorPXE) RemoveDevice(_ context.Context, req *platformv1.RemovePXEDeviceRequest) (*platformv1.RemovePXEDeviceResponse, error) {
	return answer[*platformv1.RemovePXEDeviceResponse](s, "RemoveDevice", req)
}

func (s *operatorPXE) GetDeviceByMAC(_ context.Context, req *platformv1.GetPXEDeviceByMACRequest) (*platformv1.GetPXEDeviceByMACResponse, error) {
	return answer[*platformv1.GetPXEDeviceByMACResponse](s, "GetDeviceByMAC", req)
}

func (s *operatorPXE) UpdateState(_ context.Context, req *platformv1.UpdatePXEStateRequest) (*platformv1.UpdatePXEStateResponse, error) {
	return answer[*platformv1.UpdatePXEStateResponse](s, "UpdateState", req)
}

func (s *operatorPXE) SetDeviceEnrolled(_ context.Context, req *platformv1.SetPXEDeviceEnrolledRequest) (*platformv1.SetPXEDeviceEnrolledResponse, error) {
	return answer[*platformv1.SetPXEDeviceEnrolledResponse](s, "SetDeviceEnrolled", req)
}

func (s *operatorPXE) Authorize(_ context.Context, req *platformv1.AuthorizePXEDeviceRequest) (*platformv1.AuthorizePXEDeviceResponse, error) {
	return answer[*platformv1.AuthorizePXEDeviceResponse](s, "Authorize", req)
}

func (s *operatorPXE) Quarantine(_ context.Context, req *platformv1.QuarantinePXEDeviceRequest) (*platformv1.QuarantinePXEDeviceResponse, error) {
	return answer[*platformv1.QuarantinePXEDeviceResponse](s, "Quarantine", req)
}

func (s *operatorPXE) Retry(_ context.Context, req *platformv1.RetryPXEDeviceRequest) (*platformv1.RetryPXEDeviceResponse, error) {
	return answer[*platformv1.RetryPXEDeviceResponse](s, "Retry", req)
}

func (s *operatorPXE) GetEvents(_ context.Context, req *platformv1.GetPXEEventsRequest) (*platformv1.GetPXEEventsResponse, error) {
	return answer[*platformv1.GetPXEEventsResponse](s, "GetEvents", req)
}

func (s *operatorPXE) WebhookComplete(_ context.Context, req *platformv1.PXEWebhookCompleteRequest) (*platformv1.PXEWebhookCompleteResponse, error) {
	return answer[*platformv1.PXEWebhookCompleteResponse](s, "WebhookComplete", req)
}

// handlerRoot mounts the operator routes and the enabled webhook under
// /api/v1, as v1Router does.
func handlerRoot(server platformv1.PXEServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	r := NewPXERouter(logger, server, response.NewResponseWriter(logger, nil), true)
	root := mux.NewRouter()
	sub := root.PathPrefix("/api/v1").Subrouter()
	r.RegisterMachineFacingRoutes(sub)
	r.RegisterRoutes(sub)
	return root
}

func serveHandler(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	return serveHandlerTLS(router, method, path, body, verifiedNodeTLS())
}

// serveHandlerTLS serves one request that arrived on a connection with state:
// nil is plain HTTP.
func serveHandlerTLS(router *mux.Router, method, path, body string, state *tls.ConnectionState) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.TLS = state
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// verifiedNodeTLS is a connection whose client certificate the TLS stack
// verified: a node presenting its device certificate over mTLS (#238).
func verifiedNodeTLS() *tls.ConnectionState {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "node"}}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}

// envelope is the restwire.WebServiceResponse every handler answers with.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

var handlerDevice = &platformv1.PXEDeviceInfo{
	Id:         knownDevice,
	MacAddress: "aa:bb:cc:dd:ee:ff",
	PortId:     "ge-0/0/7",
	State:      platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED,
}

var handlerOK = &platformv1.Status{Success: true, Message: "done"}

// handlerCase is one operator or webhook route: the request it is sent,
// the RPC and request message the service must receive, and the answer
// the service gives.
type handlerCase struct {
	method, path, body string
	rpc                string
	wantReq            proto.Message
	resp               proto.Message
	wantCode           int
}

var handlerCases = []handlerCase{
	{
		method: http.MethodGet, path: "/api/v1/pxe/status",
		rpc: "GetStatus", wantReq: &platformv1.GetPXEStatusRequest{},
		resp: &platformv1.GetPXEStatusResponse{Status: &platformv1.PXEServiceStatus{
			Running: true, DeviceCount: 2, IpxeServerAddr: "10.0.0.1:8080", QuarantineVlan: 999, ProvisioningVlan: 100,
		}},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/start",
		rpc: "StartService", wantReq: &platformv1.StartPXEServiceRequest{},
		resp: &platformv1.StartPXEServiceResponse{Status: handlerOK}, wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/stop",
		rpc: "StopService", wantReq: &platformv1.StopPXEServiceRequest{},
		resp: &platformv1.StopPXEServiceResponse{Status: handlerOK}, wantCode: http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/pxe/devices",
		rpc: "ListDevices", wantReq: &platformv1.ListPXEDevicesRequest{Filter: &platformv1.PXEDeviceFilter{}},
		resp:     &platformv1.ListPXEDevicesResponse{Devices: []*platformv1.PXEDeviceInfo{handlerDevice}, TotalCount: 1},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/pxe/devices?limit=10&offset=20",
		rpc: "ListDevices", wantReq: &platformv1.ListPXEDevicesRequest{Filter: &platformv1.PXEDeviceFilter{Limit: 10, Offset: 20}},
		resp:     &platformv1.ListPXEDevicesResponse{Devices: []*platformv1.PXEDeviceInfo{handlerDevice}, TotalCount: 1},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/devices",
		body: `{"macAddress":"aa:bb:cc:dd:ee:ff","portId":"ge-0/0/7"}`,
		rpc:  "RegisterDevice",
		wantReq: &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "aa:bb:cc:dd:ee:ff", PortId: "ge-0/0/7",
		},
		resp:     &platformv1.RegisterPXEDeviceResponse{Status: handlerOK, Device: handlerDevice},
		wantCode: http.StatusCreated,
	},
	{
		method: http.MethodGet, path: "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff",
		rpc: "GetDeviceByMAC", wantReq: &platformv1.GetPXEDeviceByMACRequest{MacAddress: "aa:bb:cc:dd:ee:ff"},
		resp: &platformv1.GetPXEDeviceByMACResponse{Device: handlerDevice}, wantCode: http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/pxe/devices/" + knownDevice,
		rpc: "GetDevice", wantReq: &platformv1.GetPXEDeviceRequest{DeviceId: knownDevice},
		resp: &platformv1.GetPXEDeviceResponse{Device: handlerDevice}, wantCode: http.StatusOK,
	},
	{
		method: http.MethodDelete, path: "/api/v1/pxe/devices/" + knownDevice,
		rpc: "RemoveDevice", wantReq: &platformv1.RemovePXEDeviceRequest{DeviceId: knownDevice},
		resp: &platformv1.RemovePXEDeviceResponse{Status: handlerOK}, wantCode: http.StatusOK,
	},
	{
		// The device comes from the path: a device_id in the body must not
		// redirect the transition to another device.
		method: http.MethodPut, path: "/api/v1/pxe/devices/" + knownDevice + "/state",
		body: `{"deviceId":"pxe-other","state":"PROVISIONING_STATE_FAILED","reason":"disk"}`,
		rpc:  "UpdateState",
		wantReq: &platformv1.UpdatePXEStateRequest{
			DeviceId: knownDevice, State: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED, Reason: "disk",
		},
		resp:     &platformv1.UpdatePXEStateResponse{Status: handlerOK, Device: handlerDevice},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/devices/" + knownDevice + "/enrolled",
		body: `{"deviceId":"pxe-other","certificateSerial":"0a1b2c"}`,
		rpc:  "SetDeviceEnrolled",
		wantReq: &platformv1.SetPXEDeviceEnrolledRequest{
			DeviceId: knownDevice, CertificateSerial: "0a1b2c",
		},
		resp:     &platformv1.SetPXEDeviceEnrolledResponse{Status: handlerOK, Device: handlerDevice},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/devices/" + knownDevice + "/authorize",
		body: `{"deviceId":"pxe-other","targetVlan":200}`,
		rpc:  "Authorize",
		wantReq: &platformv1.AuthorizePXEDeviceRequest{
			DeviceId: knownDevice, TargetVlan: 200,
		},
		resp:     &platformv1.AuthorizePXEDeviceResponse{Status: handlerOK, Device: handlerDevice},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/devices/" + knownDevice + "/quarantine",
		body: `{"deviceId":"pxe-other","reason":"attestation failed"}`,
		rpc:  "Quarantine",
		wantReq: &platformv1.QuarantinePXEDeviceRequest{
			DeviceId: knownDevice, Reason: "attestation failed",
		},
		resp:     &platformv1.QuarantinePXEDeviceResponse{Status: handlerOK, Device: handlerDevice},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/devices/" + knownDevice + "/retry",
		rpc: "Retry", wantReq: &platformv1.RetryPXEDeviceRequest{DeviceId: knownDevice},
		resp: &platformv1.RetryPXEDeviceResponse{Status: handlerOK, Device: handlerDevice}, wantCode: http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/pxe/devices/" + knownDevice + "/events",
		rpc: "GetEvents", wantReq: &platformv1.GetPXEEventsRequest{DeviceId: knownDevice},
		resp: &platformv1.GetPXEEventsResponse{Events: []*platformv1.ProvisioningEvent{{
			Id:        "ev-1",
			DeviceId:  knownDevice,
			FromState: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
			ToState:   platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED,
			Details:   map[string]string{"port": "ge-0/0/7"},
		}}},
		wantCode: http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/pxe/webhook/complete",
		body: `{"macAddress":"aa:bb:cc:dd:ee:ff","hostname":"node-1","success":true,"message":"installed"}`,
		rpc:  "WebhookComplete",
		wantReq: &platformv1.PXEWebhookCompleteRequest{
			MacAddress: "aa:bb:cc:dd:ee:ff", Hostname: "node-1", Success: true, Message: "installed",
		},
		resp:     &platformv1.PXEWebhookCompleteResponse{Status: handlerOK},
		wantCode: http.StatusOK,
	},
}

// TestOperatorHandlers_HandTheServiceTheRequestAndAnswerItsResponse checks,
// for every route, the RPC called, the exact request message built from the
// path and body, and the service response carried back in the envelope.
func TestOperatorHandlers_HandTheServiceTheRequestAndAnswerItsResponse(t *testing.T) {
	for _, c := range handlerCases {
		t.Run(c.rpc, func(t *testing.T) {
			server := &operatorPXE{resp: c.resp}
			rec := serveHandler(handlerRoot(server), c.method, c.path, c.body)

			require.Equal(t, c.wantCode, rec.Code, rec.Body.String())
			assert.Equal(t, c.rpc, server.rpc)
			assert.Empty(t, cmpProto(c.wantReq, server.req), "request handed to the service")

			var env envelope
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
			assert.Equal(t, c.wantCode, env.Code)
			assert.True(t, env.Success)
			got := c.resp.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(env.Payload, got))
			assert.Empty(t, cmpProto(c.resp, got), "response carried in the envelope")
		})
	}
}

// TestOperatorHandlers_MapServiceErrorsToHTTPStatus checks every route
// answers a service failure with the status its gRPC code maps to, carrying
// the service's message, instead of a success envelope.
func TestOperatorHandlers_MapServiceErrorsToHTTPStatus(t *testing.T) {
	failures := []struct {
		code     codes.Code
		wantCode int
	}{
		{codes.NotFound, http.StatusNotFound},
		{codes.FailedPrecondition, http.StatusBadRequest},
		{codes.Internal, http.StatusInternalServerError},
	}
	for _, c := range handlerCases {
		for _, f := range failures {
			t.Run(c.rpc+"/"+f.code.String(), func(t *testing.T) {
				server := &operatorPXE{err: status.Errorf(f.code, "pxe device %q refused", knownDevice)}
				rec := serveHandler(handlerRoot(server), c.method, c.path, c.body)

				assert.Equal(t, c.rpc, server.rpc)
				require.Equal(t, f.wantCode, rec.Code, rec.Body.String())
				var env envelope
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
				assert.False(t, env.Success)
				assert.Contains(t, env.Error, `pxe device "pxe-7" refused`)
			})
		}
	}
}

// TestOperatorHandlers_RefuseAMalformedBodyBeforeTheService checks every
// route that reads a body answers 400 to one that is not JSON and never
// calls the service with a half-decoded request.
func TestOperatorHandlers_RefuseAMalformedBodyBeforeTheService(t *testing.T) {
	for _, c := range handlerCases {
		if c.body == "" {
			continue
		}
		t.Run(c.rpc, func(t *testing.T) {
			server := &operatorPXE{resp: c.resp}
			rec := serveHandler(handlerRoot(server), c.method, c.path, "{not json")

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, server.rpc, "a malformed body reached the service")
		})
	}
}

// TestOperatorHandlers_AcceptAnEmptyBody checks a body-reading route with no
// body still reaches the service, with the device from the path and no other
// field set.
func TestOperatorHandlers_AcceptAnEmptyBody(t *testing.T) {
	server := &operatorPXE{resp: &platformv1.AuthorizePXEDeviceResponse{Status: handlerOK, Device: handlerDevice}}
	rec := serveHandler(handlerRoot(server), http.MethodPost, "/api/v1/pxe/devices/"+knownDevice+"/authorize", "")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, cmpProto(&platformv1.AuthorizePXEDeviceRequest{DeviceId: knownDevice}, server.req))
}

// TestWebhookComplete_NilServerAnswersUnavailable checks the machine-facing
// webhook, like the operator routes, answers 503 when no PXE service runs.
func TestWebhookComplete_NilServerAnswersUnavailable(t *testing.T) {
	rec := serveHandler(handlerRoot(nil), http.MethodPost, "/api/v1/pxe/webhook/complete",
		`{"macAddress":"aa:bb:cc:dd:ee:ff","success":true}`)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "pxe service is not available")
}

// TestWebhookComplete_RefusesAConnectionWithoutAVerifiedCertificate checks
// the webhook answers 401 to a node that presents no verified client
// certificate (#238), before the body is read or the service is called.
func TestWebhookComplete_RefusesAConnectionWithoutAVerifiedCertificate(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7)}
	for name, state := range map[string]*tls.ConnectionState{
		"plain HTTP":             nil,
		"no client certificate":  {},
		"unverified certificate": {PeerCertificates: []*x509.Certificate{leaf}},
	} {
		t.Run(name, func(t *testing.T) {
			server := &operatorPXE{resp: &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}}
			rec := serveHandlerTLS(handlerRoot(server), http.MethodPost, "/api/v1/pxe/webhook/complete",
				`{"macAddress":"aa:bb:cc:dd:ee:ff","success":true}`, state)

			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Empty(t, server.rpc, "the webhook reached the service without a verified certificate")
		})
	}
}

// cmpProto returns the difference between two proto messages, empty when
// they are equal.
func cmpProto(want, got proto.Message) string {
	if proto.Equal(want, got) {
		return ""
	}
	return "want " + protojson.Format(want) + "\ngot  " + protojson.Format(got)
}
