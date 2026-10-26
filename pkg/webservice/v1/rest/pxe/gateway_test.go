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
	"io"
	"log/slog"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

const (
	knownMAC   = "aa:bb:cc:dd:ee:01"
	unknownMAC = "aa:bb:cc:dd:ee:99"
)

// fakePXE is the PXE service the gateway routes translate onto: devices
// by MAC, with the not-found and already-exists answers the real service
// gives (pkg/api/daemon/pxe_grpc_service.go).
type fakePXE struct {
	platformv1.UnimplementedPXEServiceServer
	devices map[string]*platformv1.PXEDeviceInfo
	calls   int
}

func newFakePXE() *fakePXE {
	return &fakePXE{devices: map[string]*platformv1.PXEDeviceInfo{
		knownMAC: {Id: "dev-1", MacAddress: knownMAC, PortId: "port-1", State: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED},
	}}
}

func (f *fakePXE) RegisterDevice(_ context.Context, req *platformv1.RegisterPXEDeviceRequest) (*platformv1.RegisterPXEDeviceResponse, error) {
	f.calls++
	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, "port_id is required")
	}
	if _, exists := f.devices[req.GetMacAddress()]; exists {
		return nil, status.Error(codes.AlreadyExists, "device already registered")
	}
	device := &platformv1.PXEDeviceInfo{
		Id:         "dev-" + req.GetMacAddress(),
		MacAddress: req.GetMacAddress(),
		PortId:     req.GetPortId(),
		State:      platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
	}
	f.devices[req.GetMacAddress()] = device
	return &platformv1.RegisterPXEDeviceResponse{Device: device}, nil
}

func (f *fakePXE) GetDeviceByMAC(_ context.Context, req *platformv1.GetPXEDeviceByMACRequest) (*platformv1.GetPXEDeviceByMACResponse, error) {
	f.calls++
	device, ok := f.devices[req.GetMacAddress()]
	if !ok {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	return &platformv1.GetPXEDeviceByMACResponse{Device: device}, nil
}

func (f *fakePXE) UpdateState(_ context.Context, req *platformv1.UpdatePXEStateRequest) (*platformv1.UpdatePXEStateResponse, error) {
	f.calls++
	for _, device := range f.devices {
		if device.GetId() == req.GetDeviceId() {
			device.State = req.GetState()
			device.StateReason = req.GetReason()
			return &platformv1.UpdatePXEStateResponse{Device: device}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "device not found")
}

// scopeGrant lets a request through only when the route asks for the one
// scope it grants.
type scopeGrant struct {
	granted string
}

func (a scopeGrant) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// gatewayRoot mounts the gateway routes under /api/v1 over server, with
// the scope check authorizer makes (none when nil).
func gatewayRoot(server platformv1.PXEServiceServer, authorizer middleware.ScopeAuthorizer) *mux.Router {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), server, w, false)
	if authorizer != nil {
		r.SetScopeAuthorizer(authorizer)
	}
	root := mux.NewRouter()
	r.RegisterGatewayRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func post(root http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

func devicePath(mac, action string) string {
	return "/api/v1/provisioning/devices/" + mac + "/" + action
}

func TestGatewayRoutes_AreTheThreeDeviceReports(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, false)

	assert.Equal(t, map[string]bool{
		"POST /api/v1/provisioning/devices/{mac}/register":         true,
		"POST /api/v1/provisioning/devices/{mac}/state":            true,
		"POST /api/v1/provisioning/devices/{mac}/install-complete": true,
	}, registeredPXEPaths(r.RegisterGatewayRoutes))
}

func TestGatewayRegister_NewDevice(t *testing.T) {
	server := newFakePXE()
	rec := post(gatewayRoot(server, nil), devicePath("aa:bb:cc:dd:ee:02", "register"), `{"port_id":"port-2"}`)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Contains(t, rec.Body.String(), `"registered"`)
	require.Contains(t, server.devices, "aa:bb:cc:dd:ee:02")
	assert.Equal(t, "port-2", server.devices["aa:bb:cc:dd:ee:02"].GetPortId())
}

func TestGatewayRegister_KnownDeviceAnswersItsID(t *testing.T) {
	rec := post(gatewayRoot(newFakePXE(), nil), devicePath(knownMAC, "register"), `{"port_id":"port-1"}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"already_registered"`)
	assert.Contains(t, rec.Body.String(), `"dev-1"`)
}

func TestGatewayRegister_MissingPortRejected(t *testing.T) {
	rec := post(gatewayRoot(newFakePXE(), nil), devicePath("aa:bb:cc:dd:ee:02", "register"), `{}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGatewayReportState_MovesTheDevice(t *testing.T) {
	server := newFakePXE()
	rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "state"), `{"state":"booting","reason":"dhcp ack"}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING, server.devices[knownMAC].GetState())
	assert.Equal(t, "dhcp ack", server.devices[knownMAC].GetStateReason())
}

func TestGatewayReportState_UnknownDevice(t *testing.T) {
	rec := post(gatewayRoot(newFakePXE(), nil), devicePath(unknownMAC, "state"), `{"state":"booting"}`)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGatewayReportState_UnknownStateRejectedBeforeTheService(t *testing.T) {
	server := newFakePXE()
	rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "state"), `{"state":"rebooting"}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Zero(t, server.calls)
}

func TestGatewayInstallComplete_RecordsTheOutcome(t *testing.T) {
	for outcome, want := range map[string]platformv1.ProvisioningState{
		"success": platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE,
		"failure": platformv1.ProvisioningState_PROVISIONING_STATE_FAILED,
	} {
		t.Run(outcome, func(t *testing.T) {
			server := newFakePXE()
			rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "install-complete"),
				`{"status":"`+outcome+`","timestamp":"2026-10-14T09:30:00Z"}`)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, want, server.devices[knownMAC].GetState())
		})
	}
}

func TestGatewayInstallComplete_UnknownDevice(t *testing.T) {
	rec := post(gatewayRoot(newFakePXE(), nil), devicePath(unknownMAC, "install-complete"), `{"status":"success"}`)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGatewayInstallComplete_BadStatusRejectedBeforeTheService(t *testing.T) {
	server := newFakePXE()
	rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "install-complete"), `{"status":"done"}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Zero(t, server.calls)
}

// TestGatewayRoutes_RequireProvisioningWrite checks every report asks for
// provisioning:write: a caller holding only provisioning:read is refused
// before the service is called, and the right scope reaches it.
func TestGatewayRoutes_RequireProvisioningWrite(t *testing.T) {
	probes := map[string]string{
		devicePath(knownMAC, "register"):         `{"port_id":"port-1"}`,
		devicePath(knownMAC, "state"):            `{"state":"booting"}`,
		devicePath(knownMAC, "install-complete"): `{"status":"success"}`,
	}
	for path, body := range probes {
		t.Run(path, func(t *testing.T) {
			server := newFakePXE()
			rec := post(gatewayRoot(server, scopeGrant{granted: "provisioning:read"}), path, body)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Zero(t, server.calls, "the service must not be called without provisioning:write")

			rec = post(gatewayRoot(server, scopeGrant{granted: "provisioning:write"}), path, body)
			assert.NotEqual(t, http.StatusForbidden, rec.Code)
			assert.NotZero(t, server.calls)
		})
	}
}

func TestGatewayRoutes_NilServer(t *testing.T) {
	for action, body := range map[string]string{
		"register":         `{"port_id":"port-1"}`,
		"state":            `{"state":"booting"}`,
		"install-complete": `{"status":"success"}`,
	} {
		t.Run(action, func(t *testing.T) {
			rec := post(gatewayRoot(nil, nil), devicePath(knownMAC, action), body)

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

// TestGatewayRoutes_RefuseAMalformedBodyBeforeTheService checks each gateway
// report answers 400 to a body that is not JSON without calling the service.
func TestGatewayRoutes_RefuseAMalformedBodyBeforeTheService(t *testing.T) {
	for _, action := range []string{"register", "state", "install-complete"} {
		t.Run(action, func(t *testing.T) {
			server := newFakePXE()
			rec := post(gatewayRoot(server, nil), devicePath(knownMAC, action), "{not json")

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Zero(t, server.calls, "a malformed body reached the service")
		})
	}
}

// vanishingPXE answers AlreadyExists to the registration and then no longer
// has the device: a RemoveDevice landed between the two calls.
type vanishingPXE struct{ *fakePXE }

func (v vanishingPXE) RegisterDevice(_ context.Context, _ *platformv1.RegisterPXEDeviceRequest) (*platformv1.RegisterPXEDeviceResponse, error) {
	v.calls++
	return nil, status.Error(codes.AlreadyExists, "device already registered")
}

// TestGatewayRegister_KnownDeviceGoneBeforeTheLookup checks an
// already-registered device that cannot then be found answers the lookup's
// 404, never a success naming no device.
func TestGatewayRegister_KnownDeviceGoneBeforeTheLookup(t *testing.T) {
	server := vanishingPXE{&fakePXE{devices: map[string]*platformv1.PXEDeviceInfo{}}}
	rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "register"), `{"port_id":"port-1"}`)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "device not found")
	assert.Equal(t, 2, server.calls, "register, then the lookup")
}

// stuckPXE finds the device but refuses every state transition.
type stuckPXE struct{ *fakePXE }

func (s stuckPXE) UpdateState(_ context.Context, _ *platformv1.UpdatePXEStateRequest) (*platformv1.UpdatePXEStateResponse, error) {
	s.calls++
	return nil, status.Error(codes.FailedPrecondition, "illegal transition")
}

// TestGatewayReportState_RefusedTransition checks a transition the service
// refuses answers 400 with its reason and leaves the device where it was.
func TestGatewayReportState_RefusedTransition(t *testing.T) {
	server := stuckPXE{newFakePXE()}
	rec := post(gatewayRoot(server, nil), devicePath(knownMAC, "state"), `{"state":"booting"}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "illegal transition")
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, server.devices[knownMAC].GetState())
}

func TestProvisioningState(t *testing.T) {
	for name, want := range map[string]platformv1.ProvisioningState{
		"booting":          platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		"INSTALL_COMPLETE": platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE,
	} {
		got, err := provisioningState(name)
		assert.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
	for _, name := range []string{"", "unspecified", "rebooting"} {
		_, err := provisioningState(name)
		var unknown *ErrUnknownDeviceState
		assert.ErrorAs(t, err, &unknown, "%q must be refused", name)
	}
}

// connectGatewaySDK serves the gateway routes over TLS and returns the SDK's
// REST client for them, so the round trip runs the SDK route table against
// the server's.
func connectGatewaySDK(t *testing.T, server platformv1.PXEServiceServer) platformv1.ProvisioningGatewayClient {
	t.Helper()
	root := gatewayRoot(server, nil)
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewTLSServer(root)
	t.Cleanup(ts.Close)

	tlsConfig := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(ts.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })
	return platformv1.NewProvisioningGatewayClient(adapter.Connection())
}

func TestGatewaySDKREST_RegisterPXEDevice(t *testing.T) {
	server := newFakePXE()
	client := connectGatewaySDK(t, server)

	resp, err := client.RegisterPXEDevice(context.Background(),
		&platformv1.RegisterProvisioningDeviceRequest{MacAddress: "aa:bb:cc:dd:ee:02", PortId: "port-2"})
	require.NoError(t, err)
	assert.Equal(t, "dev-aa:bb:cc:dd:ee:02", resp.GetDeviceId())
	assert.Equal(t, "registered", resp.GetStatus())

	again, err := client.RegisterPXEDevice(context.Background(),
		&platformv1.RegisterProvisioningDeviceRequest{MacAddress: "aa:bb:cc:dd:ee:02", PortId: "port-2"})
	require.NoError(t, err)
	assert.Equal(t, "already_registered", again.GetStatus())
}

func TestGatewaySDKREST_ReportDeviceState(t *testing.T) {
	server := newFakePXE()
	client := connectGatewaySDK(t, server)

	_, err := client.ReportDeviceState(context.Background(),
		&platformv1.ReportDeviceStateRequest{MacAddress: knownMAC, State: "installing", Reason: "image fetched"})
	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, server.devices[knownMAC].GetState())

	_, err = client.ReportDeviceState(context.Background(),
		&platformv1.ReportDeviceStateRequest{MacAddress: unknownMAC, State: "booting"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGatewaySDKREST_NotifyInstallComplete(t *testing.T) {
	server := newFakePXE()
	client := connectGatewaySDK(t, server)

	_, err := client.NotifyInstallComplete(context.Background(),
		&platformv1.NotifyInstallCompleteRequest{MacAddress: knownMAC, Status: "success"})
	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE, server.devices[knownMAC].GetState())

	_, err = client.NotifyInstallComplete(context.Background(),
		&platformv1.NotifyInstallCompleteRequest{MacAddress: unknownMAC, Status: "success"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}
