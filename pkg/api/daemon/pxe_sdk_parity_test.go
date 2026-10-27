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

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The PXEService parity drivers below run every SDK transport against the
// daemon the same way: each transport file supplies only how it serves a
// PXEService servicer and connects the SDK's adapter to it.

const (
	// pxeSDKDeviceID and pxeSDKMAC name the one device the fake holds.
	pxeSDKDeviceID = "pxe-dev-1"
	pxeSDKMAC      = "aa:bb:cc:dd:ee:01"
)

// pxeSDKNow fixes every timestamp the fake answers with, so two fixtures
// answer alike.
var pxeSDKNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// pxeSDKConnect serves server through one daemon transport and connects the
// SDK's adapter for that transport as a caller holding scopes.
type pxeSDKConnect func(t *testing.T, server platformv1.PXEServiceServer, scopes ...string) grpc.ClientConnInterface

// recordingPXEService is a pxe.Service holding one device. It answers every
// method from that device on a fixed clock and records each call it serves.
// The mutex orders the transport's server goroutine against the test's
// reads of what it recorded.
type recordingPXEService struct {
	mu      sync.Mutex
	device  pxe.DeviceInfo
	running bool
	missing bool // every device lookup answers ErrDeviceNotFound
	calls   []string
}

var _ pxe.Service = (*recordingPXEService)(nil)

func newRecordingPXEService() *recordingPXEService {
	return &recordingPXEService{device: pxe.DeviceInfo{
		ID:             pxeSDKDeviceID,
		MACAddress:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		PortID:         "port-7",
		State:          pxe.StateDiscovered,
		StateReason:    "discovered on port-7",
		CurrentVLAN:    405,
		CreatedAt:      pxeSDKNow,
		UpdatedAt:      pxeSDKNow,
		StateChangedAt: pxeSDKNow,
		Events: []*pxe.ProvisioningEvent{{
			ID:        "evt-1",
			DeviceID:  pxeSDKDeviceID,
			Timestamp: pxeSDKNow,
			EventType: pxe.EventDeviceDiscovered,
			FromState: pxe.StateUnknown,
			ToState:   pxe.StateDiscovered,
			Details:   map[string]string{"port": "port-7"},
		}},
	}}
}

// record notes a call; the caller holds mu.
func (f *recordingPXEService) record(call string, args ...interface{}) {
	f.calls = append(f.calls, fmt.Sprintf("%s%v", call, args))
}

// lookup answers the held device by ID; the caller holds mu.
func (f *recordingPXEService) lookup(deviceID string) (*pxe.DeviceInfo, error) {
	if f.missing || deviceID != f.device.ID {
		return nil, pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	return &f.device, nil
}

// snapshot copies the held device so a caller reads it outside mu.
func (f *recordingPXEService) snapshot() *pxe.DeviceInfo {
	device := f.device
	return &device
}

// changed moves the held device to state and stamps the transition.
func (f *recordingPXEService) changed(device *pxe.DeviceInfo, state pxe.ProvisioningState, reason string) {
	device.State = state
	device.StateReason = reason
	device.StateChangedAt = pxeSDKNow.Add(time.Minute)
	device.UpdatedAt = device.StateChangedAt
}

// recorded is everything the fake recorded about the calls it served.
func (f *recordingPXEService) recorded() []interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []interface{}{append([]string(nil), f.calls...), *f.snapshot(), f.running}
}

func (f *recordingPXEService) Initialize(_ context.Context, _ *pxe.ServiceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Initialize")
	return nil
}

func (f *recordingPXEService) Start(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Start")
	f.running = true
	return nil
}

func (f *recordingPXEService) Stop(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Stop")
	f.running = false
	return nil
}

func (f *recordingPXEService) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *recordingPXEService) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Close")
	return nil
}

func (f *recordingPXEService) RegisterDevice(_ context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RegisterDevice", macAddress, portID)
	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, pxe.ErrInvalidMACAddress{MACAddress: macAddress, Reason: err.Error()}
	}
	return &pxe.DeviceInfo{
		ID: "pxe-dev-2", MACAddress: mac, PortID: portID, State: pxe.StateDiscovered,
		CreatedAt: pxeSDKNow, UpdatedAt: pxeSDKNow, StateChangedAt: pxeSDKNow,
	}, nil
}

func (f *recordingPXEService) GetDevice(_ context.Context, deviceID string) (*pxe.DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetDevice", deviceID)
	if _, err := f.lookup(deviceID); err != nil {
		return nil, err
	}
	return f.snapshot(), nil
}

func (f *recordingPXEService) GetDeviceByMAC(_ context.Context, macAddress string) (*pxe.DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetDeviceByMAC", macAddress)
	if f.missing || macAddress != f.device.MACAddress.String() {
		return nil, pxe.ErrDeviceNotFound{MACAddress: macAddress}
	}
	return f.snapshot(), nil
}

func (f *recordingPXEService) ListDevices(_ context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if filter == nil {
		f.record("ListDevices")
	} else {
		f.record("ListDevices", *filter)
	}
	if f.missing {
		return nil, nil
	}
	return []*pxe.DeviceInfo{f.snapshot()}, nil
}

func (f *recordingPXEService) RemoveDevice(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveDevice", deviceID)
	_, err := f.lookup(deviceID)
	return err
}

func (f *recordingPXEService) UpdateDeviceState(_ context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("UpdateDeviceState", deviceID, state, reason)
	device, err := f.lookup(deviceID)
	if err != nil {
		return err
	}
	f.changed(device, state, reason)
	return nil
}

func (f *recordingPXEService) SetDeviceEnrolled(_ context.Context, deviceID, certSerial, certFingerprint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetDeviceEnrolled", deviceID, certSerial, certFingerprint)
	device, err := f.lookup(deviceID)
	if err != nil {
		return err
	}
	device.CertificateSerial = certSerial
	f.changed(device, pxe.StateEnrolled, "enrolled")
	return nil
}

func (f *recordingPXEService) AuthorizeDevice(_ context.Context, deviceID string, targetVLAN uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("AuthorizeDevice", deviceID, targetVLAN)
	device, err := f.lookup(deviceID)
	if err != nil {
		return err
	}
	device.TargetVLAN = targetVLAN
	f.changed(device, pxe.StateAuthorized, "authorized")
	return nil
}

func (f *recordingPXEService) QuarantineDevice(_ context.Context, deviceID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("QuarantineDevice", deviceID, reason)
	device, err := f.lookup(deviceID)
	if err != nil {
		return err
	}
	f.changed(device, pxe.StateQuarantined, reason)
	return nil
}

func (f *recordingPXEService) RetryDevice(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RetryDevice", deviceID)
	device, err := f.lookup(deviceID)
	if err != nil {
		return err
	}
	device.RetryCount++
	f.changed(device, pxe.StateDiscovered, "retry")
	return nil
}

func (f *recordingPXEService) GetEvents(_ context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetEvents", deviceID)
	device, err := f.lookup(deviceID)
	if err != nil {
		return nil, err
	}
	return device.Events, nil
}

func (f *recordingPXEService) RegisterEventHandler(_ pxe.EventHandler) {}

func (f *recordingPXEService) Status() *pxe.ServiceStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Status")
	return &pxe.ServiceStatus{
		Running:          f.running,
		DeviceCount:      1,
		StartTime:        pxeSDKNow,
		IPXEServerAddr:   "10.40.5.1:69",
		QuarantineVLAN:   999,
		ProvisioningVLAN: 405,
	}
}

// pxeSDKFixture is a PXEService servicer over a recording pxe.Service.
type pxeSDKFixture struct {
	svc    *recordingPXEService
	server *PXEGRPCService
}

func newPXESDKFixture() *pxeSDKFixture {
	svc := newRecordingPXEService()
	return &pxeSDKFixture{svc: svc, server: NewPXEGRPCService(logging.DefaultLogger(), svc)}
}

// pxeSDKRequests holds one request for every PXEService method.
func pxeSDKRequests() map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.PXEService_RegisterDevice_FullMethodName: &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "aa:bb:cc:dd:ee:02", PortId: "port-8",
		},
		platformv1.PXEService_GetDevice_FullMethodName:      &platformv1.GetPXEDeviceRequest{DeviceId: pxeSDKDeviceID},
		platformv1.PXEService_GetDeviceByMAC_FullMethodName: &platformv1.GetPXEDeviceByMACRequest{MacAddress: pxeSDKMAC},
		platformv1.PXEService_ListDevices_FullMethodName: &platformv1.ListPXEDevicesRequest{Filter: &platformv1.PXEDeviceFilter{
			State: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, Vlan: 405, Limit: 10,
		}},
		platformv1.PXEService_RemoveDevice_FullMethodName: &platformv1.RemovePXEDeviceRequest{DeviceId: pxeSDKDeviceID},
		platformv1.PXEService_UpdateState_FullMethodName: &platformv1.UpdatePXEStateRequest{
			DeviceId: pxeSDKDeviceID, State: platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, Reason: "installer booted",
		},
		platformv1.PXEService_SetDeviceEnrolled_FullMethodName: &platformv1.SetPXEDeviceEnrolledRequest{
			DeviceId: pxeSDKDeviceID, CertificateSerial: "0A1B",
		},
		platformv1.PXEService_Authorize_FullMethodName: &platformv1.AuthorizePXEDeviceRequest{DeviceId: pxeSDKDeviceID, TargetVlan: 120},
		platformv1.PXEService_Quarantine_FullMethodName: &platformv1.QuarantinePXEDeviceRequest{
			DeviceId: pxeSDKDeviceID, Reason: "attestation mismatch",
		},
		platformv1.PXEService_Retry_FullMethodName:        &platformv1.RetryPXEDeviceRequest{DeviceId: pxeSDKDeviceID},
		platformv1.PXEService_GetEvents_FullMethodName:    &platformv1.GetPXEEventsRequest{DeviceId: pxeSDKDeviceID},
		platformv1.PXEService_GetStatus_FullMethodName:    &platformv1.GetPXEStatusRequest{},
		platformv1.PXEService_StartService_FullMethodName: &platformv1.StartPXEServiceRequest{},
		platformv1.PXEService_StopService_FullMethodName:  &platformv1.StopPXEServiceRequest{},
		platformv1.PXEService_WebhookComplete_FullMethodName: &platformv1.PXEWebhookCompleteRequest{
			MacAddress: pxeSDKMAC, Hostname: "node-1", Success: true, Message: "installed",
		},
	}
}

// invokePXEServer calls method on server directly, as a gRPC caller reaches
// it once authorized.
func invokePXEServer(t *testing.T, server platformv1.PXEServiceServer, method string, req proto.Message) (proto.Message, error) {
	t.Helper()
	return invokeGRPCMethodContext(grpcContext(pxeSDKClientState(t)), &platformv1.PXEService_ServiceDesc, server, method, req)
}

var (
	pxeSDKBundleOnce  sync.Once
	pxeSDKBundleValue *testutil.TestTLSBundle
)

// pxeSDKBundle is the one TLS bundle every PXE SDK transport and the direct
// gRPC call present. The webhook looks the node up by the SHA-256 of its
// client certificate (#238), and each generated bundle has a fresh key, so
// the direct and the SDK call agree only when they share one certificate.
func pxeSDKBundle(t *testing.T) *testutil.TestTLSBundle {
	t.Helper()
	pxeSDKBundleOnce.Do(func() { pxeSDKBundleValue = testutil.GenerateTestTLSBundle(t) })
	require.NotNil(t, pxeSDKBundleValue, "the shared PXE SDK TLS bundle was not generated")
	return pxeSDKBundleValue
}

// pxeSDKClientState is the TLS state of a gRPC connection from the client the
// SDK transports present: testutil's client certificate, verified. The
// webhook takes the node's identity from it (#238), so the direct call and
// the SDK call look up the same certificate fingerprint.
func pxeSDKClientState(t *testing.T) *tls.ConnectionState {
	t.Helper()
	bundle := pxeSDKBundle(t)
	leaf, err := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
	require.NoError(t, err)
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, bundle.CACert}}}
}

// testSDKPXEMethods drives every PXEService method through connect, as a
// caller holding only the scope gRPC requires for it, and checks that the
// reply and the calls the PXE service saw are the ones a direct gRPC call
// gives.
func testSDKPXEMethods(t *testing.T, transport string, connect pxeSDKConnect) {
	requests := pxeSDKRequests()
	require.Len(t, requests, len(platformv1.PXEService_ServiceDesc.Methods))
	untouched := newPXESDKFixture().svc.recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newPXESDKFixture()
			want, err := invokePXEServer(t, direct.server, method, req)
			require.NoError(t, err)

			via := newPXESDKFixture()
			got := want.ProtoReflect().New().Interface()
			scope := grpcapi.ScopeForMethod(method)
			require.NotEmpty(t, scope, "gRPC has no scope for %s", method)
			conn := connect(t, via.server, scope)
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			require.True(t, proto.Equal(want, got), "%s reply\n%v\nwant the gRPC reply\n%v", transport, got, want)
			require.NotEqual(t, untouched, via.svc.recorded(), "the PXE service saw no call")
			require.Equal(t, direct.svc.recorded(), via.svc.recorded())
		})
	}
}

// pxeRefusalCase is one method of a permission class and the scopes of a
// caller who lacks that class.
type pxeRefusalCase struct {
	class  string
	method string
	resp   proto.Message
	scopes []string
}

// pxeRefusalCases holds one method of each PXE permission class. GetDeviceByMAC
// travels as a provisioning-category sub-opcode, the other two as their own
// opcodes, so both QUIC routes are covered.
func pxeRefusalCases() []pxeRefusalCase {
	return []pxeRefusalCase{
		{
			class:  "pxe:read",
			method: platformv1.PXEService_GetDeviceByMAC_FullMethodName,
			resp:   &platformv1.GetPXEDeviceByMACResponse{},
			scopes: []string{"device:read"},
		},
		{
			class:  "pxe:write",
			method: platformv1.PXEService_UpdateState_FullMethodName,
			resp:   &platformv1.UpdatePXEStateResponse{},
			scopes: []string{"pxe:read"},
		},
		{
			class:  "pxe:delete",
			method: platformv1.PXEService_RemoveDevice_FullMethodName,
			resp:   &platformv1.RemovePXEDeviceResponse{},
			scopes: []string{"pxe:read", "pxe:write"},
		},
	}
}

// testSDKPXERefusesScope checks, for one method of each permission class,
// that a caller without the method's scope reaches the SDK caller as
// PermissionDenied, the code gRPC gives, and never reaches the PXE service.
func testSDKPXERefusesScope(t *testing.T, transport string, connect pxeSDKConnect) {
	for _, tc := range pxeRefusalCases() {
		t.Run(tc.class+" without the scope", func(t *testing.T) {
			f := newPXESDKFixture()
			before := f.svc.recorded()
			conn := connect(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, pxeSDKRequests()[tc.method], tc.resp)

			require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", transport, err)
			require.Equal(t, before, f.svc.recorded(), "a refused caller reached the PXE service")
		})
	}
}

// testSDKPXERefusesNotFound checks, for one method of each permission class,
// that a device the PXE service cannot find reaches the SDK caller as
// NotFound, the code gRPC gives.
func testSDKPXERefusesNotFound(t *testing.T, transport string, connect pxeSDKConnect) {
	for _, tc := range pxeRefusalCases() {
		req := pxeSDKRequests()[tc.method]

		t.Run(tc.class+" of a device not found", func(t *testing.T) {
			direct := newPXESDKFixture()
			direct.svc.missing = true
			_, err := invokePXEServer(t, direct.server, tc.method, req)
			require.Equal(t, codes.NotFound, status.Code(err), "gRPC: %v", err)

			via := newPXESDKFixture()
			via.svc.missing = true
			conn := connect(t, via.server, "*:*")
			err = conn.Invoke(context.Background(), tc.method, req, tc.resp)
			require.Equal(t, codes.NotFound, status.Code(err), "%s: %v", transport, err)
		})
	}
}
