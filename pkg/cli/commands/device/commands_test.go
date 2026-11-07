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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeDeviceService is an in-memory DeviceService served over a Unix socket
// in the test's temp directory, so every device command runs its real cobra
// command, SDK client and gRPC transport without a daemon. failOn makes the
// named RPC fail with the given error; the last* fields record what the CLI
// sent.
type fakeDeviceService struct {
	platformv1.UnimplementedDeviceServiceServer

	mu       sync.Mutex
	devices  map[uint64]*platformv1.Device
	profiles map[uint64]*platformv1.DeviceProfile
	failOn   map[string]error
	nextID   uint64

	lastList    *platformv1.ListDevicesRequest
	lastDisable *platformv1.DisableDeviceRequest
	lastRecord  *platformv1.RecordAttestationCertificateRequest
	lastUpdate  *platformv1.UpdateProfileRequest
	lastAssign  *platformv1.AssignProfileToDeviceRequest
	bootCalls   int
}

func (s *fakeDeviceService) GetDevice(_ context.Context, r *platformv1.GetDeviceRequest) (*platformv1.GetDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failOn["GetDevice"]; err != nil {
		return nil, err
	}
	d, ok := s.devices[r.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	return &platformv1.GetDeviceResponse{Device: d}, nil
}

func (s *fakeDeviceService) DeleteDevice(_ context.Context, r *platformv1.DeleteDeviceRequest) (*platformv1.DeleteDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[r.GetId()]; !ok {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	delete(s.devices, r.GetId())
	return &platformv1.DeleteDeviceResponse{}, nil
}

func (s *fakeDeviceService) ListDevices(_ context.Context, r *platformv1.ListDevicesRequest) (*platformv1.ListDevicesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastList = r
	if err := s.failOn["ListDevices"]; err != nil {
		return nil, err
	}
	out := &platformv1.ListDevicesResponse{}
	for _, d := range s.devices {
		out.Devices = append(out.Devices, d)
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].GetId() < out.Devices[j].GetId() })
	out.Pagination = &platformv1.PaginationResponse{TotalItems: uint64(len(out.Devices))}
	return out, nil
}

func (s *fakeDeviceService) FindDeviceBySerial(_ context.Context, r *platformv1.FindDeviceBySerialRequest) (*platformv1.FindDeviceBySerialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failOn["FindDeviceBySerial"]; err != nil {
		return nil, err
	}
	for _, d := range s.devices {
		if d.GetSerial() == r.GetSerial() {
			return &platformv1.FindDeviceBySerialResponse{Device: d}, nil
		}
	}
	// The control plane answers an unknown serial with an empty response.
	return &platformv1.FindDeviceBySerialResponse{}, nil
}

func (s *fakeDeviceService) CreateDevice(_ context.Context, r *platformv1.CreateDeviceRequest) (*platformv1.CreateDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	d := r.GetDevice()
	d.Id = s.nextID
	s.devices[d.Id] = d
	return &platformv1.CreateDeviceResponse{Device: d}, nil
}

func (s *fakeDeviceService) DisableDevice(_ context.Context, r *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastDisable = r
	if err := s.failOn["DisableDevice"]; err != nil {
		return nil, err
	}
	return &platformv1.DeviceLifecycleResponse{State: "suspended", PreviousState: "active", StateReason: "operator: " + r.GetReason()}, nil
}

func (s *fakeDeviceService) EnableDevice(context.Context, *platformv1.EnableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failOn["EnableDevice"]; err != nil {
		return nil, err
	}
	return &platformv1.DeviceLifecycleResponse{State: "quarantined", PreviousState: "suspended", ReattestationRequested: true}, nil
}

func (s *fakeDeviceService) RecordAttestationCertificate(_ context.Context, r *platformv1.RecordAttestationCertificateRequest) (*platformv1.RecordAttestationCertificateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRecord = r
	if err := s.failOn["RecordAttestationCertificate"]; err != nil {
		return nil, err
	}
	id, err := strconv.ParseUint(r.GetDeviceId(), 10, 64)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad device id")
	}
	d := s.devices[id]
	return &platformv1.RecordAttestationCertificateResponse{
		DeviceId:          id,
		Serial:            d.GetSerial(),
		Model:             d.GetModel(),
		Changed:           true,
		Source:            "reissued",
		Reissued:          r.GetReissue(),
		Subject:           "CN=" + d.GetSerial(),
		CertificateSerial: "0a1b",
		NotAfter:          timestamppb.New(time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)),
		AttestCert:        "-----BEGIN CERTIFICATE-----",
	}, nil
}

func (s *fakeDeviceService) CreateProfile(_ context.Context, r *platformv1.CreateProfileRequest) (*platformv1.CreateProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failOn["CreateProfile"]; err != nil {
		return nil, err
	}
	s.nextID++
	p := r.GetProfile()
	p.Id = s.nextID
	s.profiles[p.Id] = p
	return &platformv1.CreateProfileResponse{Profile: p}, nil
}

func (s *fakeDeviceService) GetProfile(_ context.Context, r *platformv1.GetProfileRequest) (*platformv1.GetProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[r.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	return &platformv1.GetProfileResponse{Profile: p}, nil
}

func (s *fakeDeviceService) UpdateProfile(_ context.Context, r *platformv1.UpdateProfileRequest) (*platformv1.UpdateProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUpdate = r
	if err := s.failOn["UpdateProfile"]; err != nil {
		return nil, err
	}
	s.profiles[r.GetProfile().GetId()] = r.GetProfile()
	return &platformv1.UpdateProfileResponse{Profile: r.GetProfile()}, nil
}

func (s *fakeDeviceService) AssignProfileToDevice(_ context.Context, r *platformv1.AssignProfileToDeviceRequest) (*platformv1.AssignProfileToDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAssign = r
	if err := s.failOn["AssignProfileToDevice"]; err != nil {
		return nil, err
	}
	p := s.profiles[r.GetProfileId()]
	p.EkSerial = "EK-" + strconv.FormatUint(r.GetDeviceId(), 10)
	p.Assigned = true
	return &platformv1.AssignProfileToDeviceResponse{Profile: p}, nil
}

func (s *fakeDeviceService) UnassignProfileFromDevice(_ context.Context, r *platformv1.UnassignProfileFromDeviceRequest) (*platformv1.UnassignProfileFromDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failOn["UnassignProfileFromDevice"]; err != nil {
		return nil, err
	}
	p := s.profiles[r.GetProfileId()]
	p.EkSerial = ""
	p.Assigned = false
	return &platformv1.UnassignProfileFromDeviceResponse{Profile: p}, nil
}

func (s *fakeDeviceService) BootCertificate(context.Context, *platformv1.BootCertificateRequest) (*platformv1.BootCertificateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootCalls++
	return &platformv1.BootCertificateResponse{}, nil
}

func (s *fakeDeviceService) BootDelivery(context.Context, *platformv1.BootDeliveryRequest) (*platformv1.BootDeliveryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootCalls++
	return &platformv1.BootDeliveryResponse{}, nil
}

// failNext makes the named RPC fail with an internal error.
func (s *fakeDeviceService) failNext(rpc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failOn[rpc] = status.Error(codes.Internal, "backend down")
}

// deviceHarness runs `platformctl device ...` against a fakeDeviceService.
type deviceHarness struct {
	srv  *fakeDeviceService
	sock string
}

// startDeviceServer serves a fakeDeviceService holding device 7 (SN-7) and
// profile 42 (rack-a).
func startDeviceServer(t *testing.T) *deviceHarness {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &fakeDeviceService{
		devices: map[uint64]*platformv1.Device{
			7: {Id: 7, Serial: "SN-7", Model: "r640", HashAlgoId: 11, AttestCert: "-----BEGIN CERTIFICATE-----"},
		},
		profiles: map[uint64]*platformv1.DeviceProfile{
			42: {Id: 42, Name: "rack-a", Model: "r640", TlsServerName: "compute.example.internal"},
		},
		failOn: map[string]error{},
		nextID: 100,
	}
	gs := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(gs, srv)
	go func() {
		if serveErr := gs.Serve(lis); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", serveErr)
		}
	}()
	t.Cleanup(gs.Stop)
	return &deviceHarness{srv: srv, sock: sock}
}

// run executes the device command tree with args in the given output format
// and returns what it printed to stdout.
func (h *deviceHarness) run(t *testing.T, format cli.OutputFormat, args ...string) (string, error) {
	t.Helper()
	flags := &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: h.sock}}, nil
		},
	}
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return captureStdout(t, cmd.Execute)
}

// runJSON runs a command in JSON format and decodes what it printed.
func (h *deviceHarness) runJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out, err := h.run(t, cli.OutputFormatJSON, args...)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &decoded), out)
	return decoded
}

// captureStdout runs fn with os.Stdout redirected to a pipe. The CLI printer
// binds os.Stdout when the command builds it, so the swap must precede fn.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, readErr := io.ReadAll(r)
		done <- result{data: data, err: readErr}
	}()

	original := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = original

	require.NoError(t, w.Close())
	got := <-done
	require.NoError(t, got.err)
	require.NoError(t, r.Close())
	return string(got.data), runErr
}

func TestDeviceGetCommand(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "get", "7")
	assert.EqualValues(t, 7, got["id"])
	assert.Equal(t, "SN-7", got["serial"])
	assert.Equal(t, "r640", got["model"])
	assert.EqualValues(t, 11, got["hash_algo_id"])
	assert.Equal(t, "-----BEGIN CERTIFICATE-----", got["attest_cert"])

	table, err := h.run(t, cli.OutputFormatTable, "get", "7")
	require.NoError(t, err)
	assert.Contains(t, table, "SN-7")

	_, err = h.run(t, cli.OutputFormatJSON, "get", "99")
	var getErr ErrGetDeviceFailed
	require.True(t, errors.As(err, &getErr), "err = %v", err)
	assert.Equal(t, uint64(99), getErr.ID)
	assert.Contains(t, err.Error(), "device not found", "the server's reason is shown")
}

func TestDeviceFindSerialCommand(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "find-serial", "SN-7")
	assert.EqualValues(t, 7, got["id"])
	assert.Equal(t, "r640", got["model"])

	table, err := h.run(t, cli.OutputFormatTable, "find-serial", "SN-7")
	require.NoError(t, err)
	assert.Contains(t, table, "r640")

	_, err = h.run(t, cli.OutputFormatJSON, "find-serial", "SN-404")
	assert.Equal(t, ErrDeviceNotFoundBySerial{Serial: "SN-404"}, err, "an empty answer is not found, not a nil device")

	h.srv.failNext("FindDeviceBySerial")
	_, err = h.run(t, cli.OutputFormatJSON, "find-serial", "SN-7")
	var findErr ErrFindDeviceBySerialFailed
	require.True(t, errors.As(err, &findErr), "err = %v", err)
	assert.Equal(t, "SN-7", findErr.Serial)
	assert.Contains(t, err.Error(), "backend down")
}

func TestDeviceListCommand(t *testing.T) {
	h := startDeviceServer(t)
	h.srv.devices[8] = &platformv1.Device{Id: 8, Serial: "SN-8", Model: "r650"}

	got := h.runJSON(t, "list", "--page", "2", "--page-size", "1")
	assert.EqualValues(t, 2, got["page"])
	assert.EqualValues(t, 1, got["page_size"])
	assert.EqualValues(t, 2, got["total"])
	assert.EqualValues(t, 2, got["total_pages"])
	devices, ok := got["devices"].([]any)
	require.True(t, ok, "devices = %v", got["devices"])
	require.Len(t, devices, 2)
	assert.Equal(t, "SN-8", devices[1].(map[string]any)["serial"])

	h.srv.mu.Lock()
	assert.EqualValues(t, 2, h.srv.lastList.GetPagination().GetPage(), "the page reaches the control plane")
	assert.EqualValues(t, 1, h.srv.lastList.GetPagination().GetPageSize())
	h.srv.mu.Unlock()

	table, err := h.run(t, cli.OutputFormatTable, "list")
	require.NoError(t, err)
	assert.Contains(t, table, "SN-7")
	assert.Contains(t, table, "SN-8")

	h.srv.failNext("ListDevices")
	_, err = h.run(t, cli.OutputFormatJSON, "list")
	var listErr ErrListDevicesFailed
	require.True(t, errors.As(err, &listErr), "err = %v", err)
	assert.Contains(t, err.Error(), "backend down")
}

func TestDeviceDeleteCommand(t *testing.T) {
	h := startDeviceServer(t)
	h.srv.devices[8] = &platformv1.Device{Id: 8, Serial: "SN-8"}

	got := h.runJSON(t, "delete", "7")
	assert.EqualValues(t, 7, got["id"])
	assert.Equal(t, true, got["success"])
	assert.Equal(t, "Device deleted successfully", got["message"])

	table, err := h.run(t, cli.OutputFormatTable, "delete", "8")
	require.NoError(t, err)
	assert.Equal(t, "Device 8 deleted successfully\n", table)

	h.srv.mu.Lock()
	assert.Empty(t, h.srv.devices, "delete removes the device on the control plane")
	h.srv.mu.Unlock()

	_, err = h.run(t, cli.OutputFormatJSON, "delete", "7")
	var deleteErr ErrDeleteDeviceFailed
	require.True(t, errors.As(err, &deleteErr), "err = %v", err)
	assert.Equal(t, uint64(7), deleteErr.ID)
}

func TestDeviceRegisterCommand(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "register", "--serial", "SN-9", "--model", "r750", "--hash-algo", "11")
	assert.EqualValues(t, 101, got["id"], "the id is the one the control plane assigned")
	assert.Equal(t, "SN-9", got["serial"])

	h.srv.mu.Lock()
	assert.Equal(t, "r750", h.srv.devices[101].GetModel())
	h.srv.mu.Unlock()
}

func TestDeviceDisableEnableCommands(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "disable", "7", "--reason", "RMA pending")
	assert.Equal(t, "suspended", got["state"])
	assert.Equal(t, "active", got["previous_state"])
	assert.Equal(t, "operator: RMA pending", got["state_reason"])
	h.srv.mu.Lock()
	assert.Equal(t, "7", h.srv.lastDisable.GetDeviceId())
	assert.Equal(t, "RMA pending", h.srv.lastDisable.GetReason(), "the reason reaches the control plane")
	h.srv.mu.Unlock()

	table, err := h.run(t, cli.OutputFormatTable, "enable", "7")
	require.NoError(t, err)
	assert.Contains(t, table, "Device enabled; it stays quarantined until it re-attests")
	assert.Contains(t, table, "State: quarantined")
	assert.Contains(t, table, "Re-attestation Requested: true")

	h.srv.failNext("EnableDevice")
	_, err = h.run(t, cli.OutputFormatJSON, "enable", "7")
	var enableErr ErrEnableDeviceFailed
	require.True(t, errors.As(err, &enableErr), "err = %v", err)
	assert.Equal(t, uint64(7), enableErr.ID)
}

func TestDeviceAttestCertRecordCommand(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "attest-cert", "record", "7", "--reissue")
	assert.EqualValues(t, 7, got["id"])
	assert.Equal(t, "SN-7", got["serial"])
	assert.Equal(t, true, got["reissued"])
	assert.Equal(t, "0a1b", got["certificate_serial"])
	assert.Equal(t, "2027-01-02T03:04:05Z", got["not_after"])
	h.srv.mu.Lock()
	assert.True(t, h.srv.lastRecord.GetReissue(), "--reissue reaches the control plane")
	assert.False(t, h.srv.lastRecord.GetClearOnRefusal(), "--clear-on-refusal stays off unless asked")
	h.srv.mu.Unlock()

	table, err := h.run(t, cli.OutputFormatTable, "attest-cert", "record", "7")
	require.NoError(t, err)
	assert.Contains(t, table, "Attestation certificate recorded")
	assert.Contains(t, table, "Not After: 2027-01-02T03:04:05Z")

	h.srv.failNext("RecordAttestationCertificate")
	_, err = h.run(t, cli.OutputFormatJSON, "attest-cert", "record", "7")
	var recordErr ErrRecordAttestCertFailed
	require.True(t, errors.As(err, &recordErr), "err = %v", err)
	assert.Equal(t, uint64(7), recordErr.ID)
	assert.Contains(t, err.Error(), "attestation certificate not recorded for device 7")
}

func TestDeviceProfileCreateCommand(t *testing.T) {
	h := startDeviceServer(t)
	ekCert := newCLITestEKCertPEM(t)
	configFile := filepath.Join(t.TempDir(), "platform.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("hostname: node-1\n"), 0o600))

	got := h.runJSON(t, "profile", "create", "--name", "rack-b", "--role", "worker", "--zone", "dmz",
		"--ek-cert", ekCert, "--config-file", configFile, "--tls-server-name", "worker.example.internal")
	assert.Equal(t, "101", got["id"])
	assert.Equal(t, "worker", got["role"])
	assert.Equal(t, "dmz", got["zone"])
	assert.Equal(t, "worker.example.internal", got["tls_server_name"])

	h.srv.mu.Lock()
	created := h.srv.profiles[101]
	h.srv.mu.Unlock()
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_WORKER, created.GetRole())
	assert.Equal(t, ekCert, created.GetEkCert(), "the EK certificate is prestaged on the profile")
	assert.JSONEq(t, `{"hostname":"node-1"}`, string(created.GetConfig()), "the YAML config is sent as JSON")

	table, err := h.run(t, cli.OutputFormatTable, "profile", "create", "--name", "rack-c", "--model", "r650")
	require.NoError(t, err)
	assert.Contains(t, table, "Name: rack-c")
	assert.Contains(t, table, "Model: r650")
	assert.Contains(t, table, "Assigned: false")

	_, err = h.run(t, cli.OutputFormatJSON, "profile", "create", "--model", "r650")
	assert.Equal(t, ErrProfileNameRequired{}, err, "refused before connecting")

	h.srv.failNext("CreateProfile")
	_, err = h.run(t, cli.OutputFormatJSON, "profile", "create", "--name", "rack-d")
	var createErr ErrProfileCreateFailed
	require.True(t, errors.As(err, &createErr), "err = %v", err)
	assert.Contains(t, err.Error(), "backend down")
}

func TestDeviceProfileUpdateCommand(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "profile", "update", "42", "--zone", "dmz", "--clear-tls-server-name")
	assert.Equal(t, "rack-a", got["name"], "an unsupplied flag keeps the stored value")
	assert.Equal(t, "dmz", got["zone"])
	assert.NotContains(t, got, "tls_server_name")
	h.srv.mu.Lock()
	assert.True(t, h.srv.lastUpdate.GetClearTlsServerName(), "the clear reaches the control plane")
	h.srv.mu.Unlock()

	_, err := h.run(t, cli.OutputFormatJSON, "profile", "update", "4242", "--zone", "dmz")
	var getErr ErrProfileGetFailed
	require.True(t, errors.As(err, &getErr), "err = %v", err)
	assert.Equal(t, uint64(4242), getErr.ID)

	_, err = h.run(t, cli.OutputFormatJSON, "profile", "update", "42", "--role", "mainframe")
	assert.Equal(t, ErrProfileInvalidRole{Role: "mainframe"}, err)

	_, err = h.run(t, cli.OutputFormatJSON, "profile", "update", "x")
	assert.Equal(t, ErrInvalidProfileID{ID: "x"}, err)

	h.srv.failNext("UpdateProfile")
	_, err = h.run(t, cli.OutputFormatJSON, "profile", "update", "42", "--zone", "lab")
	var updateErr ErrProfileUpdateFailed
	require.True(t, errors.As(err, &updateErr), "err = %v", err)
	assert.Equal(t, uint64(42), updateErr.ID)
}

func TestDeviceProfileAssignUnassignCommands(t *testing.T) {
	h := startDeviceServer(t)

	got := h.runJSON(t, "profile", "assign", "42", "--device", "7")
	assert.Equal(t, true, got["assigned"])
	assert.Equal(t, "EK-7", got["ek_serial"])
	h.srv.mu.Lock()
	assert.Equal(t, uint64(42), h.srv.lastAssign.GetProfileId())
	assert.Equal(t, uint64(7), h.srv.lastAssign.GetDeviceId(), "--device reaches the control plane")
	h.srv.mu.Unlock()

	table, err := h.run(t, cli.OutputFormatTable, "profile", "unassign", "42")
	require.NoError(t, err)
	assert.Contains(t, table, "Assigned: false")
	assert.NotContains(t, table, "EK Serial", "the cleared binding is not shown")

	h.srv.failNext("AssignProfileToDevice")
	_, err = h.run(t, cli.OutputFormatJSON, "profile", "assign", "42", "--mac", "00:25:90:ff:aa:02")
	var assignErr ErrProfileAssignFailed
	require.True(t, errors.As(err, &assignErr), "err = %v", err)
	assert.Equal(t, uint64(42), assignErr.ID)

	h.srv.failNext("UnassignProfileFromDevice")
	_, err = h.run(t, cli.OutputFormatJSON, "profile", "unassign", "42")
	var unassignErr ErrProfileUnassignFailed
	require.True(t, errors.As(err, &unassignErr), "err = %v", err)
	assert.Equal(t, uint64(42), unassignErr.ID)

	_, err = h.run(t, cli.OutputFormatJSON, "profile", "unassign", "x")
	assert.Equal(t, ErrInvalidProfileID{ID: "x"}, err)
}

// The boot calls must be bound to a TLS connection; a Unix socket has none,
// so the SDK refuses them before anything is sent and the CLI names the
// refusal.
func TestDeviceBootCommands_RefusedOnTheUnixSocket(t *testing.T) {
	h := startDeviceServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := writeKeyFile(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err = h.run(t, cli.OutputFormatJSON, "boot", "certificate", "--identity", "SN-7", "--key", keyPath)
	var certErr ErrBootCertificateFailed
	require.True(t, errors.As(err, &certErr), "err = %v", err)
	assert.Equal(t, "SN-7", certErr.Identity)
	assert.Contains(t, certErr.Reason, "channel binding unavailable")

	_, err = h.run(t, cli.OutputFormatJSON, "boot", "delivery", "--quote-command", "/nonexistent/quote")
	var deliveryErr ErrBootDeliveryFailed
	require.True(t, errors.As(err, &deliveryErr), "err = %v", err)
	assert.Contains(t, err.Error(), "channel binding unavailable")

	h.srv.mu.Lock()
	assert.Zero(t, h.srv.bootCalls, "an unbound boot call never reaches the control plane")
	h.srv.mu.Unlock()
}

// Every wrapping error keeps its cause reachable, so callers can match the
// SDK's typed errors, and each message names its subject.
func TestProfileErrors_NameTheirSubjectAndKeepTheCause(t *testing.T) {
	cause := errors.New("root cause")
	tests := []struct {
		err     error
		message string
	}{
		{ErrProfileEKCertReadFailed{Path: "/ek.pem", Cause: cause}, "device profile: failed to read EK certificate /ek.pem: root cause"},
		{ErrProfileConfigReadFailed{Path: "/p.yaml", Cause: cause}, "device profile: failed to read config file /p.yaml: root cause"},
		{ErrProfileConfigParseFailed{Path: "/p.yaml", Cause: cause}, "device profile: failed to parse config file /p.yaml: root cause"},
		{ErrProfileCreateFailed{Cause: cause}, "device profile: failed to create profile: root cause"},
		{ErrProfileGetFailed{ID: 3, Cause: cause}, "device profile: failed to get profile 3: root cause"},
		{ErrProfileListFailed{Cause: cause}, "device profile: failed to list profiles: root cause"},
		{ErrProfileMatchFailed{Cause: cause}, "device profile: failed to match a profile: root cause"},
		{ErrProfileUpdateFailed{ID: 3, Cause: cause}, "device profile: failed to update profile 3: root cause"},
		{ErrProfileAssignFailed{ID: 3, Cause: cause}, "device profile: failed to assign profile 3 to device: root cause"},
		{ErrProfileUnassignFailed{ID: 3, Cause: cause}, "device profile: failed to unassign profile 3 from device: root cause"},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			assert.Equal(t, tt.message, tt.err.Error())
			assert.ErrorIs(t, tt.err, cause)
		})
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []struct {
		err     error
		message string
	}{
		{ErrInvalidDeviceID{ID: "abc"}, "invalid device ID: abc"},
		{ErrDeviceNotFound{ID: 18446744073709551615}, "device not found: 18446744073709551615"},
		{ErrDeviceNotFoundBySerial{Serial: "SN-001/ABC"}, "device not found with serial: SN-001/ABC"},
		{ErrSerialNumberRequired{}, "serial number is required"},
		{ErrDeleteDeviceFailed{ID: 123, Reason: "device is currently in use"}, "failed to delete device 123: device is currently in use"},
		{ErrGetDeviceFailed{ID: 123, Reason: "connection timeout"}, "failed to get device 123: connection timeout"},
		{ErrListDevicesFailed{Reason: "operation timed out"}, "failed to list devices: operation timed out"},
		{ErrFindDeviceBySerialFailed{Serial: "ABC123", Reason: "connection refused"}, "failed to find device by serial ABC123: connection refused"},
		{ErrProfileNameRequired{}, "device profile: --name is required"},
		{ErrProfileInvalidRole{Role: "x"}, `device profile: invalid role "x", must be one of: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer`},
		{ErrProfileEKCertInvalid{Reason: "no PEM"}, "device profile: EK certificate is not a valid PEM x509 certificate: no PEM"},
		{ErrInvalidPagination{Page: 0, PageSize: 5}, "device profile: invalid pagination: page 0, page-size 5 (both must be >= 1)"},
		{ErrProfileMatchCriteriaRequired{}, "device profile: at least one of --mac, --serial or --model is required"},
		{ErrNoMatchingProfile{MACAddress: "m", Serial: "s", Model: "r"}, `device profile: no profile matches mac "m", serial "s", model "r"`},
		{ErrAssignIdentityRequired{}, "device profile: assignment requires --device, --ek-serial, or --mac"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.message, tt.err.Error())
	}
}
