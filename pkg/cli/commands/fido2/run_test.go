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

package fido2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	fido2svc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// testDevice is the authenticator every fake RPC reports.
var testDevice = &platformv1.FIDO2Device{
	Id:           "hid-1",
	Path:         "/dev/hidraw0",
	Manufacturer: "Yubico",
	Product:      "YubiKey 5",
	ProductId:    0x0407,
	VendorId:     0x1050,
}

// wantDevice is testDevice as the SDK hands it to the CLI printer.
var wantDevice = fido2svc.Device{
	ID:           "hid-1",
	Path:         "/dev/hidraw0",
	Manufacturer: "Yubico",
	Product:      "YubiKey 5",
	ProductID:    0x0407,
	VendorID:     0x1050,
}

// fakeFIDO2Server is the daemon's FIDO2 gRPC service, served in process. It
// records the last request each RPC received and, when err is set, fails
// every RPC with it.
type fakeFIDO2Server struct {
	platformv1.UnimplementedFIDO2ServiceServer

	err error

	mu   sync.Mutex
	seen seenRequests
}

// seenRequests is the last request each recording RPC received.
type seenRequests struct {
	wait     *platformv1.FIDO2WaitDeviceRequest
	info     *platformv1.FIDO2InfoRequest
	register *platformv1.FIDO2RegisterRequest
	auth     *platformv1.FIDO2AuthenticateRequest
}

// received returns the requests recorded so far; the server goroutine writes
// them, so the test reads them under the same lock.
func (s *fakeFIDO2Server) received() seenRequests {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

func (s *fakeFIDO2Server) ListDevices(_ context.Context, _ *platformv1.FIDO2ListDevicesRequest) (*platformv1.FIDO2ListDevicesResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.FIDO2ListDevicesResponse{Devices: []*platformv1.FIDO2Device{testDevice}}, nil
}

func (s *fakeFIDO2Server) WaitDevice(_ context.Context, r *platformv1.FIDO2WaitDeviceRequest) (*platformv1.FIDO2WaitDeviceResponse, error) {
	s.mu.Lock()
	s.seen.wait = r
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.FIDO2WaitDeviceResponse{Device: testDevice}, nil
}

func (s *fakeFIDO2Server) Info(_ context.Context, r *platformv1.FIDO2InfoRequest) (*platformv1.FIDO2InfoResponse, error) {
	s.mu.Lock()
	s.seen.info = r
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.FIDO2InfoResponse{Info: &platformv1.FIDO2DeviceInfo{
		Device:          testDevice,
		Aaguid:          "cb69481e-8ff7-4039-93ec-0a2729a154a8",
		FirmwareVersion: "5.4.3",
		Extensions:      []string{"credProtect", "hmac-secret"},
		Options:         map[string]bool{"rk": true, "uv": false},
		MaxMsgSize:      1200,
	}}, nil
}

func (s *fakeFIDO2Server) Register(_ context.Context, r *platformv1.FIDO2RegisterRequest) (*platformv1.FIDO2RegisterResponse, error) {
	s.mu.Lock()
	s.seen.register = r
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.FIDO2RegisterResponse{
		CredentialId: "c0ffee",
		Aaguid:       "cb69481e-8ff7-4039-93ec-0a2729a154a8",
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
	}, nil
}

func (s *fakeFIDO2Server) Authenticate(_ context.Context, r *platformv1.FIDO2AuthenticateRequest) (*platformv1.FIDO2AuthenticateResponse, error) {
	s.mu.Lock()
	s.seen.auth = r
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.FIDO2AuthenticateResponse{Authenticated: true, Counter: 42}, nil
}

// startFIDO2Server serves srv on a Unix socket in a temporary directory and
// returns the fido2 command tree with JSON-output flags pointing at it.
func startFIDO2Server(t *testing.T, srv *fakeFIDO2Server) func(args ...string) (string, error) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterFIDO2ServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped, its other clean-shutdown result.
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}

	return func(args ...string) (string, error) {
		cmd := NewCommand(getFlags)
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		var runErr error
		out := captureStdout(t, func() { runErr = cmd.Execute() })
		return out, runErr
	}
}

// captureStdout returns what f writes to os.Stdout, where the CLI printer
// writes.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	copied := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		copied <- buf.Bytes()
	}()
	f()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-copied
	require.NoError(t, r.Close())
	return string(out)
}

// decodeJSON decodes the CLI's JSON output into a value of type T.
func decodeJSON[T any](t *testing.T, out string) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal([]byte(out), &v), "output: %q", out)
	return v
}

func TestListDevices_PrintsTheDaemonsDevices(t *testing.T) {
	run := startFIDO2Server(t, &fakeFIDO2Server{})

	out, err := run("list-devices")
	require.NoError(t, err)

	got := decodeJSON[fido2svc.ListDevicesResponse](t, out)
	assert.Equal(t, []fido2svc.Device{wantDevice}, got.Devices)
}

func TestWaitDevice_SendsTheTimeoutAndPrintsTheDevice(t *testing.T) {
	srv := &fakeFIDO2Server{}
	run := startFIDO2Server(t, srv)

	out, err := run("wait-device", "--timeout", "10")
	require.NoError(t, err)

	seen := srv.received()
	require.NotNil(t, seen.wait)
	assert.Equal(t, int32(10), seen.wait.GetTimeoutSeconds())
	got := decodeJSON[fido2svc.WaitDeviceResponse](t, out)
	assert.Equal(t, wantDevice, got.Device)
}

func TestInfo_SendsTheDeviceAndPrintsItsCapabilities(t *testing.T) {
	srv := &fakeFIDO2Server{}
	run := startFIDO2Server(t, srv)

	out, err := run("info", "--device", "hid-1")
	require.NoError(t, err)

	seen := srv.received()
	require.NotNil(t, seen.info)
	assert.Equal(t, "hid-1", seen.info.GetDevice())
	got := decodeJSON[fido2svc.InfoResponse](t, out)
	assert.Equal(t, fido2svc.Info{
		Device:          wantDevice,
		AAGUID:          "cb69481e-8ff7-4039-93ec-0a2729a154a8",
		FirmwareVersion: "5.4.3",
		Extensions:      []string{"credProtect", "hmac-secret"},
		Options:         map[string]bool{"rk": true, "uv": false},
		MaxMsgSize:      1200,
	}, got.Info)
}

func TestRegister_SendsEveryFlagAndTheWireRole(t *testing.T) {
	tests := []struct {
		role string
		want platformv1.FIDO2Role
	}{
		{role: "", want: platformv1.FIDO2Role_FIDO2_ROLE_UNSPECIFIED},
		{role: "so", want: platformv1.FIDO2Role_FIDO2_ROLE_SO},
		{role: "admin", want: platformv1.FIDO2Role_FIDO2_ROLE_ADMIN},
		{role: "user", want: platformv1.FIDO2Role_FIDO2_ROLE_USER},
	}
	for _, tt := range tests {
		t.Run("role="+tt.role, func(t *testing.T) {
			srv := &fakeFIDO2Server{}
			run := startFIDO2Server(t, srv)

			out, err := run("register", "--username", "alice", "--role", tt.role,
				"--require-pin", "--require-uv", "--rp-id", "platform.example")
			require.NoError(t, err)

			seen := srv.received()
			require.NotNil(t, seen.register)
			assert.Equal(t, "alice", seen.register.GetUsername())
			assert.Equal(t, tt.want, seen.register.GetRole())
			assert.True(t, seen.register.GetRequirePin())
			assert.True(t, seen.register.GetRequireUv())
			assert.Equal(t, "platform.example", seen.register.GetRpId())

			got := decodeJSON[fido2svc.RegisterResponse](t, out)
			assert.Equal(t, fido2svc.RegisterResponse{
				CredentialID: "c0ffee",
				AAGUID:       "cb69481e-8ff7-4039-93ec-0a2729a154a8",
				PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
			}, got)
		})
	}
}

func TestRegister_DefaultsLeavePINAndUVOff(t *testing.T) {
	srv := &fakeFIDO2Server{}
	run := startFIDO2Server(t, srv)

	_, err := run("register", "--username", "bob")
	require.NoError(t, err)

	seen := srv.received()
	require.NotNil(t, seen.register)
	assert.False(t, seen.register.GetRequirePin())
	assert.False(t, seen.register.GetRequireUv())
	assert.Empty(t, seen.register.GetRpId())
}

func TestAuthenticate_SendsTheCredentialAndPrintsTheResult(t *testing.T) {
	srv := &fakeFIDO2Server{}
	run := startFIDO2Server(t, srv)

	out, err := run("authenticate", "--credential-id", "c0ffee")
	require.NoError(t, err)

	seen := srv.received()
	require.NotNil(t, seen.auth)
	assert.Equal(t, "c0ffee", seen.auth.GetCredentialId())
	got := decodeJSON[fido2svc.AuthenticateResponse](t, out)
	assert.Equal(t, fido2svc.AuthenticateResponse{Authenticated: true, Counter: 42}, got)
}

// TestCommands_ReturnTheTypedRPCFailure checks that a daemon-side failure
// reaches the caller as the SDK's typed error, carrying the gRPC status, and
// that nothing is printed.
func TestCommands_ReturnTheTypedRPCFailure(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		cause func(error) error
	}{
		{"list-devices", []string{"list-devices"}, func(err error) error {
			var e *fido2svc.ErrListDevicesFailed
			if !errors.As(err, &e) {
				return nil
			}
			return e.Cause
		}},
		{"wait-device", []string{"wait-device"}, func(err error) error {
			var e *fido2svc.ErrWaitDeviceFailed
			if !errors.As(err, &e) {
				return nil
			}
			return e.Cause
		}},
		{"info", []string{"info", "--device", "hid-1"}, func(err error) error {
			var e *fido2svc.ErrDeviceInfoFailed
			if !errors.As(err, &e) {
				return nil
			}
			return e.Cause
		}},
		{"register", []string{"register", "--username", "alice"}, func(err error) error {
			var e *fido2svc.ErrRegisterFailed
			if !errors.As(err, &e) {
				return nil
			}
			return e.Cause
		}},
		{"authenticate", []string{"authenticate", "--credential-id", "c0ffee"}, func(err error) error {
			var e *fido2svc.ErrAuthenticateFailed
			if !errors.As(err, &e) {
				return nil
			}
			return e.Cause
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := startFIDO2Server(t, &fakeFIDO2Server{err: status.Error(codes.NotFound, "no authenticator")})

			out, err := run(tt.args...)
			require.Error(t, err)
			assert.Empty(t, out)

			cause := tt.cause(err)
			require.NotNil(t, cause, "error %T is not the SDK's typed failure: %v", err, err)
			assert.Equal(t, codes.NotFound, status.Code(cause))
		})
	}
}

// TestRunFunctions_RequireAContext checks that each run function refuses to
// dial without a CLI context once its own flags are valid.
func TestRunFunctions_RequireAContext(t *testing.T) {
	noContext := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	tests := []struct {
		name string
		run  func() error
	}{
		{"list-devices", func() error { return runListDevices(noContext) }},
		{"wait-device", func() error { return runWaitDevice(noContext, &waitDeviceFlags{}) }},
		{"info", func() error { return runInfo(noContext, &infoFlags{device: "hid-1"}) }},
		{"register", func() error { return runRegister(noContext, &registerFlags{username: "alice"}) }},
		{"authenticate", func() error { return runAuthenticate(noContext, &authenticateFlags{credentialID: "c0ffee"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want cli.ErrNoContextSet
			assert.ErrorAs(t, tt.run(), &want)
		})
	}
}
