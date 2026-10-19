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

package piv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	pivsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// fakePIVServer is an in-process PIV gRPC service. It records the last
// request of each RPC and answers with canned responses, or with failure
// when it is set.
type fakePIVServer struct {
	platformv1.UnimplementedPIVServiceServer

	failure error

	listSlots *platformv1.PIVListSlotsRequest
	slotInfo  *platformv1.PIVSlotInfoRequest
	generate  *platformv1.PIVGenerateRequest
	importKey *platformv1.PIVImportRequest
	sign      *platformv1.PIVSignRequest
	attest    *platformv1.PIVAttestRequest
	reset     *platformv1.PIVResetRequest
}

func (s *fakePIVServer) ListDevices(context.Context, *platformv1.PIVListDevicesRequest) (*platformv1.PIVListDevicesResponse, error) {
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVListDevicesResponse{Devices: []*platformv1.PIVDevice{
		{Id: "yk-1", Name: "YubiKey 5", Manufacturer: "Yubico", Serial: "1234"},
	}}, nil
}

func (s *fakePIVServer) ListSlots(_ context.Context, req *platformv1.PIVListSlotsRequest) (*platformv1.PIVListSlotsResponse, error) {
	s.listSlots = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVListSlotsResponse{Slots: []*platformv1.PIVSlot{
		{Id: "9a", Name: "PIV Authentication", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA, HasKey: true},
	}}, nil
}

func (s *fakePIVServer) SlotInfo(_ context.Context, req *platformv1.PIVSlotInfoRequest) (*platformv1.PIVSlotInfoResponse, error) {
	s.slotInfo = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVSlotInfoResponse{
		Slot:         &platformv1.PIVSlot{Id: "9c", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA, HasKey: true, HasCertificate: true},
		PublicKeyPem: "PUBLIC",
	}, nil
}

func (s *fakePIVServer) Generate(_ context.Context, req *platformv1.PIVGenerateRequest) (*platformv1.PIVGenerateResponse, error) {
	s.generate = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVGenerateResponse{PublicKeyPem: "GENERATED"}, nil
}

func (s *fakePIVServer) Import(_ context.Context, req *platformv1.PIVImportRequest) (*platformv1.PIVImportResponse, error) {
	s.importKey = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVImportResponse{Imported: true}, nil
}

func (s *fakePIVServer) Sign(_ context.Context, req *platformv1.PIVSignRequest) (*platformv1.PIVSignResponse, error) {
	s.sign = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVSignResponse{Signature: []byte("sig")}, nil
}

func (s *fakePIVServer) Attest(_ context.Context, req *platformv1.PIVAttestRequest) (*platformv1.PIVAttestResponse, error) {
	s.attest = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVAttestResponse{AttestationCertPem: "LEAF", AttestationChainPem: "CHAIN"}, nil
}

func (s *fakePIVServer) Reset(_ context.Context, req *platformv1.PIVResetRequest) (*platformv1.PIVResetResponse, error) {
	s.reset = req
	if s.failure != nil {
		return nil, s.failure
	}
	return &platformv1.PIVResetResponse{Reset_: true}, nil
}

// servePIV serves srv on a Unix socket and returns flags whose local context
// points the SDK client at it, as platformctl does against platformd.
func servePIV(t *testing.T, srv *fakePIVServer) *cli.CommonFlags {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	platformv1.RegisterPIVServiceServer(server, srv)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "local", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: socket}}, nil
		},
	}
}

// runPIV executes `piv <args>` and returns what it printed to stdout.
func runPIV(t *testing.T, flags *cli.CommonFlags, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	read := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		if copyErr != nil {
			buf.WriteString(copyErr.Error())
		}
		read <- buf.String()
	}()
	os.Stdout = w
	runErr := cmd.Execute()
	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	return <-read, runErr
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func assertJSON(t *testing.T, got, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("bad expected JSON: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("output = %s, want %s", got, want)
	}
}

// Every subcommand sends its flags to the daemon's PIV service and prints the
// reply.
func TestRun_SendsTheRequestAndPrintsTheReply(t *testing.T) {
	keyFile := writeTemp(t, "key.pem", "PRIVATE KEY PEM")
	inputFile := writeTemp(t, "data.bin", "payload bytes")

	tests := []struct {
		name  string
		args  []string
		want  string
		check func(t *testing.T, srv *fakePIVServer)
	}{
		{
			name: "list-devices",
			args: []string{"list-devices"},
			want: `{"devices":[{"id":"yk-1","name":"YubiKey 5","manufacturer":"Yubico","serial":"1234"}]}`,
		},
		{
			name: "list-slots",
			args: []string{"list-slots", "--device", "yk-1"},
			want: `{"slots":[{"id":"9a","name":"PIV Authentication","algorithm":"ecdsa","has_key":true,"has_certificate":false}]}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.listSlots.GetDevice() != "yk-1" {
					t.Errorf("device = %q, want yk-1", srv.listSlots.GetDevice())
				}
			},
		},
		{
			name: "info",
			args: []string{"info", "--slot", "9c", "--device", "yk-1"},
			want: `{"slot":{"id":"9c","algorithm":"rsa","has_key":true,"has_certificate":true},"public_key_pem":"PUBLIC"}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.slotInfo.GetSlot() != "9c" || srv.slotInfo.GetDevice() != "yk-1" {
					t.Errorf("request = %v, want slot 9c on yk-1", srv.slotInfo)
				}
			},
		},
		{
			name: "generate",
			args: []string{"generate", "--slot", "9c", "--algorithm", "ed25519", "--pin", "123456"},
			want: `{"public_key_pem":"GENERATED"}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.generate.GetSlot() != "9c" || srv.generate.GetPin() != "123456" {
					t.Errorf("request = %v, want slot 9c with PIN 123456", srv.generate)
				}
				if srv.generate.GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519 {
					t.Errorf("algorithm = %v, want ED25519", srv.generate.GetAlgorithm())
				}
			},
		},
		{
			name: "import",
			args: []string{"import", "--slot", "82", "--key-file", keyFile, "--pin", "123456"},
			want: `{"imported":true}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.importKey.GetSlot() != "82" || srv.importKey.GetPin() != "123456" {
					t.Errorf("request = %v, want slot 82 with PIN 123456", srv.importKey)
				}
				if srv.importKey.GetPrivateKeyPem() != "PRIVATE KEY PEM" {
					t.Errorf("key = %q, want the key file's content", srv.importKey.GetPrivateKeyPem())
				}
			},
		},
		{
			name: "sign",
			args: []string{"sign", "--slot", "9c", "--input-file", inputFile, "--pin", "123456"},
			// []byte marshals as base64: "sig" is "c2ln".
			want: `{"signature":"c2ln"}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.sign.GetSlot() != "9c" || srv.sign.GetPin() != "123456" {
					t.Errorf("request = %v, want slot 9c with PIN 123456", srv.sign)
				}
				if string(srv.sign.GetPayload()) != "payload bytes" {
					t.Errorf("payload = %q, want the input file's content", srv.sign.GetPayload())
				}
			},
		},
		{
			name: "attest",
			args: []string{"attest", "--slot", "9a"},
			want: `{"attestation_cert_pem":"LEAF","attestation_chain_pem":"CHAIN"}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.attest.GetSlot() != "9a" {
					t.Errorf("slot = %q, want 9a", srv.attest.GetSlot())
				}
			},
		},
		{
			name: "reset",
			args: []string{"reset", "--device", "yk-1", "--yes-i-understand"},
			want: `{"reset":true}`,
			check: func(t *testing.T, srv *fakePIVServer) {
				if srv.reset.GetDevice() != "yk-1" {
					t.Errorf("device = %q, want yk-1", srv.reset.GetDevice())
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakePIVServer{}
			out, err := runPIV(t, servePIV(t, srv), tt.args...)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			assertJSON(t, out, tt.want)
			if tt.check != nil {
				tt.check(t, srv)
			}
		})
	}
}

// A daemon-side failure reaches the caller as the SDK's typed error, with
// the gRPC status still inspectable underneath, and nothing is printed.
func TestRun_ReturnsTheServiceFailure(t *testing.T) {
	keyFile := writeTemp(t, "key.pem", "PRIVATE KEY PEM")
	inputFile := writeTemp(t, "data.bin", "payload bytes")

	tests := []struct {
		name   string
		args   []string
		target any
	}{
		{"list-devices", []string{"list-devices"}, new(*pivsvc.ErrListDevicesFailed)},
		{"list-slots", []string{"list-slots", "--device", "yk-1"}, new(*pivsvc.ErrListSlotsFailed)},
		{"info", []string{"info", "--slot", "9c"}, new(*pivsvc.ErrSlotInfoFailed)},
		{"generate", []string{"generate", "--slot", "9c", "--algorithm", "rsa", "--pin", "1"}, new(*pivsvc.ErrGenerateFailed)},
		{"import", []string{"import", "--slot", "82", "--key-file", keyFile, "--pin", "1"}, new(*pivsvc.ErrImportFailed)},
		{"sign", []string{"sign", "--slot", "9c", "--input-file", inputFile, "--pin", "1"}, new(*pivsvc.ErrSignFailed)},
		{"attest", []string{"attest", "--slot", "9a"}, new(*pivsvc.ErrAttestFailed)},
		{"reset", []string{"reset", "--device", "yk-1", "--yes-i-understand"}, new(*pivsvc.ErrResetFailed)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakePIVServer{failure: status.Error(codes.FailedPrecondition, "card removed")}
			out, err := runPIV(t, servePIV(t, srv), tt.args...)
			if !errors.As(err, tt.target) {
				t.Fatalf("error = %v (%T), want %T", err, err, tt.target)
			}
			if code := status.Code(errors.Unwrap(err)); code != codes.FailedPrecondition {
				t.Errorf("status code = %v, want FailedPrecondition", code)
			}
			if out != "" {
				t.Errorf("printed %q on failure, want nothing", out)
			}
		})
	}
}

// Valid flags without a CLI context stop before any connection is made.
func TestRun_RefusesFlagsWithoutAContext(t *testing.T) {
	keyFile := writeTemp(t, "key.pem", "PRIVATE KEY PEM")
	inputFile := writeTemp(t, "data.bin", "payload bytes")

	runs := map[string]func(*cli.CommonFlags) error{
		"list-devices": runListDevices,
		"list-slots":   func(c *cli.CommonFlags) error { return runListSlots(c, &listSlotsFlags{device: "yk-1"}) },
		"info":         func(c *cli.CommonFlags) error { return runInfo(c, &infoFlags{slot: "9c"}) },
		"generate": func(c *cli.CommonFlags) error {
			return runGenerate(c, &generateFlags{slot: "9c", algorithm: "rsa", pin: "1"})
		},
		"import": func(c *cli.CommonFlags) error {
			return runImport(c, &importFlags{slot: "82", keyFile: keyFile, pin: "1"})
		},
		"sign": func(c *cli.CommonFlags) error {
			return runSign(c, &signFlags{slot: "9c", inputFile: inputFile, pin: "1"})
		},
		"attest": func(c *cli.CommonFlags) error { return runAttest(c, &attestFlags{slot: "9a"}) },
		"reset": func(c *cli.CommonFlags) error {
			return runReset(c, &resetFlags{device: "yk-1", yesIUnderstand: true})
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			var noContext cli.ErrNoContextSet
			if err := run(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}); !errors.As(err, &noContext) {
				t.Errorf("error = %v (%T), want cli.ErrNoContextSet", err, err)
			}
		})
	}
}

// A file that cannot be read is reported with its path, and the OS cause
// stays reachable through Unwrap.
func TestRun_FileReadErrorsUnwrapToTheOSCause(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	err := runImport(&cli.CommonFlags{}, &importFlags{slot: "82", keyFile: missing, pin: "1"})
	var keyErr ErrKeyFileRead
	if !errors.As(err, &keyErr) || keyErr.Path != missing {
		t.Errorf("import error = %v, want ErrKeyFileRead for %s", err, missing)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("import error = %v, want it to unwrap to fs.ErrNotExist", err)
	}

	err = runSign(&cli.CommonFlags{}, &signFlags{slot: "9c", inputFile: missing, pin: "1"})
	var inputErr ErrInputFileRead
	if !errors.As(err, &inputErr) || inputErr.Path != missing {
		t.Errorf("sign error = %v, want ErrInputFileRead for %s", err, missing)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("sign error = %v, want it to unwrap to fs.ErrNotExist", err)
	}
}
