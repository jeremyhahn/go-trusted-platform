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

package vtpm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// backendFailure is the message every fake RPC fails with when the fake is
// told to fail; the CLI must carry it into the typed error's Reason.
const backendFailure = "vtpm backend down"

// fixedTime renders as "2026-10-19 12:30:45 UTC" in details and
// "2026-10-19 12:30" in tables.
var fixedTime = time.Date(2026, 10, 19, 12, 30, 45, 0, time.UTC)

// fakeVTPMServer is an in-process VTPMService. Its response fields are set
// before the server starts and only read afterwards; the requests it
// receives are recorded under mu.
type fakeVTPMServer struct {
	platformv1.UnimplementedVTPMServiceServer

	fail       bool
	bundle     *platformv1.Bundle
	bundles    []*platformv1.Bundle
	template   *platformv1.Template
	templates  []*platformv1.Template
	running    bool
	stopped    bool
	extended   bool
	socketPath string
	value      []byte
	chunks     [][]byte

	mu       sync.Mutex
	requests []proto.Message
	imported []byte
}

func (s *fakeVTPMServer) record(req proto.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	if s.fail {
		return status.Error(codes.Unavailable, backendFailure)
	}
	return nil
}

func (s *fakeVTPMServer) lastRequest(t *testing.T) proto.Message {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.requests, "the server received no request")
	return s.requests[len(s.requests)-1]
}

func (s *fakeVTPMServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *fakeVTPMServer) importedBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imported
}

func (s *fakeVTPMServer) CreateBundle(_ context.Context, req *platformv1.CreateBundleRequest) (*platformv1.CreateBundleResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CreateBundleResponse{Bundle: s.bundle}, nil
}

func (s *fakeVTPMServer) GetBundle(_ context.Context, req *platformv1.GetBundleRequest) (*platformv1.GetBundleResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.GetBundleResponse{Bundle: s.bundle}, nil
}

func (s *fakeVTPMServer) DeleteBundle(_ context.Context, req *platformv1.DeleteBundleRequest) (*platformv1.DeleteBundleResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteBundleResponse{}, nil
}

func (s *fakeVTPMServer) ListBundles(_ context.Context, req *platformv1.ListBundlesRequest) (*platformv1.ListBundlesResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.ListBundlesResponse{Bundles: s.bundles, Total: int32(len(s.bundles))}, nil
}

func (s *fakeVTPMServer) CreateTemplate(_ context.Context, req *platformv1.CreateTemplateRequest) (*platformv1.CreateTemplateResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CreateTemplateResponse{Template: s.template}, nil
}

func (s *fakeVTPMServer) DeleteTemplate(_ context.Context, req *platformv1.DeleteTemplateRequest) (*platformv1.DeleteTemplateResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteTemplateResponse{}, nil
}

func (s *fakeVTPMServer) ListTemplates(_ context.Context, req *platformv1.ListTemplatesRequest) (*platformv1.ListTemplatesResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.ListTemplatesResponse{Templates: s.templates}, nil
}

func (s *fakeVTPMServer) CloneTemplate(_ context.Context, req *platformv1.CloneTemplateRequest) (*platformv1.CloneTemplateResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CloneTemplateResponse{Bundle: s.bundle}, nil
}

// ExportBundle streams every chunk before failing, so a failed export
// leaves a partly written file the CLI must remove.
func (s *fakeVTPMServer) ExportBundle(req *platformv1.ExportBundleRequest, stream grpc.ServerStreamingServer[platformv1.ExportBundleResponse]) error {
	failure := s.record(req)
	for _, chunk := range s.chunks {
		if err := stream.Send(&platformv1.ExportBundleResponse{Data: chunk}); err != nil {
			return err
		}
	}
	return failure
}

func (s *fakeVTPMServer) ImportBundle(stream grpc.ClientStreamingServer[platformv1.ImportBundleRequest, platformv1.ImportBundleResponse]) error {
	var received []byte
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		received = append(received, req.GetData()...)
	}
	s.mu.Lock()
	s.imported = received
	s.mu.Unlock()
	if err := s.record(&platformv1.ImportBundleRequest{Data: received}); err != nil {
		return err
	}
	return stream.SendAndClose(&platformv1.ImportBundleResponse{Bundle: s.bundle})
}

func (s *fakeVTPMServer) StartVTPM(_ context.Context, req *platformv1.StartVTPMRequest) (*platformv1.StartVTPMResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.StartVTPMResponse{BundleId: req.GetBundleId(), Running: s.running, SocketPath: s.socketPath}, nil
}

func (s *fakeVTPMServer) StopVTPM(_ context.Context, req *platformv1.StopVTPMRequest) (*platformv1.StopVTPMResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.StopVTPMResponse{BundleId: req.GetBundleId(), Stopped: s.stopped}, nil
}

func (s *fakeVTPMServer) IsVTPMRunning(_ context.Context, req *platformv1.IsVTPMRunningRequest) (*platformv1.IsVTPMRunningResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.IsVTPMRunningResponse{BundleId: req.GetBundleId(), Running: s.running}, nil
}

func (s *fakeVTPMServer) QuoteVTPM(_ context.Context, req *platformv1.QuoteVTPMRequest) (*platformv1.QuoteVTPMResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.QuoteVTPMResponse{
		BundleId:      req.GetBundleId(),
		HashAlgorithm: "SHA256",
		Quote:         []byte{0x01},
		Signature:     []byte{0x02},
		PcrValues:     map[int32][]byte{0: {0xaa}},
	}, nil
}

func (s *fakeVTPMServer) SealVTPM(_ context.Context, req *platformv1.SealVTPMRequest) (*platformv1.SealVTPMResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.SealVTPMResponse{BundleId: req.GetBundleId(), SealedData: s.value}, nil
}

func (s *fakeVTPMServer) UnsealVTPM(_ context.Context, req *platformv1.UnsealVTPMRequest) (*platformv1.UnsealVTPMResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.UnsealVTPMResponse{BundleId: req.GetBundleId(), Data: s.value}, nil
}

func (s *fakeVTPMServer) ExtendVTPMPCR(_ context.Context, req *platformv1.ExtendVTPMPCRRequest) (*platformv1.ExtendVTPMPCRResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.ExtendVTPMPCRResponse{BundleId: req.GetBundleId(), PcrIndex: req.GetPcrIndex(), Extended: s.extended}, nil
}

func (s *fakeVTPMServer) ReadVTPMPCR(_ context.Context, req *platformv1.ReadVTPMPCRRequest) (*platformv1.ReadVTPMPCRResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.ReadVTPMPCRResponse{BundleId: req.GetBundleId(), PcrIndex: req.GetPcrIndex(), Value: s.value}, nil
}

// startVTPMServer serves srv on a unix socket — the CLI's local transport
// — and returns the socket path. The directory is kept short because unix
// socket paths are limited to 108 bytes.
func startVTPMServer(t *testing.T, srv *fakeVTPMServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "vt")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	sock := filepath.Join(dir, "s.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	gs := grpc.NewServer()
	platformv1.RegisterVTPMServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped, its other clean-shutdown result.
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err)
		}
	})
	return sock
}

func socketFlags(sock string, format cli.OutputFormat) *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{
				Name:  "test",
				Type:  cli.ContextTypeLocal,
				Local: &cli.LocalContext{SocketPath: sock},
			}, nil
		},
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// what it wrote. The printer binds os.Stdout when it is built, so fn must
// build it (every run function does).
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, readErr := io.ReadAll(r)
		read <- readResult{data: data, err: readErr}
	}()

	orig := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = orig

	require.NoError(t, w.Close())
	res := <-read
	require.NoError(t, res.err)
	require.NoError(t, r.Close())
	return string(res.data), runErr
}

// withStdin feeds input to the confirmation prompt for the rest of the test.
func withStdin(t *testing.T, input string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	require.NoError(t, err)
	_, err = f.WriteString(input)
	require.NoError(t, err)
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = orig
		assert.NoError(t, f.Close())
	})
}

func decodeJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &got), "output: %s", out)
	return got
}

func assertRequest(t *testing.T, srv *fakeVTPMServer, want proto.Message) {
	t.Helper()
	got := srv.lastRequest(t)
	assert.Truef(t, proto.Equal(want, got), "request\n got: %v\nwant: %v", got, want)
}

// fullManifestBundle carries every optional field printBundleDetails prints.
func fullManifestBundle(mode platformv1.BundleMode) *platformv1.Bundle {
	return &platformv1.Bundle{
		Id:   "b-1",
		Mode: mode,
		Manifest: &platformv1.Manifest{
			Hostname:          "web-01",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
			SecureBootEnabled: true,
			ClonedFrom:        "tmpl-a",
			Labels:            map[string]string{"env": "prod"},
			CreatedAt:         timestamppb.New(fixedTime),
		},
	}
}

const fullManifestDetails = "ID: b-1\n" +
	"Mode: BUNDLE_MODE_PRE_ASSIGNED\n" +
	"Hostname: web-01\n" +
	"EK Algorithm: RSA\n" +
	"Secure Boot: Yes\n" +
	"Cloned From: tmpl-a\n" +
	"Created: 2026-10-19 12:30:45 UTC\n" +
	"\n" +
	"[INFO] Labels:\n" +
	"  env: prod\n"

func TestRunCreate_PrintsCreatedBundleAndSendsOptions(t *testing.T) {
	srv := &fakeVTPMServer{bundle: fullManifestBundle(platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED)}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runCreate(socketFlags(sock, cli.OutputFormatTable), "web-01", true, "rsa", "tmpl-a", []string{"env=prod"})
	})

	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] vTPM bundle created: b-1\n\n"+fullManifestDetails, out)
	assertRequest(t, srv, &platformv1.CreateBundleRequest{Options: &platformv1.CreateBundleOptions{
		Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
		Hostname:          "web-01",
		EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
		SecureBootEnabled: true,
		TemplateId:        "tmpl-a",
		Labels:            map[string]string{"env": "prod"},
	}})
}

func TestRunCreate_JSONAndEmptyResponse(t *testing.T) {
	srv := &fakeVTPMServer{bundle: &platformv1.Bundle{Id: "b-1", Mode: platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runCreate(socketFlags(sock, cli.OutputFormatJSON), "web-01", false, "ECC", "", nil)
	})
	require.NoError(t, err)
	bundle, ok := decodeJSON(t, out)["bundle"].(map[string]any)
	require.True(t, ok, "output: %s", out)
	assert.Equal(t, "b-1", bundle["id"])
	assert.Equal(t, "BUNDLE_MODE_PRE_ASSIGNED", bundle["mode"])

	// A daemon that answers without a bundle prints nothing in table form.
	empty := startVTPMServer(t, &fakeVTPMServer{})
	out, err = captureStdout(t, func() error {
		return runCreate(socketFlags(empty, cli.OutputFormatTable), "web-01", false, "ECC", "", nil)
	})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestRunCreate_RejectsMalformedLabelBeforeConnecting(t *testing.T) {
	err := runCreate(socketFlags("/nonexistent.sock", cli.OutputFormatTable), "web-01", false, "RSA", "", []string{"env"})

	var labelErr ErrInvalidLabel
	require.ErrorAs(t, err, &labelErr)
	assert.Equal(t, "env", labelErr.Label)
	assert.Equal(t, "invalid label format: env (use key=value)", err.Error())
}

func TestPrintBundleDetails_OptionalFields(t *testing.T) {
	tests := []struct {
		name   string
		bundle *vtpmsvc.Bundle
		want   string
	}{
		{
			name:   "no manifest and no creation time",
			bundle: &vtpmsvc.Bundle{ID: "b-2", Mode: vtpmsvc.BundleModeTemplate},
			want:   "ID: b-2\nMode: BUNDLE_MODE_TEMPLATE\n",
		},
		{
			name:   "no manifest falls back to the bundle creation time",
			bundle: &vtpmsvc.Bundle{ID: "b-2", Mode: vtpmsvc.BundleModeTemplate, CreatedAt: &fixedTime},
			want:   "ID: b-2\nMode: BUNDLE_MODE_TEMPLATE\nCreated: 2026-10-19 12:30:45 UTC\n",
		},
		{
			name: "manifest without optional fields",
			bundle: &vtpmsvc.Bundle{
				ID: "b-2", Mode: vtpmsvc.BundleModeTemplate, CreatedAt: &fixedTime,
				Manifest: &vtpmsvc.BundleManifest{EKAlgorithm: vtpmsvc.EKAlgorithmECC},
			},
			want: "ID: b-2\nMode: BUNDLE_MODE_TEMPLATE\nEK Algorithm: ECC\nSecure Boot: No\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error {
				printBundleDetails(cli.NewPrinter(cli.OutputFormatTable, true), tt.bundle)
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestRunClone_PrintsClonedBundleAndSendsOptions(t *testing.T) {
	srv := &fakeVTPMServer{bundle: fullManifestBundle(platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED)}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runClone(socketFlags(sock, cli.OutputFormatTable), "tmpl-a", "web-01", []string{"env=prod"})
	})

	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Bundle cloned successfully: b-1\n\n"+fullManifestDetails, out)
	assertRequest(t, srv, &platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{
		TemplateId: "tmpl-a",
		Hostname:   "web-01",
		Labels:     map[string]string{"env": "prod"},
	}})
}

func TestRunClone_JSONEmptyResponseAndBadLabel(t *testing.T) {
	srv := &fakeVTPMServer{bundle: &platformv1.Bundle{Id: "b-1"}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runClone(socketFlags(sock, cli.OutputFormatJSON), "tmpl-a", "web-01", nil)
	})
	require.NoError(t, err)
	bundle, ok := decodeJSON(t, out)["bundle"].(map[string]any)
	require.True(t, ok, "output: %s", out)
	assert.Equal(t, "b-1", bundle["id"])

	empty := startVTPMServer(t, &fakeVTPMServer{})
	out, err = captureStdout(t, func() error {
		return runClone(socketFlags(empty, cli.OutputFormatTable), "tmpl-a", "web-01", nil)
	})
	require.NoError(t, err)
	assert.Empty(t, out)

	// Labels are parsed after connecting, so the request is never sent.
	before := srv.requestCount()
	err = runClone(socketFlags(sock, cli.OutputFormatTable), "tmpl-a", "web-01", []string{"=x", "bad"})
	var labelErr ErrInvalidLabel
	require.ErrorAs(t, err, &labelErr)
	assert.Equal(t, "bad", labelErr.Label)
	assert.Equal(t, before, srv.requestCount())
}

// deleteCase drives runDelete and runTemplateDelete through one table.
type deleteCase struct {
	name    string
	run     func(flags *cli.CommonFlags, id string, force bool) error
	warning string
	success string
	request proto.Message
}

var deleteCases = []deleteCase{
	{
		name:    "bundle",
		run:     runDelete,
		warning: "[WARNING] This will permanently delete bundle 'x-1' and all associated files.\n",
		success: "[SUCCESS] Bundle 'x-1' deleted successfully\n",
		request: &platformv1.DeleteBundleRequest{Id: "x-1"},
	},
	{
		name:    "template",
		run:     runTemplateDelete,
		warning: "[WARNING] This will permanently delete template 'x-1' and all associated files.\n",
		success: "[SUCCESS] Template 'x-1' deleted successfully\n",
		request: &platformv1.DeleteTemplateRequest{Id: "x-1"},
	},
}

const deletePrompt = "Are you sure you want to proceed? [y/N]: "

func TestRunDelete_ForcedAndConfirmed(t *testing.T) {
	for _, tc := range deleteCases {
		t.Run(tc.name+"/forced", func(t *testing.T) {
			srv := &fakeVTPMServer{}
			sock := startVTPMServer(t, srv)

			out, err := captureStdout(t, func() error {
				return tc.run(socketFlags(sock, cli.OutputFormatTable), "x-1", true)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.success, out)
			assertRequest(t, srv, tc.request)
		})

		for _, answer := range []string{"y\n", " YES \n"} {
			t.Run(tc.name+"/confirmed "+answer, func(t *testing.T) {
				srv := &fakeVTPMServer{}
				sock := startVTPMServer(t, srv)
				withStdin(t, answer)

				out, err := captureStdout(t, func() error {
					return tc.run(socketFlags(sock, cli.OutputFormatTable), "x-1", false)
				})
				require.NoError(t, err)
				assert.Equal(t, tc.warning+deletePrompt+tc.success, out)
				assertRequest(t, srv, tc.request)
			})
		}
	}
}

func TestRunDelete_DeclinedOrUnreadableConfirmation(t *testing.T) {
	for _, tc := range deleteCases {
		t.Run(tc.name+"/declined", func(t *testing.T) {
			srv := &fakeVTPMServer{}
			sock := startVTPMServer(t, srv)
			withStdin(t, "n\n")

			out, err := captureStdout(t, func() error {
				return tc.run(socketFlags(sock, cli.OutputFormatTable), "x-1", false)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.warning+deletePrompt+"[INFO] Operation cancelled\n", out)
			assert.Zero(t, srv.requestCount(), "a declined delete must not reach the daemon")
		})

		t.Run(tc.name+"/no answer", func(t *testing.T) {
			srv := &fakeVTPMServer{}
			sock := startVTPMServer(t, srv)
			withStdin(t, "")

			_, err := captureStdout(t, func() error {
				return tc.run(socketFlags(sock, cli.OutputFormatTable), "x-1", false)
			})
			require.ErrorIs(t, err, io.EOF)
			assert.Zero(t, srv.requestCount())
		})
	}
}

func TestRunDelete_JSON(t *testing.T) {
	for _, tc := range deleteCases {
		t.Run(tc.name, func(t *testing.T) {
			sock := startVTPMServer(t, &fakeVTPMServer{})

			out, err := captureStdout(t, func() error {
				return tc.run(socketFlags(sock, cli.OutputFormatJSON), "x-1", true)
			})
			require.NoError(t, err)
			st, ok := decodeJSON(t, out)["status"].(map[string]any)
			require.True(t, ok, "output: %s", out)
			assert.Equal(t, true, st["success"])
		})
	}
}

func TestRunExport_WritesStreamedArchive(t *testing.T) {
	srv := &fakeVTPMServer{chunks: [][]byte{[]byte("abc"), []byte("defg")}}
	sock := startVTPMServer(t, srv)
	output := filepath.Join(t.TempDir(), "out.tar.gz")

	out, err := captureStdout(t, func() error {
		return runExport(socketFlags(sock, cli.OutputFormatTable), "b-1", output, false)
	})

	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Bundle exported successfully: "+output+"\n"+
		"Bundle ID: b-1\n"+
		"Output File: "+output+"\n"+
		"Size: 7 B\n", out)
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "abcdefg", string(data))
	assertRequest(t, srv, &platformv1.ExportBundleRequest{Id: "b-1"})
}

func TestRunExport_DefaultNameJSONAndOverwrite(t *testing.T) {
	srv := &fakeVTPMServer{chunks: [][]byte{[]byte("new")}}
	sock := startVTPMServer(t, srv)
	t.Chdir(t.TempDir())
	const defaultName = "bundle-b-1.vtpm.tar.gz"
	require.NoError(t, os.WriteFile(defaultName, []byte("old-content"), 0o600))

	out, err := captureStdout(t, func() error {
		return runExport(socketFlags(sock, cli.OutputFormatJSON), "b-1", "", true)
	})

	require.NoError(t, err)
	got := decodeJSON(t, out)
	assert.Equal(t, map[string]any{"bundle_id": "b-1", "output": defaultName, "size": float64(3)}, got)
	data, err := os.ReadFile(defaultName)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data), "overwrite must truncate the old archive")
}

func TestRunExport_FileErrors(t *testing.T) {
	t.Run("existing file without overwrite", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "out.tar.gz")
		require.NoError(t, os.WriteFile(output, []byte("keep"), 0o600))

		err := runExport(socketFlags("/nonexistent.sock", cli.OutputFormatTable), "b-1", output, false)

		var exists ErrOutputFileExists
		require.ErrorAs(t, err, &exists)
		assert.Equal(t, output, exists.Path)
		data, readErr := os.ReadFile(output)
		require.NoError(t, readErr)
		assert.Equal(t, "keep", string(data))
	})

	t.Run("output directory missing", func(t *testing.T) {
		srv := &fakeVTPMServer{}
		sock := startVTPMServer(t, srv)
		output := filepath.Join(t.TempDir(), "missing", "out.tar.gz")

		err := runExport(socketFlags(sock, cli.OutputFormatTable), "b-1", output, false)

		var createErr ErrCreateOutputFileFailed
		require.ErrorAs(t, err, &createErr)
		assert.Equal(t, output, createErr.Path)
		assert.NotEmpty(t, createErr.Reason)
		assert.Zero(t, srv.requestCount())
	})

	t.Run("stream failure removes the partial file", func(t *testing.T) {
		srv := &fakeVTPMServer{fail: true, chunks: [][]byte{[]byte("partial")}}
		sock := startVTPMServer(t, srv)
		output := filepath.Join(t.TempDir(), "out.tar.gz")

		err := runExport(socketFlags(sock, cli.OutputFormatTable), "b-1", output, false)

		var exportErr ErrExportBundleFailed
		require.ErrorAs(t, err, &exportErr)
		assert.Contains(t, exportErr.Reason, backendFailure)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

func TestRunImport_StreamsArchiveAndPrintsBundle(t *testing.T) {
	srv := &fakeVTPMServer{bundle: &platformv1.Bundle{
		Id:        "b-1",
		Mode:      platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
		CreatedAt: timestamppb.New(fixedTime),
	}}
	sock := startVTPMServer(t, srv)
	archive := filepath.Join(t.TempDir(), "in.tar.gz")
	require.NoError(t, os.WriteFile(archive, []byte("archive-bytes"), 0o600))

	out, err := captureStdout(t, func() error {
		return runImport(socketFlags(sock, cli.OutputFormatTable), archive)
	})

	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Bundle imported successfully\n\n"+
		"Archive: "+archive+"\n"+
		"Size: 13 B\n\n"+
		"ID: b-1\n"+
		"Mode: BUNDLE_MODE_TEMPLATE\n"+
		"Created: 2026-10-19 12:30:45 UTC\n", out)
	assert.Equal(t, "archive-bytes", string(srv.importedBytes()))
}

func TestRunImport_JSONAndNoBundle(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "in.tar.gz")
	require.NoError(t, os.WriteFile(archive, make([]byte, 2048), 0o600))

	withBundle := startVTPMServer(t, &fakeVTPMServer{bundle: &platformv1.Bundle{Id: "b-1"}})
	out, err := captureStdout(t, func() error {
		return runImport(socketFlags(withBundle, cli.OutputFormatJSON), archive)
	})
	require.NoError(t, err)
	got := decodeJSON(t, out)
	assert.Equal(t, map[string]any{"success": true}, got["status"])
	bundle, ok := got["bundle"].(map[string]any)
	require.True(t, ok, "output: %s", out)
	assert.Equal(t, "b-1", bundle["id"])

	noBundle := startVTPMServer(t, &fakeVTPMServer{})
	out, err = captureStdout(t, func() error {
		return runImport(socketFlags(noBundle, cli.OutputFormatTable), archive)
	})
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Bundle imported successfully\n\nArchive: "+archive+"\nSize: 2.0 KB\n", out)
}

func TestRunImport_UnreadableArchive(t *testing.T) {
	srv := &fakeVTPMServer{}
	sock := startVTPMServer(t, srv)

	// A directory passes the stat check but cannot be read as an archive.
	err := runImport(socketFlags(sock, cli.OutputFormatTable), t.TempDir())

	var importErr ErrImportBundleFailed
	require.ErrorAs(t, err, &importErr)
	assert.NotEmpty(t, importErr.Reason)
}

func TestRunInfo_PrintsEverySection(t *testing.T) {
	srv := &fakeVTPMServer{bundle: &platformv1.Bundle{
		Id:         "b-1",
		Mode:       platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
		ClonedFrom: "tmpl-a",
		CreatedAt:  timestamppb.New(fixedTime),
		Manifest: &platformv1.Manifest{
			Hostname:      "web-01",
			EkAlgorithm:   platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
			ClonedFrom:    "tmpl-a",
			EkCertificate: &platformv1.EKCertInfo{Fingerprint: "ab:cd"},
			CreatedAt:     timestamppb.New(fixedTime),
			Labels:        map[string]string{"env": "prod"},
			Checksums:     map[string]string{"tpm2-00.permall": "sha256:00"},
		},
		TpmState:  &platformv1.TPMState{StateDir: "/s", PermallFile: "/s/p", VolatileFile: "/s/v"},
		OvmfState: &platformv1.OVMFState{NvramFile: "/n"},
		SecureBootKeys: &platformv1.SecureBootKeyPaths{
			Dir: "/k", PkKey: "/k/pk.key", PkCrt: "/k/pk.crt",
			KekKey: "/k/kek.key", KekCrt: "/k/kek.crt", DbKey: "/k/db.key", DbCrt: "/k/db.crt",
		},
	}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runInfo(socketFlags(sock, cli.OutputFormatTable), "b-1")
	})

	require.NoError(t, err)
	assert.Equal(t, "ID: b-1\n"+
		"Mode: BUNDLE_MODE_TEMPLATE\n"+
		"Created: 2026-10-19 12:30:45 UTC\n"+
		"Cloned From: tmpl-a\n"+
		"\n[INFO] Manifest:\n"+
		"  Hostname: web-01\n"+
		"  EK Algorithm: ECC\n"+
		"  Secure Boot: No\n"+
		"  Cloned From: tmpl-a\n"+
		"  EK Fingerprint: ab:cd\n"+
		"  Manifest Created: 2026-10-19 12:30:45 UTC\n"+
		"\n[INFO]   Labels:\n"+
		"    env: prod\n"+
		"\n[INFO]   Checksums:\n"+
		"    tpm2-00.permall: sha256:00\n"+
		"\n[INFO] TPM State:\n"+
		"  State Dir: /s\n"+
		"  Permall File: /s/p\n"+
		"  Volatile File: /s/v\n"+
		"\n[INFO] OVMF State:\n"+
		"  NVRAM File: /n\n"+
		"\n[INFO] Secure Boot Keys:\n"+
		"  Directory: /k\n"+
		"  PK Key: /k/pk.key\n"+
		"  PK Cert: /k/pk.crt\n"+
		"  KEK Key: /k/kek.key\n"+
		"  KEK Cert: /k/kek.crt\n"+
		"  DB Key: /k/db.key\n"+
		"  DB Cert: /k/db.crt\n", out)
	assertRequest(t, srv, &platformv1.GetBundleRequest{Id: "b-1"})
}

func TestRunInfo_EmptySectionsJSONAndMissingBundle(t *testing.T) {
	sparse := startVTPMServer(t, &fakeVTPMServer{bundle: &platformv1.Bundle{
		Id:             "b-1",
		Manifest:       &platformv1.Manifest{},
		TpmState:       &platformv1.TPMState{},
		OvmfState:      &platformv1.OVMFState{},
		SecureBootKeys: &platformv1.SecureBootKeyPaths{},
	}})
	out, err := captureStdout(t, func() error {
		return runInfo(socketFlags(sparse, cli.OutputFormatTable), "b-1")
	})
	require.NoError(t, err)
	assert.Equal(t, "ID: b-1\nMode: UNSPECIFIED\n"+
		"\n[INFO] Manifest:\n  EK Algorithm: UNSPECIFIED\n  Secure Boot: No\n"+
		"\n[INFO] TPM State:\n"+
		"\n[INFO] OVMF State:\n"+
		"\n[INFO] Secure Boot Keys:\n", out)

	out, err = captureStdout(t, func() error {
		return runInfo(socketFlags(sparse, cli.OutputFormatJSON), "b-1")
	})
	require.NoError(t, err)
	bundle, ok := decodeJSON(t, out)["bundle"].(map[string]any)
	require.True(t, ok, "output: %s", out)
	assert.Equal(t, "b-1", bundle["id"])

	missing := startVTPMServer(t, &fakeVTPMServer{})
	err = runInfo(socketFlags(missing, cli.OutputFormatTable), "b-9")
	var notFound ErrBundleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "b-9", notFound.ID)
}

func TestRunIsRunning_TableAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{running: true}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runIsRunning(socketFlags(sock, cli.OutputFormatTable), "b-1")
	})
	require.NoError(t, err)
	assert.Equal(t, "Bundle ID: b-1\nRunning: Yes\n", out)
	assertRequest(t, srv, &platformv1.IsVTPMRunningRequest{BundleId: "b-1"})

	out, err = captureStdout(t, func() error {
		return runIsRunning(socketFlags(sock, cli.OutputFormatJSON), "b-1")
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"bundle_id": "b-1", "running": true}, decodeJSON(t, out))
}

func TestRunList_PrintsTableWithTruncationAndFallbackTime(t *testing.T) {
	srv := &fakeVTPMServer{bundles: []*platformv1.Bundle{
		{
			Id:   "0123456789abcdef",
			Mode: platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Manifest: &platformv1.Manifest{
				Hostname:          "a-very-long-hostname-for-the-table",
				EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
				SecureBootEnabled: true,
				CreatedAt:         timestamppb.New(fixedTime),
			},
		},
		{
			Id:        "b-2",
			Mode:      platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
			CreatedAt: timestamppb.New(fixedTime.Add(time.Hour)),
		},
	}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runList(socketFlags(sock, cli.OutputFormatTable), "template", 5, 10)
	})

	require.NoError(t, err)
	for _, want := range []string{
		"ID", "MODE", "HOSTNAME", "EK ALG", "SECURE BOOT", "CREATED",
		"012345678...", "a-very-long-hostname-f...", "RSA", "Yes", "2026-10-19 12:30",
		"b-2", "BUNDLE_MODE_TEMPLATE", "2026-10-19 13:30",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "0123456789abcdef")
	assert.True(t, len(out) > 0 && out[len(out)-len("\nTotal: 2 bundles\n"):] == "\nTotal: 2 bundles\n", "output: %s", out)
	assertRequest(t, srv, &platformv1.ListBundlesRequest{Options: &platformv1.ListBundleOptions{
		Mode:   platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
		Limit:  5,
		Offset: 10,
	}})
}

func TestRunList_EmptyAndJSON(t *testing.T) {
	empty := startVTPMServer(t, &fakeVTPMServer{})
	out, err := captureStdout(t, func() error {
		return runList(socketFlags(empty, cli.OutputFormatTable), "", 0, 0)
	})
	require.NoError(t, err)
	assert.Equal(t, "[INFO] No bundles found\n", out)

	one := startVTPMServer(t, &fakeVTPMServer{bundles: []*platformv1.Bundle{{Id: "b-1"}}})
	out, err = captureStdout(t, func() error {
		return runList(socketFlags(one, cli.OutputFormatJSON), "", 0, 0)
	})
	require.NoError(t, err)
	got := decodeJSON(t, out)
	assert.Equal(t, float64(1), got["total"])
	bundles, ok := got["bundles"].([]any)
	require.True(t, ok, "output: %s", out)
	assert.Len(t, bundles, 1)
}

func TestRunPCRExtend_ExtendedAndRefused(t *testing.T) {
	tests := []struct {
		name     string
		extended bool
		want     string
	}{
		{name: "extended", extended: true, want: "[SUCCESS] PCR[7] extended for bundle: b-1\n"},
		{name: "refused", extended: false, want: "[ERROR] Failed to extend PCR[7] for bundle: b-1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeVTPMServer{extended: tt.extended}
			sock := startVTPMServer(t, srv)

			out, err := captureStdout(t, func() error {
				return runPCRExtend(socketFlags(sock, cli.OutputFormatTable), "b-1", 7, "abcd")
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			assertRequest(t, srv, &platformv1.ExtendVTPMPCRRequest{BundleId: "b-1", PcrIndex: 7, Data: []byte{0xab, 0xcd}})
		})
	}

	t.Run("json", func(t *testing.T) {
		sock := startVTPMServer(t, &fakeVTPMServer{extended: true})
		out, err := captureStdout(t, func() error {
			return runPCRExtend(socketFlags(sock, cli.OutputFormatJSON), "b-1", 7, "abcd")
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"bundle_id": "b-1", "pcr_index": float64(7), "extended": true}, decodeJSON(t, out))
	})
}

func TestRunPCRRead_TableAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{value: []byte{0x01, 0x02}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runPCRRead(socketFlags(sock, cli.OutputFormatTable), "b-1", 7)
	})
	require.NoError(t, err)
	assert.Equal(t, "Bundle ID: b-1\nPCR[7]: 0102\n", out)
	assertRequest(t, srv, &platformv1.ReadVTPMPCRRequest{BundleId: "b-1", PcrIndex: 7})

	out, err = captureStdout(t, func() error {
		return runPCRRead(socketFlags(sock, cli.OutputFormatJSON), "b-1", 7)
	})
	require.NoError(t, err)
	got := decodeJSON(t, out)
	assert.Equal(t, "b-1", got["bundle_id"])
	assert.Equal(t, float64(7), got["pcr_index"])
}

func TestRunQuote_TableAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runQuote(socketFlags(sock, cli.OutputFormatTable), "b-1", "beef", "0, 7")
	})
	require.NoError(t, err)
	assert.Equal(t, "Bundle ID: b-1\n"+
		"Hash Algorithm: SHA256\n"+
		"Quote: 01\n"+
		"Signature: 02\n"+
		"\n[INFO] PCR Values:\n"+
		"  PCR[0]: aa\n", out)
	assertRequest(t, srv, &platformv1.QuoteVTPMRequest{BundleId: "b-1", Nonce: []byte{0xbe, 0xef}, Pcrs: []int32{0, 7}})

	out, err = captureStdout(t, func() error {
		return runQuote(socketFlags(sock, cli.OutputFormatJSON), "b-1", "beef", "0")
	})
	require.NoError(t, err)
	got := decodeJSON(t, out)
	assert.Equal(t, "SHA256", got["hash_algorithm"])
	assert.Equal(t, "AQ==", got["quote"])
	assert.Equal(t, map[string]any{"0": "qg=="}, got["pcr_values"])
}

func TestRunSeal_TableAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{value: []byte{0xde, 0xad}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runSeal(socketFlags(sock, cli.OutputFormatTable), "b-1", "aGVsbG8=", "7", "pw")
	})
	require.NoError(t, err)
	assert.Equal(t, "Bundle ID: b-1\nSealed Data: 3q0=\n", out)
	assertRequest(t, srv, &platformv1.SealVTPMRequest{BundleId: "b-1", Data: []byte("hello"), Pcrs: []int32{7}, AuthValue: "pw"})

	// Without --pcrs the data is sealed to no PCR policy.
	out, err = captureStdout(t, func() error {
		return runSeal(socketFlags(sock, cli.OutputFormatJSON), "b-1", "aGVsbG8=", "", "")
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"bundle_id": "b-1", "sealed_data": "3q0="}, decodeJSON(t, out))
	assertRequest(t, srv, &platformv1.SealVTPMRequest{BundleId: "b-1", Data: []byte("hello")})
}

func TestRunSeal_RejectsOutOfRangePCRBeforeConnecting(t *testing.T) {
	err := runSeal(socketFlags("/nonexistent.sock", cli.OutputFormatTable), "b-1", "aGVsbG8=", "7,24", "")

	var pcrErr ErrInvalidPCRIndex
	require.ErrorAs(t, err, &pcrErr)
	assert.Equal(t, "24", pcrErr.Index)
	assert.Equal(t, "PCR index must be between 0 and 23", pcrErr.Reason)
}

func TestRunUnseal_TableAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{value: []byte("hello")}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runUnseal(socketFlags(sock, cli.OutputFormatTable), "b-1", "3q0=", "pw")
	})
	require.NoError(t, err)
	assert.Equal(t, "Bundle ID: b-1\nData: aGVsbG8=\n", out)
	assertRequest(t, srv, &platformv1.UnsealVTPMRequest{BundleId: "b-1", SealedData: []byte{0xde, 0xad}, AuthValue: "pw"})

	out, err = captureStdout(t, func() error {
		return runUnseal(socketFlags(sock, cli.OutputFormatJSON), "b-1", "3q0=", "")
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"bundle_id": "b-1", "data": "aGVsbG8="}, decodeJSON(t, out))
}

func TestRunStart_States(t *testing.T) {
	tests := []struct {
		name string
		srv  *fakeVTPMServer
		want string
	}{
		{
			name: "running with socket",
			srv:  &fakeVTPMServer{running: true, socketPath: "/run/vtpm/b-1.sock"},
			want: "[SUCCESS] vTPM started for bundle: b-1\nSocket Path: /run/vtpm/b-1.sock\n",
		},
		{
			name: "running without socket",
			srv:  &fakeVTPMServer{running: true},
			want: "[SUCCESS] vTPM started for bundle: b-1\n",
		},
		{
			name: "not running",
			srv:  &fakeVTPMServer{},
			want: "[ERROR] Failed to start vTPM for bundle: b-1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sock := startVTPMServer(t, tt.srv)
			out, err := captureStdout(t, func() error {
				return runStart(socketFlags(sock, cli.OutputFormatTable), "b-1")
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			assertRequest(t, tt.srv, &platformv1.StartVTPMRequest{BundleId: "b-1"})
		})
	}

	t.Run("json", func(t *testing.T) {
		sock := startVTPMServer(t, &fakeVTPMServer{running: true, socketPath: "/s"})
		out, err := captureStdout(t, func() error {
			return runStart(socketFlags(sock, cli.OutputFormatJSON), "b-1")
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"bundle_id": "b-1", "running": true, "socket_path": "/s"}, decodeJSON(t, out))
	})
}

func TestRunStop_States(t *testing.T) {
	tests := []struct {
		name    string
		stopped bool
		want    string
	}{
		{name: "stopped", stopped: true, want: "[SUCCESS] vTPM stopped for bundle: b-1\n"},
		{name: "still running", stopped: false, want: "[ERROR] Failed to stop vTPM for bundle: b-1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeVTPMServer{stopped: tt.stopped}
			sock := startVTPMServer(t, srv)
			out, err := captureStdout(t, func() error {
				return runStop(socketFlags(sock, cli.OutputFormatTable), "b-1")
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			assertRequest(t, srv, &platformv1.StopVTPMRequest{BundleId: "b-1"})
		})
	}

	t.Run("json", func(t *testing.T) {
		sock := startVTPMServer(t, &fakeVTPMServer{stopped: true})
		out, err := captureStdout(t, func() error {
			return runStop(socketFlags(sock, cli.OutputFormatJSON), "b-1")
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"bundle_id": "b-1", "stopped": true}, decodeJSON(t, out))
	})
}

func TestRunTemplateCreate_PrintsTemplateAndSendsOptions(t *testing.T) {
	tests := []struct {
		name     string
		template *platformv1.Template
		want     string
	}{
		{
			name: "every field",
			template: &platformv1.Template{
				Id:                "t-1",
				Description:       "golden image",
				EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
				SecureBootEnabled: true,
				TpmStateDir:       "/t/tpm",
				NvramPath:         "/t/nvram.fd",
				SecureBootKeysDir: "/t/keys",
				CreatedAt:         timestamppb.New(fixedTime),
			},
			want: "[SUCCESS] Template created: t-1\n\n" +
				"ID: t-1\n" +
				"Description: golden image\n" +
				"EK Algorithm: ECC\n" +
				"Secure Boot: Yes\n" +
				"TPM State Dir: /t/tpm\n" +
				"NVRAM Path: /t/nvram.fd\n" +
				"Secure Boot Keys Dir: /t/keys\n" +
				"Created: 2026-10-19 12:30:45 UTC\n",
		},
		{
			name:     "required fields only",
			template: &platformv1.Template{Id: "t-1", EkAlgorithm: platformv1.EKAlgorithm_EK_ALGORITHM_ECC},
			want:     "[SUCCESS] Template created: t-1\n\nID: t-1\nEK Algorithm: ECC\nSecure Boot: No\n",
		},
		{
			name: "no template in the response",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeVTPMServer{template: tt.template}
			sock := startVTPMServer(t, srv)

			out, err := captureStdout(t, func() error {
				return runTemplateCreate(socketFlags(sock, cli.OutputFormatTable), "t-1", "golden image", true, "ecc")
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			assertRequest(t, srv, &platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{
				Id:                "t-1",
				Description:       "golden image",
				EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
				SecureBootEnabled: true,
			}})
		})
	}

	t.Run("json", func(t *testing.T) {
		sock := startVTPMServer(t, &fakeVTPMServer{template: &platformv1.Template{Id: "t-1"}})
		out, err := captureStdout(t, func() error {
			return runTemplateCreate(socketFlags(sock, cli.OutputFormatJSON), "t-1", "", false, "RSA")
		})
		require.NoError(t, err)
		tmpl, ok := decodeJSON(t, out)["template"].(map[string]any)
		require.True(t, ok, "output: %s", out)
		assert.Equal(t, "t-1", tmpl["id"])
	})
}

func TestRunTemplateList_TableEmptyAndJSON(t *testing.T) {
	srv := &fakeVTPMServer{templates: []*platformv1.Template{
		{
			Id:                "a-template-identifier-longer-than-twenty",
			Description:       "a description that is longer than thirty characters",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
			SecureBootEnabled: true,
			CreatedAt:         timestamppb.New(fixedTime),
		},
		{Id: "t-2", EkAlgorithm: platformv1.EKAlgorithm_EK_ALGORITHM_ECC},
	}}
	sock := startVTPMServer(t, srv)

	out, err := captureStdout(t, func() error {
		return runTemplateList(socketFlags(sock, cli.OutputFormatTable))
	})
	require.NoError(t, err)
	for _, want := range []string{
		"DESCRIPTION", "a-template-identi...", "a description that is longe...", "RSA", "Yes", "2026-10-19 12:30",
		"t-2", "ECC", "No",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "longer-than-twenty")
	assert.True(t, len(out) > 0 && out[len(out)-len("\nTotal: 2 templates\n"):] == "\nTotal: 2 templates\n", "output: %s", out)
	assertRequest(t, srv, &platformv1.ListTemplatesRequest{})

	out, err = captureStdout(t, func() error {
		return runTemplateList(socketFlags(sock, cli.OutputFormatJSON))
	})
	require.NoError(t, err)
	templates, ok := decodeJSON(t, out)["templates"].([]any)
	require.True(t, ok, "output: %s", out)
	assert.Len(t, templates, 2)

	empty := startVTPMServer(t, &fakeVTPMServer{})
	out, err = captureStdout(t, func() error {
		return runTemplateList(socketFlags(empty, cli.OutputFormatTable))
	})
	require.NoError(t, err)
	assert.Equal(t, "[INFO] No templates found\n", out)
}

// runCase calls one run function against the socket with the given format.
type runCase struct {
	name string
	run  func(t *testing.T, flags *cli.CommonFlags) error
}

func archiveFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "in.tar.gz")
	require.NoError(t, os.WriteFile(path, []byte("archive"), 0o600))
	return path
}

var runCases = []runCase{
	{"create", func(_ *testing.T, f *cli.CommonFlags) error { return runCreate(f, "web-01", false, "RSA", "", nil) }},
	{"clone", func(_ *testing.T, f *cli.CommonFlags) error { return runClone(f, "tmpl-a", "web-01", nil) }},
	{"delete", func(_ *testing.T, f *cli.CommonFlags) error { return runDelete(f, "b-1", true) }},
	{"export", func(t *testing.T, f *cli.CommonFlags) error {
		return runExport(f, "b-1", filepath.Join(t.TempDir(), "out.tar.gz"), false)
	}},
	{"import", func(t *testing.T, f *cli.CommonFlags) error { return runImport(f, archiveFile(t)) }},
	{"info", func(_ *testing.T, f *cli.CommonFlags) error { return runInfo(f, "b-1") }},
	{"is-running", func(_ *testing.T, f *cli.CommonFlags) error { return runIsRunning(f, "b-1") }},
	{"list", func(_ *testing.T, f *cli.CommonFlags) error { return runList(f, "", 0, 0) }},
	{"pcr-extend", func(_ *testing.T, f *cli.CommonFlags) error { return runPCRExtend(f, "b-1", 7, "abcd") }},
	{"pcr-read", func(_ *testing.T, f *cli.CommonFlags) error { return runPCRRead(f, "b-1", 7) }},
	{"quote", func(_ *testing.T, f *cli.CommonFlags) error { return runQuote(f, "b-1", "beef", "0") }},
	{"seal", func(_ *testing.T, f *cli.CommonFlags) error { return runSeal(f, "b-1", "aGVsbG8=", "", "") }},
	{"unseal", func(_ *testing.T, f *cli.CommonFlags) error { return runUnseal(f, "b-1", "3q0=", "") }},
	{"start", func(_ *testing.T, f *cli.CommonFlags) error { return runStart(f, "b-1") }},
	{"stop", func(_ *testing.T, f *cli.CommonFlags) error { return runStop(f, "b-1") }},
	{"template-create", func(_ *testing.T, f *cli.CommonFlags) error {
		return runTemplateCreate(f, "t-1", "", false, "RSA")
	}},
	{"template-list", func(_ *testing.T, f *cli.CommonFlags) error { return runTemplateList(f) }},
	{"template-delete", func(_ *testing.T, f *cli.CommonFlags) error { return runTemplateDelete(f, "t-1", true) }},
}

func TestRunCommands_RejectUnknownOutputFormat(t *testing.T) {
	for _, tc := range runCases {
		t.Run(tc.name, func(t *testing.T) {
			sock := startVTPMServer(t, &fakeVTPMServer{bundle: &platformv1.Bundle{Id: "b-1"}})

			_, err := captureStdout(t, func() error {
				return tc.run(t, socketFlags(sock, cli.OutputFormat("xml")))
			})

			var formatErr cli.ErrInvalidOutputFormat
			require.ErrorAs(t, err, &formatErr)
			assert.Equal(t, "xml", formatErr.Format)
		})
	}
}

// reasonOf extracts the Reason every daemon-failure error carries.
func reasonOf(err error) (string, bool) {
	var (
		create         ErrCreateBundleFailed
		clone          ErrCloneBundleFailed
		deleteBundle   ErrDeleteBundleFailed
		export         ErrExportBundleFailed
		importBundle   ErrImportBundleFailed
		info           ErrGetBundleInfoFailed
		isRunning      ErrIsRunningFailed
		list           ErrListBundlesFailed
		extend         ErrExtendPCRFailed
		read           ErrReadPCRFailed
		quote          ErrQuoteVTPMFailed
		seal           ErrSealVTPMFailed
		unseal         ErrUnsealVTPMFailed
		start          ErrStartVTPMFailed
		stop           ErrStopVTPMFailed
		createTemplate ErrCreateTemplateFailed
		listTemplates  ErrListTemplatesFailed
		deleteTemplate ErrDeleteTemplateFailed
	)
	switch {
	case errors.As(err, &create):
		return create.Reason, true
	case errors.As(err, &clone):
		return clone.Reason, true
	case errors.As(err, &deleteBundle):
		return deleteBundle.Reason, true
	case errors.As(err, &export):
		return export.Reason, true
	case errors.As(err, &importBundle):
		return importBundle.Reason, true
	case errors.As(err, &info):
		return info.Reason, true
	case errors.As(err, &isRunning):
		return isRunning.Reason, true
	case errors.As(err, &list):
		return list.Reason, true
	case errors.As(err, &extend):
		return extend.Reason, true
	case errors.As(err, &read):
		return read.Reason, true
	case errors.As(err, &quote):
		return quote.Reason, true
	case errors.As(err, &seal):
		return seal.Reason, true
	case errors.As(err, &unseal):
		return unseal.Reason, true
	case errors.As(err, &start):
		return start.Reason, true
	case errors.As(err, &stop):
		return stop.Reason, true
	case errors.As(err, &createTemplate):
		return createTemplate.Reason, true
	case errors.As(err, &listTemplates):
		return listTemplates.Reason, true
	case errors.As(err, &deleteTemplate):
		return deleteTemplate.Reason, true
	}
	return "", false
}

func TestRunCommands_WrapDaemonFailure(t *testing.T) {
	want := map[string]error{
		"create":          ErrCreateBundleFailed{},
		"clone":           ErrCloneBundleFailed{},
		"delete":          ErrDeleteBundleFailed{},
		"export":          ErrExportBundleFailed{},
		"import":          ErrImportBundleFailed{},
		"info":            ErrGetBundleInfoFailed{},
		"is-running":      ErrIsRunningFailed{},
		"list":            ErrListBundlesFailed{},
		"pcr-extend":      ErrExtendPCRFailed{},
		"pcr-read":        ErrReadPCRFailed{},
		"quote":           ErrQuoteVTPMFailed{},
		"seal":            ErrSealVTPMFailed{},
		"unseal":          ErrUnsealVTPMFailed{},
		"start":           ErrStartVTPMFailed{},
		"stop":            ErrStopVTPMFailed{},
		"template-create": ErrCreateTemplateFailed{},
		"template-list":   ErrListTemplatesFailed{},
		"template-delete": ErrDeleteTemplateFailed{},
	}
	require.Len(t, want, len(runCases))

	for _, tc := range runCases {
		t.Run(tc.name, func(t *testing.T) {
			sock := startVTPMServer(t, &fakeVTPMServer{fail: true})

			out, err := captureStdout(t, func() error {
				return tc.run(t, socketFlags(sock, cli.OutputFormatTable))
			})

			require.Error(t, err)
			assert.IsType(t, want[tc.name], err)
			reason, ok := reasonOf(err)
			require.True(t, ok, "untyped error: %v", err)
			assert.Contains(t, reason, backendFailure)
			assert.Empty(t, out, "nothing is printed when the daemon fails")
		})
	}
}
