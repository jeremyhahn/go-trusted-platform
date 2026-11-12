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

package registry

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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errRegistryDown is the failure the fake daemon returns for every RPC a
// test arms to fail.
var errRegistryDown = status.Error(codes.Unavailable, "registry down")

// fakeRegistryServer is an in-process RegistryService the run functions
// reach over a real gRPC connection on a temporary Unix socket. It records
// what each RPC received and answers with what the test armed.
type fakeRegistryServer struct {
	platformv1.UnimplementedRegistryServiceServer

	mu sync.Mutex

	pushMetadata *platformv1.PushMetadata
	pushed       []byte
	pushResp     *platformv1.PushResponse
	pushErr      error

	pullReq   *platformv1.PullRequest
	pullResps []*platformv1.PullResponse
	pullErr   error

	listReq  *platformv1.ListArtifactsRequest
	listResp *platformv1.ListArtifactsResponse
	listErr  error

	inspectReq  *platformv1.InspectArtifactRequest
	inspectResp *platformv1.InspectArtifactResponse
	inspectErr  error

	deleteReq  *platformv1.DeleteArtifactRequest
	deleteResp *platformv1.DeleteArtifactResponse
	deleteErr  error

	statusResp *platformv1.RegistryStatusResponse
	statusErr  error
}

func (s *fakeRegistryServer) Push(stream grpc.ClientStreamingServer[platformv1.PushRequest, platformv1.PushResponse]) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		if md := req.GetMetadata(); md != nil {
			s.pushMetadata = md
		}
		s.pushed = append(s.pushed, req.GetChunk()...)
		s.mu.Unlock()
	}
	if s.pushErr != nil {
		return s.pushErr
	}
	return stream.SendAndClose(s.pushResp)
}

func (s *fakeRegistryServer) Pull(req *platformv1.PullRequest, stream grpc.ServerStreamingServer[platformv1.PullResponse]) error {
	s.mu.Lock()
	s.pullReq = req
	s.mu.Unlock()
	if s.pullErr != nil {
		return s.pullErr
	}
	for _, resp := range s.pullResps {
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeRegistryServer) List(_ context.Context, req *platformv1.ListArtifactsRequest) (*platformv1.ListArtifactsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listReq = req
	return s.listResp, s.listErr
}

func (s *fakeRegistryServer) Inspect(_ context.Context, req *platformv1.InspectArtifactRequest) (*platformv1.InspectArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspectReq = req
	return s.inspectResp, s.inspectErr
}

func (s *fakeRegistryServer) Delete(_ context.Context, req *platformv1.DeleteArtifactRequest) (*platformv1.DeleteArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteReq = req
	return s.deleteResp, s.deleteErr
}

func (s *fakeRegistryServer) Status(context.Context, *platformv1.RegistryStatusRequest) (*platformv1.RegistryStatusResponse, error) {
	return s.statusResp, s.statusErr
}

// received returns a snapshot of what the server recorded, taken under its lock.
func (s *fakeRegistryServer) received() fakeRegistryServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fakeRegistryServer{
		pushMetadata: s.pushMetadata,
		pushed:       append([]byte(nil), s.pushed...),
		pullReq:      s.pullReq,
		listReq:      s.listReq,
		inspectReq:   s.inspectReq,
		deleteReq:    s.deleteReq,
	}
}

// startRegistryServer serves srv on a temporary Unix socket and returns a
// flags factory whose local context points the CLI at it.
func startRegistryServer(t *testing.T, srv *fakeRegistryServer) func(format cli.OutputFormat) *cli.CommonFlags {
	t.Helper()
	sock := filepath.Join(socktest.Dir(t), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterRegistryServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})

	return func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
}

// captureRegistryStdout runs f with os.Stdout redirected and returns what it wrote.
func captureRegistryStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	copied := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		if copyErr != nil {
			buf.WriteString(copyErr.Error())
		}
		copied <- buf.Bytes()
	}()
	f()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-copied
	require.NoError(t, r.Close())
	return string(out)
}

// withStdin runs f with os.Stdin reading input.
func withStdin(t *testing.T, input string, f func()) {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	os.Stdin = r
	defer func() {
		os.Stdin = orig
		require.NoError(t, r.Close())
	}()
	f()
}

func decodeRegistryJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.NewDecoder(bytes.NewBufferString(out)).Decode(&doc), "output: %q", out)
	return doc
}

func TestRunFunctions_RequireAContext(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	runs := map[string]func() error{
		"push":    func() error { return runPush(flags, "app:v1", false, "", false, "", false, "") },
		"pull":    func() error { return runPull(flags, "app:v1", false, false, "", "") },
		"list":    func() error { return runList(flags, "", "", 10, "", "", false, false) },
		"inspect": func() error { return runInspect(flags, "app:v1", false, false, false, false) },
		"delete":  func() error { return runDelete(flags, "app:v1", true, false, false) },
		"status":  func() error { return runStatus(flags, false, false, false, false) },
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			assert.ErrorAs(t, run(), &cli.ErrNoContextSet{})
		})
	}
}

func TestRunFunctions_InvalidOutputFormat(t *testing.T) {
	srv := &fakeRegistryServer{
		pushResp:    &platformv1.PushResponse{Artifact: &platformv1.Artifact{Digest: "sha256:aa"}},
		pullResps:   []*platformv1.PullResponse{},
		listResp:    &platformv1.ListArtifactsResponse{},
		inspectResp: &platformv1.InspectArtifactResponse{},
		statusResp:  &platformv1.RegistryStatusResponse{},
	}
	newFlags := startRegistryServer(t, srv)
	input := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(input, []byte("x"), 0o600))
	flags := newFlags("xml")

	runs := map[string]func() error{
		"push":    func() error { return runPush(flags, "app:v1", false, "", false, "", false, input) },
		"pull":    func() error { return runPull(flags, "app:v1", false, false, "", "") },
		"list":    func() error { return runList(flags, "", "", 10, "", "", false, false) },
		"inspect": func() error { return runInspect(flags, "app:v1", false, false, false, false) },
		"status":  func() error { return runStatus(flags, false, false, false, false) },
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			var err error
			captureRegistryStdout(t, func() { err = run() })
			var target cli.ErrInvalidOutputFormat
			require.ErrorAs(t, err, &target)
			assert.Equal(t, "xml", target.Format)
		})
	}
}

func TestRunFunctions_ReturnTheTypedRPCFailure(t *testing.T) {
	srv := &fakeRegistryServer{
		pushErr:    errRegistryDown,
		pullErr:    errRegistryDown,
		listErr:    errRegistryDown,
		inspectErr: errRegistryDown,
		deleteErr:  errRegistryDown,
		statusErr:  errRegistryDown,
	}
	newFlags := startRegistryServer(t, srv)
	flags := newFlags(cli.OutputFormatJSON)
	input := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(input, []byte("x"), 0o600))

	tests := []struct {
		name   string
		run    func() error
		target any
	}{
		{"push", func() error { return runPush(flags, "app:v1", false, "", false, "", false, input) }, &ErrPushFailed{}},
		{"pull", func() error { return runPull(flags, "app:v1", false, false, "", "") }, &ErrPullFailed{}},
		{"list", func() error { return runList(flags, "", "", 10, "", "", false, false) }, &ErrListFailed{}},
		{"inspect", func() error { return runInspect(flags, "app:v1", false, false, false, false) }, &ErrInspectFailed{}},
		{"delete", func() error { return runDelete(flags, "app:v1", true, false, false) }, &ErrDeleteFailed{}},
		{"status", func() error { return runStatus(flags, false, false, false, false) }, &ErrStatusFailed{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			captureRegistryStdout(t, func() { err = tt.run() })
			require.ErrorAs(t, err, tt.target)
			assert.ErrorContains(t, err, "registry down")
		})
	}
}

func TestRunPush_StreamsTheFileWithItsAnnotations(t *testing.T) {
	srv := &fakeRegistryServer{pushResp: &platformv1.PushResponse{
		Status: &platformv1.Status{Success: true},
		Artifact: &platformv1.Artifact{
			Digest: "sha256:abc",
			Annotations: map[string]string{
				registry.ManifestAnnotationEncrypted: "true",
				registry.ManifestAnnotationSigned:    "true",
			},
		},
		BytesReceived: 11,
		Timestamp:     timestamppb.New(timestamppb.Now().AsTime()),
	}}
	newFlags := startRegistryServer(t, srv)
	input := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(input, []byte("image-bytes"), 0o600))

	var err error
	out := captureRegistryStdout(t, func() {
		err = runPush(newFlags(cli.OutputFormatJSON), "team/app:v2", true, "kek-1", true, "sig-1", true, input)
	})
	require.NoError(t, err)

	got := srv.received()
	assert.Equal(t, []byte("image-bytes"), got.pushed)
	require.NotNil(t, got.pushMetadata)
	assert.Equal(t, "team/app", got.pushMetadata.GetRepository())
	assert.Equal(t, "v2", got.pushMetadata.GetTag())
	assert.Equal(t, int64(11), got.pushMetadata.GetTotalSize())
	annotations := got.pushMetadata.GetAnnotations()
	assert.Equal(t, "true", annotations[registry.PushAnnotationEncrypt])
	assert.Equal(t, "kek-1", annotations[registry.PushAnnotationKeyID])
	assert.Equal(t, "true", annotations[registry.PushAnnotationSign])
	assert.Equal(t, "sig-1", annotations[registry.PushAnnotationSigningKeyID])

	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, "team/app:v2", doc["reference"])
	assert.Equal(t, "sha256:abc", doc["digest"])
	assert.Equal(t, float64(11), doc["size"])
	assert.Equal(t, true, doc["encrypted"])
	assert.Equal(t, true, doc["signed"])
	assert.Equal(t, "kek-1", doc["key_id"])
}

func TestRunPush_TableOutputReportsTheDigest(t *testing.T) {
	srv := &fakeRegistryServer{pushResp: &platformv1.PushResponse{
		Artifact:      &platformv1.Artifact{Digest: "sha256:tabledigest"},
		BytesReceived: 3,
	}}
	newFlags := startRegistryServer(t, srv)
	input := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(input, []byte("abc"), 0o600))

	var err error
	out := captureRegistryStdout(t, func() {
		err = runPush(newFlags(cli.OutputFormatTable), "app:v1", true, "kek-9", false, "", false, input)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Image pushed successfully: app:v1")
	assert.Contains(t, out, "sha256:tabledigest")
	assert.Contains(t, out, "kek-9")
}

func TestRunPush_Failures(t *testing.T) {
	srv := &fakeRegistryServer{pushResp: &platformv1.PushResponse{
		Status: &platformv1.Status{Success: false, Message: "quota exceeded"},
	}}
	newFlags := startRegistryServer(t, srv)
	flags := newFlags(cli.OutputFormatJSON)
	input := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(input, []byte("abc"), 0o600))

	t.Run("encryption without a key", func(t *testing.T) {
		err := runPush(flags, "app:v1", true, "", false, "", false, input)
		assert.ErrorAs(t, err, &ErrEncryptionKeyRequired{})
	})
	t.Run("invalid reference", func(t *testing.T) {
		err := runPush(flags, "", false, "", false, "", false, input)
		assert.Error(t, err)
		assert.Nil(t, srv.received().pushMetadata)
	})
	t.Run("missing input file", func(t *testing.T) {
		err := runPush(flags, "app:v1", false, "", false, "", false, filepath.Join(t.TempDir(), "absent"))
		var target ErrPushFailed
		require.ErrorAs(t, err, &target)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("daemon reports failure", func(t *testing.T) {
		err := runPush(flags, "app:v1", false, "", false, "", false, input)
		var target ErrPushFailed
		require.ErrorAs(t, err, &target)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "quota exceeded", msg.Error())
	})
}

func TestRunPull_WritesTheStreamToTheOutputFile(t *testing.T) {
	srv := &fakeRegistryServer{pullResps: []*platformv1.PullResponse{
		{Data: &platformv1.PullResponse_Metadata{Metadata: &platformv1.PullMetadata{
			Artifact: &platformv1.Artifact{Digest: "sha256:pulled", Os: "linux", Architecture: "arm64"},
		}}},
		{Data: &platformv1.PullResponse_Chunk{Chunk: []byte("hello ")}},
		{Data: &platformv1.PullResponse_Chunk{Chunk: []byte("world")}},
	}}
	newFlags := startRegistryServer(t, srv)
	outFile := filepath.Join(t.TempDir(), "out.tar")

	var err error
	out := captureRegistryStdout(t, func() {
		err = runPull(newFlags(cli.OutputFormatJSON), "team/app:v3", true, true, "", outFile)
	})
	require.NoError(t, err)

	data, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)
	assert.Equal(t, "hello world", string(data))

	req := srv.received().pullReq
	require.NotNil(t, req)
	assert.Equal(t, "team/app", req.GetRepository())
	assert.Equal(t, "v3", req.GetReference())

	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, "sha256:pulled", doc["digest"])
	assert.Equal(t, "linux/arm64", doc["platform"])
	assert.Equal(t, float64(11), doc["size"])
	assert.Equal(t, true, doc["decrypted"])
	assert.Equal(t, true, doc["verified"])
}

func TestRunPull_DigestReferenceAndStdout(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	srv := &fakeRegistryServer{pullResps: []*platformv1.PullResponse{
		{Data: &platformv1.PullResponse_Chunk{Chunk: []byte("raw-bytes")}},
	}}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runPull(newFlags(cli.OutputFormatJSON), "app@"+digest, false, false, "", "")
	})
	require.NoError(t, err)
	// Without an output file the artifact itself is the only thing on stdout.
	assert.Equal(t, "raw-bytes", out)

	req := srv.received().pullReq
	require.NotNil(t, req)
	assert.Equal(t, digest, req.GetDigest())
	assert.Empty(t, req.GetReference())
}

func TestRunPull_TableOutputAndUnwritableFile(t *testing.T) {
	srv := &fakeRegistryServer{pullResps: []*platformv1.PullResponse{
		{Data: &platformv1.PullResponse_Metadata{Metadata: &platformv1.PullMetadata{
			Artifact: &platformv1.Artifact{Digest: "sha256:tbl", Os: "linux", Architecture: "amd64"},
		}}},
		{Data: &platformv1.PullResponse_Chunk{Chunk: []byte("abc")}},
	}}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runPull(newFlags(cli.OutputFormatTable), "app:v1", false, false, "", filepath.Join(t.TempDir(), "out.tar"))
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Image pulled successfully: app:v1")
	assert.Contains(t, out, "sha256:tbl")
	assert.Contains(t, out, "linux/amd64")

	err = runPull(newFlags(cli.OutputFormatTable), "app:v1", false, false, "", filepath.Join(t.TempDir(), "missing-dir", "out.tar"))
	var target ErrPullFailed
	require.ErrorAs(t, err, &target)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunList_ConvertsTheDaemonsArtifacts(t *testing.T) {
	srv := &fakeRegistryServer{listResp: &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "team/app", Tag: "v1", Digest: "sha256:one", Size: 2048,
				Os: "linux", Architecture: "arm64",
				Manifest: &platformv1.ArtifactManifest{Layers: []*platformv1.ArtifactLayer{{}, {}}},
			},
			{Repository: "team/db", Digest: "sha256:two", Size: 10},
		},
		Total:      2,
		HasMore:    true,
		NextCursor: "cursor-2",
	}}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runList(newFlags(cli.OutputFormatJSON), "team", "", 5, "c1", "name", true, false)
	})
	require.NoError(t, err)

	req := srv.received().listReq
	require.NotNil(t, req)
	assert.Equal(t, "team", req.GetRepository())
	assert.Equal(t, int32(5), req.GetLimit())
	assert.Equal(t, "c1", req.GetCursor())
	assert.Equal(t, "name", req.GetSortBy())
	assert.False(t, req.GetAscending(), "--desc must ask for descending order")

	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, float64(2), doc["total_count"])
	assert.Equal(t, true, doc["has_more"])
	assert.Equal(t, "cursor-2", doc["next_cursor"])
	images, ok := doc["images"].([]any)
	require.True(t, ok)
	require.Len(t, images, 2)
	first := images[0].(map[string]any)
	assert.Equal(t, "team/app:v1", first["reference"])
	assert.Equal(t, "linux/arm64", first["platform"])
	assert.Equal(t, float64(2), first["layer_count"])
	second := images[1].(map[string]any)
	assert.Equal(t, "team/db", second["reference"])
	assert.NotContains(t, second, "platform")
}

func TestRunList_TableOutput(t *testing.T) {
	srv := &fakeRegistryServer{listResp: &platformv1.ListArtifactsResponse{
		Artifacts:  []*platformv1.Artifact{{Repository: "team/app", Tag: "v1", Digest: "sha256:one", Size: 2048}},
		Total:      1,
		HasMore:    true,
		NextCursor: "next-page",
	}}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runList(newFlags(cli.OutputFormatTable), "", "", 10, "", "", false, false)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "team/app:v1")
	assert.Contains(t, out, "next-page")
	assert.True(t, srv.received().listReq.GetAscending())

	srv.listResp = &platformv1.ListArtifactsResponse{}
	out = captureRegistryStdout(t, func() {
		err = runList(newFlags(cli.OutputFormatTable), "", "", 10, "", "", false, false)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "No images found")
}

func TestRunInspect_ConvertsTheArtifactDetail(t *testing.T) {
	srv := &fakeRegistryServer{inspectResp: &platformv1.InspectArtifactResponse{
		Detail: &platformv1.ArtifactDetail{
			Artifact: &platformv1.Artifact{
				Digest: "sha256:insp", Os: "linux", Architecture: "riscv64",
				Manifest: &platformv1.ArtifactManifest{
					MediaType:    "application/vnd.oci.image.manifest.v1+json",
					ConfigDigest: "sha256:cfg",
					Size:         512,
					Layers:       []*platformv1.ArtifactLayer{{Digest: "sha256:l1", Size: 100, MediaType: "layer"}},
				},
			},
			Signatures: []*platformv1.ArtifactSignature{{
				Signer: "release-bot", KeyId: "sig-key", Algorithm: "ecdsa-p256",
				SignedAt: timestamppb.New(timestamppb.Now().AsTime()),
			}},
		},
	}}
	newFlags := startRegistryServer(t, srv)
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	var err error
	out := captureRegistryStdout(t, func() {
		err = runInspect(newFlags(cli.OutputFormatJSON), "app@"+digest, true, true, false, false)
	})
	require.NoError(t, err)

	req := srv.received().inspectReq
	require.NotNil(t, req)
	assert.Equal(t, digest, req.GetDigest())
	assert.Empty(t, req.GetReference())
	assert.True(t, req.GetIncludeSignatures())

	manifest, ok := decodeRegistryJSON(t, out)["manifest"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "sha256:insp", manifest["digest"])
	assert.Equal(t, "riscv64", manifest["architecture"])
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", manifest["media_type"])
	config := manifest["config"].(map[string]any)
	assert.Equal(t, "sha256:cfg", config["digest"])
	layers := manifest["layers"].([]any)
	require.Len(t, layers, 1)
	assert.Equal(t, "sha256:l1", layers[0].(map[string]any)["digest"])
	signature := manifest["signature"].(map[string]any)
	assert.Equal(t, "release-bot", signature["signed_by"])
	assert.Equal(t, "sig-key", signature["key_id"])
	assert.Equal(t, true, signature["valid"])
}

func TestRunInspect_TableOutput(t *testing.T) {
	srv := &fakeRegistryServer{inspectResp: &platformv1.InspectArtifactResponse{
		Detail: &platformv1.ArtifactDetail{Artifact: &platformv1.Artifact{Digest: "sha256:tableinspect"}},
	}}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runInspect(newFlags(cli.OutputFormatTable), "team/app:v1", false, false, false, false)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "sha256:tableinspect")
	req := srv.received().inspectReq
	assert.Equal(t, "team/app", req.GetRepository())
	assert.Equal(t, "v1", req.GetReference())
}

func TestRunDelete_Confirmation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDeleted bool
		wantOut     string
	}{
		{name: "yes deletes", input: "yes\n", wantDeleted: true, wantOut: "sha256:gone"},
		{name: "y deletes", input: "Y\n", wantDeleted: true, wantOut: "sha256:gone"},
		{name: "anything else cancels", input: "no\n", wantDeleted: false, wantOut: "Delete operation cancelled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeRegistryServer{deleteResp: &platformv1.DeleteArtifactResponse{
				Status: &platformv1.Status{Success: true}, Digest: "sha256:gone", BytesFreed: 42,
			}}
			newFlags := startRegistryServer(t, srv)

			var err error
			var out string
			withStdin(t, tt.input, func() {
				out = captureRegistryStdout(t, func() {
					err = runDelete(newFlags(cli.OutputFormatTable), "app:v1", false, false, false)
				})
			})
			require.NoError(t, err)
			assert.Contains(t, out, `Are you sure you want to delete image "app:v1"?`)
			assert.Contains(t, out, tt.wantOut)
			assert.Equal(t, tt.wantDeleted, srv.received().deleteReq != nil)
		})
	}
}

func TestRunDelete_UnreadableConfirmationFails(t *testing.T) {
	srv := &fakeRegistryServer{}
	newFlags := startRegistryServer(t, srv)

	var err error
	withStdin(t, "", func() {
		captureRegistryStdout(t, func() {
			err = runDelete(newFlags(cli.OutputFormatTable), "app:v1", false, false, false)
		})
	})
	var target ErrDeleteFailed
	require.ErrorAs(t, err, &target)
	assert.ErrorIs(t, err, io.EOF)
	assert.Nil(t, srv.received().deleteReq)
}

func TestRunDelete_DryRunNeverCallsTheDaemon(t *testing.T) {
	srv := &fakeRegistryServer{}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runDelete(newFlags(cli.OutputFormatJSON), "app:v1", false, true, false)
	})
	require.NoError(t, err)
	assert.Nil(t, srv.received().deleteReq)
	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, "sha256:pending", doc["digest"])
	assert.Equal(t, false, doc["deleted"])
}

func TestRunDelete_ForcedDigestDelete(t *testing.T) {
	srv := &fakeRegistryServer{deleteResp: &platformv1.DeleteArtifactResponse{
		Digest: "sha256:gone", BytesFreed: 4096,
	}}
	newFlags := startRegistryServer(t, srv)
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	var err error
	out := captureRegistryStdout(t, func() {
		err = runDelete(newFlags(cli.OutputFormatJSON), "app@"+digest, true, false, false)
	})
	require.NoError(t, err)

	req := srv.received().deleteReq
	require.NotNil(t, req)
	assert.Equal(t, "app", req.GetRepository())
	assert.Equal(t, digest, req.GetDigest())
	assert.Empty(t, req.GetReference())
	assert.True(t, req.GetForce())

	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, true, doc["deleted"])
	assert.Equal(t, float64(4096), doc["bytes_freed"])
}

func registryStatusResponse() *platformv1.RegistryStatusResponse {
	return &platformv1.RegistryStatusResponse{
		Health:    platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:   "2.0.0",
		StartedAt: &timestamppb.Timestamp{Seconds: 1000},
		Timestamp: &timestamppb.Timestamp{Seconds: 1090},
		Storage:   &platformv1.StorageStats{UsedBytes: 8192, ArtifactCount: 4},
		Components: []*platformv1.ComponentHealth{
			{Name: "storage", Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, Details: map[string]string{"backend": "objstore"}},
			{Name: "attestation", Status: platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
			{Name: "encryption", Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		},
	}
}

func TestRunStatus_RendersTheDaemonsStatus(t *testing.T) {
	srv := &fakeRegistryServer{statusResp: registryStatusResponse()}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runStatus(newFlags(cli.OutputFormatJSON), false, false, false, false)
	})
	require.NoError(t, err)
	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, true, doc["healthy"])
	assert.Equal(t, "2.0.0", doc["version"])
	assert.Equal(t, float64(90), doc["uptime_seconds"])
	assert.Equal(t, float64(4), doc["image_count"])
	assert.Equal(t, "objstore", doc["storage_backend"])

	// YAML renders the same flat document through MarshalYAML.
	out = captureRegistryStdout(t, func() {
		err = runStatus(newFlags(cli.OutputFormatYAML), false, false, false, false)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "storage_backend: objstore")
	assert.Contains(t, out, "uptime_seconds: 90")
	assert.Contains(t, out, "version: 2.0.0")

	out = captureRegistryStdout(t, func() {
		err = runStatus(newFlags(cli.OutputFormatTable), true, true, true, true)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "2.0.0")
	assert.Contains(t, out, "objstore")
}

func TestConvertStatusDomainResponse_ComponentsWithoutStorageStats(t *testing.T) {
	resp := registryStatusResponse()
	resp.Storage = nil
	resp.StartedAt = nil

	srv := &fakeRegistryServer{statusResp: resp}
	newFlags := startRegistryServer(t, srv)

	var err error
	out := captureRegistryStdout(t, func() {
		err = runStatus(newFlags(cli.OutputFormatJSON), false, false, false, false)
	})
	require.NoError(t, err)
	doc := decodeRegistryJSON(t, out)
	assert.Equal(t, "objstore", doc["storage_backend"])
	// Without a start time there is no uptime to report.
	assert.Equal(t, float64(0), doc["uptime_seconds"])
	assert.Equal(t, true, doc["healthy"])
}
