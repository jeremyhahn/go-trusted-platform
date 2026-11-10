package container

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// fakeComputeServer answers the container RPCs the CLI commands call and
// records the last request of each kind so the tests can assert what the
// command sent.
type fakeComputeServer struct {
	platformv1.UnimplementedComputeServiceServer

	mu        sync.Mutex
	err       error
	container *platformv1.Container
	status    *platformv1.Status
	logs      []*platformv1.LogEntry

	createReq *platformv1.CreateContainerRequest
	stopReq   *platformv1.StopContainerRequest
	deleteReq *platformv1.DeleteContainerRequest
	listReq   *platformv1.ListContainersRequest
	lastID    string
}

func (f *fakeComputeServer) CreateContainer(_ context.Context, req *platformv1.CreateContainerRequest) (*platformv1.CreateContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.CreateContainerResponse{Status: f.status, Container: f.container}, nil
}

func (f *fakeComputeServer) StartContainer(_ context.Context, req *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastID = req.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.StartContainerResponse{Status: f.status}, nil
}

func (f *fakeComputeServer) StopContainer(_ context.Context, req *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopReq = req
	f.lastID = req.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.StopContainerResponse{Status: f.status}, nil
}

func (f *fakeComputeServer) DeleteContainer(_ context.Context, req *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteReq = req
	f.lastID = req.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteContainerResponse{Status: f.status}, nil
}

func (f *fakeComputeServer) GetContainer(_ context.Context, req *platformv1.GetContainerRequest) (*platformv1.GetContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastID = req.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetContainerResponse{Container: f.container}, nil
}

func (f *fakeComputeServer) ListContainers(_ context.Context, req *platformv1.ListContainersRequest) (*platformv1.ListContainersResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listReq = req
	if f.err != nil {
		return nil, f.err
	}
	var containers []*platformv1.Container
	if f.container != nil {
		containers = append(containers, f.container)
	}
	return &platformv1.ListContainersResponse{Containers: containers}, nil
}

func (f *fakeComputeServer) GetContainerLogs(req *platformv1.GetContainerLogsRequest, stream grpc.ServerStreamingServer[platformv1.LogEntry]) error {
	f.mu.Lock()
	f.lastID = req.GetId()
	err, logs := f.err, f.logs
	f.mu.Unlock()
	if err != nil {
		return err
	}
	for _, entry := range logs {
		if sendErr := stream.Send(entry); sendErr != nil {
			return sendErr
		}
	}
	return nil
}

func (f *fakeComputeServer) requestedID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastID
}

// startComputeServer serves srv on a Unix socket and returns its path.
func startComputeServer(t *testing.T, srv *fakeComputeServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ct")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	sock := filepath.Join(dir, "s.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	gs := grpc.NewServer()
	platformv1.RegisterComputeServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err)
		}
	})
	return sock
}

func computeFlags(sock string, format cli.OutputFormat) *cli.CommonFlags {
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

// runCaptured runs fn with os.Stdout redirected and returns what it printed.
func runCaptured(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	read := make(chan []byte, 1)
	go func() {
		data, readErr := io.ReadAll(r)
		assert.NoError(t, readErr)
		read <- data
	}()

	orig := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = orig

	require.NoError(t, w.Close())
	data := <-read
	require.NoError(t, r.Close())
	return string(data), runErr
}

func runningContainer() *platformv1.Container {
	return &platformv1.Container{
		Id:    "c-964",
		State: platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		Config: &platformv1.ContainerConfig{
			Name:      "web",
			Image:     "nginx:1",
			ImageHash: "sha256:abc",
		},
	}
}

var errDaemon = status.Error(codes.Internal, "daemon refused")

func TestParseSpecLists(t *testing.T) {
	envs, err := parseEnvVars([]string{"A=1", "B=x=y"})
	require.NoError(t, err)
	require.Len(t, envs, 2)
	assert.Equal(t, "B", envs[1].Name)
	assert.Equal(t, "x=y", envs[1].Value, "only the first = splits")

	labels, err := parseLabels([]string{"tier=web", "env=prod"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"tier": "web", "env": "prod"}, labels)

	ports, err := parsePortMappings([]string{"8080:80", "53:53/UDP"})
	require.NoError(t, err)
	require.Len(t, ports, 2)
	assert.Equal(t, computesvc.PortMapping{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}, *ports[0])
	assert.Equal(t, "udp", ports[1].Protocol)

	mounts, err := parseMountSpecs([]string{"/a:/b", "/c:/d:ro", "/e:/f:readonly", "/g:/h:rw"})
	require.NoError(t, err)
	require.Len(t, mounts, 4)
	assert.Equal(t, []bool{false, true, true, false},
		[]bool{mounts[0].Readonly, mounts[1].Readonly, mounts[2].Readonly, mounts[3].Readonly})
	assert.Equal(t, "/d", mounts[1].Destination)

	for name, fn := range map[string]func() (bool, error){
		"env":    func() (bool, error) { v, err := parseEnvVars(nil); return v == nil, err },
		"labels": func() (bool, error) { v, err := parseLabels(nil); return v == nil, err },
		"ports":  func() (bool, error) { v, err := parsePortMappings(nil); return v == nil, err },
		"mounts": func() (bool, error) { v, err := parseMountSpecs(nil); return v == nil, err },
	} {
		isNil, err := fn()
		require.NoError(t, err, name)
		assert.True(t, isNil, "%s: an empty list parses to nil", name)
	}
}

func TestParseSpecLists_RejectMalformedEntries(t *testing.T) {
	tests := []struct {
		name   string
		parse  func() error
		target any
	}{
		{"env without =", func() error { _, err := parseEnvVars([]string{"A=1", "NOVALUE"}); return err }, &ErrInvalidEnvVar{}},
		{"label without =", func() error { _, err := parseLabels([]string{"k"}); return err }, &ErrInvalidLabel{}},
		{"port without colon", func() error { _, err := parsePortMappings([]string{"8080"}); return err }, &ErrInvalidPortMapping{}},
		{"port bad host", func() error { _, err := parsePortMappings([]string{"x:80"}); return err }, &ErrInvalidPortMapping{}},
		{"port bad container", func() error { _, err := parsePortMappings([]string{"80:y/tcp"}); return err }, &ErrInvalidPortMapping{}},
		{"mount one part", func() error { _, err := parseMountSpecs([]string{"/a"}); return err }, &ErrInvalidMountSpec{}},
		{"mount four parts", func() error { _, err := parseMountSpecs([]string{"/a:/b:ro:x"}); return err }, &ErrInvalidMountSpec{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parse()
			require.Error(t, err)
			assert.ErrorAs(t, err, tt.target)
		})
	}
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		spec string
		want uint64
	}{
		{"", 0},
		{"2097152b", 2},
		{"2048k", 2},
		{"512m", 512},
		{" 2G ", 2048},
		{"1t", 1024 * 1024},
	}
	for _, tt := range tests {
		got, err := parseMemory(tt.spec)
		require.NoError(t, err, tt.spec)
		assert.Equal(t, tt.want, got, tt.spec)
	}

	for _, bad := range []string{"m", "xm", "12q", "-1m"} {
		_, err := parseMemory(bad)
		var specErr ErrInvalidMemorySpec
		assert.ErrorAs(t, err, &specErr, bad)
	}
}

func TestErrorMessagesAndUnwrap(t *testing.T) {
	missing := ErrContainerMissingFromResponse{Operation: "create", ID: "web"}
	assert.Equal(t, "container create web: the daemon answered no container", missing.Error())

	cause := errors.New("cause")
	wrapped := &WrappedError{Msg: "context", Err: cause}
	assert.Equal(t, "context: cause", wrapped.Error())
	assert.ErrorIs(t, wrapped, cause)
}

func TestRunCreate_SendsParsedConfig(t *testing.T) {
	srv := &fakeComputeServer{container: runningContainer()}
	sock := startComputeServer(t, srv)
	opts := &createOptions{
		name: "web", image: "nginx:1",
		env: []string{"A=1"}, label: []string{"tier=web"},
		port: []string{"8080:80"}, mount: []string{"/a:/b:ro"},
		memory: "1g", cpu: "2", workDir: "/srv", command: []string{"run"},
		privileged: true, tpmAccess: true, start: true, attest: true,
	}

	out, err := runCaptured(t, func() error { return runCreate(computeFlags(sock, cli.OutputFormatJSON), opts) })
	require.NoError(t, err)
	assert.Contains(t, out, "c-964")

	cfg := srv.createReq.GetConfig()
	assert.Equal(t, "web", cfg.GetName())
	assert.Equal(t, "nginx:1", cfg.GetImage())
	assert.Equal(t, "A", cfg.GetEnv()[0].GetName())
	assert.Equal(t, map[string]string{"tier": "web"}, cfg.GetLabels())
	assert.Equal(t, uint32(8080), cfg.GetPorts()[0].GetHostPort())
	assert.True(t, cfg.GetVolumes()[0].GetReadonly())
	assert.Equal(t, uint64(1024), cfg.GetResources().GetMaxMemoryMb())
	assert.Equal(t, "/srv", cfg.GetWorkingDir())
	assert.True(t, cfg.GetPrivileged())
	assert.True(t, cfg.GetTpmAccess())
	assert.True(t, srv.createReq.GetStart())
	assert.True(t, srv.createReq.GetAttestOnCreate())

	out, err = runCaptured(t, func() error { return runCreate(computeFlags(sock, cli.OutputFormatTable), opts) })
	require.NoError(t, err)
	assert.Contains(t, out, "Container created successfully: c-964")
}

func TestRunCreate_Failures(t *testing.T) {
	base := func() *createOptions { return &createOptions{name: "web", image: "nginx:1"} }
	tests := []struct {
		name   string
		srv    *fakeComputeServer
		opts   func(*createOptions)
		format cli.OutputFormat
		check  func(t *testing.T, err error)
	}{
		{"bad env", &fakeComputeServer{}, func(o *createOptions) { o.env = []string{"X"} }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidEnvVar{}) }},
		{"bad label", &fakeComputeServer{}, func(o *createOptions) { o.label = []string{"X"} }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidLabel{}) }},
		{"bad port", &fakeComputeServer{}, func(o *createOptions) { o.port = []string{"X"} }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidPortMapping{}) }},
		{"bad mount", &fakeComputeServer{}, func(o *createOptions) { o.mount = []string{"X"} }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidMountSpec{}) }},
		{"bad memory", &fakeComputeServer{}, func(o *createOptions) { o.memory = "lots" }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidMemorySpec{}) }},
		{"bad cpu", &fakeComputeServer{}, func(o *createOptions) { o.cpu = "many" }, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrInvalidCPUSpec{}) }},
		{"daemon error", &fakeComputeServer{err: errDaemon}, func(*createOptions) {}, cli.OutputFormatJSON,
			func(t *testing.T, err error) {
				var opErr ErrContainerOperationFailed
				require.ErrorAs(t, err, &opErr)
				assert.Equal(t, "create", opErr.Operation)
				assert.Equal(t, "web", opErr.ID)
			}},
		{"no container answered", &fakeComputeServer{}, func(*createOptions) {}, cli.OutputFormatJSON,
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &ErrContainerMissingFromResponse{}) }},
		{"unknown format", &fakeComputeServer{container: runningContainer()}, func(*createOptions) {}, cli.OutputFormat("xml"),
			func(t *testing.T, err error) { assert.ErrorAs(t, err, &cli.ErrInvalidOutputFormat{}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sock := startComputeServer(t, tt.srv)
			opts := base()
			tt.opts(opts)
			_, err := runCaptured(t, func() error { return runCreate(computeFlags(sock, tt.format), opts) })
			require.Error(t, err)
			tt.check(t, err)
		})
	}
}

// lifecycleCase runs one of the start / stop / remove commands.
type lifecycleCase struct {
	operation string
	verb      string
	run       func(flags *cli.CommonFlags, id string) error
}

var lifecycleCases = []lifecycleCase{
	{"start", "started", runStart},
	{"stop", "stopped", func(f *cli.CommonFlags, id string) error { return runStop(f, id, &stopOptions{timeout: 7}) }},
	{"remove", "removed", func(f *cli.CommonFlags, id string) error {
		return runRemove(f, id, &removeOptions{force: true, deleteVolumes: true})
	}},
}

func TestRunLifecycle_ReportsDaemonStatus(t *testing.T) {
	for _, tc := range lifecycleCases {
		t.Run(tc.operation, func(t *testing.T) {
			srv := &fakeComputeServer{status: &platformv1.Status{Success: true}}
			sock := startComputeServer(t, srv)

			out, err := runCaptured(t, func() error { return tc.run(computeFlags(sock, cli.OutputFormatTable), "c-964") })
			require.NoError(t, err)
			assert.Contains(t, out, "[SUCCESS] Container "+tc.verb+" successfully: c-964")
			assert.Equal(t, "c-964", srv.requestedID())

			srv.status = &platformv1.Status{Success: false, Message: "busy"}
			out, err = runCaptured(t, func() error { return tc.run(computeFlags(sock, cli.OutputFormatTable), "c-964") })
			require.NoError(t, err)
			assert.Contains(t, out, "[ERROR] Failed to "+tc.operation+" container: busy")

			out, err = runCaptured(t, func() error { return tc.run(computeFlags(sock, cli.OutputFormatJSON), "c-964") })
			require.NoError(t, err)
			assert.Contains(t, out, "busy")

			_, err = runCaptured(t, func() error { return tc.run(computeFlags(sock, cli.OutputFormat("xml")), "c-964") })
			assert.ErrorAs(t, err, &cli.ErrInvalidOutputFormat{})

			srv.err = errDaemon
			_, err = runCaptured(t, func() error { return tc.run(computeFlags(sock, cli.OutputFormatJSON), "c-964") })
			var opErr ErrContainerOperationFailed
			require.ErrorAs(t, err, &opErr)
			assert.Equal(t, tc.operation, opErr.Operation)
			assert.Equal(t, "c-964", opErr.ID)
		})
	}
}

func TestRunStopAndRemove_SendOptions(t *testing.T) {
	srv := &fakeComputeServer{status: &platformv1.Status{Success: true}}
	sock := startComputeServer(t, srv)

	_, err := runCaptured(t, func() error {
		return runStop(computeFlags(sock, cli.OutputFormatJSON), "c-1", &stopOptions{timeout: 7})
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(7), srv.stopReq.GetTimeoutSeconds())

	_, err = runCaptured(t, func() error {
		return runRemove(computeFlags(sock, cli.OutputFormatJSON), "c-1", &removeOptions{force: true, deleteVolumes: true})
	})
	require.NoError(t, err)
	assert.True(t, srv.deleteReq.GetForce())
	assert.True(t, srv.deleteReq.GetDeleteVolumes())
}

func TestRunGet(t *testing.T) {
	srv := &fakeComputeServer{container: runningContainer()}
	sock := startComputeServer(t, srv)

	out, err := runCaptured(t, func() error { return runGet(computeFlags(sock, cli.OutputFormatTable), "c-964") })
	require.NoError(t, err)
	assert.Contains(t, out, "Image Hash: sha256:abc")
	assert.Equal(t, "c-964", srv.requestedID())

	out, err = runCaptured(t, func() error { return runGet(computeFlags(sock, cli.OutputFormatJSON), "c-964") })
	require.NoError(t, err)
	assert.Contains(t, out, "nginx:1")

	_, err = runCaptured(t, func() error { return runGet(computeFlags(sock, cli.OutputFormat("xml")), "c-964") })
	assert.ErrorAs(t, err, &cli.ErrInvalidOutputFormat{})

	srv.err = status.Error(codes.NotFound, "no such container")
	_, err = runCaptured(t, func() error { return runGet(computeFlags(sock, cli.OutputFormatJSON), "c-404") })
	var notFound ErrContainerNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "c-404", notFound.ID)
}

func TestRunList(t *testing.T) {
	srv := &fakeComputeServer{container: runningContainer()}
	sock := startComputeServer(t, srv)

	out, err := runCaptured(t, func() error {
		return runList(computeFlags(sock, cli.OutputFormatTable), &listOptions{pageSize: 5})
	})
	require.NoError(t, err)
	assert.Contains(t, out, "web")
	assert.Equal(t, []platformv1.ContainerState{platformv1.ContainerState_CONTAINER_STATE_RUNNING}, srv.listReq.GetStates(),
		"without --all only running containers are listed")
	assert.Equal(t, int32(5), int32(srv.listReq.GetPagination().GetPageSize()))

	_, err = runCaptured(t, func() error {
		return runList(computeFlags(sock, cli.OutputFormatJSON), &listOptions{all: true, filter: []string{"state=stopped", "label=tier=web"}})
	})
	require.NoError(t, err)
	assert.Equal(t, []platformv1.ContainerState{platformv1.ContainerState_CONTAINER_STATE_STOPPED}, srv.listReq.GetStates())
	assert.Equal(t, "web", srv.listReq.GetSelector().GetMatchLabels()["tier"])

	_, err = runCaptured(t, func() error {
		return runList(computeFlags(sock, cli.OutputFormatJSON), &listOptions{all: true})
	})
	require.NoError(t, err)
	assert.Empty(t, srv.listReq.GetStates(), "--all lists every state")

	_, err = runCaptured(t, func() error {
		return runList(computeFlags(sock, cli.OutputFormatJSON), &listOptions{filter: []string{"nokey"}})
	})
	assert.ErrorAs(t, err, &ErrInvalidFilter{})

	_, err = runCaptured(t, func() error { return runList(computeFlags(sock, cli.OutputFormat("xml")), &listOptions{}) })
	assert.ErrorAs(t, err, &cli.ErrInvalidOutputFormat{})

	srv.err = errDaemon
	_, err = runCaptured(t, func() error { return runList(computeFlags(sock, cli.OutputFormatJSON), &listOptions{}) })
	var opErr ErrContainerOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "list", opErr.Operation)
}

func TestRunAttest(t *testing.T) {
	srv := &fakeComputeServer{container: runningContainer()}
	sock := startComputeServer(t, srv)

	out, err := runCaptured(t, func() error {
		return runAttest(computeFlags(sock, cli.OutputFormatTable), "c-964", &attestOptions{nonce: "c0ffee", pcrs: "0,7"})
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Nonce: c0ffee")
	assert.Contains(t, out, "Name: web")
	assert.Contains(t, out, "Image Digest: sha256:abc")
	assert.Contains(t, out, "PCR Indices:")

	out, err = runCaptured(t, func() error {
		return runAttest(computeFlags(sock, cli.OutputFormatJSON), "c-964", &attestOptions{})
	})
	require.NoError(t, err)
	var result containerAttestationResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Len(t, result.Nonce, 64, "a generated nonce is 32 random bytes")
	assert.Equal(t, "nginx:1", result.ImageID)

	tests := []struct {
		name   string
		format cli.OutputFormat
		opts   *attestOptions
		target any
	}{
		{"bad nonce", cli.OutputFormatJSON, &attestOptions{nonce: "zz"}, &ErrInvalidContainerConfig{}},
		{"bad pcrs", cli.OutputFormatJSON, &attestOptions{nonce: "00", pcrs: "x"}, nil},
		{"unknown format", cli.OutputFormat("xml"), &attestOptions{nonce: "00"}, &cli.ErrInvalidOutputFormat{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runCaptured(t, func() error { return runAttest(computeFlags(sock, tt.format), "c-964", tt.opts) })
			require.Error(t, err)
			if tt.target != nil {
				assert.ErrorAs(t, err, tt.target)
			}
		})
	}

	srv.err = errDaemon
	_, err = runCaptured(t, func() error { return runAttest(computeFlags(sock, cli.OutputFormatJSON), "c-404", &attestOptions{}) })
	assert.ErrorAs(t, err, &ErrContainerNotFound{})
}

func TestRunLogs(t *testing.T) {
	stamp := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	srv := &fakeComputeServer{logs: []*platformv1.LogEntry{
		{Timestamp: timestamppb.New(stamp), Message: "first", Source: "stdout"},
		{Message: "second", Source: "stderr"},
	}}
	sock := startComputeServer(t, srv)

	out, err := runCaptured(t, func() error {
		return runLogs(computeFlags(sock, cli.OutputFormatTable), "c-964", &logsOptions{timestamps: true, stdout: true})
	})
	require.NoError(t, err)
	assert.Equal(t, "2026-10-30T12:00:00Z first\nsecond\n", out, "an entry without a time prints bare")
	assert.Equal(t, "c-964", srv.requestedID())

	out, err = runCaptured(t, func() error {
		return runLogs(computeFlags(sock, cli.OutputFormatTable), "c-964", &logsOptions{})
	})
	require.NoError(t, err)
	assert.Equal(t, "first\nsecond\n", out)

	out, err = runCaptured(t, func() error {
		return runLogs(computeFlags(sock, cli.OutputFormatJSON), "c-964", &logsOptions{})
	})
	require.NoError(t, err)
	var batch struct {
		Count int `json:"count"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &batch))
	assert.Equal(t, 2, batch.Count)

	srv.err = errDaemon
	_, err = runCaptured(t, func() error {
		return runLogs(computeFlags(sock, cli.OutputFormatJSON), "c-964", &logsOptions{})
	})
	var opErr ErrContainerOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "logs", opErr.Operation)

	_, err = runCaptured(t, func() error {
		return runLogs(computeFlags(sock, cli.OutputFormatTable), "c-964", &logsOptions{})
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "daemon refused"))
}
