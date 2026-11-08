package db

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	dbsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/db"
)

// errDBBackendDown is the failure the fake daemon reports when a test asks
// it to fail an RPC.
var errDBBackendDown = status.Error(codes.Unavailable, "database backend down")

// fakeDBDaemon serves the two database RPCs of the platform daemon from
// canned data, so runList and runDump run end to end over a real gRPC
// connection on a unix socket in the test's temporary directory.
type fakeDBDaemon struct {
	platformv1.UnimplementedPlatformDaemonServer

	list    *platformv1.ListEntityTypesResponse
	entries []*platformv1.DumpEntityTypeResponse
	// failList and failDump make the matching RPC return errDBBackendDown.
	failList bool
	failDump bool
	// lastDump records the request the dump RPC received.
	lastDump *platformv1.DumpEntityTypeRequest
}

func (f *fakeDBDaemon) ListEntityTypes(_ context.Context, _ *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error) {
	if f.failList {
		return nil, errDBBackendDown
	}
	return f.list, nil
}

func (f *fakeDBDaemon) DumpEntityType(req *platformv1.DumpEntityTypeRequest, stream grpc.ServerStreamingServer[platformv1.DumpEntityTypeResponse]) error {
	f.lastDump = req
	if f.failDump {
		return errDBBackendDown
	}
	for _, entry := range f.entries {
		if err := stream.Send(entry); err != nil {
			return err
		}
	}
	return nil
}

// startDBDaemon serves fake on a unix socket and returns CLI flags whose
// local context dials it.
func startDBDaemon(t *testing.T, fake *fakeDBDaemon) *cli.CommonFlags {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	gs := grpc.NewServer()
	platformv1.RegisterPlatformDaemonServer(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
		},
	}
}

// captureDBStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureDBStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w

	done := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-done
	require.NoError(t, r.Close())
	return string(out), runErr
}

func dumpEntry(entityType string, id uint64, data string) *platformv1.DumpEntityTypeResponse {
	return &platformv1.DumpEntityTypeResponse{EntityType: entityType, EntityId: id, Data: []byte(data)}
}

func TestRunList_PrintsEntityTypeTable(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{list: &platformv1.ListEntityTypesResponse{
		DatabasePath:  "/var/lib/platform/db",
		TotalEntities: 7,
		ActiveTypes:   1,
		EntityTypes: []*platformv1.EntityTypeInfo{
			{Name: "device", EntityCount: 7, Status: "active"},
			{Name: "tenant", EntityCount: 0, Status: "empty"},
		},
	}})

	out, err := captureDBStdout(t, func() error { return runList(flags, &listFlags{}) })
	require.NoError(t, err)

	assert.Contains(t, out, "ENTITY TYPE")
	lines := strings.Split(out, "\n")
	var deviceRow, tenantRow string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "device" {
			deviceRow = line
		}
		if len(fields) == 3 && fields[0] == "tenant" {
			tenantRow = line
		}
	}
	assert.Equal(t, []string{"device", "7", "active"}, strings.Fields(deviceRow))
	assert.Equal(t, []string{"tenant", "0", "empty"}, strings.Fields(tenantRow))
}

func TestRunList_DaemonErrorIsWrapped(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{failList: true})

	_, err := captureDBStdout(t, func() error { return runList(flags, &listFlags{}) })

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to list entity types", wrapped.Msg)
	var listErr *dbsvc.ErrListEntityTypesFailed
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, codes.Unavailable, status.Code(listErr.Cause))
}

func TestRunList_NoContextIsConnectError(t *testing.T) {
	err := runList(&cli.CommonFlags{}, &listFlags{})

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to connect to platformd", wrapped.Msg)
	assert.ErrorIs(t, err, cli.ErrNoContextSet{})
}

func TestRunDump_WritesOneFilePerEntity(t *testing.T) {
	tests := []struct {
		name   string
		format string
		pretty bool
		data   string
		want   string
	}{
		{name: "json raw", format: "json", data: `{"a":1}`, want: `{"a":1}`},
		{name: "json pretty", format: "JSON", pretty: true, data: `{"a":1}`, want: "{\n  \"a\": 1\n}"},
		{name: "json pretty keeps unparsable data", format: "json", pretty: true, data: `not-json`, want: `not-json`},
		{name: "yaml", format: "yaml", data: `{"a":1}`, want: "a: 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeDBDaemon{entries: []*platformv1.DumpEntityTypeResponse{
				dumpEntry("device", 1, tt.data),
				dumpEntry("device", 2, tt.data),
			}}
			flags := startDBDaemon(t, fake)
			outDir := filepath.Join(t.TempDir(), "dump")

			err := runDump(flags, &dumpFlags{output: outDir, format: tt.format, pretty: tt.pretty, entityType: "device"})
			require.NoError(t, err)

			ext := strings.ToLower(tt.format)
			for _, id := range []string{"1", "2"} {
				got, readErr := os.ReadFile(filepath.Join(outDir, "device", id+"."+ext))
				require.NoError(t, readErr)
				assert.Equal(t, tt.want, string(got))
			}
			require.NotNil(t, fake.lastDump)
			assert.Equal(t, "device", fake.lastDump.EntityType)
			assert.Equal(t, ext, fake.lastDump.Format)
			assert.Equal(t, tt.pretty, fake.lastDump.Pretty)
		})
	}
}

func TestRunDump_YAMLRoundTripsNestedData(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{entries: []*platformv1.DumpEntityTypeResponse{
		dumpEntry("tenant", 9, `{"name":"acme","tags":["a","b"]}`),
	}})
	outDir := t.TempDir()

	require.NoError(t, runDump(flags, &dumpFlags{output: outDir, format: "yaml"}))

	raw, err := os.ReadFile(filepath.Join(outDir, "tenant", "9.yaml"))
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, yaml.Unmarshal(raw, &got))
	assert.Equal(t, "acme", got["name"])
	assert.Equal(t, []interface{}{"a", "b"}, got["tags"])
}

func TestRunDump_EmptyDatabaseWritesNothing(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{})
	outDir := filepath.Join(t.TempDir(), "dump")

	require.NoError(t, runDump(flags, &dumpFlags{output: outDir, format: "json"}))

	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRunDump_InvalidFormat(t *testing.T) {
	err := runDump(&cli.CommonFlags{}, &dumpFlags{format: "xml"})

	var formatErr ErrInvalidFormat
	require.ErrorAs(t, err, &formatErr)
	assert.Equal(t, "xml", formatErr.Format)
}

func TestRunDump_NoContextIsConnectError(t *testing.T) {
	err := runDump(&cli.CommonFlags{}, &dumpFlags{format: "json"})

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to connect to platformd", wrapped.Msg)
	assert.ErrorIs(t, err, cli.ErrNoContextSet{})
}

func TestRunDump_DaemonStreamError(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{failDump: true})

	err := runDump(flags, &dumpFlags{output: t.TempDir(), format: "json"})

	var streamErr *dbsvc.ErrDumpStreamFailed
	require.ErrorAs(t, err, &streamErr)
	assert.Equal(t, codes.Unavailable, status.Code(streamErr.Cause))
}

func TestRunDump_YAMLRejectsInvalidJSON(t *testing.T) {
	flags := startDBDaemon(t, &fakeDBDaemon{entries: []*platformv1.DumpEntityTypeResponse{
		dumpEntry("device", 4, `{broken`),
	}})

	err := runDump(flags, &dumpFlags{output: t.TempDir(), format: "yaml"})

	var deserErr ErrDeserializationFailed
	require.ErrorAs(t, err, &deserErr)
	assert.Equal(t, "device", deserErr.EntityType)
	assert.Equal(t, uint64(4), deserErr.ID)
}

func TestRunDump_FilesystemFailures(t *testing.T) {
	tests := []struct {
		name string
		// prepare lays out outDir so one filesystem step fails, and returns
		// the output path to pass to runDump and the path the error names.
		prepare func(t *testing.T, outDir string) (output, failPath string)
		check   func(t *testing.T, err error, failPath string)
	}{
		{
			name: "output path is a file",
			prepare: func(t *testing.T, outDir string) (string, string) {
				blocker := filepath.Join(outDir, "blocker")
				require.NoError(t, os.WriteFile(blocker, nil, 0o600))
				output := filepath.Join(blocker, "dump")
				return output, output
			},
			check: func(t *testing.T, err error, failPath string) {
				var dirErr ErrOutputDirectoryFailed
				require.ErrorAs(t, err, &dirErr)
				assert.Equal(t, failPath, dirErr.Path)
			},
		},
		{
			name: "entity directory path is a file",
			prepare: func(t *testing.T, outDir string) (string, string) {
				entityDir := filepath.Join(outDir, "device")
				require.NoError(t, os.WriteFile(entityDir, nil, 0o600))
				return outDir, entityDir
			},
			check: func(t *testing.T, err error, failPath string) {
				var dirErr ErrOutputDirectoryFailed
				require.ErrorAs(t, err, &dirErr)
				assert.Equal(t, failPath, dirErr.Path)
			},
		},
		{
			name: "entity file path is a directory",
			prepare: func(t *testing.T, outDir string) (string, string) {
				target := filepath.Join(outDir, "device", "1.json")
				require.NoError(t, os.MkdirAll(target, 0o700))
				return outDir, target
			},
			check: func(t *testing.T, err error, failPath string) {
				var writeErr ErrFileWriteFailed
				require.ErrorAs(t, err, &writeErr)
				assert.Equal(t, failPath, writeErr.Path)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := startDBDaemon(t, &fakeDBDaemon{entries: []*platformv1.DumpEntityTypeResponse{
				dumpEntry("device", 1, `{"a":1}`),
			}})
			output, failPath := tt.prepare(t, t.TempDir())

			err := runDump(flags, &dumpFlags{output: output, format: "json"})

			require.Error(t, err)
			tt.check(t, err, failPath)
		})
	}
}

func TestWrappedError_MessageAndUnwrap(t *testing.T) {
	err := &WrappedError{Msg: "failed to connect to platformd", Err: errDBBackendDown}

	assert.Equal(t, "failed to connect to platformd: "+errDBBackendDown.Error(), err.Error())
	assert.Same(t, errDBBackendDown, errors.Unwrap(err))
}
