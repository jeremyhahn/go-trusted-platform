package tenant

import (
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestRunQuotasSet_AllGroupsMergeExisting sets one field in every quota
// group and asserts the server receives the new value while the fields the
// caller left alone keep the tenant's existing limits.
func TestRunQuotasSet_AllGroupsMergeExisting(t *testing.T) {
	srv, flags := startTenantServer(t)

	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatYAML} {
		name := "merge-" + string(format)
		f := flags(format)
		require.NoError(t, runTenantCreate(f, &createTenantOptions{
			Name: name, MaxVMs: 5, MaxBridges: 2, MaxVolumesGB: 10,
		}))

		require.NoError(t, runQuotasSet(f, name, &quotasSetOptions{
			MaxContainers: 4, setMaxContainers: true,
			MaxVCPUs: 8, setMaxVCPUs: true,
			MaxMemoryGB: 3, setMaxMemoryGB: true,
			MaxPorts: 16, setMaxPorts: true,
			MaxBandwidthMbps: 100, setMaxBandwidthMbps: true,
			MaxSnapshots: 6, setMaxSnapshots: true,
		}))

		srv.mu.Lock()
		got, err := srv.byName(name)
		srv.mu.Unlock()
		require.NoError(t, err)

		compute := got.GetComputeQuota()
		assert.Equal(t, int64(5), compute.GetMaxVms(), "untouched MaxVMs keeps the existing limit")
		assert.Equal(t, int64(4), compute.GetMaxContainers())
		assert.Equal(t, int64(8), compute.GetMaxVcpus())
		assert.Equal(t, int64(3*1024), compute.GetMaxMemoryMb(), "memory is given in GB and sent in MB")

		network := got.GetNetworkQuota()
		assert.Equal(t, int64(2), network.GetMaxBridges(), "untouched MaxBridges keeps the existing limit")
		assert.Equal(t, int64(16), network.GetMaxPorts())
		assert.Equal(t, int64(100), network.GetMaxBandwidthMbps())

		storage := got.GetStorageQuota()
		assert.Equal(t, int64(10), storage.GetMaxVolumesGb(), "untouched MaxVolumesGB keeps the existing limit")
		assert.Equal(t, int64(6), storage.GetMaxSnapshots())
	}
}

// TestRunQuotasSet_OverridesEveryField asserts each explicitly set flag
// replaces the existing limit.
func TestRunQuotasSet_OverridesEveryField(t *testing.T) {
	srv, flags := startTenantServer(t)
	f := flags(cli.OutputFormatJSON)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{
		Name: "override", MaxVMs: 5, MaxBridges: 2, MaxVolumesGB: 10,
	}))

	require.NoError(t, runQuotasSet(f, "override", &quotasSetOptions{
		MaxVMs: 9, setMaxVMs: true,
		MaxBridges: 7, setMaxBridges: true,
		MaxVolumesGB: 50, setMaxVolumesGB: true,
	}))

	srv.mu.Lock()
	got, err := srv.byName("override")
	srv.mu.Unlock()
	require.NoError(t, err)
	assert.Equal(t, int64(9), got.GetComputeQuota().GetMaxVms())
	assert.Equal(t, int64(7), got.GetNetworkQuota().GetMaxBridges())
	assert.Equal(t, int64(50), got.GetStorageQuota().GetMaxVolumesGb())
}

// TestRunQuotasSet_InvalidOutputFormat asserts an unknown output format is
// reported as a typed error after the update.
func TestRunQuotasSet_InvalidOutputFormat(t *testing.T) {
	_, flags := startTenantServer(t)
	require.NoError(t, runTenantCreate(flags(cli.OutputFormatJSON), &createTenantOptions{Name: "fmt"}))

	err := runQuotasSet(flags(cli.OutputFormat("xml")), "fmt", &quotasSetOptions{MaxVMs: 1, setMaxVMs: true})
	var want cli.ErrInvalidOutputFormat
	require.ErrorAs(t, err, &want)
	assert.Equal(t, "xml", want.Format)
}

// TestRunBarrierUnseal_KeyArguments covers the key decoding that runs before
// any connection is made.
func TestRunBarrierUnseal_KeyArguments(t *testing.T) {
	tests := []struct {
		name   string
		keyHex string
		keyB64 string
	}{
		{name: "both keys", keyHex: "00", keyB64: "AA=="},
		{name: "bad hex", keyHex: "zz"},
		{name: "bad base64", keyB64: "!!not-base64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, flags := startUnsealRecordingServer(t)
			f := flags(cli.OutputFormatJSON)
			require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "acme"}))

			err := runBarrierUnseal(f, "acme", tc.keyHex, tc.keyB64)
			var want ErrInvalidArguments
			require.ErrorAs(t, err, &want)
			assert.Contains(t, err.Error(), "invalid arguments: ")
			assert.Empty(t, srv.unsealRequests(), "a rejected key must not reach the unseal RPC")
		})
	}
}

// TestRunBarrierUnseal_Base64Key asserts a base64 key unseals the barrier
// and that the "0x" hex prefix is accepted.
func TestRunBarrierUnseal_Base64Key(t *testing.T) {
	srv, flags := startUnsealRecordingServer(t)
	f := flags(cli.OutputFormatJSON)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "b64"}))
	tenantID := srv.tenantIDByName(t, "b64")

	want := []byte{0x00, 0x11, 0x22, 0x33}
	key := base64.StdEncoding.EncodeToString(want)
	require.NoError(t, runBarrierUnseal(f, "b64", "", key))
	require.NoError(t, runBarrierUnseal(f, "b64", "0x00112233", ""))
	assert.ErrorAs(t, runBarrierUnseal(f, "ghost", "", key), new(ErrTenantNotFound))

	reqs := srv.unsealRequests()
	require.Len(t, reqs, 2, "one unseal RPC per accepted key, none for an unknown tenant")
	for i, input := range []string{"base64", "prefixed hex"} {
		assert.Equal(t, tenantID, reqs[i].GetTenantId(), "%s: tenant ID", input)
		assert.Equal(t, want, reqs[i].GetKey(), "%s: decoded key bytes", input)
	}
}

// unsealRecordingServer is the in-process tenant server with every
// UnsealTenantBarrier request recorded, so a test can assert what the CLI
// actually sent.
type unsealRecordingServer struct {
	*inProcTenantServer
	unsealMu sync.Mutex
	unseals  []*platformv1.UnsealTenantBarrierRequest
}

func (s *unsealRecordingServer) UnsealTenantBarrier(ctx context.Context, r *platformv1.UnsealTenantBarrierRequest) (*platformv1.UnsealTenantBarrierResponse, error) {
	s.unsealMu.Lock()
	s.unseals = append(s.unseals, r)
	s.unsealMu.Unlock()
	return s.inProcTenantServer.UnsealTenantBarrier(ctx, r)
}

func (s *unsealRecordingServer) unsealRequests() []*platformv1.UnsealTenantBarrierRequest {
	s.unsealMu.Lock()
	defer s.unsealMu.Unlock()
	return append([]*platformv1.UnsealTenantBarrierRequest(nil), s.unseals...)
}

func (s *unsealRecordingServer) tenantIDByName(t *testing.T, name string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tn := range s.tenants {
		if tn.GetName() == name {
			return id
		}
	}
	require.FailNow(t, "tenant not created", name)
	return ""
}

// startUnsealRecordingServer is startTenantServer with the recording wrapper
// registered in place of the bare in-process server.
func startUnsealRecordingServer(t *testing.T) (*unsealRecordingServer, func(cli.OutputFormat) *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &unsealRecordingServer{inProcTenantServer: &inProcTenantServer{tenants: map[string]*platformv1.Tenant{}}}
	gs := grpc.NewServer()
	platformv1.RegisterTenantServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	flags := func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
	return srv, flags
}

// TestCommands_RunEWiring executes each cobra command against the in-process
// server and asserts the RunE wrapper hands the argument and flags through.
func TestCommands_RunEWiring(t *testing.T) {
	_, flags := startTenantServer(t)
	getFlags := func() *cli.CommonFlags { return flags(cli.OutputFormatJSON) }
	require.NoError(t, runTenantCreate(getFlags(), &createTenantOptions{Name: "wired"}))

	notFound := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{name: "show", cmd: NewShowCommand(getFlags), args: []string{"ghost"}},
		{name: "suspend", cmd: NewSuspendCommand(getFlags), args: []string{"ghost"}},
		{name: "resume", cmd: NewResumeCommand(getFlags), args: []string{"ghost"}},
		{name: "usage", cmd: NewUsageCommand(getFlags), args: []string{"ghost"}},
		{name: "delete", cmd: NewDeleteCommand(getFlags), args: []string{"ghost", "--force"}},
		{name: "quotas get", cmd: newQuotasGetCommand(getFlags), args: []string{"ghost"}},
		{name: "barrier seal", cmd: newBarrierSealCommand(getFlags), args: []string{"ghost"}},
		{name: "barrier status", cmd: newBarrierStatusCommand(getFlags), args: []string{"ghost"}},
	}
	for _, tc := range notFound {
		t.Run(tc.name+" unknown tenant", func(t *testing.T) {
			tc.cmd.SetArgs(tc.args)
			tc.cmd.SilenceUsage = true
			tc.cmd.SilenceErrors = true
			var want ErrTenantNotFound
			require.ErrorAs(t, tc.cmd.Execute(), &want)
			assert.Equal(t, "ghost", want.Name)
		})
	}

	found := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{name: "show", cmd: NewShowCommand(getFlags), args: []string{"wired"}},
		{name: "usage", cmd: NewUsageCommand(getFlags), args: []string{"wired"}},
		{name: "quotas get", cmd: newQuotasGetCommand(getFlags), args: []string{"wired"}},
		{name: "list", cmd: NewListCommand(getFlags), args: []string{}},
		{name: "sync", cmd: NewSyncCommand(getFlags), args: []string{}},
		{name: "suspend", cmd: NewSuspendCommand(getFlags), args: []string{"wired"}},
		{name: "resume", cmd: NewResumeCommand(getFlags), args: []string{"wired"}},
		{name: "barrier status", cmd: newBarrierStatusCommand(getFlags), args: []string{"wired"}},
		{name: "delete", cmd: NewDeleteCommand(getFlags), args: []string{"wired", "--force"}},
	}
	for _, tc := range found {
		t.Run(tc.name, func(t *testing.T) {
			tc.cmd.SetArgs(tc.args)
			tc.cmd.SilenceUsage = true
			tc.cmd.SilenceErrors = true
			require.NoError(t, tc.cmd.Execute())
		})
	}
}
