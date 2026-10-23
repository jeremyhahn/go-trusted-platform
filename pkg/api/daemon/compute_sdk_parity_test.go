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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkcommon "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	sdkcompute "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// vmSDKVerb drives one VM lifecycle verb through the Go SDK compute client.
type vmSDKVerb struct {
	name string
	call func(ctx context.Context, c *sdkcompute.Client, id string) error
	// typed reports whether err is the client's typed error for the verb.
	typed func(err error) bool
	// ops are the orchestrator operations the verb runs, in order.
	ops []string
}

func typedAs[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

var vmSDKVerbs = []vmSDKVerb{
	{"start", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.StartVM(ctx, id) },
		typedAs[*sdkcompute.ErrStartVMFailed], []string{"start"}},
	{"stop", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.StopVM(ctx, id, false, 0) },
		typedAs[*sdkcompute.ErrStopVMFailed], []string{"stop"}},
	{"reboot", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.RebootVM(ctx, id, false) },
		typedAs[*sdkcompute.ErrRebootVMFailed], []string{"stop", "start"}},
	{"suspend", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.SuspendVM(ctx, id) },
		typedAs[*sdkcompute.ErrSuspendVMFailed], []string{"run-state"}},
	{"resume", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.ResumeVM(ctx, id) },
		typedAs[*sdkcompute.ErrResumeVMFailed], []string{"run-state"}},
	{"delete", func(ctx context.Context, c *sdkcompute.Client, id string) error { return c.DeleteVM(ctx, id, false) },
		typedAs[*sdkcompute.ErrDeleteVMFailed], []string{"delete"}},
}

// vmSDKTransport serves the daemon's compute handlers for one protocol and
// returns an SDK compute client connected to them.
type vmSDKTransport struct {
	name string
	dial func(t *testing.T, provider *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client
	// wrongState is the class a VM in the wrong state reaches the caller as.
	wrongState codes.Code
}

var vmSDKTransports = []vmSDKTransport{
	// Both REST servers render FailedPrecondition as 400, which the SDK
	// reads back as InvalidArgument.
	{"REST", dialComputeREST, codes.InvalidArgument},
	{"QUIC", dialComputeQUIC, codes.FailedPrecondition},
	{"MCP", dialComputeMCP, codes.FailedPrecondition},
	{"gRPC", dialComputeGRPC, codes.FailedPrecondition},
	{"Unix", dialComputeUnix, codes.FailedPrecondition},
	{"embedded", dialComputeEmbedded, codes.FailedPrecondition},
}

func dialComputeREST(t *testing.T, _ *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client {
	tlsBundle := testutil.GenerateTestTLSBundle(t)
	router := mux.NewRouter()
	guard := restapi.NewScopeGuard(scopedTokenValidator{scopes: []string{"*:*"}}, nil, nil)
	restapi.NewComputeHandlers(svc, guard, nil).RegisterRoutes(router)
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	srv := httptest.NewUnstartedServer(router)
	srv.TLS = tlsBundle.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(srv.URL),
		platform.WithTLSConfig(tlsBundle.ClientTLSConfig()),
		platform.WithBearerToken("tok"),
	))
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(connection(t, adapter, err)))
}

// dialComputeGRPC serves the compute service as the daemon's TCP listener
// does, gRPC over TLS, and returns an SDK client connected to it.
func dialComputeGRPC(t *testing.T, _ *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client {
	serverTLS, clientTLS := testGRPCTLSCredentials(t)
	buf := bufconn.Listen(1 << 20)
	conn := serveTestGRPC(t, registerCompute(svc), buf, "passthrough:///bufnet", serverTLS, clientTLS,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return buf.DialContext(ctx)
		}))
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(conn))
}

// dialComputeUnix serves the compute service as the daemon's Unix socket
// does, gRPC with local credentials, and returns an SDK client connected
// to it.
func dialComputeUnix(t *testing.T, _ *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client {
	lis, socket := testUnixListener(t)
	conn := serveTestGRPC(t, registerCompute(svc), lis, "unix://"+socket,
		local.NewCredentials(), local.NewCredentials(), nil)
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(conn))
}

func registerCompute(svc *ComputeGRPCService) func(*grpc.Server) {
	return func(server *grpc.Server) { platformv1.RegisterComputeServiceServer(server, svc) }
}

// dialComputeEmbedded returns an SDK client over the in-process embedded
// transport, which dispatches straight to the service.
func dialComputeEmbedded(t *testing.T, _ *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client {
	adapter, err := embedded.New(&embedded.ServiceRegistry{Compute: svc})
	require.NoError(t, err)
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(adapter.Connection()))
}

func dialComputeQUIC(t *testing.T, _ *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client {
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"*:*"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	handler.SetComputeGRPCService(svc)
	conn := serveQUIC(t, testutil.GenerateTestTLSBundle(t), handler)
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(conn))
}

func dialComputeMCP(t *testing.T, provider *MCPServiceProvider, _ *ComputeGRPCService) *sdkcompute.Client {
	srv := httptest.NewServer(mcpToolBridge(t, mcp.NewToolRegistry(provider, logging.DefaultLogger())))
	t.Cleanup(srv.Close)
	adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
	return sdkcompute.NewClientFromGRPC(platformv1.NewComputeServiceClient(connection(t, adapter, err)))
}

// recordVMOps makes every lifecycle operation of orch answer with err and
// report its name on the returned channel.
func recordVMOps(orch *computeParityOrchestrator, err error) <-chan string {
	ops := make(chan string, 4)
	record := func(op string) func(context.Context, string) error {
		return func(context.Context, string) error {
			ops <- op
			return err
		}
	}
	orch.startFunc, orch.stopFunc, orch.deleteFunc = record("start"), record("stop"), record("delete")
	orch.runStateFunc = record("run-state")
	return ops
}

func drain(ops <-chan string) []string {
	var got []string
	for {
		select {
		case op := <-ops:
			got = append(got, op)
		default:
			return got
		}
	}
}

func TestVMLifecycleSDKParity_RunsTheVerb(t *testing.T) {
	for _, transport := range vmSDKTransports {
		for _, verb := range vmSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				ops := recordVMOps(orch, nil)
				client := transport.dial(t, provider, svc)

				require.NoError(t, verb.call(context.Background(), client, "vm-1"))
				assert.Equal(t, verb.ops, drain(ops))
			})
		}
	}
}

func TestVMLifecycleSDKParity_UnknownVM(t *testing.T) {
	notFound := &compute.SentinelCauseError{Sentinel: compute.ErrInstanceNotFound, Cause: &compute.MessageError{Msg: "no such vm"}}
	for _, transport := range vmSDKTransports {
		for _, verb := range vmSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				recordVMOps(orch, notFound)
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "vm-missing")
				assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
				assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
			})
		}
	}
}

// Extends TestVMLifecycleParity_WrongState to the SDK adapters.
func TestVMLifecycleSDKParity_WrongState(t *testing.T) {
	for _, sentinel := range []error{compute.ErrInstanceNotRunning, compute.ErrInstanceNotSuspended} {
		for _, transport := range vmSDKTransports {
			for _, verb := range vmSDKVerbs {
				if verb.name != "suspend" && verb.name != "resume" {
					continue
				}
				t.Run(transport.name+" "+verb.name+" "+sentinel.Error(), func(t *testing.T) {
					provider, svc, orch := seededVMPair()
					recordVMOps(orch, &compute.SentinelCauseError{Sentinel: sentinel, Cause: &compute.MessageError{Msg: "wrong state"}})
					client := transport.dial(t, provider, svc)

					err := verb.call(context.Background(), client, "vm-1")
					assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
					assert.Equal(t, transport.wrongState, status.Code(err), "err = %v", err)
				})
			}
		}
	}
}

// seededVMListPair seeds three VMs a ListVMs filter can tell apart:
//
//	vm-a  web  running  created t0+1h
//	vm-b  db   stopped  created t0+2h
//	vm-c  api  running  created t0
func seededVMListPair() (*MCPServiceProvider, *ComputeGRPCService, *computeParityOrchestrator) {
	provider, svc, orch := newComputeParityPair()
	t0 := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	seed := []struct {
		id, name string
		state    compute.InstanceState
		created  time.Duration
	}{
		{"vm-a", "web", compute.StateRunning, time.Hour},
		{"vm-b", "db", compute.StateStopped, 2 * time.Hour},
		{"vm-c", "api", compute.StateRunning, 0},
	}
	for _, vm := range seed {
		orch.instances[vm.id] = &compute.Instance{
			ID: vm.id, Name: vm.name, Type: compute.ComputeTypeVM, State: vm.state,
			CreatedAt: t0.Add(vm.created), UpdatedAt: t0.Add(vm.created),
		}
	}
	return provider, svc, orch
}

func TestVMListSDKParity_Filters(t *testing.T) {
	running := platformv1.VMState_VM_STATE_RUNNING
	tests := []struct {
		name     string
		req      *platformv1.ListVMsRequest
		wantIDs  []string
		wantPage *sdkcommon.PageResult
	}{
		{
			name:     "no filter",
			req:      &platformv1.ListVMsRequest{},
			wantIDs:  []string{"vm-a", "vm-b", "vm-c"},
			wantPage: &sdkcommon.PageResult{Page: 1, PageSize: 3, TotalPages: 1, TotalItems: 3},
		},
		{
			name:     "state",
			req:      &platformv1.ListVMsRequest{States: []platformv1.VMState{running}},
			wantIDs:  []string{"vm-a", "vm-c"},
			wantPage: &sdkcommon.PageResult{Page: 1, PageSize: 2, TotalPages: 1, TotalItems: 2},
		},
		{
			name: "sort and page",
			req: &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{
				Page: 2, PageSize: 2, SortBy: "created_at", Ascending: true,
			}},
			wantIDs:  []string{"vm-b"},
			wantPage: &sdkcommon.PageResult{Page: 2, PageSize: 2, TotalPages: 2, TotalItems: 3},
		},
		{
			name: "no VM carries the label",
			req: &platformv1.ListVMsRequest{Selector: &platformv1.LabelSelector{
				MatchLabels: map[string]string{"tier": "web"},
			}},
			wantIDs:  []string{},
			wantPage: &sdkcommon.PageResult{Page: 1, PageSize: 0, TotalPages: 1, TotalItems: 0},
		},
		{
			name: "state, sort and page combine",
			req: &platformv1.ListVMsRequest{
				States:     []platformv1.VMState{running},
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 1, SortBy: "name", Ascending: true},
			},
			wantIDs:  []string{"vm-c"},
			wantPage: &sdkcommon.PageResult{Page: 1, PageSize: 1, TotalPages: 2, TotalItems: 2},
		},
	}
	for _, transport := range vmSDKTransports {
		for _, tt := range tests {
			t.Run(transport.name+" "+tt.name, func(t *testing.T) {
				provider, svc, _ := seededVMListPair()
				client := transport.dial(t, provider, svc)

				vms, page, err := client.ListVMs(context.Background(), tt.req)

				require.NoError(t, err)
				ids := make([]string, 0, len(vms))
				for _, vm := range vms {
					ids = append(ids, vm.GetId())
				}
				assert.Equal(t, tt.wantIDs, ids)
				assert.Equal(t, tt.wantPage, page)
			})
		}
	}
}

func TestVMListSDKParity_InvalidFilter(t *testing.T) {
	tests := []struct {
		name string
		req  *platformv1.ListVMsRequest
	}{
		{"unknown state", &platformv1.ListVMsRequest{States: []platformv1.VMState{99}}},
		{"selector expression", &platformv1.ListVMsRequest{Selector: &platformv1.LabelSelector{
			MatchExpressions: []string{"env=prod"},
		}}},
		{"unsupported sort field", &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{SortBy: "memory"}}},
	}
	for _, transport := range vmSDKTransports {
		for _, tt := range tests {
			t.Run(transport.name+" "+tt.name, func(t *testing.T) {
				provider, svc, _ := seededVMListPair()
				client := transport.dial(t, provider, svc)

				vms, _, err := client.ListVMs(context.Background(), tt.req)

				assert.Nil(t, vms)
				assert.True(t, typedAs[*sdkcompute.ErrListVMsFailed](err), "err = %T, want *ErrListVMsFailed", err)
				assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			})
		}
	}
}

func TestVMCreateSDKParity_ConfigReachesTheOrchestrator(t *testing.T) {
	labels := map[string]string{"tier": "web"}
	config := &platformv1.VMConfig{
		Name:       "vm-web",
		Firmware:   platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
		BootDevice: platformv1.BootDevice_BOOT_DEVICE_NETWORK,
		Cpu:        &platformv1.CPUConfig{Cores: 4},
		Memory:     &platformv1.MemoryConfig{SizeMb: 4096},
		Disks:      []*platformv1.DiskConfig{{SizeGb: 40, Bus: platformv1.DiskBus_DISK_BUS_SATA}},
		Networks:   []*platformv1.NetworkConfig{{MacAddress: "52:54:00:12:34:56"}},
		Tpm:        &platformv1.TPMConfig{Enabled: true},
		Labels:     labels,
	}
	want := compute.VMSpec{
		MemoryMB: 4096, CPUs: 4, DiskSizeGB: 40, DiskBus: compute.DiskBusSATA,
		SecureBoot: true, BootMode: compute.BootModePXE, MACAddress: "52:54:00:12:34:56", Labels: labels,
	}
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			client := transport.dial(t, provider, svc)

			vm, err := client.CreateVM(context.Background(), config, true)
			require.NoError(t, err)

			assert.Equal(t, []compute.VMSpec{want}, orch.recordedSpecs())
			assert.Equal(t, platformv1.VMState_VM_STATE_RUNNING, vm.GetState())
			assert.Equal(t, labels, vm.GetConfig().GetLabels())
		})
	}
}

func TestVMCreateSDKParity_RefusedField(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			client := transport.dial(t, provider, svc)

			vm, err := client.CreateVM(context.Background(), &platformv1.VMConfig{
				Name:     "vm-bios",
				Firmware: platformv1.FirmwareType_FIRMWARE_TYPE_BIOS,
			}, false)

			assert.Nil(t, vm)
			assert.True(t, typedAs[*sdkcompute.ErrCreateVMFailed](err), "err = %T, want *ErrCreateVMFailed", err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			assert.Contains(t, err.Error(), "config.firmware")
			assert.Empty(t, orch.recordedSpecs())
		})
	}
}

func TestVMCreateSDKParity_StartFailureLeavesNoVM(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.startFunc = func(context.Context, string) error { return compute.ErrDiskNotFound }
			client := transport.dial(t, provider, svc)

			vm, err := client.CreateVM(context.Background(), &platformv1.VMConfig{Name: "vm-nostart"}, true)

			assert.Nil(t, vm)
			assert.True(t, typedAs[*sdkcompute.ErrCreateVMFailed](err), "err = %T, want *ErrCreateVMFailed", err)
			assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
			_, getErr := orch.Get(context.Background(), "vm-nostart-instance")
			assert.Error(t, getErr, "the VM that failed to start must be deleted")
		})
	}
}
