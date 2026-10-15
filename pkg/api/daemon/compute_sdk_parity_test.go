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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkcompute "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
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
	name  string
	dial  func(t *testing.T, provider *MCPServiceProvider, svc *ComputeGRPCService) *sdkcompute.Client
	verbs map[string]bool
	// wrongState is the class a VM in the wrong state reaches the caller as.
	wrongState codes.Code
}

// allVMVerbs is every verb; QUIC carries only reboot, suspend and resume
// because platformd's QUIC listener answers no other VM verb.
var (
	allVMVerbs  = map[string]bool{"start": true, "stop": true, "reboot": true, "suspend": true, "resume": true, "delete": true}
	quicVMVerbs = map[string]bool{"reboot": true, "suspend": true, "resume": true}
)

var vmSDKTransports = []vmSDKTransport{
	// Both REST servers render FailedPrecondition as 400, which the SDK
	// reads back as InvalidArgument.
	{"REST", dialComputeREST, allVMVerbs, codes.InvalidArgument},
	{"QUIC", dialComputeQUIC, quicVMVerbs, codes.FailedPrecondition},
	{"MCP", dialComputeMCP, allVMVerbs, codes.FailedPrecondition},
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
			if !transport.verbs[verb.name] {
				continue
			}
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
			if !transport.verbs[verb.name] {
				continue
			}
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

// platformd's QUIC listener answers no start, stop or delete, so the SDK
// refuses them before the wire and the orchestrator never runs.
func TestVMLifecycleSDKParity_QUICVerbsWithoutAServerAnswer(t *testing.T) {
	for _, verb := range vmSDKVerbs {
		if quicVMVerbs[verb.name] {
			continue
		}
		t.Run(verb.name, func(t *testing.T) {
			provider, svc, orch := seededVMPair()
			ops := recordVMOps(orch, nil)
			client := dialComputeQUIC(t, provider, svc)

			err := verb.call(context.Background(), client, "vm-1")
			assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
			assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
			assert.Empty(t, drain(ops))
		})
	}
}
