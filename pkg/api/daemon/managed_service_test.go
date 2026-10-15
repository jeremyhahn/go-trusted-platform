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

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

const ownedReason = "owned by the process"

// newOwnedService is a process-owned subsystem whose running state the test
// controls.
func newOwnedService(name string, running bool) *subsystemService {
	return &subsystemService{name: name, reason: ownedReason, running: func() bool { return running }}
}

func TestSubsystemService_RefusesStartAndStop(t *testing.T) {
	svc := newOwnedService("tpm", true)
	want := ErrServiceNotControllable{ServiceName: "tpm", Reason: ownedReason}

	for verb, call := range map[string]func(context.Context) error{"start": svc.Start, "stop": svc.Stop} {
		err := call(context.Background())
		var refusal ErrServiceNotControllable
		require.True(t, errors.As(err, &refusal), "%s: got %v", verb, err)
		assert.Equal(t, want, refusal, verb)
	}
	assert.True(t, svc.IsRunning(), "a refused stop must not change the subsystem's state")
	assert.Equal(t, "tpm", svc.Name())
}

func TestSubsystemService_IsRunningFollowsTheProbe(t *testing.T) {
	assert.True(t, newOwnedService("dns", true).IsRunning())
	assert.False(t, newOwnedService("dns", false).IsRunning())
}

func TestErrServiceNotControllable_IsFailedPrecondition(t *testing.T) {
	err := ErrServiceNotControllable{ServiceName: "sdn", Reason: ownedReason}

	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, err.Error(), "sdn")
	assert.Contains(t, err.Error(), ownedReason)
}

func TestProcessOwned(t *testing.T) {
	refusal, owned := processOwned(newOwnedService("compute", false))
	assert.True(t, owned)
	assert.Equal(t, ErrServiceNotControllable{ServiceName: "compute", Reason: ownedReason}, refusal)

	_, owned = processOwned(newMockService("compute"))
	assert.False(t, owned, "a registry-controlled service is not process-owned")
}

func TestSubsystemSpecs_CoverEveryNamedServiceType(t *testing.T) {
	for _, name := range []string{"tpm", "sdn", "compute", "dns", "acme", "webservice", "attestation"} {
		spec, ok := subsystemSpecs[serviceTypeFromName(name)]
		require.True(t, ok, "%s has no subsystem spec", name)
		assert.NotEmpty(t, spec.reason, name)
	}
	_, ok := subsystemSpecs[platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED]
	assert.False(t, ok, "an unnamed service type must not be registered")
}

func TestSubsystemProbe_WiredStateIsReadOnce(t *testing.T) {
	d := &Daemon{}
	for _, wired := range []bool{true, false} {
		calls := 0
		probe := d.subsystemProbe(platformv1.ServiceType_SERVICE_TYPE_TPM, subsystemSpec{
			wired: func(*Daemon) bool { calls++; return wired },
		})
		// Status RPCs call the probe while Stop may hold d.mu, so the wiring
		// is read once at registration and never again.
		for i := 0; i < 3; i++ {
			assert.Equal(t, wired, probe())
		}
		assert.Equal(t, 1, calls)
	}
}

func TestSubsystemProbe_ExternalStateComesFromSetSubsystemProbe(t *testing.T) {
	d := &Daemon{}
	probe := d.subsystemProbe(platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, subsystemSpec{})

	assert.False(t, probe(), "no probe set: not running")

	serving := true
	d.SetSubsystemProbe(platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, func() bool { return serving })
	assert.True(t, probe())
	serving = false
	assert.False(t, probe(), "the probe is read on every call")

	d.SetSubsystemProbe(platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, nil)
	assert.False(t, probe(), "a nil probe clears the state")
}

func TestRegisterConfiguredServices_RegistersOnlyEnabledSubsystems(t *testing.T) {
	config := testConfig("/tmp/test-svclife-register.sock")
	config.Services = map[string]ServiceConfig{
		"tpm":        {Enabled: true, Timeout: time.Second},
		"webservice": {Enabled: true, Timeout: time.Second},
		"dns":        {Enabled: false, Timeout: time.Second},
		"kms":        {Enabled: true, Timeout: time.Second},
	}
	d, err := New(config)
	require.NoError(t, err)

	d.registerConfiguredServices()

	d.service.mu.RLock()
	defer d.service.mu.RUnlock()
	require.Contains(t, d.service.services, "tpm")
	require.Contains(t, d.service.services, "webservice")
	assert.NotContains(t, d.service.services, "dns", "a disabled service is not registered")
	assert.NotContains(t, d.service.services, "kms", "a service with no subsystem spec is not registered")
	for _, name := range []string{"tpm", "webservice"} {
		_, owned := processOwned(d.service.services[name].service)
		assert.True(t, owned, name)
	}
}

func TestAutoStart_SkipsProcessOwnedServices(t *testing.T) {
	config := testConfig("/tmp/test-svclife-autostart.sock")
	config.Services = map[string]ServiceConfig{
		"tpm": {Enabled: true, AutoStart: true, Timeout: 5 * time.Second},
	}
	autoStarted := make(chan struct{}, 1)
	d, err := New(config, withAutoStartObserver(func() { autoStarted <- struct{}{} }))
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	<-autoStarted

	state := d.service.services["tpm"]
	require.NotNil(t, state)
	state.mu.RLock()
	lastError := state.lastError
	state.mu.RUnlock()
	assert.Empty(t, lastError, "auto-start must not record the refusal as a failure")
	assert.NotEqual(t, platformv1.ServiceStatus_SERVICE_STATUS_ERROR, state.observedStatus())

	require.NoError(t, d.Stop(ctx))
}

func TestShutdown_LeavesProcessOwnedServicesAlone(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	require.NoError(t, err)
	require.NoError(t, svc.RegisterService(newOwnedService("tpm", true)))
	controlled := newMockService("dns")
	require.NoError(t, svc.RegisterService(controlled))
	_, err = svc.StartService(context.Background(), &platformv1.StartServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS})
	require.NoError(t, err)

	resp, err := svc.Shutdown(context.Background(), &platformv1.ShutdownRequest{Graceful: true})
	require.NoError(t, err)

	assert.True(t, resp.GetStatus().GetSuccess(), "shutdown reported %v", resp.GetStatus().GetError())
	assert.Equal(t, int32(1), controlled.stopCount.Load(), "a registry-controlled service is still stopped")
}

// A registry-controlled service is driven for real: each verb changes the
// service's own state, and status reports that state.
func TestControllableService_VerbsChangeRealState(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	require.NoError(t, err)
	mock := newMockService("dns")
	require.NoError(t, svc.RegisterService(mock))
	ctx := context.Background()
	dns := platformv1.ServiceType_SERVICE_TYPE_DNS

	_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{Service: dns})
	require.NoError(t, err)
	assert.True(t, mock.IsRunning())
	assert.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, serviceStatusOf(t, svc, dns))

	_, err = svc.StopService(ctx, &platformv1.StopServiceRequest{Service: dns})
	require.NoError(t, err)
	assert.False(t, mock.IsRunning())
	assert.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, serviceStatusOf(t, svc, dns))

	_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{Service: dns})
	require.NoError(t, err)
	_, err = svc.RestartService(ctx, &platformv1.RestartServiceRequest{Service: dns})
	require.NoError(t, err)
	assert.True(t, mock.IsRunning())
	assert.Equal(t, int32(3), mock.startCount.Load())
	assert.Equal(t, int32(2), mock.stopCount.Load())

	// A service that stops on its own is reported stopped, whatever the
	// registry last recorded.
	mock.running.Store(false)
	assert.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, serviceStatusOf(t, svc, dns))
}

func serviceStatusOf(t *testing.T, svc *Service, svcType platformv1.ServiceType) platformv1.ServiceStatus {
	t.Helper()
	resp, err := svc.GetServiceStatus(context.Background(), &platformv1.GetServiceStatusRequest{Service: svcType})
	require.NoError(t, err)
	return resp.GetService().GetStatus()
}

// lifecycleTransport sends one lifecycle verb for the "tpm" service over one
// transport and reports the transport's own answer as a gRPC class, so every
// transport is held to the same class.
type lifecycleTransport func(t *testing.T, svc *Service, verb string) codes.Code

// grpcLifecycleOver serves svc's PlatformDaemon on lis and sends the verb
// through a real gRPC client.
func grpcLifecycleOver(t *testing.T, svc *Service, lis net.Listener, target string) platformv1.PlatformDaemonClient {
	t.Helper()
	server := grpc.NewServer()
	platformv1.RegisterPlatformDaemonServer(server, svc)
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		assert.NoError(t, <-served)
	})

	// Local credentials refuse any dial that is not loopback or a Unix socket.
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(local.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return platformv1.NewPlatformDaemonClient(conn)
}

func sendGRPCLifecycle(client platformv1.PlatformDaemonClient, verb string) error {
	ctx := context.Background()
	tpm := platformv1.ServiceType_SERVICE_TYPE_TPM
	var err error
	switch verb {
	case "start":
		_, err = client.StartService(ctx, &platformv1.StartServiceRequest{Service: tpm})
	case "stop":
		_, err = client.StopService(ctx, &platformv1.StopServiceRequest{Service: tpm})
	case "restart":
		_, err = client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: tpm})
	}
	return err
}

var lifecycleTransports = map[string]lifecycleTransport{
	"gRPC": func(t *testing.T, svc *Service, verb string) codes.Code {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		client := grpcLifecycleOver(t, svc, lis, lis.Addr().String())
		return status.Code(sendGRPCLifecycle(client, verb))
	},
	"Unix": func(t *testing.T, svc *Service, verb string) codes.Code {
		// A short directory keeps the socket path under the sun_path limit.
		dir, err := os.MkdirTemp("", "svclife")
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
		socket := filepath.Join(dir, "d.sock")
		lis, err := net.Listen("unix", socket)
		require.NoError(t, err)
		client := grpcLifecycleOver(t, svc, lis, "unix://"+socket)
		return status.Code(sendGRPCLifecycle(client, verb))
	},
	"REST": func(t *testing.T, svc *Service, verb string) codes.Code {
		server, err := NewRESTServer(DefaultConfig(), svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/services/tpm/"+verb, nil))
		assert.Contains(t, rec.Body.String(), "cannot be started or stopped at runtime")
		// 400 is how the platform REST mapper sends FailedPrecondition.
		if rec.Code == http.StatusBadRequest {
			return codes.FailedPrecondition
		}
		return codes.Unknown
	},
	"QUIC": func(t *testing.T, svc *Service, verb string) codes.Code {
		h := &QUICServiceHandler{logger: logging.DefaultLogger(), daemonService: svc}
		payload, err := quicwire.EncodePayload(QUICDaemonServiceRequest{Name: "tpm"})
		require.NoError(t, err)
		handlers := map[string]func(context.Context, *quicwire.Request) *quicwire.Response{
			"start":   h.handleDaemonStartService,
			"stop":    h.handleDaemonStopService,
			"restart": h.handleDaemonRestartService,
		}
		resp := handlers[verb](context.Background(), &quicwire.Request{Payload: payload})
		assert.Contains(t, string(resp.Payload), "cannot be started or stopped at runtime")
		// StatusInvalidRequest is the QUIC status FailedPrecondition maps to.
		if resp.Status == quicwire.StatusInvalidRequest {
			return codes.FailedPrecondition
		}
		return codes.Unknown
	},
	"MCP": func(t *testing.T, svc *Service, verb string) codes.Code {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{HealthService: svc, Logger: testLogger()})
		registry := mcp.NewToolRegistry(provider, logging.DefaultLogger())
		_, err := registry.ExecuteTool(context.Background(), "platform_daemon_"+verb+"_service",
			map[string]interface{}{"name": "tpm"})
		return status.Code(err)
	},
}

// A process-owned service refuses every lifecycle verb with the same class on
// every transport, and the refusal leaves it running.
func TestProcessOwnedService_RefusedOnEveryTransport(t *testing.T) {
	for transport, send := range lifecycleTransports {
		for _, verb := range []string{"start", "stop", "restart"} {
			t.Run(transport+"/"+verb, func(t *testing.T) {
				svc, err := NewService(DefaultConfig())
				require.NoError(t, err)
				require.NoError(t, svc.RegisterService(newOwnedService("tpm", true)))

				assert.Equal(t, codes.FailedPrecondition, send(t, svc, verb))

				resp, err := svc.GetServiceStatus(context.Background(),
					&platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
				require.NoError(t, err)
				assert.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, resp.GetService().GetStatus())
				assert.Equal(t, "0", resp.GetService().GetMetadata()["start_count"])
				assert.Equal(t, "0", resp.GetService().GetMetadata()["stop_count"])
			})
		}
	}
}
