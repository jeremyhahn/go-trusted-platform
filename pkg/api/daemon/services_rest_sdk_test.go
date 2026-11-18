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
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingManagedService is the fake backend behind the daemon's service
// routes: it records every Start and Stop the handler drives into it.
type recordingManagedService struct {
	name string

	mu      sync.Mutex
	running bool
	starts  int
	stops   int
}

func (f *recordingManagedService) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.running = true
	return nil
}

func (f *recordingManagedService) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	f.running = false
	return nil
}

func (f *recordingManagedService) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *recordingManagedService) Name() string { return f.name }

func (f *recordingManagedService) calls() (starts, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops
}

// connectServicesREST mounts the daemon's real REST router with the fake
// services registered and returns a PlatformDaemon client over the SDK REST
// transport (#1947).
func connectServicesREST(t *testing.T, services ...*recordingManagedService) platformv1.PlatformDaemonClient {
	t.Helper()
	s := newTestRESTServerForPhase35(t)
	for _, svc := range services {
		require.NoError(t, s.service.RegisterService(svc))
	}
	return platformv1.NewPlatformDaemonClient(connectPhase35REST(t, s.router).Connection())
}

// TestSDKREST_DaemonServicesRoundTrip drives ListServices, GetServiceStatus,
// StartService, StopService and RestartService through the SDK REST adapter
// into the daemon's handler and requires the backend to receive the verb on
// the named service and the decoded replies to carry what the handler wrote.
func TestSDKREST_DaemonServicesRoundTrip(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	dns := &recordingManagedService{name: "dns"}
	client := connectServicesREST(t, tpm, dns)

	list, err := client.ListServices(ctx, &platformv1.ListServicesRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetServices(), 2)
	got := list.GetServices()
	sort.Slice(got, func(i, j int) bool { return got[i].GetName() < got[j].GetName() })
	require.Equal(t, "dns", got[0].GetName())
	require.Equal(t, platformv1.ServiceType_SERVICE_TYPE_DNS, got[0].GetType())
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, got[0].GetStatus())
	require.Equal(t, "tpm", got[1].GetName())
	require.Equal(t, platformv1.ServiceType_SERVICE_TYPE_TPM, got[1].GetType())
	require.Nil(t, got[1].GetStartedAt(), "a service never started carries no started_at")

	start, err := client.StartService(ctx, &platformv1.StartServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	require.True(t, start.GetStatus().GetSuccess())
	require.Equal(t, "service started successfully", start.GetStatus().GetMessage())
	require.Equal(t, platformv1.ServiceType_SERVICE_TYPE_TPM, start.GetService().GetType())
	require.Equal(t, "tpm", start.GetService().GetName())
	starts, stops := tpm.calls()
	require.Equal(t, 1, starts)
	require.Equal(t, 0, stops)
	dnsStarts, dnsStops := dns.calls()
	require.Zero(t, dnsStarts+dnsStops, "the verb reaches only the named service")

	st, err := client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	info := st.GetService()
	require.Equal(t, platformv1.ServiceType_SERVICE_TYPE_TPM, info.GetType())
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, info.GetStatus())
	require.NotNil(t, info.GetStartedAt())
	require.Equal(t, "1", info.GetMetadata()["start_count"])
	require.Equal(t, "0", info.GetMetadata()["stop_count"])

	restart, err := client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	require.True(t, restart.GetStatus().GetSuccess())
	require.Equal(t, "tpm", restart.GetService().GetName())
	starts, stops = tpm.calls()
	require.Equal(t, 2, starts)
	require.Equal(t, 1, stops)

	stop, err := client.StopService(ctx, &platformv1.StopServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	require.True(t, stop.GetStatus().GetSuccess())
	require.Equal(t, "service stopped successfully", stop.GetStatus().GetMessage())
	starts, stops = tpm.calls()
	require.Equal(t, 2, starts)
	require.Equal(t, 2, stops)

	st, err = client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, st.GetService().GetStatus())
	require.Equal(t, "2", st.GetService().GetMetadata()["start_count"])
	require.Equal(t, "2", st.GetService().GetMetadata()["stop_count"])
}

// TestSDKREST_DaemonServicesRefuse requires the handler's refusals to reach
// the caller as gRPC codes, and the SDK to refuse a request field the daemon
// route does not honour before the backend is reached.
func TestSDKREST_DaemonServicesRefuse(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	client := connectServicesREST(t, tpm)

	_, err := client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS})
	require.Equal(t, codes.NotFound, status.Code(err), "an unregistered service: %v", err)

	_, err = client.StopService(ctx, &platformv1.StopServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "stopping a stopped service, as gRPC answers: %v", err)

	_, err = client.StopService(ctx, &platformv1.StopServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM, Force: true})
	require.Error(t, err)

	_, err = client.StartService(ctx, &platformv1.StartServiceRequest{
		Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		Options: map[string]string{"mode": "fast"},
	})
	require.Error(t, err, "the daemon route ignores options, so the SDK refuses them")

	starts, stops := tpm.calls()
	require.Zero(t, starts+stops, "no refused request reaches the backend")
}

// TestSDKREST_DaemonServicesConflictCodes pins the gRPC class of each 409 the
// daemon's service routes answer: the SDK REST transport reads them back as
// the gRPC service returns them, not as the default POST 409, AlreadyExists.
func TestSDKREST_DaemonServicesConflictCodes(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	s := newTestRESTServerForPhase35(t)
	require.NoError(t, s.service.RegisterService(tpm))
	require.NoError(t, s.service.RegisterService(newOwnedService("compute", true)))
	client := platformv1.NewPlatformDaemonClient(connectPhase35REST(t, s.router).Connection())

	tpmType := platformv1.ServiceType_SERVICE_TYPE_TPM
	_, err := client.StopService(ctx, &platformv1.StopServiceRequest{Service: tpmType})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "stop of a stopped service: %v", err)

	_, err = client.StartService(ctx, &platformv1.StartServiceRequest{Service: tpmType})
	require.NoError(t, err)
	_, err = client.StartService(ctx, &platformv1.StartServiceRequest{Service: tpmType})
	require.Equal(t, codes.AlreadyExists, status.Code(err), "start of a running service: %v", err)

	owned := platformv1.ServiceType_SERVICE_TYPE_COMPUTE
	_, err = client.StartService(ctx, &platformv1.StartServiceRequest{Service: owned})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "start of a process-owned service: %v", err)
	_, err = client.StopService(ctx, &platformv1.StopServiceRequest{Service: owned})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "stop of a process-owned service: %v", err)
	_, err = client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: owned})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "restart of a process-owned service: %v", err)
}

// TestSDKREST_DaemonRestartOfAStoppedServiceIsRefused pins transport parity
// for a restart of a stopped service: gRPC RestartService is StopService then
// StartService, so a stopped service is refused with FailedPrecondition and
// nothing is started. The REST route answers the same, with no backend call.
func TestSDKREST_DaemonRestartOfAStoppedServiceIsRefused(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	s := newTestRESTServerForPhase35(t)
	require.NoError(t, s.service.RegisterService(tpm))
	client := platformv1.NewPlatformDaemonClient(connectPhase35REST(t, s.router).Connection())

	tpmType := platformv1.ServiceType_SERVICE_TYPE_TPM
	_, err := client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: tpmType})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "REST restart of a stopped service: %v", err)
	starts, stops := tpm.calls()
	require.Equal(t, 0, starts, "a refused restart starts nothing")
	require.Equal(t, 0, stops, "a refused restart stops nothing")

	st, err := client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: tpmType})
	require.NoError(t, err)
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, st.GetService().GetStatus())
	require.Equal(t, "0", st.GetService().GetMetadata()["start_count"])

	_, err = s.service.RestartService(ctx, &platformv1.RestartServiceRequest{Service: tpmType})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "gRPC restart of a stopped service: %v", err)
	starts, stops = tpm.calls()
	require.Equal(t, 0, starts)
	require.Equal(t, 0, stops)
}
