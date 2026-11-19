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
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
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

// allowServiceRoutes mounts the service-control routes on s behind a scope
// guard over servicesTokens, as the daemon mounts them behind restGuard.
func allowServiceRoutes(t *testing.T, s *RESTServer) {
	t.Helper()
	require.NoError(t, s.SetServiceControlHandlers(restapi.NewScopeGuard(servicesTokens, nil, nil)))
}

// servicesRequest is httptest.NewRequest presenting a bearer that holds
// platform:read and platform:write.
func servicesRequest(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer writer")
	return req
}

// serviceTokenScopes maps a bearer token to the scopes it was granted; an
// unknown token is refused as unauthenticated.
type serviceTokenScopes map[string][]string

func (s serviceTokenScopes) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	scopes, ok := s[token]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unknown token")
	}
	return &platformtoken.AuthorizedContext{Subject: token, Scopes: scopes}, nil
}

// servicesTokens grants the service-control routes' catalog scopes: reader
// holds platform:read only, writer holds platform:read and platform:write.
var servicesTokens = serviceTokenScopes{
	"reader": {"platform:read"},
	"writer": {"platform:read", "platform:write"},
}

// connectServicesREST mounts the daemon's real REST router with the fake
// services registered and returns a PlatformDaemon client over the SDK REST
// transport (#1947), presenting a bearer that holds platform:write.
func connectServicesREST(t *testing.T, services ...*recordingManagedService) platformv1.PlatformDaemonClient {
	t.Helper()
	s := newTestRESTServerForPhase35(t)
	for _, svc := range services {
		require.NoError(t, s.service.RegisterService(svc))
	}
	return connectServicesRESTAs(t, s, "writer")
}

// connectServicesRESTAs mounts the service-control routes behind a scope
// guard over servicesTokens and returns a PlatformDaemon client over the SDK
// REST transport presenting token ("" sends no bearer).
func connectServicesRESTAs(t *testing.T, s *RESTServer, token string) platformv1.PlatformDaemonClient {
	t.Helper()
	require.NoError(t, s.SetServiceControlHandlers(restapi.NewScopeGuard(servicesTokens, nil, nil)))
	server := httptest.NewTLSServer(s.router)
	t.Cleanup(server.Close)

	opts := []platform.Option{
		platform.WithRESTAddr(server.URL),
		platform.WithTLSConfig(phase35ClientTLS(server)),
	}
	if token != "" {
		opts = append(opts, platform.WithBearerToken(token))
	}
	conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(opts...))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	a, ok := conn.(*sdkrest.Adapter)
	if !ok {
		t.Fatalf("Connect returned %T, want *rest.Adapter", conn)
	}
	return platformv1.NewPlatformDaemonClient(a.Connection())
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
	require.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, info.GetHealth())
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
	require.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED, st.GetService().GetHealth())
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
	client := connectServicesRESTAs(t, s, "writer")

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

// TestSDKREST_DaemonRestartOfAStoppedServiceStartsIt: a REST restart of a
// stopped service starts it with no Stop call, as before #1947 (ruling 939).
func TestSDKREST_DaemonRestartOfAStoppedServiceStartsIt(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	s := newTestRESTServerForPhase35(t)
	require.NoError(t, s.service.RegisterService(tpm))
	client := connectServicesRESTAs(t, s, "writer")

	tpmType := platformv1.ServiceType_SERVICE_TYPE_TPM
	_, err := client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: tpmType})
	require.NoError(t, err, "REST restart of a stopped service")
	starts, stops := tpm.calls()
	require.Equal(t, 1, starts, "a restart of a stopped service starts it")
	require.Equal(t, 0, stops, "a restart of a stopped service stops nothing")

	st, err := client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: tpmType})
	require.NoError(t, err)
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, st.GetService().GetStatus())
	require.Equal(t, "1", st.GetService().GetMetadata()["start_count"])
}

// serviceRPCs calls each of the five service-control RPCs on tpm and returns
// their errors, keyed by RPC name.
func serviceRPCs(ctx context.Context, client platformv1.PlatformDaemonClient) map[string]error {
	tpmType := platformv1.ServiceType_SERVICE_TYPE_TPM
	errs := map[string]error{}
	_, errs["ListServices"] = client.ListServices(ctx, &platformv1.ListServicesRequest{})
	_, errs["GetServiceStatus"] = client.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: tpmType})
	_, errs["StartService"] = client.StartService(ctx, &platformv1.StartServiceRequest{Service: tpmType})
	_, errs["StopService"] = client.StopService(ctx, &platformv1.StopServiceRequest{Service: tpmType})
	_, errs["RestartService"] = client.RestartService(ctx, &platformv1.RestartServiceRequest{Service: tpmType})
	return errs
}

// requireServicesRefused drives every service-control RPC as token and
// requires each to fail with want before reaching the backend.
func requireServicesRefused(t *testing.T, token string, want codes.Code) {
	t.Helper()
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	s := newTestRESTServerForPhase35(t)
	require.NoError(t, s.service.RegisterService(tpm))
	client := connectServicesRESTAs(t, s, token)

	for rpc, err := range serviceRPCs(ctx, client) {
		require.Equal(t, want, status.Code(err), "%s: %v", rpc, err)
	}
	starts, stops := tpm.calls()
	require.Equal(t, 0, starts, "a refused caller starts nothing")
	require.Equal(t, 0, stops, "a refused caller stops nothing")

	st, err := s.service.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	require.NoError(t, err)
	require.Equal(t, platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, st.GetService().GetStatus())
}

// TestSDKREST_DaemonServicesRefuseACallerWithNoCredential requires every
// service-control route to answer a caller with no credential 401
// (Unauthenticated) before reading state or driving the backend.
func TestSDKREST_DaemonServicesRefuseACallerWithNoCredential(t *testing.T) {
	requireServicesRefused(t, "", codes.Unauthenticated)
}

// TestSDKREST_DaemonServicesRefuseAnUnknownBearer requires a bearer the
// guard cannot verify to be refused as Unauthenticated on every route.
func TestSDKREST_DaemonServicesRefuseAnUnknownBearer(t *testing.T) {
	requireServicesRefused(t, "forged", codes.Unauthenticated)
}

// TestSDKREST_DaemonServicesReadScopeCannotDriveLifecycle requires
// platform:read to list and read services, and platform:write, as the gRPC
// catalog does, for start, stop and restart.
func TestSDKREST_DaemonServicesReadScopeCannotDriveLifecycle(t *testing.T) {
	ctx := context.Background()
	tpm := &recordingManagedService{name: "tpm"}
	s := newTestRESTServerForPhase35(t)
	require.NoError(t, s.service.RegisterService(tpm))
	client := connectServicesRESTAs(t, s, "reader")

	errs := serviceRPCs(ctx, client)
	require.NoError(t, errs["ListServices"])
	require.NoError(t, errs["GetServiceStatus"])
	for _, rpc := range []string{"StartService", "StopService", "RestartService"} {
		require.Equal(t, codes.PermissionDenied, status.Code(errs[rpc]), "%s: %v", rpc, errs[rpc])
	}
	starts, stops := tpm.calls()
	require.Equal(t, 0, starts)
	require.Equal(t, 0, stops)
}

// countingPeers admits every verified client certificate with every scope
// and counts how often it was asked.
type countingPeers struct{ calls atomic.Int32 }

func (p *countingPeers) AuthenticatePeer(context.Context, []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	p.calls.Add(1)
	return &platformtoken.AuthorizedContext{Subject: "peer", Scopes: []string{"*:*"}}, nil
}

// TestDaemonServicesREST_ABadBearerIsNotRescuedByAClientCertificate requires
// an invalid bearer to be refused even when the TLS handshake verified a
// client certificate: the guard never falls back to the certificate.
func TestDaemonServicesREST_ABadBearerIsNotRescuedByAClientCertificate(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	peers := &countingPeers{}
	require.NoError(t, s.SetServiceControlHandlers(restapi.NewScopeGuard(servicesTokens, peers, nil)))

	certRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
		return req
	}

	forged := certRequest()
	forged.Header.Set("Authorization", "Bearer forged")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, forged)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Zero(t, peers.calls.Load(), "a bad bearer never falls back to the certificate")

	rec = httptest.NewRecorder()
	s.router.ServeHTTP(rec, certRequest())
	require.Equal(t, http.StatusOK, rec.Code, "the verified certificate alone still admits")
	require.Equal(t, int32(1), peers.calls.Load())
}
