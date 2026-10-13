package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestBuildHandlerMap_AllServicesNil(t *testing.T) {
	registry := &ServiceRegistry{}
	m := buildHandlerMap(registry)

	if len(m) != 0 {
		t.Errorf("expected empty handler map for nil services, got %d entries", len(m))
	}
}

func TestBuildHandlerMap_DaemonOnly(t *testing.T) {
	registry := &ServiceRegistry{
		Daemon: &testDaemonServer{},
	}
	m := buildHandlerMap(registry)

	if len(m) == 0 {
		t.Fatal("expected handlers registered for Daemon service")
	}

	// Daemon should register exactly 14 unary methods.
	if len(m) != 13 {
		t.Errorf("expected 13 daemon handlers, got %d", len(m))
	}

	// Verify a few known methods are present.
	methods := []string{
		platformv1.PlatformDaemon_GetStatus_FullMethodName,
		platformv1.PlatformDaemon_GetHealth_FullMethodName,
		platformv1.PlatformDaemon_GetVersion_FullMethodName,
		platformv1.PlatformDaemon_Shutdown_FullMethodName,
		platformv1.PlatformDaemon_GetConfig_FullMethodName,
	}
	for _, method := range methods {
		if _, ok := m[method]; !ok {
			t.Errorf("expected handler for %q to be registered", method)
		}
	}
}

func TestBuildHandlerMap_FullRegistry(t *testing.T) {
	registry := fullTestRegistry()
	m := buildHandlerMap(registry)

	// All 20 services registered should yield 347 handlers (320 base +
	// 6 gateway load balancer VIP methods + 3 gateway perf methods +
	// 4 IPAM pool CRUD + 4 network zone CRUD - 2 retired tenant VLAN/bridge
	// methods, #708 + gateway.GetNAT64Status, #601 + ca.SignCSR, #691 + 6 device
	// attestation, template and profile-assignment methods, #250 +
	// CreateTemplate, #497 + attestation.PollDeviceVerdicts, #709).
	if len(m) < 300 {
		t.Errorf("expected at least 300 handlers for full registry, got %d", len(m))
	}

	if len(m) != 347 {
		t.Errorf("expected exactly 347 handlers for full registry, got %d", len(m))
	}
}

// signCSRServer records the SignCSR request the dispatcher hands it.
type signCSRServer struct {
	platformv1.UnimplementedCAServiceServer
	got *platformv1.SignCSRRequest
}

func (s *signCSRServer) SignCSR(_ context.Context, req *platformv1.SignCSRRequest) (*platformv1.IssueCertificateResponse, error) {
	s.got = req
	return &platformv1.IssueCertificateResponse{Certificate: &platformv1.Certificate{Serial: "01"}}, nil
}

func TestDispatch_CASignCSR(t *testing.T) {
	server := &signCSRServer{}
	handler, ok := buildHandlerMap(&ServiceRegistry{CA: server})[platformv1.CAService_SignCSR_FullMethodName]
	if !ok {
		t.Fatal("expected SignCSR handler to be registered")
	}

	req := &platformv1.SignCSRRequest{CsrPem: "csr", ValidDays: 30}
	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}
	if server.got != req {
		t.Errorf("SignCSR received %v, want the dispatched request", server.got)
	}
	if issued, isIssued := resp.(*platformv1.IssueCertificateResponse); !isIssued || issued.GetCertificate().GetSerial() != "01" {
		t.Errorf("response = %v, want the server's certificate", resp)
	}
}

// A CA server without SignCSR answers Unimplemented; dispatch must not mask
// that as an empty certificate.
func TestDispatch_CASignCSR_Unimplemented(t *testing.T) {
	handler := buildHandlerMap(&ServiceRegistry{CA: &platformv1.UnimplementedCAServiceServer{}})[platformv1.CAService_SignCSR_FullMethodName]
	if _, err := handler(context.Background(), &platformv1.SignCSRRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("handler error = %v, want Unimplemented", err)
	}
}

func TestBuildHandlerMap_PartialRegistry(t *testing.T) {
	daemonOnly := &ServiceRegistry{
		Daemon: &testDaemonServer{},
	}
	daemonCount := len(buildHandlerMap(daemonOnly))

	caOnly := &ServiceRegistry{
		CA: &platformv1.UnimplementedCAServiceServer{},
	}
	caCount := len(buildHandlerMap(caOnly))

	combined := &ServiceRegistry{
		Daemon: &testDaemonServer{},
		CA:     &platformv1.UnimplementedCAServiceServer{},
	}
	combinedCount := len(buildHandlerMap(combined))

	if combinedCount != daemonCount+caCount {
		t.Errorf("expected combined count %d = daemon(%d) + CA(%d), got %d",
			daemonCount+caCount, daemonCount, caCount, combinedCount)
	}
}

func TestDispatch_DaemonGetVersion(t *testing.T) {
	registry := testRegistry()
	m := buildHandlerMap(registry)

	handler, ok := m[platformv1.PlatformDaemon_GetVersion_FullMethodName]
	if !ok {
		t.Fatal("expected GetVersion handler to be registered")
	}

	req := &platformv1.GetVersionRequest{}
	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	versionResp, ok := resp.(*platformv1.GetVersionResponse)
	if !ok {
		t.Fatalf("expected *GetVersionResponse, got %T", resp)
	}

	if versionResp.Version != "1.0.0-test" {
		t.Errorf("expected Version = %q, got %q", "1.0.0-test", versionResp.Version)
	}
}

func TestDispatch_DaemonGetHealth(t *testing.T) {
	registry := testRegistry()
	m := buildHandlerMap(registry)

	handler, ok := m[platformv1.PlatformDaemon_GetHealth_FullMethodName]
	if !ok {
		t.Fatal("expected GetHealth handler to be registered")
	}

	req := &platformv1.GetHealthRequest{}
	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	healthResp, ok := resp.(*platformv1.GetHealthResponse)
	if !ok {
		t.Fatalf("expected *GetHealthResponse, got %T", resp)
	}

	if healthResp.Status != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("expected HEALTHY status, got %v", healthResp.Status)
	}
}

func TestDispatch_DaemonGetStatus(t *testing.T) {
	registry := testRegistry()
	m := buildHandlerMap(registry)

	handler, ok := m[platformv1.PlatformDaemon_GetStatus_FullMethodName]
	if !ok {
		t.Fatal("expected GetStatus handler to be registered")
	}

	req := &platformv1.GetStatusRequest{}
	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response from GetStatus")
	}
}

// fullTestRegistry returns a ServiceRegistry with all services populated
// using the UnimplementedXxxServer stubs from generated protobuf code.
func fullTestRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		Daemon:      &testDaemonServer{},
		CA:          &platformv1.UnimplementedCAServiceServer{},
		TPM:         &platformv1.UnimplementedTPMServiceServer{},
		VTPM:        &platformv1.UnimplementedVTPMServiceServer{},
		Device:      &platformv1.UnimplementedDeviceServiceServer{},
		IAM:         &platformv1.UnimplementedPlatformIAMServiceServer{},
		KMS:         &platformv1.UnimplementedKeyManagementServiceServer{},
		SDN:         &platformv1.UnimplementedSDNServiceServer{},
		Compute:     &platformv1.UnimplementedComputeServiceServer{},
		IDevID:      &platformv1.UnimplementedIDevIDServiceServer{},
		Attestation: &platformv1.UnimplementedAttestationServiceServer{},
		Tenant:      &platformv1.UnimplementedTenantServiceServer{},
		PXE:         &platformv1.UnimplementedPXEServiceServer{},
		DNS:         &platformv1.UnimplementedDNSServiceServer{},
		Gateway:     &platformv1.UnimplementedGatewayServiceServer{},
		Overlay:     &platformv1.UnimplementedOverlayServiceServer{},
		Registry:    &platformv1.UnimplementedRegistryServiceServer{},
		Cluster:     &platformv1.UnimplementedClusterServiceServer{},
		EAB:         &platformv1.UnimplementedEABServiceServer{},
		Invitation:  &platformv1.UnimplementedInvitationServiceServer{},
	}
}
