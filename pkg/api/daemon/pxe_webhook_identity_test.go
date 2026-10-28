// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	pxerest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The install-completion webhook (#238) takes the node's identity from the
// verified client certificate of its connection, never from the body. These
// tests drive every transport the call arrives on with the four identities a
// caller can present and assert the device state, not only the answer.

const (
	webhookNodeMAC  = "00:11:22:33:44:a1"
	webhookOtherMAC = "00:11:22:33:44:b2"
)

// webhookCert is a certificate with the given serial from the named issuer.
// Raw stands in for the DER encoding the fingerprint is taken over: two
// certificates from different issuers differ in it even when their serials
// are equal, as real DER does through the issuer and signature fields.
func webhookCert(serial int64, issuer string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "node"},
		Issuer:       pkix.Name{CommonName: issuer},
		Raw:          []byte(issuer + "/" + big.NewInt(serial).String()),
	}
}

var (
	webhookNodeCert  = webhookCert(4242, "platform CA")
	webhookOtherCert = webhookCert(7777, "platform CA")
)

// webhookFixture is a PXE service holding two installing nodes, each with its
// installer certificate bound (BindDeviceCertificate): the one whose
// certificate the tests present and a second one it must not be able to
// complete.
type webhookFixture struct {
	mock *mockPXEService
	svc  *PXEGRPCService
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	mock := newMockPXEService()
	ctx := context.Background()
	installing := map[string]*x509.Certificate{
		webhookNodeMAC:  webhookNodeCert,
		webhookOtherMAC: webhookOtherCert,
	}
	for mac, cert := range installing {
		device, err := mock.RegisterDevice(ctx, mac, "port-1")
		require.NoError(t, err)
		require.NoError(t, mock.UpdateDeviceState(ctx, device.ID, pxe.StateInstalling, "installer booted"))
		require.NoError(t, mock.BindDeviceCertificate(ctx, device.ID, pxe.CertificateFingerprintOf(cert)))
	}
	return &webhookFixture{mock: mock, svc: NewPXEGRPCService(logging.DefaultLogger(), mock)}
}

func (f *webhookFixture) state(mac string) pxe.ProvisioningState {
	return f.mock.devices["device-"+mac].State
}

// verifiedState is a connection whose client chain the TLS stack verified.
func verifiedState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}

// unverifiedState is a connection that sent the node's certificate but whose
// chain was never verified: PeerCertificates is attacker-controlled.
func unverifiedState() *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{webhookNodeCert}}
}

// webhookCaller sends one webhook request carrying the given connection state
// and returns the gRPC code of the answer (codes.OK on success).
type webhookCaller func(t *testing.T, f *webhookFixture, state *tls.ConnectionState, req *platformv1.PXEWebhookCompleteRequest) codes.Code

func callWithContext(build func(state *tls.ConnectionState) context.Context) webhookCaller {
	return func(t *testing.T, f *webhookFixture, state *tls.ConnectionState, req *platformv1.PXEWebhookCompleteRequest) codes.Code {
		_, err := f.svc.WebhookComplete(build(state), req)
		return status.Code(err)
	}
}

func grpcContext(state *tls.ConnectionState) context.Context {
	p := &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 40000}}
	if state != nil {
		p.AuthInfo = credentials.TLSInfo{State: *state}
	}
	return peer.NewContext(context.Background(), p)
}

func quicContext(state *tls.ConnectionState) context.Context {
	return apiquic.WithConnectionTLS(context.Background(), state)
}

func mcpContext(state *tls.ConnectionState) context.Context {
	return channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, state)
}

// callREST serves the request through the PXE router exactly as the daemon
// mounts the machine-facing route, with the connection state on req.TLS.
func callREST(t *testing.T, f *webhookFixture, state *tls.ConnectionState, req *platformv1.PXEWebhookCompleteRequest) codes.Code {
	t.Helper()
	logger := logging.DefaultLogger()
	router := pxerest.NewPXERouter(logger, f.svc, response.NewResponseWriter(logger, nil), true)
	root := mux.NewRouter()
	router.RegisterMachineFacingRoutes(root.PathPrefix("/api/v1").Subrouter())

	body := `{"macAddress":"` + req.GetMacAddress() + `","hostname":"node","success":` +
		map[bool]string{true: "true", false: "false"}[req.GetSuccess()] + `}`
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httpReq)

	return map[int]codes.Code{
		http.StatusOK:                 codes.OK,
		http.StatusUnauthorized:       codes.Unauthenticated,
		http.StatusForbidden:          codes.PermissionDenied,
		http.StatusBadRequest:         codes.InvalidArgument,
		http.StatusServiceUnavailable: codes.Unavailable,
	}[rec.Code]
}

func webhookTransports() map[string]webhookCaller {
	return map[string]webhookCaller{
		"REST": callREST,
		"gRPC": callWithContext(grpcContext),
		"QUIC": callWithContext(quicContext),
		"MCP":  callWithContext(mcpContext),
	}
}

// TestWebhookComplete_RefusesWithoutTheNodesVerifiedIdentity pins, on every
// TLS transport, that a caller without a verified certificate, with an
// unenrolled certificate, or naming another node's MAC in the body is refused
// and that no device changes state.
func TestWebhookComplete_RefusesWithoutTheNodesVerifiedIdentity(t *testing.T) {
	cases := map[string]struct {
		state *tls.ConnectionState
		mac   string
		want  codes.Code
	}{
		"no certificate":         {state: nil, mac: webhookNodeMAC, want: codes.Unauthenticated},
		"unverified certificate": {state: unverifiedState(), mac: webhookNodeMAC, want: codes.Unauthenticated},
		"unknown certificate":    {state: verifiedState(webhookCert(9999, "platform CA")), mac: webhookNodeMAC, want: codes.PermissionDenied},
		"another node's MAC":     {state: verifiedState(webhookNodeCert), mac: webhookOtherMAC, want: codes.PermissionDenied},
		// Codex review on #1100: a serial is unique only within its issuer, so
		// a certificate from another trusted issuer that reuses the node's
		// serial must not stand in for the node, with or without its MAC.
		"node's serial, other issuer":         {state: verifiedState(webhookCert(4242, "caller anchor")), mac: webhookNodeMAC, want: codes.PermissionDenied},
		"node's serial, other issuer, no MAC": {state: verifiedState(webhookCert(4242, "caller anchor")), mac: "", want: codes.PermissionDenied},
	}
	for transport, call := range webhookTransports() {
		for name, tc := range cases {
			t.Run(transport+"/"+name, func(t *testing.T) {
				f := newWebhookFixture(t)

				got := call(t, f, tc.state, &platformv1.PXEWebhookCompleteRequest{MacAddress: tc.mac, Success: true})

				assert.Equal(t, tc.want, got)
				assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
				assert.Equal(t, pxe.StateInstalling, f.state(webhookOtherMAC))
			})
		}
	}
}

// TestWebhookComplete_CompletesTheCertificatesNode pins, on every TLS
// transport, that the verified certificate's node is the one completed, with
// or without its MAC in the body, and that a failure report fails it.
func TestWebhookComplete_CompletesTheCertificatesNode(t *testing.T) {
	cases := map[string]struct {
		mac     string
		success bool
		want    pxe.ProvisioningState
	}{
		"matching MAC":     {mac: webhookNodeMAC, success: true, want: pxe.StateInstallComplete},
		"no MAC in body":   {mac: "", success: true, want: pxe.StateInstallComplete},
		"reported failure": {mac: webhookNodeMAC, success: false, want: pxe.StateFailed},
	}
	for transport, call := range webhookTransports() {
		for name, tc := range cases {
			t.Run(transport+"/"+name, func(t *testing.T) {
				f := newWebhookFixture(t)

				got := call(t, f, verifiedState(webhookNodeCert), &platformv1.PXEWebhookCompleteRequest{MacAddress: tc.mac, Success: tc.success})

				assert.Equal(t, codes.OK, got)
				assert.Equal(t, tc.want, f.state(webhookNodeMAC))
				assert.Equal(t, pxe.StateInstalling, f.state(webhookOtherMAC))
			})
		}
	}
}

// TestWebhookComplete_RefusesTransportsWithoutAPeerCertificate pins that the
// transports that never carry a client certificate — the Unix socket, MCP
// over stdio and the embedded in-process call — refuse the webhook outright,
// whatever the body says.
func TestWebhookComplete_RefusesTransportsWithoutAPeerCertificate(t *testing.T) {
	contexts := map[string]context.Context{
		"Unix": peer.NewContext(context.Background(), &peer.Peer{
			Addr: &net.UnixAddr{Name: "/run/platformd.sock", Net: "unix"},
		}),
		"MCP stdio": channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, nil),
		"embedded":  context.Background(),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			f := newWebhookFixture(t)

			_, err := f.svc.WebhookComplete(ctx, &platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})

			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "verified device certificate")
			assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
		})
	}
}

// TestWebhookComplete_ErrorPaths covers the refusals after authentication:
// a malformed body MAC, a certificate shared by two records, a failed lookup
// and a failed state update, none of which completes the node.
func TestWebhookComplete_ErrorPaths(t *testing.T) {
	t.Run("malformed MAC", func(t *testing.T) {
		f := newWebhookFixture(t)

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
			&platformv1.PXEWebhookCompleteRequest{MacAddress: "not-a-mac", Success: true})

		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
	})

	t.Run("certificate on two records", func(t *testing.T) {
		f := newWebhookFixture(t)
		require.NoError(t, f.mock.BindDeviceCertificate(context.Background(), "device-"+webhookOtherMAC, pxe.CertificateFingerprintOf(webhookNodeCert)))

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
			&platformv1.PXEWebhookCompleteRequest{Success: true})

		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
	})

	t.Run("lookup fails", func(t *testing.T) {
		f := newWebhookFixture(t)
		f.mock.listErr = pxe.ErrServiceNotRunning{}

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
			&platformv1.PXEWebhookCompleteRequest{Success: true})

		require.Error(t, err)
		assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
	})

	t.Run("state update fails", func(t *testing.T) {
		f := newWebhookFixture(t)
		f.mock.updateStateErr = pxe.ErrServiceNotRunning{}

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
			&platformv1.PXEWebhookCompleteRequest{Success: true})

		require.Error(t, err)
		assert.Equal(t, pxe.StateInstalling, f.state(webhookNodeMAC))
	})

	t.Run("no PXE service", func(t *testing.T) {
		svc := NewPXEGRPCService(logging.DefaultLogger(), nil)

		_, err := svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)), &platformv1.PXEWebhookCompleteRequest{Success: true})

		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

// newRealPXEService returns an initialized production PXE service
// (pxe.NewService) on a no-op VLAN integration, so a test is held to the
// transitions ValidTransitions allows rather than the permissive mock's.
func newRealPXEService(t *testing.T) pxe.Service {
	t.Helper()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)
	cfg, err := pxe.NewServiceConfig(plan)
	require.NoError(t, err)
	cfg.BridgeName = "br-test"
	// Initialize builds the iPXE server without opening listeners. The
	// server config still validates, so it gets hermetic directories, offline
	// firmware and one boot entry; nothing here touches the network. A
	// loopback BindHost is the server IP (ipxe.ServerConfig.GetServerIP), so
	// Initialize never auto-detects one from the host's interfaces.
	ipxeCfg := ipxe.DefaultServerConfig()
	ipxeCfg.BindHost = "127.0.0.1"
	ipxeCfg.LocalFilesDir = t.TempDir()
	ipxeCfg.InstallsDir = t.TempDir()
	ipxeCfg.FirmwareDir = t.TempDir()
	ipxeCfg.FirmwareOffline = true
	ipxeCfg.BootEntries = []ipxe.BootEntry{
		{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
	}
	cfg.IPXEConfig = ipxeCfg
	svc := pxe.NewService(pxe.WithVLANIntegration(pxe.NewNoopVLANIntegration(plan)))
	require.NoError(t, svc.Initialize(context.Background(), cfg))
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc
}

// TestWebhookComplete_RealServiceWorkflow drives one node through the whole
// provisioning lifecycle on the production state machine: the installer's
// certificate is bound while the node is installing, the webhook over that
// verified certificate completes the install, and the node then enrols. The
// binding has to exist before InstallComplete, because Enrolling and Enrolled
// come after it and never lead back (Codex review on #1100).
func TestWebhookComplete_RealServiceWorkflow(t *testing.T) {
	ctx := context.Background()
	pxeService := newRealPXEService(t)
	svc := NewPXEGRPCService(logging.DefaultLogger(), pxeService)

	reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: webhookNodeMAC, PortId: "port-1"})
	require.NoError(t, err)
	deviceID := reg.GetDevice().GetId()
	advance := func(state platformv1.ProvisioningState) {
		t.Helper()
		_, err := svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{DeviceId: deviceID, State: state, Reason: "workflow"})
		require.NoError(t, err)
	}
	advance(platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING)
	advance(platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING)

	_, err = svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "an unbound certificate must not complete the install")

	bound, err := svc.BindDeviceCertificate(ctx, &platformv1.BindPXEDeviceCertificateRequest{
		DeviceId: deviceID, CertificateFingerprint: pxe.CertificateFingerprintOf(webhookNodeCert),
	})
	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, bound.GetDevice().GetState())

	_, err = svc.WebhookComplete(grpcContext(verifiedState(webhookOtherCert)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "another certificate must not complete the install")

	_, err = svc.WebhookComplete(grpcContext(verifiedState(webhookNodeCert)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.NoError(t, err)
	device, err := pxeService.GetDevice(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, pxe.StateInstallComplete, device.State)

	_, err = svc.BindDeviceCertificate(ctx, &platformv1.BindPXEDeviceCertificateRequest{
		DeviceId: deviceID, CertificateFingerprint: pxe.CertificateFingerprintOf(webhookOtherCert),
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "the binding closes once the install completes")

	advance(platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLING)
	enrolled, err := svc.SetDeviceEnrolled(ctx, &platformv1.SetPXEDeviceEnrolledRequest{DeviceId: deviceID, CertificateSerial: "4242"})
	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLED, enrolled.GetDevice().GetState())
	assert.Equal(t, pxe.CertificateFingerprintOf(webhookNodeCert), enrolled.GetDevice().GetCertificateFingerprint())
}
