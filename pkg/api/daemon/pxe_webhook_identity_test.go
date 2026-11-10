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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	pxerest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	pxeclient "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/pxe"
)

// The install-completion webhook (#238) takes the node's identity from the
// verified client certificate of its connection, never from the body. The
// installer binds that certificate's SHA-256 when the node enters installing;
// these tests drive the real PXE state machine through that binding on every
// transport and assert the device state, not only the answer.

const (
	webhookNodeMAC  = "00:11:22:33:44:a1"
	webhookOtherMAC = "00:11:22:33:44:b2"
	webhookSerial   = 4242
)

// webhookIssuer is a CA the listener trusts for client certificates.
type webhookIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newWebhookIssuer(t *testing.T, name string) *webhookIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &webhookIssuer{cert: cert, key: key}
}

// issue signs a node installer certificate with the given serial: a client
// certificate carrying the tp-pxeInstaller marker the CA signs PXE_INSTALLER
// requests with.
func (i *webhookIssuer) issue(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	marker, err := issuance.InstallerMarkerExtension()
	require.NoError(t, err)
	cert, _ := i.issueWith(t, serial, marker)
	return cert
}

// issueInstallerTLS is issue's installer certificate with its private key, as
// a TLS client presents it.
func (i *webhookIssuer) issueInstallerTLS(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	marker, err := issuance.InstallerMarkerExtension()
	require.NoError(t, err)
	cert, key := i.issueWith(t, serial, marker)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

// The operator's certificate, which carries no installer marker, is
// issueOperator (mtls_installer_scope_test.go).

func (i *webhookIssuer) issueWith(t *testing.T, serial int64, extra ...pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "node", Organization: []string{"Test Platform Client"}},
		NotBefore:    i.cert.NotBefore,
		NotAfter:     i.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// An extended key usage extension here replaces the one ExtKeyUsage
		// would produce.
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// webhookFixture is the real PXE service holding two installing nodes, the
// one whose certificate the tests present and another, each bound to its own
// installer certificate from issuer A. Issuer B is a second trusted CA.
type webhookFixture struct {
	backend pxe.Service
	svc     *PXEGRPCService
	issuerA *webhookIssuer
	issuerB *webhookIssuer
	node    *x509.Certificate
	other   *x509.Certificate
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)
	cfg, err := pxe.NewServiceConfig(plan)
	require.NoError(t, err)
	cfg.BridgeName = "br-test"
	// The iPXE server is constructed but never started: no port is bound. A
	// loopback BindHost is the server IP (ipxe.ServerConfig.GetServerIP), so
	// Initialize never auto-detects one from the host's interfaces.
	cfg.IPXEConfig = ipxe.DefaultServerConfig()
	cfg.IPXEConfig.BindHost = "127.0.0.1"
	cfg.IPXEConfig.LocalFilesDir = t.TempDir()
	cfg.IPXEConfig.InstallsDir = t.TempDir()
	cfg.IPXEConfig.FirmwareDir = t.TempDir()
	cfg.IPXEConfig.FirmwareOffline = true
	cfg.IPXEConfig.BootEntries = []ipxe.BootEntry{
		{Name: "install", Description: "Install", Kernel: "http://example.com/kernel"},
	}
	backend := pxe.NewService(pxe.WithVLANIntegration(pxe.NewNoopVLANIntegration(plan)))
	require.NoError(t, backend.Initialize(context.Background(), cfg))

	f := &webhookFixture{
		backend: backend,
		svc:     NewPXEGRPCService(logging.DefaultLogger(), backend),
		issuerA: newWebhookIssuer(t, "issuer A"),
		issuerB: newWebhookIssuer(t, "issuer B"),
	}
	f.node = f.issuerA.issue(t, webhookSerial)
	f.other = f.issuerA.issue(t, webhookSerial+1)
	f.install(t, webhookNodeMAC, f.node)
	f.install(t, webhookOtherMAC, f.other)
	return f
}

// install registers a node, netboots it and binds its installer certificate
// through UpdateState, the call the installer makes on entering installing.
func (f *webhookFixture) install(t *testing.T, mac string, cert *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	device, err := f.backend.RegisterDevice(ctx, mac, "port-"+mac)
	require.NoError(t, err)
	require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "netboot"))
	_, err = f.svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId:                 device.ID,
		State:                    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
		InstallCertificateSha256: pxe.CertificateSHA256(cert.Raw),
	})
	require.NoError(t, err)
}

func (f *webhookFixture) state(t *testing.T, mac string) pxe.ProvisioningState {
	t.Helper()
	device, err := f.backend.GetDeviceByMAC(context.Background(), mac)
	require.NoError(t, err)
	return device.State
}

// verifiedState is a connection whose client chain the TLS stack verified.
func verifiedState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}

// unverifiedState is a connection that presented a certificate the TLS stack
// did not verify.
func unverifiedState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
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
		state func(f *webhookFixture) *tls.ConnectionState
		mac   string
		want  codes.Code
	}{
		"no certificate": {
			state: func(*webhookFixture) *tls.ConnectionState { return nil },
			mac:   webhookNodeMAC, want: codes.Unauthenticated,
		},
		"unverified certificate": {
			state: func(f *webhookFixture) *tls.ConnectionState { return unverifiedState(f.node) },
			mac:   webhookNodeMAC, want: codes.Unauthenticated,
		},
		"unbound certificate": {
			state: func(f *webhookFixture) *tls.ConnectionState { return verifiedState(f.issuerA.issue(t, 9999)) },
			mac:   webhookNodeMAC, want: codes.PermissionDenied,
		},
		"another node's MAC": {
			state: func(f *webhookFixture) *tls.ConnectionState { return verifiedState(f.node) },
			mac:   webhookOtherMAC, want: codes.PermissionDenied,
		},
		"no MAC in body": {
			state: func(f *webhookFixture) *tls.ConnectionState { return verifiedState(f.node) },
			mac:   "", want: codes.InvalidArgument,
		},
	}
	for transport, call := range webhookTransports() {
		for name, tc := range cases {
			t.Run(transport+"/"+name, func(t *testing.T) {
				f := newWebhookFixture(t)

				got := call(t, f, tc.state(f), &platformv1.PXEWebhookCompleteRequest{MacAddress: tc.mac, Success: true})

				assert.Equal(t, tc.want, got)
				assert.Equal(t, pxe.StateInstalling, f.state(t, webhookNodeMAC))
				assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))
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
		"reported failure": {mac: webhookNodeMAC, success: false, want: pxe.StateFailed},
	}
	for transport, call := range webhookTransports() {
		for name, tc := range cases {
			t.Run(transport+"/"+name, func(t *testing.T) {
				f := newWebhookFixture(t)

				got := call(t, f, verifiedState(f.node), &platformv1.PXEWebhookCompleteRequest{MacAddress: tc.mac, Success: tc.success})

				assert.Equal(t, codes.OK, got)
				assert.Equal(t, tc.want, f.state(t, webhookNodeMAC))
				assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))
			})
		}
	}
}

// TestWebhookComplete_FirstInstallReachesEnrollment walks a node through the
// real state machine in the documented order: the webhook completes the
// install before the node has enrolled, and enrollment follows it.
func TestWebhookComplete_FirstInstallReachesEnrollment(t *testing.T) {
	f := newWebhookFixture(t)
	ctx := context.Background()

	_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.NoError(t, err)

	device, err := f.backend.GetDeviceByMAC(ctx, webhookNodeMAC)
	require.NoError(t, err)
	assert.Empty(t, device.CertificateSerial, "the webhook must not need an enrolled certificate")
	require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, pxe.StateEnrolling, "enrolling"))
	require.NoError(t, f.backend.SetDeviceEnrolled(ctx, device.ID, "1001"))
	assert.Equal(t, pxe.StateEnrolled, f.state(t, webhookNodeMAC))

	_, err = f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "a replayed webhook must not move an enrolled node")
	assert.Equal(t, pxe.StateEnrolled, f.state(t, webhookNodeMAC))
}

// The installer certificate authorizes only the installation it was bound
// to: once the device has moved on, neither a success nor a failure callback
// moves it, so a replayed failure cannot fail or quarantine a provisioned node.
func TestWebhookComplete_RefusesCallbacksAfterTheInstallationEnded(t *testing.T) {
	ctx := context.Background()
	stages := []struct {
		name  string
		state pxe.ProvisioningState
		reach []pxe.ProvisioningState
	}{
		{"enrolled", pxe.StateEnrolled, []pxe.ProvisioningState{pxe.StateEnrolling, pxe.StateEnrolled}},
		{"authorized", pxe.StateAuthorized, []pxe.ProvisioningState{pxe.StateEnrolling, pxe.StateEnrolled, pxe.StateAuthorizing, pxe.StateAuthorized}},
		{"install failed", pxe.StateFailed, nil},
	}
	for _, stage := range stages {
		for _, success := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/success=%t", stage.name, success), func(t *testing.T) {
				f := newWebhookFixture(t)
				_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
					&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: stage.reach != nil})
				require.NoError(t, err)
				device, err := f.backend.GetDeviceByMAC(ctx, webhookNodeMAC)
				require.NoError(t, err)
				assert.Empty(t, device.InstallCertificateSHA256, "ending the installation must clear the binding")
				for _, next := range stage.reach {
					require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, next, "provisioning"))
				}
				require.Equal(t, stage.state, f.state(t, webhookNodeMAC))

				_, err = f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
					&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: success})

				assert.Equal(t, codes.PermissionDenied, status.Code(err))
				assert.Equal(t, stage.state, f.state(t, webhookNodeMAC))
			})
		}
	}
}

// A certificate released by one installation may be bound to another device.
// A callback resent for the first installation must not end the second one:
// the body must name its device, and the certificate must be bound to that
// device's open installation (Codex review 7971).
func TestWebhookComplete_RefusesACallbackAfterItsCertificateIsRebound(t *testing.T) {
	// The first device's installer keeps its key after its installation ends,
	// so its certificate is never bound to another device: otherwise its
	// callback naming that device's MAC would end that installation (Codex 8144).
	ctx := context.Background()
	f := newWebhookFixture(t)
	fingerprint := pxe.CertificateSHA256(f.node.Raw)
	_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.NoError(t, err)

	const otherMAC = "00:11:22:33:44:c5"
	other, err := f.backend.RegisterDevice(ctx, otherMAC, "port-"+otherMAC)
	require.NoError(t, err)
	require.NoError(t, f.backend.UpdateDeviceState(ctx, other.ID, pxe.StateBooting, "netboot"))
	_, err = f.svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId:                 other.ID,
		State:                    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
		InstallCertificateSha256: fingerprint,
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, pxe.ErrInstallCertificateReused{DeviceID: other.ID, CertificateSHA256: fingerprint}.Error(),
		status.Convert(err).Message())

	for _, mac := range []string{otherMAC, webhookNodeMAC} {
		for _, success := range []bool{false, true} {
			t.Run(fmt.Sprintf("mac=%s/success=%t", mac, success), func(t *testing.T) {
				_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
					&platformv1.PXEWebhookCompleteRequest{MacAddress: mac, Success: success})

				assert.Equal(t, codes.PermissionDenied, status.Code(err))
				device, err := f.backend.GetDevice(ctx, other.ID)
				require.NoError(t, err)
				assert.Equal(t, pxe.StateBooting, device.State)
				assert.Empty(t, device.InstallCertificateSHA256)
				assert.Equal(t, pxe.StateInstallComplete, f.state(t, webhookNodeMAC))
			})
		}
	}
}

// A retried installation needs a fresh installer certificate: the first
// attempt's certificate cannot be bound again, and a late callback from the
// first attempt, with its certificate and the same MAC, cannot end the second
// (Codex review 7979).
func TestWebhookComplete_RefusesTheFailedAttemptsCallbackAfterARetry(t *testing.T) {
	ctx := context.Background()
	f := newWebhookFixture(t)
	first := pxe.CertificateSHA256(f.node.Raw)
	_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: false})
	require.NoError(t, err)
	device, err := f.backend.GetDeviceByMAC(ctx, webhookNodeMAC)
	require.NoError(t, err)
	require.NoError(t, f.backend.RetryDevice(ctx, device.ID))
	require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "netboot"))

	installing := func(fingerprint string) error {
		_, err := f.svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
			DeviceId:                 device.ID,
			State:                    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
			InstallCertificateSha256: fingerprint,
		})
		return err
	}
	err = installing(first)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, pxe.ErrInstallCertificateReused{DeviceID: device.ID, CertificateSHA256: first}.Error(),
		status.Convert(err).Message())
	assert.Equal(t, pxe.StateBooting, f.state(t, webhookNodeMAC))

	retry := f.issuerA.issue(t, webhookSerial+2)
	second := pxe.CertificateSHA256(retry.Raw)
	require.NoError(t, installing(second))

	for _, success := range []bool{false, true} {
		t.Run(fmt.Sprintf("first attempt resent/success=%t", success), func(t *testing.T) {
			_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
				&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: success})

			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Equal(t, ErrPXEWebhookUnknownIdentity{CertificateSHA256: first}.Error(), status.Convert(err).Message())
			current, err := f.backend.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, pxe.StateInstalling, current.State)
			assert.Equal(t, second, current.InstallCertificateSHA256)
		})
	}

	_, err = f.svc.WebhookComplete(grpcContext(verifiedState(retry)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
	require.NoError(t, err, "the second attempt's own callback still ends it")
	assert.Equal(t, pxe.StateInstallComplete, f.state(t, webhookNodeMAC))
}

// A device moved out of installing by another path, here a quarantine, loses
// its binding with the move, so the installer cannot complete it afterwards.
func TestWebhookComplete_RefusesAfterQuarantineDuringInstall(t *testing.T) {
	f := newWebhookFixture(t)
	ctx := context.Background()
	device, err := f.backend.GetDeviceByMAC(ctx, webhookNodeMAC)
	require.NoError(t, err)
	require.NoError(t, f.backend.QuarantineDevice(ctx, device.ID, "operator"))

	_, err = f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: false})

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, pxe.StateQuarantined, f.state(t, webhookNodeMAC))
}

// pxeConnAdapter presents one SDK transport connection as the
// transport.Adapter the public PXE service client is built on.
type pxeConnAdapter struct{ conn grpc.ClientConnInterface }

func (a pxeConnAdapter) Connection() grpc.ClientConnInterface { return a.conn }
func (a pxeConnAdapter) Close() error                         { return nil }
func (a pxeConnAdapter) IsConnected() bool                    { return true }
func (a pxeConnAdapter) Target() string                       { return "pxe-test" }

// testWebhookCompleteThroughSDKClient proves the public PXE service client
// binds the installer certificate as it moves the device to installing over
// one SDK transport, and that the binding is what lets the installer's webhook
// complete the installation. Each transport's _sdk_test.go file calls it.
func testWebhookCompleteThroughSDKClient(t *testing.T, connect pxeSDKConnect) {
	t.Run("completes", func(t *testing.T) {
		f := newWebhookFixture(t)
		ctx := context.Background()
		device, err := f.backend.RegisterDevice(ctx, "00:11:22:33:44:c4", "port-c4")
		require.NoError(t, err)
		require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "netboot"))
		installer := f.issuerB.issue(t, webhookSerial+2)

		client, err := pxeclient.NewClient(pxeConnAdapter{conn: connect(t, f.svc, "pxe:write")})
		require.NoError(t, err)
		installing, err := client.SetDeviceInstalling(ctx, device.ID, pxe.CertificateSHA256(installer.Raw), "installer booted")
		require.NoError(t, err)
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, installing.GetState())
		assert.Equal(t, pxe.CertificateSHA256(installer.Raw), installing.GetInstallCertificateSha256())

		_, err = f.svc.WebhookComplete(grpcContext(verifiedState(installer)),
			&platformv1.PXEWebhookCompleteRequest{MacAddress: "00:11:22:33:44:c4", Success: true})
		require.NoError(t, err)
		assert.Equal(t, pxe.StateInstallComplete, f.state(t, "00:11:22:33:44:c4"))
	})

	t.Run("refusal", func(t *testing.T) {
		f := newWebhookFixture(t)
		client, err := pxeclient.NewClient(pxeConnAdapter{conn: connect(t, f.svc, "pxe:write")})
		require.NoError(t, err)

		_, err = client.SetDeviceInstalling(context.Background(), "nonexistent", pxe.CertificateSHA256(f.node.Raw), "installer booted")

		var failed *pxeclient.ErrSetInstallingFailed
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, "nonexistent", failed.ID)
		assert.Equal(t, codes.NotFound, status.Code(failed.Cause))
	})
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
			assert.Equal(t, pxe.StateInstalling, f.state(t, webhookNodeMAC))
		})
	}
}

// TestWebhookComplete_ErrorPaths covers the refusals after authentication:
// a malformed body MAC, a certificate shared by two records, a failed lookup
// and a failed state update, none of which completes the node.
func TestWebhookComplete_ErrorPaths(t *testing.T) {
	t.Run("malformed MAC", func(t *testing.T) {
		f := newWebhookFixture(t)

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
			&platformv1.PXEWebhookCompleteRequest{MacAddress: "not-a-mac", Success: true})

		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Equal(t, pxe.StateInstalling, f.state(t, webhookNodeMAC))
	})

	// A certificate is bound to one device at a time (Codex review 7952): a
	// second device cannot take the node's binding, so the webhook still
	// resolves the node's certificate to exactly one record.
	t.Run("certificate on two records", func(t *testing.T) {
		f := newWebhookFixture(t)
		ctx := context.Background()
		const otherMAC = "00:11:22:33:44:c3"
		other, err := f.backend.RegisterDevice(ctx, otherMAC, "port-"+otherMAC)
		require.NoError(t, err)
		require.NoError(t, f.backend.UpdateDeviceState(ctx, other.ID, pxe.StateBooting, "netboot"))

		_, err = f.svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
			DeviceId:                 other.ID,
			State:                    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
			InstallCertificateSha256: pxe.CertificateSHA256(f.node.Raw),
		})
		assert.Equal(t, codes.AlreadyExists, status.Code(err))
		assert.Equal(t, pxe.StateBooting, f.state(t, otherMAC))

		_, err = f.svc.WebhookComplete(grpcContext(verifiedState(f.node)),
			&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
		require.NoError(t, err)
		assert.Equal(t, pxe.StateInstallComplete, f.state(t, webhookNodeMAC))
		assert.Equal(t, pxe.StateBooting, f.state(t, otherMAC))
	})

	t.Run("certificate without DER", func(t *testing.T) {
		f := newWebhookFixture(t)

		_, err := f.svc.WebhookComplete(grpcContext(verifiedState(&x509.Certificate{})),
			&platformv1.PXEWebhookCompleteRequest{Success: true})

		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Equal(t, pxe.StateInstalling, f.state(t, webhookNodeMAC))
	})

	// The two failures below cannot be provoked on the real service, so a
	// mock holding one bound node stands in for it.
	mockFixture := func(t *testing.T) (*mockPXEService, *PXEGRPCService, *x509.Certificate) {
		t.Helper()
		cert := newWebhookIssuer(t, "issuer A").issue(t, webhookSerial)
		mock := newMockPXEService()
		device, err := mock.RegisterDevice(context.Background(), webhookNodeMAC, "port-1")
		require.NoError(t, err)
		require.NoError(t, mock.SetDeviceInstalling(context.Background(), device.ID, pxe.CertificateSHA256(cert.Raw), "installing"))
		return mock, NewPXEGRPCService(logging.DefaultLogger(), mock), cert
	}

	t.Run("lookup fails", func(t *testing.T) {
		mock, svc, cert := mockFixture(t)
		mock.listErr = pxe.ErrServiceNotRunning{}

		_, err := svc.WebhookComplete(grpcContext(verifiedState(cert)), &platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})

		require.Error(t, err)
		assert.Equal(t, pxe.StateInstalling, mock.devices["device-"+webhookNodeMAC].State)
	})

	t.Run("state update fails", func(t *testing.T) {
		mock, svc, cert := mockFixture(t)
		mock.updateStateErr = pxe.ErrServiceNotRunning{}

		_, err := svc.WebhookComplete(grpcContext(verifiedState(cert)), &platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})

		require.Error(t, err)
		assert.Equal(t, pxe.StateInstalling, mock.devices["device-"+webhookNodeMAC].State)
	})

	t.Run("no PXE service", func(t *testing.T) {
		svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
		cert := newWebhookIssuer(t, "issuer A").issue(t, webhookSerial)

		_, err := svc.WebhookComplete(grpcContext(verifiedState(cert)), &platformv1.PXEWebhookCompleteRequest{Success: true})

		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}
