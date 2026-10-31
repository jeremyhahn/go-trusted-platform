package daemon

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// installerPeer is the production mTLS peer authenticator over the fixture's
// real PXE store, trusting the issuer of the fixture's install certificates.
func installerPeer(t *testing.T, f *webhookFixture) (mtlsPeerAuthenticator, *x509.CertPool) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.issuerA.cert)
	adapter, err := auth.NewMTLSAdapterFromRoots(logging.DefaultLogger(), pool)
	require.NoError(t, err)
	return newMTLSPeerAuthenticator(adapter, pxeInstallBindings{service: f.svc}), pool
}

// An installer certificate stays an installer's after its installation ends:
// every transition out of installing clears the device's binding, and the
// same still-valid certificate must not then become the operator (Codex
// 8652). Each case ends the installation, then presents the certificate to
// the production peer authenticator and the REST CA scope guard.
func TestInstallerCertificate_StaysAnInstallerAfterItsInstallationEnds(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, f *webhookFixture, deviceID string){
		"completed and enrolled": func(t *testing.T, f *webhookFixture, deviceID string) {
			got := callWithContext(grpcContext)(t, f, verifiedState(f.node),
				&platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
			require.Equal(t, codes.OK, got)
			require.NoError(t, f.backend.UpdateDeviceState(ctx, deviceID, pxe.StateEnrolling, "enrolling"))
			require.NoError(t, f.backend.SetDeviceEnrolled(ctx, deviceID, "0a"))
		},
		"quarantined": func(t *testing.T, f *webhookFixture, deviceID string) {
			require.NoError(t, f.backend.QuarantineDevice(ctx, deviceID, "operator quarantine"))
		},
		"failed and removed": func(t *testing.T, f *webhookFixture, deviceID string) {
			require.NoError(t, f.backend.UpdateDeviceState(ctx, deviceID, pxe.StateFailed, "install failed"))
			require.NoError(t, f.backend.RemoveDevice(ctx, deviceID))
		},
	}
	for name, endInstallation := range cases {
		t.Run(name, func(t *testing.T) {
			f := newWebhookFixture(t)
			device, err := f.backend.GetDeviceByMAC(ctx, webhookNodeMAC)
			require.NoError(t, err)

			endInstallation(t, f, device.ID)

			bound, err := f.backend.ListDevices(ctx, &pxe.DeviceFilter{InstallCertificateSHA256: pxe.CertificateSHA256(f.node.Raw)})
			require.NoError(t, err)
			require.Empty(t, bound, "the installation ended, so no device binds the certificate any more")

			peer, pool := installerPeer(t, f)
			chain := []*x509.Certificate{f.node, f.issuerA.cert}
			authCtx, err := peer.AuthenticatePeer(ctx, chain)
			require.NoError(t, err)
			assert.Equal(t, []string{installerScope}, authCtx.Scopes)
			assert.False(t, authCtx.HasScope("certs:generate"), "an installer certificate is never the operator")

			router := guardedCARouter(t, pool, pxeInstallBindings{service: f.svc})
			assert.Equal(t, http.StatusForbidden, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates", chain))
			assert.Equal(t, http.StatusForbidden, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates/01/renew", chain))
		})
	}
}

// A trusted certificate no installation ever bound is still the operator's.
func TestInstallerCertificate_OperatorCertificateKeepsEveryScope(t *testing.T) {
	f := newWebhookFixture(t)
	peer, pool := installerPeer(t, f)
	operator := f.issuerA.issue(t, webhookSerial+100)
	chain := []*x509.Certificate{operator, f.issuerA.cert}

	authCtx, err := peer.AuthenticatePeer(context.Background(), chain)
	require.NoError(t, err)
	assert.Equal(t, []string{mtlsOperatorScope}, authCtx.Scopes)
	assert.True(t, authCtx.HasScope("certs:generate"))

	router := guardedCARouter(t, pool, pxeInstallBindings{service: f.svc})
	assert.NotEqual(t, http.StatusForbidden, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates", chain))
	assert.NotEqual(t, http.StatusUnauthorized, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates", chain))
}

// pxeOperation is one PXE operation as each catalog names it. An empty name
// is an operation that catalog does not list.
type pxeOperation struct {
	grpcMethod string
	quicOpcode byte
	quicSub    []byte
	mcpTool    string
}

// operatorPXEOperations are the PXE operations that take pxe:write. The
// REST routes take the gRPC method's scope (pkg/webservice/v1/rest/pxe).
var operatorPXEOperations = map[string]pxeOperation{
	"UpdateState": {platformv1.PXEService_UpdateState_FullMethodName, quicwire.OpPXEUpdateState, nil, "pxe_update_state"},
	"Authorize":   {platformv1.PXEService_Authorize_FullMethodName, quicwire.OpPXEAuthorize, nil, "pxe_authorize_device"},
	"Quarantine":  {platformv1.PXEService_Quarantine_FullMethodName, quicwire.OpPXEQuarantine, nil, "pxe_quarantine_device"},
	"Retry":       {platformv1.PXEService_Retry_FullMethodName, quicwire.OpPXERetry, nil, "pxe_retry_device"},
	"RegisterDevice": {platformv1.PXEService_RegisterDevice_FullMethodName, quicwire.OpPXERegisterDevice, nil,
		"pxe_register_device"},
	"SetDeviceEnrolled": {platformv1.PXEService_SetDeviceEnrolled_FullMethodName, quicwire.OpProvisioningCategory,
		[]byte{quicwire.PXESubSetDeviceEnrolled}, "pxe_set_device_enrolled"},
	"StartService": {platformv1.PXEService_StartService_FullMethodName, quicwire.OpProvisioningCategory,
		[]byte{quicwire.PXESubStartService}, "pxe_start_service"},
	"StopService": {platformv1.PXEService_StopService_FullMethodName, quicwire.OpProvisioningCategory,
		[]byte{quicwire.PXESubStopService}, "pxe_stop_service"},
}

// webhookCompleteOperation is the installer callback in every catalog.
var webhookCompleteOperation = pxeOperation{
	platformv1.PXEService_WebhookComplete_FullMethodName, quicwire.OpProvisioningCategory,
	[]byte{quicwire.PXESubWebhookComplete}, "pxe_webhook_complete",
}

// authorizeEverywhere checks op against the gRPC, QUIC and MCP catalogs for
// the caller presenting leaf, and returns each catalog's verdict.
func authorizeEverywhere(t *testing.T, peer mtlsPeerAuthenticator, leaf *x509.Certificate, op pxeOperation) map[string]bool {
	t.Helper()
	authCtx, err := peer.AuthenticatePeer(context.Background(), []*x509.Certificate{leaf})
	require.NoError(t, err)

	quicPerm, preAuth, err := quic.LookupOperationPermission(op.quicOpcode, op.quicSub)
	require.NoError(t, err)
	require.False(t, preAuth)

	checker := mcp.NewAuthorizationChecker(nil, nil, mcp.WithPeerAuthenticator(peer))
	_, mcpErr := checker.AuthorizeTool(mcpContext(verifiedState(leaf)), op.mcpTool, "")

	return map[string]bool{
		"gRPC and REST": authCtx.RequireScope(grpccreds.ScopeForMethod(op.grpcMethod)) == nil,
		"QUIC":          authCtx.RequireScope(quicPerm.Scope()) == nil,
		"MCP":           mcpErr == nil,
	}
}

// An installer certificate holds pxe:complete and nothing else: every
// operator PXE operation is refused it in every catalog (Codex 8652), while
// the operator's certificate passes them all.
func TestInstallerCertificate_IsRefusedEveryOperatorPXEOperation(t *testing.T) {
	f := newWebhookFixture(t)
	peer, _ := installerPeer(t, f)
	operator := f.issuerA.issue(t, webhookSerial+100)

	for name, op := range operatorPXEOperations {
		for catalog, allowed := range authorizeEverywhere(t, peer, f.node, op) {
			assert.False(t, allowed, "%s on %s: an installer certificate holds no pxe:write", name, catalog)
		}
		for catalog, allowed := range authorizeEverywhere(t, peer, operator, op) {
			assert.True(t, allowed, "%s on %s: the operator certificate holds every scope", name, catalog)
		}
	}
	for catalog, allowed := range authorizeEverywhere(t, peer, f.node, webhookCompleteOperation) {
		assert.True(t, allowed, "WebhookComplete on %s takes pxe:complete, which the installer holds", catalog)
	}
}

// The scope admits the installer to the webhook, and the webhook then
// accepts its certificate only for the device the certificate is bound to.
func TestInstallerCertificate_CompletesOnlyItsOwnDevice(t *testing.T) {
	for transport, call := range webhookTransports() {
		t.Run(transport, func(t *testing.T) {
			f := newWebhookFixture(t)

			got := call(t, f, verifiedState(f.node), &platformv1.PXEWebhookCompleteRequest{MacAddress: webhookOtherMAC, Success: true})
			assert.Equal(t, codes.PermissionDenied, got, "the certificate is not bound to the other device")
			assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))

			got = call(t, f, verifiedState(f.node), &platformv1.PXEWebhookCompleteRequest{MacAddress: webhookNodeMAC, Success: true})
			assert.Equal(t, codes.OK, got)
			assert.Equal(t, pxe.StateInstallComplete, f.state(t, webhookNodeMAC))
		})
	}
}
