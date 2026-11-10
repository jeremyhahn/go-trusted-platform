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
	"errors"
	"net/url"
	"os"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Transport names used in fail-closed authentication errors.
const (
	transportGRPCTCP = "grpc"
	transportQUIC    = "quic"
	transportREST    = "rest"
	transportMCP     = "mcp"

	// transportIAMToken names the IAM VerifyToken verifier, which every
	// transport shares.
	transportIAMToken = "iam-token"
)

// grpcAuthSelection is the authentication the gRPC TCP transport resolved to.
// A selection with nil interceptors and required=false is only ever produced
// under SkipIAMValidation, the testing-only opt-out; every other path either
// yields interceptors that require a credential or a typed error.
type grpcAuthSelection struct {
	unary     grpc.UnaryServerInterceptor
	stream    grpc.StreamServerInterceptor
	validator *grpcTokenValidator
	required  bool
}

// options renders the selection as gRPC server options.
func (s grpcAuthSelection) options() []grpc.ServerOption {
	if s.unary == nil || s.stream == nil {
		return nil
	}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(s.unary),
		grpc.ChainStreamInterceptor(s.stream),
	}
}

// selectGRPCTCPAuth decides how the gRPC TCP transport authenticates callers.
//
// Before #550 the OIDC interceptors were installed with
// WithRequireAuth(tokenValidator != nil): whenever no validator could be built
// the interceptor was present but inert and the whole daemon API was served
// anonymously. The interceptor now always requires a credential, and a
// configuration under which no backend exists refuses the transport with
// ErrTransportAuthRequired instead. SkipIAMValidation remains the explicit,
// testing-only opt-out, mirroring the MCP precedent (#440).
//
// The local validator's tokens carry no scope claims, so each method's catalog
// permission is decided by the IAM policy enforcement point (pep): without one
// the transport is refused rather than letting any valid token reach every
// method, Shutdown and BMC power included (#768).
// grpcTCPSkipMethods are the gRPC methods the TCP transport serves without a
// credential, under both the mTLS and the OIDC interceptor. The unary health
// probe and the status-only Liveness and Readiness probes are here, but not
// PlatformDaemon/GetHealth: it names every component with its failure
// message, so it needs a credential like the REST /api/v1/platform/health
// route (#768). The diskless boot calls are here
// because a diskless node holds no platform token and, for BootCertificate,
// no certificate yet; the boot service authenticates both itself, verifying
// the node's proof or its chain and quote, bound to the connection. The OIDC
// interceptor adds its own documented pre-auth list (method_permissions.go)
// and refuses every method absent from its scope catalog.
var grpcTCPSkipMethods = []string{
	"/grpc.health.v1.Health/Check",
	platformv1.PlatformDaemon_Liveness_FullMethodName,
	platformv1.PlatformDaemon_Readiness_FullMethodName,
	platformv1.DeviceService_BootCertificate_FullMethodName,
	platformv1.DeviceService_BootDelivery_FullMethodName,
}

func selectGRPCTCPAuth(config *Config, shared *platformTokenValidator, pep quicbaassdk.IAMPEPClient, installs installCertificateBindings, logger *logging.Logger, skipMethods []string) (grpcAuthSelection, error) {
	if config.EnableMTLS {
		if config.CAService == nil {
			return grpcAuthSelection{}, ErrTransportAuthRequired{
				Transport: transportGRPCTCP,
				Reason:    "mTLS is enabled but no CA service is available to verify client certificates",
			}
		}
		var mtlsOpts []auth.MTLSOption
		if config.MTLSClientCAPool != nil {
			mtlsOpts = append(mtlsOpts, auth.WithTrustedRoots(config.MTLSClientCAPool))
		}
		mtlsAuth, err := auth.NewMTLSAdapter(logger, config.CAService, mtlsOpts...)
		if err != nil {
			return grpcAuthSelection{}, ErrTLSConfigFailed{Reason: "gRPC mTLS auth: " + err.Error()}
		}
		interceptorCfg := &MTLSInterceptorConfig{
			Authenticator:       mtlsAuth,
			Peers:               newMTLSPeerAuthenticator(mtlsAuth, installs, config.MTLSOperatorTrustDomain),
			Logger:              logger,
			SkipMethods:         skipMethods,
			OperatorTrustDomain: config.MTLSOperatorTrustDomain,
		}
		logger.Info("gRPC TCP server: mTLS authentication enabled")
		return grpcAuthSelection{
			unary:    MTLSUnaryInterceptor(interceptorCfg),
			stream:   MTLSStreamInterceptor(interceptorCfg),
			required: true,
		}, nil
	}

	if config.SkipIAMValidation {
		logger.Warn("gRPC TCP server: authentication DISABLED by SkipIAMValidation (testing only)")
		return grpcAuthSelection{}, nil
	}

	var local *grpcTokenValidator
	opts := []grpccreds.OIDCInterceptorOption{
		grpccreds.WithSkipMethods(skipMethods...),
		grpccreds.WithRequireAuth(true),
	}
	if shared != nil {
		// Preferred path: validate broker platform tokens and project
		// scp -> RBAC / tenant_id -> RLS into the request context.
		opts = append(opts, grpccreds.WithTokenValidator(shared))
		logger.Info("gRPC TCP server: platform-token validation enabled")
	} else {
		local = buildLocalTokenValidator(config, logger, transportGRPCTCP)
		if local == nil {
			return grpcAuthSelection{}, ErrTransportAuthRequired{
				Transport: transportGRPCTCP,
				Reason:    "neither the platform-token validator, the QuicBaaS service nor a platform JWT verifier is available",
			}
		}
		authorizer, err := newIAMTokenAuthorizer(local, pep)
		if err != nil {
			return grpcAuthSelection{}, ErrTransportAuthRequired{
				Transport: transportGRPCTCP,
				Reason:    "tokens without scope claims need the IAM policy enforcement point to be authorized: " + err.Error(),
			}
		}
		opts = append(opts,
			grpccreds.WithTokenValidator(local),
			grpccreds.WithAuthorizationChecker(authorizer),
		)
	}

	return grpcAuthSelection{
		unary:     grpccreds.OIDCUnaryInterceptor(opts...),
		stream:    grpccreds.OIDCStreamInterceptor(opts...),
		validator: local,
		required:  true,
	}, nil
}

// selectQUICAuth decides how the QUIC transport authenticates callers. It
// always returns a middleware, because the QUIC dispatcher authorizes every
// request against the operation catalog (#767). Under mTLS the TLS layer
// verifies the client certificate against clientCAPool and the middleware
// turns it into the principal of a tokenless request, so the per-operation
// scope checks see an authorized caller (#720); a presented token is still
// validated when the shared platform-token validator exists. Under the
// SkipIAMValidation opt-out authentication is skipped, but unclassified
// operations are still refused. A configuration with no backend is refused
// with ErrTransportAuthRequired instead of yielding an unauthenticated server
// (#550).
func selectQUICAuth(config *Config, shared *platformTokenValidator, clientCAPool *x509.CertPool, installs installCertificateBindings, logger *logging.Logger) (*quic.AuthMiddleware, *grpcTokenValidator, error) {
	if config.EnableMTLS {
		if clientCAPool == nil {
			return nil, nil, ErrTransportAuthRequired{
				Transport: transportQUIC,
				Reason:    "mTLS is enabled but no client CA pool is available to authenticate client certificates",
			}
		}
		mtlsAuth, err := auth.NewMTLSAdapterFromRoots(logger, clientCAPool)
		if err != nil {
			return nil, nil, ErrTLSConfigFailed{Reason: "QUIC mTLS auth: " + err.Error()}
		}
		logger.Info("QUIC server: mTLS authentication enabled")
		opts := []quic.AuthMiddlewareOption{
			quic.WithQUICPeerAuthenticator(newMTLSPeerAuthenticator(mtlsAuth, installs, config.MTLSOperatorTrustDomain)),
			quic.WithQUICRequireAuth(true),
		}
		if shared != nil {
			opts = append(opts, quic.WithQUICTokenValidator(shared))
		}
		return quic.NewAuthMiddleware(opts...), nil, nil
	}
	if config.SkipIAMValidation {
		logger.Warn("QUIC server: authentication DISABLED by SkipIAMValidation (testing only)")
		return quic.NewAuthMiddleware(quic.WithQUICRequireAuth(false)), nil, nil
	}
	if shared != nil {
		logger.Info("QUIC server: platform-token validation enabled")
		return quic.NewAuthMiddleware(
			quic.WithQUICTokenValidator(shared),
			quic.WithQUICRequireAuth(true),
		), nil, nil
	}
	local := buildLocalTokenValidator(config, logger, transportQUIC)
	if local == nil {
		return nil, nil, ErrTransportAuthRequired{
			Transport: transportQUIC,
			Reason:    "neither the platform-token validator, the QuicBaaS service nor a platform JWT verifier is available",
		}
	}
	return quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(local),
		quic.WithQUICRequireAuth(true),
	), local, nil
}

// The daemon's client CA pool admits two principals:
//
//   - the operator, holding the admin bundle /init issues. Its leaf names the
//     platform admin as the SPIFFE ID
//     spiffe://<trust domain>/tenant/<system tenant>/user/<admin> and carries
//     the system tenant as its subject organization. It is granted every
//     operation (mtlsOperatorScope).
//
//   - an installer, holding the certificate the installer presents to complete
//     an install: one that carries the tp-pxeInstaller EKU marker, or whose
//     SHA-256 was ever bound to a device through PXE UpdateState. It holds
//     only installerScope, the scope of the install-completion webhook, which
//     checks the marker and the binding itself; every other scope-guarded
//     gRPC, REST, QUIC and MCP operation refuses it (peerScopes).
//
//   - a tenant principal, holding a tenant admin or user certificate. Its leaf
//     carries exactly one subject organization, a tenant other than the system
//     tenant, and names the same tenant in the SPIFFE ID
//     spiffe://<trust domain>/tenant/<tenant>/user/<name>. It is granted every
//     operation (mtlsOperatorScope), which tenant authorization then limits to
//     its own tenant.
//
//   - a service principal (mtlsServicePrincipal), which holds no scope and is
//     admitted by the gRPC interceptors alone, to the methods of its role.
//
// Any other certificate holds no scope and reaches only the methods in
// mtlsInstallerMethods, whose handler refuses it without the installer
// marker and binding. That includes every machine certificate: the daemon's
// and the ISO-built certificates carry a non-system organization but no
// /user/ SPIFFE ID, so a subject organization alone never grants a scope.
const mtlsOperatorScope = "*:*"

// mtlsPeerAuthenticator turns the verified client certificate of a QUIC
// connection, REST request or MCP session into the principal it acts as,
// through the same certificate authenticator the gRPC mTLS interceptor uses,
// and grants it what peerScopes decides.
type mtlsPeerAuthenticator struct {
	authenticator auth.Authenticator
	// installs tells a certificate ever bound as an install certificate from
	// every other one. Nil on a listener with no PXE install flow: an
	// installer is then known by its EKU marker alone.
	installs installCertificateBindings
	// trustDomain is the SPIFFE trust domain the operator certificate names.
	trustDomain string
}

// newMTLSPeerAuthenticator builds the peer authenticator every mTLS listener
// shares. installs is read on each request, so a PXE service configured
// after the listener is built still separates installers from the operator.
// An empty trustDomain names no operator and no tenant principal.
func newMTLSPeerAuthenticator(authenticator auth.Authenticator, installs installCertificateBindings, trustDomain string) mtlsPeerAuthenticator {
	return mtlsPeerAuthenticator{authenticator: authenticator, installs: installs, trustDomain: trustDomain}
}

// installerScope is the one scope an install certificate holds: only the PXE
// webhook (WebhookComplete) takes it, and the webhook then accepts the
// certificate only for the device it is bound to. It reaches no certs:*
// operation and none of the operator PXE operations, which take pxe:write
// (Codex 8652).
const installerScope = "pxe:complete"

// installCertificateBindings reports whether a certificate, by the lowercase
// hex SHA-256 of its DER, is or ever was bound as a device's install
// certificate. The answer outlives the installation: an installer's
// certificate is never the operator's (Codex 8652).
type installCertificateBindings interface {
	IsInstallCertificate(ctx context.Context, certificateSHA256 string) (bool, error)
}

// pxeInstallBindings reads the installer identities of the PXE store the PXE
// handlers use: every certificate a device's installation was ever bound to,
// whether or not that installation has ended.
type pxeInstallBindings struct {
	service *PXEGRPCService
}

// IsInstallCertificate implements installCertificateBindings. A node with no
// PXE service binds no install certificate.
func (b pxeInstallBindings) IsInstallCertificate(ctx context.Context, certificateSHA256 string) (bool, error) {
	if b.service == nil || b.service.pxeService == nil {
		return false, nil
	}
	return b.service.pxeService.IsInstallerCertificate(ctx, certificateSHA256)
}

// InstallBindingLookupError is a verified certificate whose install binding
// could not be read. The peer is refused rather than treated as the operator.
type InstallBindingLookupError struct {
	CertificateSHA256 string
	Err               error
}

func (e *InstallBindingLookupError) Error() string {
	return "mTLS peer " + e.CertificateSHA256 + ": read the PXE install certificate binding: " + e.Err.Error()
}

func (e *InstallBindingLookupError) Unwrap() error { return e.Err }

// mtlsInstallerMethods are the only methods an installer certificate may
// invoke, named by gRPC full method. It is the one list for every transport:
// gRPC reads it directly, QUIC and MCP through mtlsPeerAuthenticator.AdmitsMethod.
var mtlsInstallerMethods = map[string]struct{}{
	platformv1.PXEService_WebhookComplete_FullMethodName: {},
}

// isMTLSOperator reports whether leaf is the operator's admin certificate for
// trustDomain. An empty trustDomain names no operator, so it fails closed.
func isMTLSOperator(leaf *x509.Certificate, trustDomain string) bool {
	if leaf == nil || trustDomain == "" {
		return false
	}
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != app.SystemTenantID {
		return false
	}
	for _, uri := range leaf.URIs {
		if isMTLSOperatorSPIFFEID(uri, trustDomain) {
			return true
		}
	}
	return false
}

// isMTLSOperatorSPIFFEID reports whether uri is
// spiffe://<trustDomain>/tenant/<system tenant>/user/<admin>.
func isMTLSOperatorSPIFFEID(uri *url.URL, trustDomain string) bool {
	if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") || uri.Host != trustDomain {
		return false
	}
	want := "/tenant/" + app.SystemTenantID + "/user/" + common.AdminUsername
	return uri.Path == want && uri.RawQuery == "" && uri.Fragment == ""
}

// mtlsGrantFor is the scope grant of the principal leaf authenticates: every
// operation for the operator and a tenant principal, nothing for an installer.
func mtlsGrantFor(leaf *x509.Certificate, trustDomain string) []string {
	if isMTLSPrincipal(leaf, trustDomain) {
		return []string{mtlsOperatorScope}
	}
	return nil
}

// isMTLSPrincipal reports whether leaf may go beyond the installer methods:
// it is the operator or a tenant principal for trustDomain.
func isMTLSPrincipal(leaf *x509.Certificate, trustDomain string) bool {
	return isMTLSOperator(leaf, trustDomain) || isMTLSTenantPrincipal(leaf, trustDomain)
}

// isMTLSTenantPrincipal reports whether leaf is a tenant principal for
// trustDomain: exactly one subject organization, not the system tenant, and a
// SPIFFE ID spiffe://<trustDomain>/tenant/<that organization>/user/<name>. An
// empty trustDomain names no principal, so it fails closed.
func isMTLSTenantPrincipal(leaf *x509.Certificate, trustDomain string) bool {
	if leaf == nil || trustDomain == "" {
		return false
	}
	if len(leaf.Subject.Organization) != 1 {
		return false
	}
	tenant := leaf.Subject.Organization[0]
	if tenant == "" || tenant == app.SystemTenantID {
		return false
	}
	for _, uri := range leaf.URIs {
		if isMTLSTenantUserSPIFFEID(uri, trustDomain, tenant) {
			return true
		}
	}
	return false
}

// isMTLSTenantUserSPIFFEID reports whether uri is
// spiffe://<trustDomain>/tenant/<tenant>/user/<name> with a non-empty name that
// holds no further path segment.
func isMTLSTenantUserSPIFFEID(uri *url.URL, trustDomain, tenant string) bool {
	if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") || uri.Host != trustDomain {
		return false
	}
	if uri.RawQuery != "" || uri.Fragment != "" {
		return false
	}
	name, ok := strings.CutPrefix(uri.Path, "/tenant/"+tenant+"/user/")
	return ok && name != "" && !strings.Contains(name, "/")
}

// mtlsServiceRoles maps each platform service that authenticates to the
// daemon by a platform-issued certificate to the scopes its role holds. A
// service principal reaches a gRPC method only when the method's scope in
// the gRPC catalog (grpccreds.ScopeForMethod) is one of them.
var mtlsServiceRoles = map[string]map[string]struct{}{
	// gatewayd: proxy sync (ProxyService/GetProxyConfig, GetZoneMatrix),
	// the attestation gate and overlay verdicts, overlay IPAM allocations
	// and overlay device reads. Every one is a read.
	"gatewayd": {
		"proxy:read":       {},
		"attestation:read": {},
		"sdn:read":         {},
		"device:read":      {},
	},
}

// mtlsServiceKind is the CA's SPIFFE kind for a service.
const mtlsServiceKind = "svc"

// mtlsServicePrincipal returns the service a certificate names when it is a
// service principal: its subject O is exactly the system tenant and a URI
// SAN is spiffe://<trust domain>/tenant/<system tenant>/svc/<name>, the
// form the CA issues for a service, for a service in mtlsServiceRoles. An empty trust domain makes no certificate a service.
func mtlsServicePrincipal(leaf *x509.Certificate, trustDomain string) (string, bool) {
	if leaf == nil || trustDomain == "" {
		return "", false
	}
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != app.SystemTenantID {
		return "", false
	}
	for _, uri := range leaf.URIs {
		if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") || uri.Host != trustDomain {
			continue
		}
		if uri.RawQuery != "" || uri.Fragment != "" {
			continue
		}
		name, ok := strings.CutPrefix(uri.Path, "/tenant/"+app.SystemTenantID+"/"+mtlsServiceKind+"/")
		if !ok {
			continue
		}
		if _, known := mtlsServiceRoles[name]; known {
			return name, true
		}
	}
	return "", false
}

// mtlsServiceAdmitsMethod reports whether a service's role holds the scope
// the gRPC catalog gives method. A method outside the catalog is refused.
func mtlsServiceAdmitsMethod(service, method string) bool {
	scope := grpccreds.ScopeForMethod(method)
	if scope == "" {
		return false
	}
	_, ok := mtlsServiceRoles[service][scope]
	return ok
}

// AdmitsMethod reports whether method is one an installer certificate may
// invoke. It is how the QUIC guard and the MCP checker share
// mtlsInstallerMethods with the gRPC interceptors; the operator never needs
// it, holding every scope.
func (a mtlsPeerAuthenticator) AdmitsMethod(method string) bool {
	_, ok := mtlsInstallerMethods[method]
	return ok
}

// AuthenticatePeer authenticates the leaf of chain and returns its principal.
// It implements quic.PeerAuthenticator.
func (a mtlsPeerAuthenticator) AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	return a.authenticate(ctx, chain, false)
}

// AuthenticateInstallerPeer is AuthenticatePeer for a method AdmitsMethod
// admits: a verified certificate without a subject organization is admitted
// with no tenant and no scope (authenticateMTLSCertificate). The method's
// handler still requires the certificate's fingerprint to be bound.
func (a mtlsPeerAuthenticator) AuthenticateInstallerPeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	return a.authenticate(ctx, chain, true)
}

func (a mtlsPeerAuthenticator) authenticate(ctx context.Context, chain []*x509.Certificate, installerMethod bool) (*platformtoken.AuthorizedContext, error) {
	if len(chain) == 0 {
		return nil, quic.ErrMissingClientCertificate{}
	}
	identity, err := authenticateMTLSCertificate(ctx, a.authenticator, chain[0], installerMethod)
	if err != nil {
		return nil, err
	}
	scopes, err := a.peerScopes(ctx, chain[0])
	if err != nil {
		return nil, err
	}
	return &platformtoken.AuthorizedContext{
		Subject:  identity.ID,
		Username: identity.Name,
		TenantID: identity.TenantID,
		Scopes:   scopes,
	}, nil
}

// peerScopes is what a verified certificate may do. A certificate carrying
// the installer EKU marker, or ever bound as a device's install certificate,
// is an installer, never the operator: the listener trusts it so the
// installer can report its result, so it holds only the scope the PXE webhook
// takes (Codex 8646), during its installation and after it ends (Codex 8652).
// The installer check comes first, so a certificate that also names the
// operator, a tenant principal or a service is still only an installer. Any
// other certificate holds what mtlsGrantFor decides: every operation for the
// operator and a tenant principal of the trust domain, nothing for the rest.
func (a mtlsPeerAuthenticator) peerScopes(ctx context.Context, leaf *x509.Certificate) ([]string, error) {
	// The marker is read from the certificate itself, before any binding
	// lookup, so a daemon that has restarted, or another instance, without
	// the binding history still restricts an installer (Codex 8673, #1362).
	if issuance.HasInstallerMarker(leaf) {
		return []string{installerScope}, nil
	}
	if a.installs == nil {
		return mtlsGrantFor(leaf, a.trustDomain), nil
	}
	fingerprint := pxe.CertificateSHA256(leaf.Raw)
	bound, err := a.installs.IsInstallCertificate(ctx, fingerprint)
	if err != nil {
		// Fail closed: a certificate whose role cannot be read gets no scope.
		return nil, &InstallBindingLookupError{CertificateSHA256: fingerprint, Err: err}
	}
	if bound {
		return []string{installerScope}, nil
	}
	return mtlsGrantFor(leaf, a.trustDomain), nil
}

// authenticateMTLSCertificate authenticates cert. The installer certificate
// carries no subject organization, so the authenticator, which takes the
// tenant from it, refuses it with auth.ErrTenantNotFound after the chain,
// validity and identity checks have passed. On an installer method
// (mtlsInstallerMethods) that refusal alone is waived and the certificate is
// admitted with no tenant: the method's handler admits only the certificate
// whose fingerprint SetDeviceInstalling bound, as the REST webhook does. On
// every other method the refusal stands unchanged.
func authenticateMTLSCertificate(ctx context.Context, authenticator auth.Authenticator, cert *x509.Certificate, installerMethod bool) (*auth.Identity, error) {
	identity, err := authenticator.Authenticate(ctx, cert)
	if err == nil || !installerMethod {
		return identity, err
	}
	var noTenant auth.ErrTenantNotFound
	if !errors.As(err, &noTenant) {
		return nil, err
	}
	return authenticator.ExtractIdentity(cert)
}

// newRESTScopeGuard builds the guard that checks each daemon REST route's
// scope. It accepts the same credentials as QUIC: a platform token through
// the shared validator, else a client certificate verified against the mTLS
// client CA pool and granted what mtlsGrantFor decides. A credential with no verifier
// configured is refused, so the guard never admits by default.
func newRESTScopeGuard(config *Config, shared *platformTokenValidator, installs installCertificateBindings, logger *logging.Logger) (*restapi.ScopeGuard, error) {
	var tokens restapi.TokenAuthorizer
	// A nil *platformTokenValidator must not become a non-nil interface.
	if shared != nil {
		tokens = shared
	}
	var peers restapi.PeerAuthenticator
	clientCAPool, err := resolveMTLSClientCAPool(config, transportREST)
	if err != nil {
		return nil, err
	}
	if clientCAPool != nil {
		mtlsAuth, authErr := auth.NewMTLSAdapterFromRoots(logger, clientCAPool)
		if authErr != nil {
			return nil, ErrTLSConfigFailed{Reason: "REST mTLS auth: " + authErr.Error()}
		}
		peers = newMTLSPeerAuthenticator(mtlsAuth, installs, config.MTLSOperatorTrustDomain)
	}
	return restapi.NewScopeGuard(tokens, peers, logger.Slog()), nil
}

// newMCPPeerAuthenticator builds the authenticator that admits a tokenless
// MCP-over-HTTP request by its verified client certificate, the credential
// REST, gRPC and QUIC accept under mTLS. It returns nil without mTLS: the MCP
// listener then requests no client certificate and only bearer tokens
// authenticate.
func newMCPPeerAuthenticator(config *Config, installs installCertificateBindings, logger *logging.Logger) (mcp.PeerAuthenticator, error) {
	clientCAPool, err := resolveMTLSClientCAPool(config, transportMCP)
	if err != nil {
		return nil, err
	}
	if clientCAPool == nil {
		return nil, nil
	}
	mtlsAuth, err := auth.NewMTLSAdapterFromRoots(logger, clientCAPool)
	if err != nil {
		return nil, ErrTLSConfigFailed{Reason: "MCP mTLS auth: " + err.Error()}
	}
	logger.Info("MCP server: mTLS authentication enabled")
	return newMTLSPeerAuthenticator(mtlsAuth, installs, config.MTLSOperatorTrustDomain), nil
}

// buildLocalTokenValidator builds the per-transport token validator from the
// QuicBaaS service or, failing that, the platform JWT verifier. It returns nil
// when neither is available — the caller turns that into a typed refusal.
func buildLocalTokenValidator(config *Config, logger *logging.Logger, transport string) *grpcTokenValidator {
	if config.App == nil {
		return nil
	}
	var local *grpcTokenValidator
	if dbSvc := config.App.QuicBaaSService(); dbSvc != nil {
		local = newGRPCTokenValidator(&quicbaasServiceAdapter{svc: dbSvc}, logger)
		logger.Info("OIDC authentication enabled via QuicBaaS", "transport", transport)
	} else if config.PlatformJWTVerifier != nil {
		// QuicBaaS auth not available, but platform JWT is — build a
		// JWT-only validator so /api/v1/login tokens still authenticate.
		local = newGRPCTokenValidator(nil, logger)
	}
	if local == nil {
		return nil
	}
	if config.PlatformJWTVerifier != nil {
		local.SetJWTVerifier(config.PlatformJWTVerifier)
		logger.Info("platform JWT verification enabled", "transport", transport)
	}
	return local
}

// iamTokenVerifierFor selects the verifier behind IAM VerifyToken: the
// validator a transport authenticates with when one does, otherwise a local
// validator over the daemon's QuicBaaS service and platform JWT verifier. An
// mTLS deployment authenticates callers by certificate, so no transport builds
// a token validator, yet the tokens those issuers mint must still verify on
// every transport. It returns a nil interface when no issuer is wired.
func iamTokenVerifierFor(config *Config, logger *logging.Logger, shared *platformTokenValidator, grpcValidator, quicValidator *grpcTokenValidator) iamTokenVerifier {
	if verifier := selectIAMTokenVerifier(shared, grpcValidator, quicValidator); verifier != nil {
		return verifier
	}
	if local := buildLocalTokenValidator(config, logger, transportIAMToken); local != nil {
		return local
	}
	return nil
}

// resolveMTLSClientCAPool returns the client CA pool a transport must verify
// peer certificates against. With mTLS disabled it returns nil, nil. With mTLS
// enabled it fails closed: an unreadable or unparseable CA file is
// ErrTLSConfigFailed, and having neither a pool nor a file is
// ErrTransportAuthRequired — previously QUIC logged a Warn and served without
// client authentication in both cases (#550).
func resolveMTLSClientCAPool(config *Config, transport string) (*x509.CertPool, error) {
	if !config.EnableMTLS {
		return nil, nil
	}
	if config.MTLSClientCAPool != nil {
		return config.MTLSClientCAPool, nil
	}
	if config.MTLSClientCAFile == "" {
		return nil, ErrTransportAuthRequired{
			Transport: transport,
			Reason:    "mTLS is enabled but no client CA pool or file is configured",
		}
	}
	caCert, readErr := os.ReadFile(config.MTLSClientCAFile)
	if readErr != nil {
		return nil, ErrTLSConfigFailed{Reason: transport + ": failed to read mTLS client CA file: " + readErr.Error()}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, ErrTLSConfigFailed{Reason: transport + ": failed to parse mTLS client CA certificates"}
	}
	return pool, nil
}

// newServerTLSConfig builds the server TLS configuration a TCP transport
// serves cert with. When mTLS is enabled it requires and verifies a client
// certificate against the pool resolveMTLSClientCAPool resolves for the
// transport, failing closed on the same terms (#550). REST, gRPC and MCP
// share it so every listener presents one identity under one trust policy.
func newServerTLSConfig(config *Config, transport string, cert tls.Certificate) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	// A renewable identity is read per handshake. Certificates must stay
	// empty: crypto/tls prefers Certificates[0] over GetCertificate when a
	// client sends no SNI, which would pin the boot-time certificate (#36).
	if config.TLSIdentity.Current() != nil {
		tlsConfig.Certificates = nil
		tlsConfig.GetCertificate = config.TLSIdentity.GetCertificate
	}

	clientCAPool, err := resolveMTLSClientCAPool(config, transport)
	if err != nil {
		return nil, err
	}
	if clientCAPool != nil {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = clientCAPool
	}
	return tlsConfig, nil
}
