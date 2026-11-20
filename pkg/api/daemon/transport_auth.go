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
	"os"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
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

func selectGRPCTCPAuth(config *Config, shared *platformTokenValidator, pep quicbaassdk.IAMPEPClient, logger *logging.Logger, skipMethods []string) (grpcAuthSelection, error) {
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
			Authenticator: mtlsAuth,
			Logger:        logger,
			SkipMethods:   skipMethods,
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
func selectQUICAuth(config *Config, shared *platformTokenValidator, clientCAPool *x509.CertPool, logger *logging.Logger) (*quic.AuthMiddleware, *grpcTokenValidator, error) {
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
			quic.WithQUICPeerAuthenticator(mtlsPeerAuthenticator{authenticator: mtlsAuth, principals: config.MTLSPrincipals}),
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

// mtlsPeerAuthenticator turns the verified client certificate of a QUIC
// connection or REST request into the principal it acts as, through the same
// certificate authenticator the gRPC mTLS interceptor uses. The caller is
// granted its IAM principal's permissions, never a default grant: a client
// CA can issue more than operator certificates, so a verified chain proves
// who the caller is, not what it may do (#1107). A certificate without a
// resolvable principal is refused.
type mtlsPeerAuthenticator struct {
	authenticator auth.Authenticator
	principals    CertificatePrincipalResolver
}

// AuthenticatePeer implements quic.PeerAuthenticator.
func (a mtlsPeerAuthenticator) AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	if len(chain) == 0 {
		return nil, quic.ErrMissingClientCertificate{}
	}
	identity, err := a.authenticator.Authenticate(ctx, chain[0])
	if err != nil {
		return nil, err
	}
	if a.principals == nil {
		return nil, ErrCertificatePrincipalUnresolved{Reason: "no IAM principal resolver is wired"}
	}
	principal, err := a.principals.ResolveCertificatePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}
	return &platformtoken.AuthorizedContext{
		Subject:  principal.Subject,
		Username: identity.Name,
		TenantID: principal.TenantID,
		Scopes:   principal.Scopes,
		Roles:    principal.Roles,
	}, nil
}

// newRESTScopeGuard builds the guard that checks each daemon REST route's
// scope. It accepts the same credentials as QUIC: a platform token through
// the shared validator, else a client certificate verified against the mTLS
// client CA pool, granted its IAM principal's permissions. A credential with no verifier
// configured is refused, so the guard never admits by default.
func newRESTScopeGuard(config *Config, shared *platformTokenValidator, logger *logging.Logger) (*restapi.ScopeGuard, error) {
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
		peers = mtlsPeerAuthenticator{authenticator: mtlsAuth, principals: config.MTLSPrincipals}
	}
	return restapi.NewScopeGuard(tokens, peers, logger.Slog()), nil
}

// newMCPPeerAuthenticator builds the authenticator that admits a tokenless
// MCP-over-HTTP request by its verified client certificate, the credential
// REST, gRPC and QUIC accept under mTLS. It returns nil without mTLS: the MCP
// listener then requests no client certificate and only bearer tokens
// authenticate.
func newMCPPeerAuthenticator(config *Config, logger *logging.Logger) (mcp.PeerAuthenticator, error) {
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
	return mtlsPeerAuthenticator{authenticator: mtlsAuth, principals: config.MTLSPrincipals}, nil
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
