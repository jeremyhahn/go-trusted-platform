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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Transport names used in fail-closed authentication errors.
const (
	transportGRPCTCP = "grpc"
	transportQUIC    = "quic"
	transportREST    = "rest"
	transportMCP     = "mcp"
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
func selectGRPCTCPAuth(config *Config, shared *platformTokenValidator, logger *logging.Logger, skipMethods []string) (grpcAuthSelection, error) {
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

	var tokenValidator grpccreds.TokenValidator
	var local *grpcTokenValidator
	if shared != nil {
		// Preferred path: validate broker platform tokens and project
		// scp -> RBAC / tenant_id -> RLS into the request context.
		tokenValidator = shared
		logger.Info("gRPC TCP server: platform-token validation enabled")
	} else {
		local = buildLocalTokenValidator(config, logger, transportGRPCTCP)
		if local == nil {
			return grpcAuthSelection{}, ErrTransportAuthRequired{
				Transport: transportGRPCTCP,
				Reason:    "neither the platform-token validator, the QuicBaaS service nor a platform JWT verifier is available",
			}
		}
		tokenValidator = local
	}

	return grpcAuthSelection{
		unary: grpccreds.OIDCUnaryInterceptor(
			grpccreds.WithTokenValidator(tokenValidator),
			grpccreds.WithSkipMethods(skipMethods...),
			grpccreds.WithRequireAuth(true),
		),
		stream: grpccreds.OIDCStreamInterceptor(
			grpccreds.WithTokenValidator(tokenValidator),
			grpccreds.WithSkipMethods(skipMethods...),
			grpccreds.WithRequireAuth(true),
		),
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
			quic.WithQUICPeerAuthenticator(mtlsPeerAuthenticator{authenticator: mtlsAuth}),
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

// mtlsOperatorScope is the grant of a principal authenticated by an mTLS
// client certificate. The daemon's client CA pool admits only operator
// certificates (the admin bundle /init issues), and gRPC and REST authorize
// such a caller for every operation without a scope check, so QUIC grants the
// same authority rather than refusing the operator its own platform.
const mtlsOperatorScope = "*:*"

// mtlsPeerAuthenticator turns the verified client certificate of a QUIC
// connection into the principal its requests act as, through the same
// certificate authenticator the gRPC mTLS interceptor uses.
type mtlsPeerAuthenticator struct {
	authenticator auth.Authenticator
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
	return &platformtoken.AuthorizedContext{
		Subject:  identity.ID,
		Username: identity.Name,
		TenantID: identity.TenantID,
		Scopes:   []string{mtlsOperatorScope},
	}, nil
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
