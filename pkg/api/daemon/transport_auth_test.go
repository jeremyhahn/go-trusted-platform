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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The gRPC TCP and QUIC transports used to install their token interceptor with
// WithRequireAuth(tokenValidator != nil): whenever no validator could be
// built the interceptor was present but inert and the whole daemon API was
// served anonymously (#550). These tests pin the fail-closed contract: with
// SkipIAMValidation off, no authentication backend means no server, and the
// refusal is a typed error rather than a Warn.

// alwaysValidJWTVerifier accepts every token and reports claims as its
// verified principal.
type alwaysValidJWTVerifier struct {
	claims jwt.TokenClaims
}

func (v alwaysValidJWTVerifier) VerifyTokenClaims(string) (*jwt.TokenClaims, error) {
	claims := v.claims
	return &claims, nil
}

// pepAllowing is an IAM PEP double that allows exactly one subject to perform
// one action on one resource, and records the last request it decided.
func pepAllowing(subject, resource, action string, last **sdkiam.CheckRequest) *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		*last = req
		allowed := req.Subject.ID == subject && req.Resource == resource && req.Action == action
		return &sdkiam.CheckResponse{Allowed: allowed}, nil
	}}
}

func failClosedConfig() *Config {
	config := DefaultConfig()
	config.SkipIAMValidation = false
	return config
}

// --- selectGRPCTCPAuth ------------------------------------------------------

func TestSelectGRPCTCPAuth_NoBackend_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	cases := map[string]*Config{
		"nil App, nil verifier": failClosedConfig(),
		"App without QuicBaaS, nil verifier": func() *Config {
			c := failClosedConfig()
			c.App = &app.App{}
			return c
		}(),
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			sel, err := selectGRPCTCPAuth(config, nil, nil, logging.DefaultLogger(), nil)
			require.Error(t, err)
			var want ErrTransportAuthRequired
			require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
			assert.Equal(t, transportGRPCTCP, want.Transport)
			assert.Nil(t, sel.unary, "no interceptor may be built without a backend")
			assert.Nil(t, sel.stream)
			assert.Nil(t, sel.validator)
		})
	}
}

func TestSelectGRPCTCPAuth_MTLSWithoutCAService_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

	_, err := selectGRPCTCPAuth(config, nil, nil, logging.DefaultLogger(), nil)
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.Equal(t, transportGRPCTCP, want.Transport)
	assert.Contains(t, want.Reason, "mTLS")
}

func TestSelectGRPCTCPAuth_JWTVerifier_BuildsRequiredAuth(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

	sel, err := selectGRPCTCPAuth(config, nil, &mockSDKPEPClient{}, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.Len(t, sel.options(), 2, "unary and stream interceptors")
	require.NotNil(t, sel.validator, "the local validator is retained for SetPlatformJWTVerifier")
	assert.True(t, sel.required, "authentication is always required when a backend exists")
}

// Platform tokens off (the default): the local validator's tokens carry no
// scopes, so without the IAM PEP to authorize them the transport must not
// start — otherwise any valid token would reach every method, Shutdown and
// the BMC power RPCs included (#768).
func TestSelectGRPCTCPAuth_LocalValidatorWithoutPEP_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

	sel, err := selectGRPCTCPAuth(config, nil, nil, logging.DefaultLogger(), nil)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportGRPCTCP, want.Transport)
	assert.Contains(t, want.Reason, "IAM policy enforcement point")
	assert.Nil(t, sel.unary)
	assert.Nil(t, sel.stream)
	assert.Nil(t, sel.validator)
}

func TestSelectGRPCTCPAuth_LocalValidator_AuthorizesEachMethodThroughIAM(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{claims: jwt.TokenClaims{
		UserIDStr: "42", TenantID: "acme", Roles: []string{"operator"},
	}}
	var last *sdkiam.CheckRequest
	pep := pepAllowing("42", "platform", "read", &last)

	sel, err := selectGRPCTCPAuth(config, nil, pep, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.NotNil(t, sel.unary)

	call := func(method string) (bool, error) {
		reached := false
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer jwt"))
		_, err := sel.unary(ctx, struct{}{}, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, interface{}) (interface{}, error) {
				reached = true
				return nil, nil
			})
		return reached, err
	}

	// The principal holds platform:read: GetStatus is allowed...
	reached, err := call("/platform.v1.PlatformDaemon/GetStatus")
	require.NoError(t, err)
	assert.True(t, reached)
	require.NotNil(t, last)
	assert.Equal(t, sdkiam.CheckSubject{ID: "42", TenantID: "acme", Roles: []string{"operator"}}, last.Subject)

	// ...but the same valid token cannot shut the daemon down.
	reached, err = call("/platform.v1.PlatformDaemon/Shutdown")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, reached, "a token without platform:admin must never reach Shutdown")
	assert.Equal(t, "admin", last.Action)
}

// Only the unary Health/Check probe and the status-only Liveness and Readiness
// probes are served without a token. GetHealth names every component with its failure message and Health/Watch holds a stream
// open, so the daemon's own skip list must not reopen what the interceptor's
// catalog scopes (#768).
func TestSelectGRPCTCPAuth_OnlyHealthCheckIsAnonymous(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

	sel, err := selectGRPCTCPAuth(config, nil, &mockSDKPEPClient{}, logging.DefaultLogger(), grpcTCPSkipMethods)
	require.NoError(t, err)
	require.NotNil(t, sel.unary)
	require.NotNil(t, sel.stream)

	for _, method := range []string{
		"/grpc.health.v1.Health/Check",
		platformv1.PlatformDaemon_Liveness_FullMethodName,
		platformv1.PlatformDaemon_Readiness_FullMethodName,
	} {
		reached := false
		_, err = sel.unary(context.Background(), struct{}{},
			&grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, interface{}) (interface{}, error) {
				reached = true
				return nil, nil
			})
		require.NoError(t, err, method)
		assert.True(t, reached, "the %s probe must answer without a token", method)
	}

	reached := false
	_, err = sel.unary(context.Background(), struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/platform.v1.PlatformDaemon/GetHealth"},
		func(context.Context, interface{}) (interface{}, error) {
			reached = true
			return nil, nil
		})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, reached, "the component health report must not answer anonymously")

	reached = false
	err = sel.stream(nil, &mockServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"},
		func(interface{}, grpc.ServerStream) error {
			reached = true
			return nil
		})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, reached, "the health Watch stream must not answer anonymously")
}

func TestSelectGRPCTCPAuth_SharedValidator_BuildsRequiredAuth(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	shared := &platformTokenValidator{}

	sel, err := selectGRPCTCPAuth(config, shared, nil, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.Len(t, sel.options(), 2)
	assert.Nil(t, sel.validator, "the shared validator is not a local one")
	assert.True(t, sel.required)
}

func TestSelectGRPCTCPAuth_SkipIAMValidation_IsTheOnlyOptOut(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.SkipIAMValidation = true

	sel, err := selectGRPCTCPAuth(config, nil, nil, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	assert.Empty(t, sel.options(), "the testing opt-out installs no token interceptor at all")
	assert.False(t, sel.required)
}

// --- selectQUICAuth -----------------------------------------------------------

func TestSelectQUICAuth_NoBackend_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	cases := map[string]*Config{
		"nil App, nil verifier": failClosedConfig(),
		"App without QuicBaaS, nil verifier": func() *Config {
			c := failClosedConfig()
			c.App = &app.App{}
			return c
		}(),
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			mw, validator, err := selectQUICAuth(config, nil, nil, logging.DefaultLogger())
			require.Error(t, err)
			var want ErrTransportAuthRequired
			require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
			assert.Equal(t, transportQUIC, want.Transport)
			assert.Nil(t, mw)
			assert.Nil(t, validator)
		})
	}
}

func TestSelectQUICAuth_JWTVerifier_BuildsRequiredMiddleware(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

	mw, validator, err := selectQUICAuth(config, nil, nil, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)
	require.NotNil(t, validator)
}

func TestSelectQUICAuth_SharedValidator_BuildsRequiredMiddleware(t *testing.T) {
	t.Parallel()
	mw, validator, err := selectQUICAuth(failClosedConfig(), &platformTokenValidator{}, nil, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)
	assert.Nil(t, validator)
}

// Under mTLS the QUIC connection's client certificate is the credential, and
// the middleware must turn it into a principal: without one every category
// operation guarded by AuthorizeSubOpcode is refused (#720). The QUIC
// dispatcher always authorizes, so the middleware is never nil (#767).
func TestSelectQUICAuth_MTLS_AuthenticatesByCertificate(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	issuer := newWebhookIssuer(t, "admin CA")

	mw, validator, err := selectQUICAuth(config, nil, issuer.pool(), logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw, "the QUIC dispatcher always authorizes; mTLS supplies the identity")
	assert.Nil(t, validator)

	// The verified operator certificate authenticates a tokenless request...
	verified := quic.WithConnectionTLS(context.Background(), &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{issuer.issueOperator(t, 100), issuer.cert}},
	})
	_, resp := mw.GuardRequest(verified, &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey})
	assert.Nil(t, resp)
	// ...but an unclassified operation is still refused...
	_, resp = mw.GuardRequest(verified, &quicwire.Request{Opcode: quicwire.OpJWTVerify})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
	// ...and a connection with no verified certificate is not authenticated.
	_, resp = mw.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusUnauthorized, resp.Status)
}

func TestSelectQUICAuth_MTLS_WithSharedValidator_ValidatesPresentedTokens(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	shared := &platformTokenValidator{}
	mw, _, err := selectQUICAuth(config, shared, testutil.GenerateTestTLSBundle(t).CAPool, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)

	// A zero platformTokenValidator has no verifier: a presented token cannot
	// validate, so it must be refused rather than ignored.
	_, resp := mw.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey, Token: "presented"})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusUnauthorized, resp.Status)
}

func TestSelectQUICAuth_MTLSWithoutClientCAPool_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true

	mw, validator, err := selectQUICAuth(config, nil, nil, logging.DefaultLogger())
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportQUIC, want.Transport)
	assert.Nil(t, mw)
	assert.Nil(t, validator)
}

// --- mtlsPeerAuthenticator -----------------------------------------------------

func newTestMTLSPeerAuthenticator(t *testing.T, roots *x509.CertPool) mtlsPeerAuthenticator {
	t.Helper()
	adapter, err := auth.NewMTLSAdapterFromRoots(logging.DefaultLogger(), roots)
	require.NoError(t, err)
	return mtlsPeerAuthenticator{authenticator: adapter, trustDomain: testOperatorTrustDomain}
}

func leafOf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return leaf
}

func TestMTLSPeerAuthenticator_TrustedCertificate_IsTheOperator(t *testing.T) {
	t.Parallel()
	issuer := newWebhookIssuer(t, "admin CA")
	peer := newTestMTLSPeerAuthenticator(t, issuer.pool())

	authCtx, err := peer.AuthenticatePeer(context.Background(), []*x509.Certificate{issuer.issueOperator(t, 100), issuer.cert})
	require.NoError(t, err)
	assert.Equal(t, common.AdminUsername, authCtx.Subject)
	assert.Equal(t, common.AdminUsername, authCtx.Username)
	assert.Equal(t, app.SystemTenantID, authCtx.TenantID)
	assert.True(t, authCtx.HasScope("piv:sign"), "an operator certificate holds every scope, as on gRPC and REST")
	assert.True(t, authCtx.HasScope("ceremony:init"))
}

func TestMTLSPeerAuthenticator_UntrustedCertificate_ReturnsError(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	foreign := testutil.GenerateTestTLSBundle(t)
	peer := newTestMTLSPeerAuthenticator(t, trusted.CAPool)

	authCtx, err := peer.AuthenticatePeer(context.Background(), []*x509.Certificate{leafOf(t, foreign.ClientCert)})
	require.Error(t, err)
	assert.Nil(t, authCtx)
}

func TestMTLSPeerAuthenticator_EmptyChain_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	peer := newTestMTLSPeerAuthenticator(t, testutil.GenerateTestTLSBundle(t).CAPool)

	authCtx, err := peer.AuthenticatePeer(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.As(err, &quic.ErrMissingClientCertificate{}), "error is %T", err)
	assert.Nil(t, authCtx)
}

func TestSelectQUICAuth_SkipIAMValidation_IsTheOnlyOptOut(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.SkipIAMValidation = true
	mw, validator, err := selectQUICAuth(config, nil, nil, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)
	assert.Nil(t, validator)

	_, resp := mw.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey})
	assert.Nil(t, resp, "the opt-out skips authentication")
	_, resp = mw.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpJWTVerify})
	require.NotNil(t, resp, "the opt-out never serves an unclassified operation")
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}

// --- resolveMTLSClientCAPool ---------------------------------------------------

func TestResolveMTLSClientCAPool_Disabled_ReturnsNil(t *testing.T) {
	t.Parallel()
	pool, err := resolveMTLSClientCAPool(failClosedConfig(), transportQUIC)
	require.NoError(t, err)
	assert.Nil(t, pool)
}

func TestResolveMTLSClientCAPool_ConfiguredPool_IsReturned(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = x509.NewCertPool()
	pool, err := resolveMTLSClientCAPool(config, transportQUIC)
	require.NoError(t, err)
	assert.Same(t, config.MTLSClientCAPool, pool)
}

func TestResolveMTLSClientCAPool_EnabledWithNoPoolAndNoFile_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	pool, err := resolveMTLSClientCAPool(config, transportQUIC)
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.Equal(t, transportQUIC, want.Transport)
	assert.Nil(t, pool)
}

func TestResolveMTLSClientCAPool_UnreadableFile_ReturnsTLSConfigError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAFile = filepath.Join(t.TempDir(), "missing.pem")
	pool, err := resolveMTLSClientCAPool(config, transportGRPCTCP)
	require.Error(t, err)
	var want ErrTLSConfigFailed
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.Nil(t, pool)
}

func TestResolveMTLSClientCAPool_UnparseableFile_ReturnsTLSConfigError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	path := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0o600))
	config.MTLSClientCAFile = path
	pool, err := resolveMTLSClientCAPool(config, transportGRPCTCP)
	require.Error(t, err)
	var want ErrTLSConfigFailed
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.Nil(t, pool)
}

// --- New() ------------------------------------------------------------------

// TestNew_GRPCTCPWithoutAuthBackend_RefusesToConstruct is the daemon-level
// assertion: the state a node is in when its IAM wiring failed (no shared
// validator, no App) must not yield a gRPC server, let alone a listener.
func TestNew_GRPCTCPWithoutAuthBackend_RefusesToConstruct(t *testing.T) {
	t.Parallel()
	config := testConfig(filepath.Join(t.TempDir(), "grpc-fail-closed.sock"))
	config.SkipIAMValidation = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Nil(t, d, "no daemon, and therefore no gRPC server, may exist without an auth backend")
}

func TestNew_QUICMTLSWithUnreadableCAFile_RefusesToConstruct(t *testing.T) {
	t.Parallel()
	config := testConfig(filepath.Join(t.TempDir(), "quic-ca.sock"))
	config.EnableREST = false
	config.EnableMCP = false
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"
	config.EnableMTLS = true
	config.MTLSClientCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")

	d, err := New(config)
	require.Error(t, err)
	var want ErrTLSConfigFailed
	require.True(t, errors.As(err, &want), "error is %T, want ErrTLSConfigFailed", err)
	assert.True(t, strings.HasPrefix(want.Reason, transportQUIC+":"), "reason %q names the QUIC transport", want.Reason)
	assert.Nil(t, d, "no daemon, and therefore no QUIC listener, may exist without its client CA pool")
}

// TestNew_GRPCTCPWithJWTVerifier_RejectsAnonymousCalls proves the interceptor
// that IS installed requires a credential: an unauthenticated unary call is
// refused with Unauthenticated instead of reaching the handler.
func TestNew_GRPCTCPWithJWTVerifier_RejectsAnonymousCalls(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}
	sel, err := selectGRPCTCPAuth(config, nil, &mockSDKPEPClient{}, logging.DefaultLogger(), nil)
	require.NoError(t, err)

	unary := sel.unary
	require.NotNil(t, unary)

	handlerCalled := false
	_, err = unary(context.Background(), struct{}{}, &grpc.UnaryServerInfo{FullMethod: "/platform.v1.PlatformDaemon/GetStatus"},
		func(context.Context, interface{}) (interface{}, error) {
			handlerCalled = true
			return nil, nil
		})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handlerCalled, "an anonymous call must never reach the handler")
}

// --- ErrTransportAuthRequired ---------------------------------------------------

func TestErrTransportAuthRequired_Error(t *testing.T) {
	t.Parallel()
	err := ErrTransportAuthRequired{Transport: transportQUIC, Reason: "no validator"}
	assert.Contains(t, err.Error(), "quic")
	assert.Contains(t, err.Error(), "no validator")
	assert.Contains(t, ErrTransportAuthRequired{Transport: transportGRPCTCP}.Error(), "refusing")
}

// --- REST ---------------------------------------------------------------------

// The daemon REST server has no token middleware; mTLS at the TLS layer is its
// only authentication. Before #550/#312 `platformd serve` in daemon-only mode
// (`--enable-rest` true, `--enable-mtls` false by default) bound an
// unauthenticated REST listener serving BMC power control. Both the daemon
// constructor and the server refuse that state now.

func TestNew_RESTWithoutMTLS_RefusesToConstruct(t *testing.T) {
	t.Parallel()
	config := testConfig(filepath.Join(t.TempDir(), "rest-fail-closed.sock"))
	config.SkipIAMValidation = false
	config.EnableREST = true

	d, err := New(config)
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportREST, want.Transport)
	assert.Nil(t, d)
}

func TestRESTServerStart_WithoutMTLS_RefusesToListen(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.Equal(t, transportREST, want.Transport)
	assert.False(t, server.IsRunning(), "a refused start must not report running")
}

// Config.Validate already refuses mTLS with neither a pool nor a file; the
// case Validate cannot see is a file that fails to load at start time, which
// used to be tolerated by REST as a typed start error and by QUIC as a Warn.
func TestRESTServerStart_MTLSWithUnloadableCAFile_RefusesToListen(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert
	config.EnableMTLS = true
	config.MTLSClientCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	var want ErrTLSConfigFailed
	require.True(t, errors.As(err, &want), "error is %T", err)
	assert.False(t, server.IsRunning())
}

func TestRESTServerStart_MTLSWithPool_Listens(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert
	config.EnableMTLS = true
	config.MTLSClientCAPool = x509.NewCertPool()
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.ForceStop() })
	assert.True(t, server.IsRunning())
}
