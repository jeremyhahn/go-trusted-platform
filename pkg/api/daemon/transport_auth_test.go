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
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The gRPC TCP and QUIC transports used to install their token interceptor with
// WithRequireAuth(tokenValidator != nil): whenever no validator could be
// built the interceptor was present but inert and the whole daemon API was
// served anonymously (#550). These tests pin the fail-closed contract: with
// SkipIAMValidation off, no authentication backend means no server, and the
// refusal is a typed error rather than a Warn.

type alwaysValidJWTVerifier struct{}

func (alwaysValidJWTVerifier) VerifyToken(string) (bool, error) { return true, nil }

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
			sel, err := selectGRPCTCPAuth(config, nil, logging.DefaultLogger(), nil)
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

	_, err := selectGRPCTCPAuth(config, nil, logging.DefaultLogger(), nil)
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

	sel, err := selectGRPCTCPAuth(config, nil, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.Len(t, sel.options(), 2, "unary and stream interceptors")
	require.NotNil(t, sel.validator, "the local validator is retained for SetPlatformJWTVerifier")
	assert.True(t, sel.required, "authentication is always required when a backend exists")
}

func TestSelectGRPCTCPAuth_SharedValidator_BuildsRequiredAuth(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	shared := &platformTokenValidator{}

	sel, err := selectGRPCTCPAuth(config, shared, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.Len(t, sel.options(), 2)
	assert.Nil(t, sel.validator, "the shared validator is not a local one")
	assert.True(t, sel.required)
}

func TestSelectGRPCTCPAuth_SkipIAMValidation_IsTheOnlyOptOut(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.SkipIAMValidation = true

	sel, err := selectGRPCTCPAuth(config, nil, logging.DefaultLogger(), nil)
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
			mw, validator, err := selectQUICAuth(config, nil, logging.DefaultLogger())
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

	mw, validator, err := selectQUICAuth(config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)
	require.NotNil(t, validator)
}

func TestSelectQUICAuth_SharedValidator_BuildsRequiredMiddleware(t *testing.T) {
	t.Parallel()
	mw, validator, err := selectQUICAuth(failClosedConfig(), &platformTokenValidator{}, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, mw)
	assert.Nil(t, validator)
}

func TestSelectQUICAuth_MTLS_DefersToTLSLayer(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true
	mw, validator, err := selectQUICAuth(config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Nil(t, mw, "mTLS authenticates at the TLS layer; resolveMTLSClientCAPool enforces that it really does")
	assert.Nil(t, validator)
}

func TestSelectQUICAuth_SkipIAMValidation_IsTheOnlyOptOut(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.SkipIAMValidation = true
	mw, validator, err := selectQUICAuth(config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Nil(t, mw)
	assert.Nil(t, validator)
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

// TestNew_GRPCTCPWithJWTVerifier_RejectsAnonymousCalls proves the interceptor
// that IS installed requires a credential: an unauthenticated unary call is
// refused with Unauthenticated instead of reaching the handler.
func TestNew_GRPCTCPWithJWTVerifier_RejectsAnonymousCalls(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.App = &app.App{}
	config.PlatformJWTVerifier = alwaysValidJWTVerifier{}
	sel, err := selectGRPCTCPAuth(config, nil, logging.DefaultLogger(), nil)
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
