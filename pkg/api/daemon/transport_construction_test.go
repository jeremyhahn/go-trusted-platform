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

// transport_construction_test.go asserts the construction half of the
// fail-closed transport rule (#444): an enabled transport that cannot be
// constructed fails New with ErrTransportConstructionFailed, and a disabled
// transport is never constructed at all.

package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testQUICServerConfig returns a QUIC server config that quic.NewServer
// accepts: loopback on an ephemeral port, TLS 1.3, serving cert.
func testQUICServerConfig(cert tls.Certificate) *quic.ServerConfig {
	config := quic.DefaultServerConfig()
	config.ListenAddr = "127.0.0.1:0"
	config.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	return config
}

// errRESTConstruction is the cause failRESTConstruction injects.
type errRESTConstruction struct{}

func (errRESTConstruction) Error() string { return "simulated REST construction failure" }

// failRESTConstruction makes the built-in REST constructor fail for the rest
// of the test and returns a pointer to its call count. The REST constructor
// has no failure path of its own, so the seam is the only way to force one.
// Callers must not run in parallel: the seam is package state.
func failRESTConstruction(t *testing.T) *int {
	t.Helper()
	calls := 0
	original := newRESTServer
	newRESTServer = func(*Config, *Service, *slog.Logger) (*RESTServer, error) {
		calls++
		return nil, errRESTConstruction{}
	}
	t.Cleanup(func() { newRESTServer = original })
	return &calls
}

func TestErrTransportConstructionFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errRESTConstruction{}
	err := ErrTransportConstructionFailed{Transport: transportREST, Cause: cause}

	assert.Equal(t,
		"rest: server could not be constructed: simulated REST construction failure; refusing to run without the enabled transport",
		err.Error())
	assert.ErrorIs(t, err, cause)
}

func TestErrTransportConstructionFailed_NilCause(t *testing.T) {
	err := ErrTransportConstructionFailed{Transport: transportMCP}

	assert.Contains(t, err.Error(), "mcp: server could not be constructed")
	assert.NoError(t, errors.Unwrap(err))
}

func TestNew_EnabledRESTThatCannotBeConstructedIsFatal(t *testing.T) {
	calls := failRESTConstruction(t)

	cert := sharedTestTLSCertificate()
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.TLSCertificate = &cert

	d, err := New(config)
	require.Error(t, err)
	assert.Nil(t, d)
	assert.Equal(t, 1, *calls)

	var constructFailed ErrTransportConstructionFailed
	require.ErrorAs(t, err, &constructFailed)
	assert.Equal(t, transportREST, constructFailed.Transport)
	var cause errRESTConstruction
	assert.ErrorAs(t, err, &cause, "the cause must be the constructor's own error")
}

// TestNew_DisabledTransportsAreNeverConstructed asserts the rule binds only
// enabled transports: each disabled one is configured so that constructing it
// would fail, and the daemon still builds and starts without it.
func TestNew_DisabledTransportsAreNeverConstructed(t *testing.T) {
	calls := failRESTConstruction(t)

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableGRPCTCP = false
	config.EnableREST = false // the REST constructor would fail
	config.EnableQUIC = false
	config.QUICConfig = nil // QUIC construction would fail without TLS
	config.EnableMCP = false
	config.MCPConfig = DefaultMCPConfig()
	config.MCPConfig.Transport = "http" // MCP-HTTP would fail without a certificate
	config.EnableGRPCUDS = true
	config.GRPCSocketPath = t.TempDir() + "/platformd-test.sock"
	config.SocketPath = config.GRPCSocketPath

	d, err := New(config)
	require.NoError(t, err)
	assert.Zero(t, *calls, "a disabled REST transport must not be constructed")
	assert.Nil(t, d.restServer)
	assert.Nil(t, d.quicServer)
	assert.Nil(t, d.mcpServer)

	require.NoError(t, d.Start(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, d.Stop(ctx))
}

// TestNew_QUICReplacementSupersedesConstructionFailure asserts a
// WithQUICServer replacement stands in for a built-in QUIC server that could
// not be constructed: New succeeds and keeps the replacement.
func TestNew_QUICReplacementSupersedesConstructionFailure(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = true
	config.QUICConfig = nil // the built-in server cannot be constructed
	config.QUICListenAddr = "127.0.0.1:0"

	replacement := &partialQUICServer{}
	d, err := New(config, WithQUICServer(replacement))
	require.NoError(t, err)
	assert.Same(t, replacement, d.quicServer)
}
