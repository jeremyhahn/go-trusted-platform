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

package commands

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// TestServeCommand_ListenerFlagsAreRegistered pins the flag surface of
// the serve command: a bind-host and a port flag per transport, defaulting
// to loopback on the canonical ports.
func TestServeCommand_ListenerFlagsAreRegistered(t *testing.T) {
	for flag, def := range map[string]string{
		"rest-bind-host": tpconfig.LoopbackBindHost, "rest-port": "8443",
		"grpc-bind-host": tpconfig.LoopbackBindHost, "grpc-port": "10443",
		"quic-bind-host": tpconfig.LoopbackBindHost, "quic-port": "9444",
		"mcp-bind-host": tpconfig.LoopbackBindHost, "mcp-port": "9445",
	} {
		f := serveCmd.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		assert.Equal(t, def, f.DefValue, flag)
	}
}

// TestResolveDaemonListeners_DefaultsAndEnv proves the serve command
// resolves through the global viper the root and serve inits wired: the
// defaults are loopback, and the PLATFORMD_ environment layer is live.
func TestResolveDaemonListeners_DefaultsAndEnv(t *testing.T) {
	got, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:10443", got.GRPC.Address())

	t.Setenv("PLATFORMD_DAEMON_GRPC_BIND_HOST", "0.0.0.0")
	t.Setenv("PLATFORMD_DAEMON_GRPC_PORT", "20443")
	got, err = resolveDaemonListeners(serveCmd)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:20443", got.GRPC.Address())
	assert.Equal(t, "127.0.0.1:9444", got.QUIC.Address(), "other transports keep their defaults")
}

// TestResolveDaemonListeners_InvalidValueIsAStartupError proves a bad
// value stops startup with the serve command's typed error, naming the
// listener phase, and is printed for the operator.
func TestResolveDaemonListeners_InvalidValueIsAStartupError(t *testing.T) {
	t.Setenv("PLATFORMD_DAEMON_REST_PORT", "99999")
	var stderr bytes.Buffer
	serveCmd.SetErr(&stderr)
	defer serveCmd.SetErr(nil)

	_, err := resolveDaemonListeners(serveCmd)
	var startup ErrServeStartup
	require.True(t, errors.As(err, &startup), "got %v", err)
	assert.Equal(t, "daemon listener configuration", startup.Phase)
	var port *tpconfig.ErrInvalidListenerPort
	assert.True(t, errors.As(startup.Cause, &port))
	assert.Contains(t, stderr.String(), "daemon.rest.port")
}
