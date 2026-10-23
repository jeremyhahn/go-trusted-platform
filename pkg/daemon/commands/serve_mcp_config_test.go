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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

// TestApplyDaemonListeners_RunnerFlagsEnableAndBindMCP is the #533 proof on
// the daemon side: with the serve command's defaults, as the integration
// runner starts platformd, MCP is enabled and its HTTPS transport is bound
// to the resolved MCP listener rather than the library default address.
func TestApplyDaemonListeners_RunnerFlagsEnableAndBindMCP(t *testing.T) {
	enable := serveCmd.Flags().Lookup("enable-mcp")
	require.NotNil(t, enable)
	enabledByDefault, err := strconv.ParseBool(enable.DefValue)
	require.NoError(t, err)

	t.Setenv("PLATFORMD_DAEMON_MCP_PORT", "19445")
	listeners, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)

	cfg := daemon.DefaultConfig()
	cfg.EnableMCP = enabledByDefault
	applyDaemonListeners(cfg, listeners)

	assert.True(t, cfg.EnableMCP, "--enable-mcp must default to on")
	require.NotNil(t, cfg.MCPConfig)
	assert.Equal(t, "http", cfg.MCPConfig.Transport)
	assert.Equal(t, "127.0.0.1:19445", cfg.MCPConfig.HTTPAddr)
}

// TestApplyDaemonListeners_KeepsConfiguredMCPSettings proves a config file's
// MCP settings survive the listener binding with only the address replaced.
func TestApplyDaemonListeners_KeepsConfiguredMCPSettings(t *testing.T) {
	listeners, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)

	configured := daemon.DefaultMCPConfig()
	configured.ServerName = "configured"
	cfg := daemon.DefaultConfig()
	cfg.MCPConfig = configured

	applyDaemonListeners(cfg, listeners)

	assert.Same(t, configured, cfg.MCPConfig)
	assert.Equal(t, "configured", cfg.MCPConfig.ServerName)
	assert.Equal(t, listeners.MCP.Address(), cfg.MCPConfig.HTTPAddr)
}
