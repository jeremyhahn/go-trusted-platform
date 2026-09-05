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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateMCPServer_RefusesWithoutAnAuthorizationBackend is the daemon half
// of #440. With SkipIAMValidation off and neither the platform-token validator
// nor the QuicBaaS adapter available, createMCPServer used to log "MCP server
// running without QuicBaaS authorization" and build the server anyway, on a
// checker that allowed every tool. It now returns
// ErrMCPAuthorizationBackendRequired and builds nothing.
func TestCreateMCPServer_RefusesWithoutAnAuthorizationBackend(t *testing.T) {
	// Build a real daemon the way every other createMCPServer test does
	// (testConfig sets SkipIAMValidation so New can run without QuicBaaS),
	// then withdraw the opt-out: no App, no DAOFactory, no platform-token
	// validator -- the state a node is in when its IAM wiring failed.
	config := testConfig("/tmp/test-mcp-no-backend.sock")
	config.EnableMCP = false
	d, err := New(config)
	require.NoError(t, err)
	d.config.SkipIAMValidation = false
	d.config.MCPConfig = &MCPConfig{Transport: "stdio"}

	server, err := d.createMCPServer()
	require.Error(t, err, "an MCP server must not be created without an authorization backend")
	var want ErrMCPAuthorizationBackendRequired
	assert.True(t, errors.As(err, &want), "error is %T, want ErrMCPAuthorizationBackendRequired", err)
	assert.Nil(t, server, "no server may exist when the backend is missing")
}

// TestCreateMCPServer_SkipIAMValidationIsTheOnlyOptOut pins the explicit
// escape hatch: the testing-only flag still yields a server with no backend,
// and that server's checker refuses every tool that requires a permission
// (pkg/api/mcp TestNoAuthorizationBackend_RefusesEveryToolThatNeedsAPermission)
// -- so even the opt-out is not the old open mode.
func TestCreateMCPServer_SkipIAMValidationIsTheOnlyOptOut(t *testing.T) {
	config := testConfig("/tmp/test-mcp-optout.sock")
	config.EnableMCP = false
	d, err := New(config)
	require.NoError(t, err)
	d.config.MCPConfig = &MCPConfig{Transport: "stdio"}

	server, err := d.createMCPServer()
	require.NoError(t, err)
	require.NotNil(t, server)
}
