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

package mcp

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestNoAuthorizationBackend_RefusesEveryToolThatNeedsAPermission is the
// fail-closed assertion for #440.
//
// AuthorizeTool used to begin with "when no authorization backend is
// configured, allow all operations". The daemon reaches that state whenever
// its IAM wiring fails at startup (it logs "MCP server running without
// QuicBaaS authorization" and starts the transport anyway), and in it every
// registered tool -- BMC power control, TPM clear, the 334 tools #300 made
// refuse for lack of a mapping -- was served to any caller with no token.
//
// This walks the BUILT registry rather than a sample, so the assertion covers
// every tool that exists rather than the ones someone remembered: with both
// backends nil, every tool whose permission is non-empty is refused with
// AuthErrorMissingToken, every unmapped tool is refused with
// AuthErrorToolNotClassified, and only the tools explicitly mapped to "" are
// admitted -- "" means no permission is required of anyone, backend or not.
//
// Positive control: the pre-#440 nil-backend branch (return ctx, nil before
// the map lookup) turns this red on every refused count.
func TestNoAuthorizationBackend_RefusesEveryToolThatNeedsAPermission(t *testing.T) {
	log := logging.NewLogger(slog.LevelError, io.Discard)
	registry := NewToolRegistry(nil, log)
	checker := NewAuthorizationChecker(nil, nil)

	tools := registry.ListTools()
	require.NotEmpty(t, tools, "the registry built no tools; this test would pass vacuously")

	var refusedMissingToken, refusedUnclassified, admitted []string
	for _, tool := range tools {
		_, authErr := checker.AuthorizeTool(context.Background(), tool.Name, "")
		switch {
		case authErr == nil:
			admitted = append(admitted, tool.Name)
		case authErr.Type == AuthErrorMissingToken:
			refusedMissingToken = append(refusedMissingToken, tool.Name)
		case authErr.Type == AuthErrorToolNotClassified:
			refusedUnclassified = append(refusedUnclassified, tool.Name)
		default:
			t.Errorf("%s: unexpected refusal type %v (%s)", tool.Name, authErr.Type, authErr.Message)
		}
	}
	sort.Strings(admitted)

	// The admitted set must be exactly the tools mapped to "": no permission
	// required. Anything else admitted without a backend is the defect.
	var explicitlyOpen []string
	for name, permission := range checker.toolPermissions {
		if permission == "" {
			explicitlyOpen = append(explicitlyOpen, name)
		}
	}
	sort.Strings(explicitlyOpen)
	assert.Equal(t, explicitlyOpen, admitted,
		"with no authorization backend, only tools explicitly mapped to \"\" may be admitted")

	assert.Equal(t, len(tools), len(admitted)+len(refusedMissingToken)+len(refusedUnclassified),
		"every registered tool must be accounted for")
	assert.NotEmpty(t, refusedMissingToken,
		"no mapped tool was refused for the missing backend; the fail-closed branch is not reached")
	assert.NotEmpty(t, refusedUnclassified,
		"no unmapped tool was refused; the map lookup no longer runs before the backend check")
	t.Logf("registered=%d admitted(open)=%d refused(no backend)=%d refused(unclassified)=%d",
		len(tools), len(admitted), len(refusedMissingToken), len(refusedUnclassified))
}

// TestNoAuthorizationBackend_RefusalNamesTheCause pins the message an operator
// reads on the wire: the refusal is the existing authentication-required
// error (-32001), and it says WHY -- no backend -- so a misconfigured node is
// diagnosed from the response rather than from a Warn line in a log.
func TestNoAuthorizationBackend_RefusalNamesTheCause(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	_, authErr := checker.AuthorizeTool(context.Background(), "platform_bmc_power_off", "any-token")
	require.NotNil(t, authErr, "a protected tool must be refused without a backend even when a token is presented: nothing can validate it")
	assert.Equal(t, AuthErrorMissingToken, authErr.Type)
	assert.Contains(t, authErr.Message, "no authorization backend is configured")
}
