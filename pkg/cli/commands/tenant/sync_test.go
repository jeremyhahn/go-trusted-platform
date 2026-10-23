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

package tenant

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewSyncCommand(t *testing.T) {
	cmd := NewSyncCommand(testGetFlags)

	assert.Equal(t, "sync", cmd.Use)
	assert.NoError(t, cmd.Args(cmd, nil))
	assert.Error(t, cmd.Args(cmd, []string{"acme"}), "sync takes no tenant")
}

// TestRunTenantSync_Idempotent: sync succeeds and succeeds again.
func TestRunTenantSync_Idempotent(t *testing.T) {
	_, flags := startTenantServer(t)
	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON, cli.OutputFormatYAML} {
		require.NoError(t, runTenantSync(flags(format)))
		require.NoError(t, runTenantSync(flags(format)))
	}
}

func TestRunTenantSync_Errors(t *testing.T) {
	srv, flags := startTenantServer(t)

	var badFormat cli.ErrInvalidOutputFormat
	assert.True(t, errors.As(runTenantSync(flags("xml")), &badFormat))

	var noCtx cli.ErrNoContextSet
	assert.True(t, errors.As(runTenantSync(&cli.CommonFlags{}), &noCtx))

	srv.mu.Lock()
	srv.fail = status.Error(codes.Internal, "backend down")
	srv.mu.Unlock()
	var opErr ErrOperationFailed
	assert.True(t, errors.As(runTenantSync(flags(cli.OutputFormatTable)), &opErr))
	assert.Equal(t, "sync", opErr.Operation)
}
