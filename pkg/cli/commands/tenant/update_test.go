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

func TestNewUpdateCommand(t *testing.T) {
	cmd := NewUpdateCommand(testGetFlags)

	assert.Equal(t, "update <tenant-name>", cmd.Use)
	for _, name := range []string{"display-name", "labels", "annotations"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "flag --%s", name)
	}
	assert.Error(t, cmd.Args(cmd, nil), "the tenant name is required")
	assert.NoError(t, cmd.Args(cmd, []string{"acme"}))
}

// TestRunTenantUpdate_ChangesTheTenant: the values given reach the server and
// a value not given is left alone.
func TestRunTenantUpdate_ChangesTheTenant(t *testing.T) {
	srv, flags := startTenantServer(t)
	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		name := "acme-" + string(format)
		f := flags(format)
		require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: name, DisplayName: "Before"}))

		require.NoError(t, runTenantUpdate(f, name, &updateTenantOptions{Labels: map[string]string{"env": "prod"}}))
		require.NoError(t, runTenantUpdate(f, name, &updateTenantOptions{DisplayName: "After"}))

		srv.mu.Lock()
		stored, err := srv.byName(name)
		srv.mu.Unlock()
		require.NoError(t, err)
		assert.Equal(t, "After", stored.GetDisplayName())
		assert.Equal(t, map[string]string{"env": "prod"}, stored.GetLabels(), "the second update gave no labels")
	}
}

func TestRunTenantUpdate_Errors(t *testing.T) {
	srv, flags := startTenantServer(t)
	f := flags(cli.OutputFormatTable)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "acme"}))

	var invalid ErrInvalidArguments
	assert.True(t, errors.As(runTenantUpdate(f, "acme", &updateTenantOptions{}), &invalid),
		"an update that changes nothing is refused before any call")

	var notFound ErrTenantNotFound
	assert.True(t, errors.As(runTenantUpdate(f, "ghost", &updateTenantOptions{DisplayName: "x"}), &notFound))

	var badFormat cli.ErrInvalidOutputFormat
	assert.True(t, errors.As(runTenantUpdate(flags("xml"), "acme", &updateTenantOptions{DisplayName: "x"}), &badFormat))

	srv.mu.Lock()
	srv.fail = status.Error(codes.Internal, "backend down")
	srv.mu.Unlock()
	var opErr ErrOperationFailed
	assert.True(t, errors.As(runTenantUpdate(f, "acme", &updateTenantOptions{DisplayName: "x"}), &opErr))
	assert.Equal(t, "update", opErr.Operation)
}
