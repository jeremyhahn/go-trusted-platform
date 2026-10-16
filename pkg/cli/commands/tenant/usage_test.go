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

// TestRunTenantUsage_AsksTheServer: usage is fetched from the server in every
// output format, not filled in as zeros from the quota.
func TestRunTenantUsage_AsksTheServer(t *testing.T) {
	_, flags := startTenantServer(t)
	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON, cli.OutputFormatYAML} {
		name := "acme-" + string(format)
		f := flags(format)
		require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: name, MaxVMs: 5}))
		require.NoError(t, runTenantUsage(f, name))
	}
}

func TestRunTenantUsage_Errors(t *testing.T) {
	srv, flags := startTenantServer(t)
	f := flags(cli.OutputFormatTable)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "acme"}))

	var notFound ErrTenantNotFound
	assert.True(t, errors.As(runTenantUsage(f, "ghost"), &notFound))

	var badFormat cli.ErrInvalidOutputFormat
	assert.True(t, errors.As(runTenantUsage(flags("xml"), "acme"), &badFormat))

	srv.mu.Lock()
	srv.fail = status.Error(codes.Internal, "usage tracker down")
	srv.mu.Unlock()
	var usageErr ErrUsageRetrievalFailed
	require.True(t, errors.As(runTenantUsage(f, "acme"), &usageErr), "a failed usage call is reported, not printed as zero usage")
	assert.NotEmpty(t, usageErr.TenantID)
}
