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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewQuotasCheckCommand(t *testing.T) {
	cmd := newQuotasCheckCommand(testGetFlags)

	assert.Equal(t, "check <tenant-name>", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("resource"))
	assert.NotNil(t, cmd.Flags().Lookup("amount"))
	assert.Error(t, cmd.Args(cmd, nil), "the tenant name is required")

	found := false
	for _, sub := range NewQuotasCommand(testGetFlags).Commands() {
		found = found || sub.Use == cmd.Use
	}
	assert.True(t, found, "quotas registers check")
}

// TestRunQuotasCheck_OverQuotaIsAResult: a request within quota and one over
// it both succeed; going over quota is an answer, not a failure.
func TestRunQuotasCheck_OverQuotaIsAResult(t *testing.T) {
	_, flags := startTenantServer(t)
	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		name := "acme-" + string(format)
		f := flags(format)
		require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: name, MaxVMs: 5}))

		assert.NoError(t, runQuotasCheck(f, name, "vms", 1))
		assert.NoError(t, runQuotasCheck(f, name, "vms", 100))
	}
}

func TestRunQuotasCheck_Errors(t *testing.T) {
	_, flags := startTenantServer(t)
	f := flags(cli.OutputFormatTable)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "acme", MaxVMs: 5}))

	var invalid ErrInvalidArguments
	assert.True(t, errors.As(runQuotasCheck(f, "acme", "", 1), &invalid), "--resource is required")

	var badAmount ErrInvalidQuotaValue
	assert.True(t, errors.As(runQuotasCheck(f, "acme", "vms", 0), &badAmount), "amount must be positive")

	var notFound ErrTenantNotFound
	assert.True(t, errors.As(runQuotasCheck(f, "ghost", "vms", 1), &notFound))

	var opErr ErrOperationFailed
	assert.True(t, errors.As(runQuotasCheck(f, "acme", "gpus", 1), &opErr), "the server rejects an unknown resource")
	assert.Equal(t, "quotas check", opErr.Operation)

	var badFormat cli.ErrInvalidOutputFormat
	assert.True(t, errors.As(runQuotasCheck(flags("xml"), "acme", "vms", 1), &badFormat))
}
