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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenantpkg "github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

func TestCLIAdapterQuotaSetArgs(t *testing.T) {
	args, err := quotaSetArgs(UpdateQuotasOptions{
		Compute: &ComputeQuotaUpdate{MaxVMs: 20, MaxVCPUs: 80, MaxMemoryMB: 131072, MaxDiskGB: 1000},
		Storage: &StorageQuotaUpdate{MaxSnapshots: 5},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"--max-vms", "20", "--max-containers", "0", "--max-vcpus", "80", "--max-memory-gb", "128",
		"--max-volumes-gb", "0", "--max-snapshots", "5",
	}, args, "every field of a given section is passed, memory in GB, disk on no flag, network left out")
}

func TestCLIAdapterQuotaSetArgs_PartialGigabyte(t *testing.T) {
	_, err := quotaSetArgs(UpdateQuotasOptions{Compute: &ComputeQuotaUpdate{MaxMemoryMB: 1500}})
	var unsupported ErrCLIUnsupportedValue
	require.True(t, errors.As(err, &unsupported), "a memory quota that is not whole GB is refused, not rounded")
	assert.Equal(t, "MaxMemoryMB", unsupported.Field)
}

func TestCLIAdapterJoinPairs(t *testing.T) {
	assert.Equal(t, "a=1,env=prod", joinPairs(map[string]string{"env": "prod", "a": "1"}))
	assert.Empty(t, joinPairs(nil))
}

func TestCLIAdapterTenantDetail(t *testing.T) {
	detail := cliTenantDetail{
		ID:        "t-1",
		Name:      "acme",
		State:     "TENANT_STATE_SUSPENDED",
		CreatedAt: "2026-10-16T08:00:00Z",
		UpdatedAt: "N/A",
	}
	detail.Quotas.Compute = &ComputeQuotaData{MaxVMs: 10}

	data, err := detail.toTenantData()
	require.NoError(t, err)
	assert.Equal(t, tenantpkg.StateSuspended, data.State, "the CLI's SDK state maps to the tenant state")
	assert.Equal(t, int64(10), data.ComputeQuota.MaxVMs)
	assert.Equal(t, time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC), data.CreatedAt.UTC())
	assert.True(t, data.UpdatedAt.IsZero(), "N/A is an unset time")
}

func TestCLIAdapterTenantDetail_BadTime(t *testing.T) {
	detail := cliTenantDetail{CreatedAt: "yesterday"}
	_, err := detail.toTenantData()
	var failed ErrCLICommandFailed
	require.True(t, errors.As(err, &failed))
	assert.Equal(t, "created_at", failed.Operation)
}

// TestCLIAdapterNameForID_Cached: a tenant the adapter has seen resolves
// without running the CLI.
func TestCLIAdapterNameForID_Cached(t *testing.T) {
	a := &CLIAdapter{cliPath: "false"}
	a.remember("t-1", "acme")

	name, err := a.nameForID(context.Background(), "t-1")
	require.NoError(t, err)
	assert.Equal(t, "acme", name)
}

// TestCLIAdapterNameForID_Errors: an unseen ID goes to `tenant list`, and its
// failure is reported.
func TestCLIAdapterNameForID_Errors(t *testing.T) {
	a := &CLIAdapter{cliPath: "false"}
	_, err := a.nameForID(context.Background(), "t-1")
	var failed ErrCLICommandFailed
	require.True(t, errors.As(err, &failed))
	assert.Contains(t, failed.Operation, "tenant list")
}

// TestCLIAdapterRunJSON_NotJSON: output that is not JSON is a typed failure
// carrying the output.
func TestCLIAdapterRunJSON_NotJSON(t *testing.T) {
	a := &CLIAdapter{cliPath: "echo"}
	var out struct{}
	err := a.runJSON(context.Background(), "Echo", &out, "hello")
	var failed ErrCLICommandFailed
	require.True(t, errors.As(err, &failed))
	assert.Equal(t, "Echo", failed.Operation)
	assert.Contains(t, failed.Output, "hello --output json")
}

func TestCLIAdapterTeardown_RemovesConfigDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("x"), 0o600))

	a := &CLIAdapter{configDir: dir}
	require.NoError(t, a.Teardown(context.Background()))
	_, err := os.Stat(dir)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestCLIAdapterTeardown_NoConfigDir(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	a := &CLIAdapter{}
	require.NoError(t, a.Teardown(context.Background()))
	_, err = os.Stat(cwd)
	assert.NoError(t, err, "Teardown without a config dir must not remove anything")
}
