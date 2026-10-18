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
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// =============================================================================
// printTenantDetails Tests
// =============================================================================

func TestPrintTenantDetails_FullTenant(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	tenant := &sdktenant.Tenant{
		ID:          "t1",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		State:       sdktenant.StateActive,
		Labels:      map[string]string{"env": "prod"},
		Annotations: map[string]string{"note": "test"},
		CreatedAt:   now,
		UpdatedAt:   now,
		ComputeQuota: &sdktenant.ComputeQuota{
			MaxVMs:        50,
			MaxContainers: 100,
			MaxVCPUs:      200,
			MaxMemoryMB:   4096,
		},
		NetworkQuota: &sdktenant.NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         50,
			MaxBandwidthMbps: 1000,
		},
		StorageQuota: &sdktenant.StorageQuota{
			MaxVolumesGB: 500,
			MaxSnapshots: 25,
		},
	}

	printTenantDetails(printer, tenant)
	out := output.String()
	assert.Contains(t, out, "t1")
	assert.Contains(t, out, "test-tenant")
	assert.Contains(t, out, "Test Tenant")
}

func TestPrintTenantDetails_NoQuotas(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	tenant := &sdktenant.Tenant{
		ID:    "t2",
		Name:  "minimal",
		State: sdktenant.StateActive,
	}

	printTenantDetails(printer, tenant)
	out := output.String()
	assert.Contains(t, out, "t2")
	assert.Contains(t, out, "minimal")
}

// =============================================================================
// printComputeQuota Tests
// =============================================================================

func TestPrintComputeQuota(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	quota := &sdktenant.ComputeQuota{
		MaxVMs:        10,
		MaxContainers: 20,
		MaxVCPUs:      40,
		MaxMemoryMB:   2048,
	}

	printComputeQuota(printer, quota)
	out := output.String()
	assert.Contains(t, out, "10")
	assert.Contains(t, out, "20")
	assert.Contains(t, out, "40")
	assert.Contains(t, out, "2048")
}

// =============================================================================
// printNetworkQuota Tests
// =============================================================================

func TestPrintNetworkQuota(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	quota := &sdktenant.NetworkQuota{
		MaxBridges:       5,
		MaxPorts:         50,
		MaxBandwidthMbps: 1000,
	}

	printNetworkQuota(printer, quota)
	out := output.String()
	assert.Contains(t, out, "5")
	assert.Contains(t, out, "50")
	assert.Contains(t, out, "1000")
}

// =============================================================================
// printStorageQuota Tests
// =============================================================================

func TestPrintStorageQuota(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	quota := &sdktenant.StorageQuota{
		MaxVolumesGB: 100,
		MaxSnapshots: 10,
	}

	printStorageQuota(printer, quota)
	out := output.String()
	assert.Contains(t, out, "100")
	assert.Contains(t, out, "10")
}

// =============================================================================
// truncateID Tests
// =============================================================================

func TestTruncateID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short ID", "abc123", "abc123"},
		{"exact 12 chars", "123456789012", "123456789012"},
		{"long ID", "1234567890123456", "123456789012..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, truncateID(tt.input))
		})
	}
}

// =============================================================================
// formatQuotaLimit Tests
// =============================================================================

func TestFormatQuotaLimit(t *testing.T) {
	tests := []struct {
		name     string
		limit    int64
		expected string
	}{
		{"zero is unlimited", 0, "unlimited"},
		{"negative is unlimited", -1, "unlimited"},
		{"positive value", 100, "100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatQuotaLimit(tt.limit))
		})
	}
}

// =============================================================================
// printUsageTable Tests
// =============================================================================

// TestPrintUsageTable: every resource gets a row with what is used and its
// limit, and a 0 limit reads as unlimited.
func TestPrintUsageTable(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	summary := &UsageSummary{
		Compute: ComputeUsageSummary{VMs: UsageItem{Used: 3, Max: 50}},
		Storage: StorageUsageSummary{VolumesGB: UsageItem{Used: 80, Max: 0}},
	}

	require.NoError(t, printUsageTable(printer, summary))
	text := output.String()
	for _, label := range []string{"VMs", "Containers", "vCPUs", "Memory (MB)", "Bridges", "Ports", "Bandwidth (Mbps)", "Volumes (GB)", "Snapshots"} {
		assert.Contains(t, text, label)
	}
	assert.Regexp(t, `VMs\s+3\s+50`, text)
	assert.Regexp(t, `Volumes \(GB\)\s+80\s+unlimited`, text)
}

// =============================================================================
// toTenantDetail Tests
// =============================================================================

func TestToTenantDetail_FullTenant(t *testing.T) {
	now := time.Now()
	tenant := &sdktenant.Tenant{
		ID:          "t1",
		Name:        "test",
		DisplayName: "Test",
		State:       sdktenant.StateActive,
		Labels:      map[string]string{"env": "prod"},
		Annotations: map[string]string{"note": "test"},
		CreatedAt:   now,
		UpdatedAt:   now,
		ComputeQuota: &sdktenant.ComputeQuota{
			MaxVMs: 50, MaxContainers: 100, MaxVCPUs: 200, MaxMemoryMB: 4096,
		},
		NetworkQuota: &sdktenant.NetworkQuota{
			MaxBridges: 5, MaxPorts: 50, MaxBandwidthMbps: 1000,
		},
		StorageQuota: &sdktenant.StorageQuota{
			MaxVolumesGB: 500, MaxSnapshots: 25,
		},
	}

	detail := toTenantDetail(tenant)
	require.NotNil(t, detail)
	assert.Equal(t, "t1", detail.ID)
	assert.Equal(t, "test", detail.Name)
	assert.Equal(t, "Test", detail.DisplayName)

	require.NotNil(t, detail.Quotas)
	require.NotNil(t, detail.Quotas.Compute)
	assert.Equal(t, int64(50), detail.Quotas.Compute.MaxVMs)
	require.NotNil(t, detail.Quotas.Network)
	assert.Equal(t, int64(5), detail.Quotas.Network.MaxBridges)
	require.NotNil(t, detail.Quotas.Storage)
	assert.Equal(t, int64(500), detail.Quotas.Storage.MaxVolumesGB)
}

func TestNewShowCommand_Structure(t *testing.T) {
	cmd := NewShowCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "show")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestNewSuspendCommand_Structure(t *testing.T) {
	cmd := NewSuspendCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "suspend")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestNewResumeCommand_Structure(t *testing.T) {
	cmd := NewResumeCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "resume")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestNewUsageCommand_Structure(t *testing.T) {
	cmd := NewUsageCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "usage")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestNewQuotasGetCommand_Structure(t *testing.T) {
	cmd := newQuotasGetCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "get")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestToTenantDetail_Minimal(t *testing.T) {
	tenant := &sdktenant.Tenant{
		ID:    "t2",
		Name:  "minimal",
		State: sdktenant.StateActive,
	}

	detail := toTenantDetail(tenant)
	require.NotNil(t, detail)
	require.NotNil(t, detail.Quotas)
	require.NotNil(t, detail.Quotas.Compute)
	assert.Equal(t, int64(0), detail.Quotas.Compute.MaxVMs)
}
