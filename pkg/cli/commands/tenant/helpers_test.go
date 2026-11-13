package tenant

import (
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		ts       time.Time
		expected string
	}{
		{name: "zero time", ts: time.Time{}, expected: "N/A"},
		{name: "valid time", ts: time.Date(2025, 1, 15, 12, 30, 0, 0, time.UTC), expected: "2025-01-15T12:30:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.ts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatQuotaValue(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		suffix   string
		expected string
	}{
		{name: "unlimited zero", value: 0, suffix: "", expected: "unlimited"},
		{name: "unlimited negative", value: -1, suffix: "", expected: "unlimited"},
		{name: "value no suffix", value: 100, suffix: "", expected: "100"},
		{name: "value with suffix", value: 512, suffix: "MB", expected: "512 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatQuotaValue(tt.value, tt.suffix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatState(t *testing.T) {
	result := formatState(sdktenant.StateActive)
	assert.Equal(t, "TENANT_STATE_ACTIVE", result)
}

func TestFormatLabels(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		expected string
	}{
		{name: "nil labels", labels: nil, expected: "none"},
		{name: "empty labels", labels: map[string]string{}, expected: "none"},
		{name: "single label", labels: map[string]string{"env": "prod"}, expected: "env=prod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatLabels(tt.labels)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatAnnotations(t *testing.T) {
	result := formatAnnotations(nil)
	assert.Equal(t, "none", result)

	result = formatAnnotations(map[string]string{"key": "val"})
	assert.Contains(t, result, "key=val")
}

func TestToQuotaSummary(t *testing.T) {
	tenant := &sdktenant.Tenant{
		ID:   "t1",
		Name: "test",
		ComputeQuota: &sdktenant.ComputeQuota{
			MaxVMs:        100,
			MaxContainers: 200,
			MaxVCPUs:      400,
			MaxMemoryMB:   8192,
		},
		NetworkQuota: &sdktenant.NetworkQuota{
			MaxBridges:       10,
			MaxPorts:         100,
			MaxBandwidthMbps: 1000,
		},
		StorageQuota: &sdktenant.StorageQuota{
			MaxVolumesGB: 500,
			MaxSnapshots: 50,
		},
	}

	summary := toQuotaSummary("t1", tenant)
	require.NotNil(t, summary)
	assert.Equal(t, "t1", summary.TenantID)
	assert.Equal(t, int64(100), summary.Compute.MaxVMs)
	assert.Equal(t, int64(200), summary.Compute.MaxContainers)
	assert.Equal(t, int64(400), summary.Compute.MaxVCPUs)
	assert.Equal(t, int64(8192), summary.Compute.MaxMemoryMB)
	assert.Equal(t, int64(10), summary.Network.MaxBridges)
	assert.Equal(t, int64(100), summary.Network.MaxPorts)
	assert.Equal(t, int64(1000), summary.Network.MaxBandwidthMbps)
	assert.Equal(t, int64(500), summary.Storage.MaxVolumesGB)
	assert.Equal(t, int64(50), summary.Storage.MaxSnapshots)
}

func TestToQuotaSummary_NilQuotas(t *testing.T) {
	tenant := &sdktenant.Tenant{ID: "t1", Name: "test"}
	summary := toQuotaSummary("t1", tenant)
	require.NotNil(t, summary)
	assert.Equal(t, int64(0), summary.Compute.MaxVMs)
	assert.Equal(t, int64(0), summary.Network.MaxBridges)
	assert.Equal(t, int64(0), summary.Storage.MaxVolumesGB)
}

// TestToUsageSummary: each used value sits beside the quota of the same
// resource, and storage in use is the disk usage in GB.
func TestToUsageSummary(t *testing.T) {
	tenant := &sdktenant.Tenant{
		ID: "t1",
		ComputeQuota: &sdktenant.ComputeQuota{
			MaxVMs:   100,
			MaxVCPUs: 400,
		},
		NetworkQuota: &sdktenant.NetworkQuota{
			MaxBridges:       10,
			MaxBandwidthMbps: 1000,
		},
		StorageQuota: &sdktenant.StorageQuota{
			MaxVolumesGB: 500,
		},
	}
	usage := &platformv1.TenantUsage{TenantId: "t1", Vms: 3, Vcpus: 12, Bridges: 2, BandwidthMbps: 250, Volumes: 4, DiskGb: 80}

	summary := toUsageSummary(tenant, usage)
	require.NotNil(t, summary)
	assert.Equal(t, "t1", summary.TenantID)
	assert.Equal(t, UsageItem{Used: 3, Max: 100}, summary.Compute.VMs)
	assert.Equal(t, UsageItem{Used: 12, Max: 400}, summary.Compute.VCPUs)
	assert.Equal(t, UsageItem{Used: 2, Max: 10}, summary.Network.Bridges)
	assert.Equal(t, UsageItem{Used: 250, Max: 1000}, summary.Network.BandwidthMbps)
	assert.Equal(t, UsageItem{Used: 80, Max: 500}, summary.Storage.VolumesGB, "GB in use against the GB quota, not the volume count")
}

// TestToUsageSummary_NilQuotasAndUsage: a tenant with no quotas and no usage
// reported gives zeros, not a panic.
func TestToUsageSummary_NilQuotasAndUsage(t *testing.T) {
	summary := toUsageSummary(&sdktenant.Tenant{ID: "t1"}, nil)
	require.NotNil(t, summary)
	assert.Equal(t, "t1", summary.TenantID)
	assert.Equal(t, UsageItem{}, summary.Compute.VMs)
	assert.Equal(t, UsageItem{}, summary.Storage.Snapshots)
}
