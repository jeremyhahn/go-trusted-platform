package tenant

import (
	"testing"
	"time"

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

func TestToUsageSummary(t *testing.T) {
	tenant := &sdktenant.Tenant{
		ID: "t1",
		ComputeQuota: &sdktenant.ComputeQuota{
			MaxVMs:   100,
			MaxVCPUs: 400,
		},
		NetworkQuota: &sdktenant.NetworkQuota{
			MaxBridges: 10,
		},
		StorageQuota: &sdktenant.StorageQuota{
			MaxVolumesGB: 500,
		},
	}

	summary := toUsageSummary("t1", tenant)
	require.NotNil(t, summary)
	assert.Equal(t, "t1", summary.TenantID)
	assert.Equal(t, int64(0), summary.Compute.VMs.Used)
	assert.Equal(t, int64(100), summary.Compute.VMs.Max)
	assert.Equal(t, int64(0), summary.Network.Bridges.Used)
	assert.Equal(t, int64(10), summary.Network.Bridges.Max)
}

func TestToUsageSummary_NilQuotas(t *testing.T) {
	tenant := &sdktenant.Tenant{ID: "t1"}
	summary := toUsageSummary("t1", tenant)
	require.NotNil(t, summary)
	assert.Equal(t, int64(0), summary.Compute.VMs.Max)
}

func TestTenantSummaryStruct(t *testing.T) {
	summary := TenantSummary{
		ID:          "t1",
		Name:        "test",
		DisplayName: "Test Tenant",
		State:       "active",
		Labels:      map[string]string{"env": "prod"},
		Annotations: map[string]string{"note": "test"},
		CreatedAt:   "2025-01-15T12:00:00Z",
		UpdatedAt:   "2025-01-16T12:00:00Z",
	}

	assert.Equal(t, "t1", summary.ID)
	assert.Equal(t, "test", summary.Name)
	assert.Equal(t, "Test Tenant", summary.DisplayName)
}
