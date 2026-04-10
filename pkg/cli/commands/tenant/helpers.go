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
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// formatTime formats a time.Time for display.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatVLANRange formats a VLAN range for display
func formatVLANRange(start, end uint32) string {
	if start == 0 && end == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// formatVLANSize formats the size of a VLAN range
func formatVLANSize(start, end uint32) string {
	if start == 0 && end == 0 {
		return "0"
	}
	size := int(end-start) + 1
	return fmt.Sprintf("%d", size)
}

// formatQuotaValue formats a quota value for display
func formatQuotaValue(value int64, suffix string) string {
	if value <= 0 {
		return "unlimited"
	}
	if suffix != "" {
		return fmt.Sprintf("%d %s", value, suffix)
	}
	return fmt.Sprintf("%d", value)
}

// formatState formats a domain TenantState for display.
func formatState(state sdktenant.TenantState) string {
	return string(state)
}

// formatLabels formats a label map for display
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ", ")
}

// formatAnnotations formats an annotation map for display
func formatAnnotations(annotations map[string]string) string {
	return formatLabels(annotations)
}

// printTenantDetails prints tenant details from domain types in a formatted way.
func printTenantDetails(printer *cli.Printer, t *sdktenant.Tenant) {
	printer.PrintKeyValue("ID", t.ID)
	printer.PrintKeyValue("Name", t.Name)
	printer.PrintKeyValue("Display Name", t.DisplayName)
	printer.PrintKeyValue("State", formatState(t.State))
	printer.PrintKeyValue("OVS Bridge", t.OVSBridge)
	printer.PrintKeyValue("VLAN Range", formatVLANRange(t.VLANStart, t.VLANEnd))
	printer.PrintKeyValue("VLAN Count", formatVLANSize(t.VLANStart, t.VLANEnd))

	fmt.Println()
	printer.PrintKeyValue("Labels", formatLabels(t.Labels))
	printer.PrintKeyValue("Annotations", formatAnnotations(t.Annotations))

	fmt.Println()
	printer.PrintKeyValue("Created At", formatTime(t.CreatedAt))
	printer.PrintKeyValue("Updated At", formatTime(t.UpdatedAt))

	if t.ComputeQuota != nil {
		fmt.Println()
		printComputeQuota(printer, t.ComputeQuota)
	}

	if t.NetworkQuota != nil {
		fmt.Println()
		printNetworkQuota(printer, t.NetworkQuota)
	}

	if t.StorageQuota != nil {
		fmt.Println()
		printStorageQuota(printer, t.StorageQuota)
	}
}

// printComputeQuota prints compute quota details from domain types.
func printComputeQuota(printer *cli.Printer, quota *sdktenant.ComputeQuota) {
	fmt.Println("Compute Quotas:")
	printer.PrintKeyValue("  Max VMs", formatQuotaValue(quota.MaxVMs, ""))
	printer.PrintKeyValue("  Max Containers", formatQuotaValue(quota.MaxContainers, ""))
	printer.PrintKeyValue("  Max vCPUs", formatQuotaValue(quota.MaxVCPUs, ""))
	printer.PrintKeyValue("  Max Memory", formatQuotaValue(quota.MaxMemoryMB, "MB"))
}

// printNetworkQuota prints network quota details from domain types.
func printNetworkQuota(printer *cli.Printer, quota *sdktenant.NetworkQuota) {
	fmt.Println("Network Quotas:")
	printer.PrintKeyValue("  Max Bridges", formatQuotaValue(quota.MaxBridges, ""))
	printer.PrintKeyValue("  Max Ports", formatQuotaValue(quota.MaxPorts, ""))
	printer.PrintKeyValue("  Max Bandwidth", formatQuotaValue(quota.MaxBandwidthMbps, "Mbps"))
}

// printStorageQuota prints storage quota details from domain types.
func printStorageQuota(printer *cli.Printer, quota *sdktenant.StorageQuota) {
	fmt.Println("Storage Quotas:")
	printer.PrintKeyValue("  Max Volumes", formatQuotaValue(quota.MaxVolumesGB, "GB"))
	printer.PrintKeyValue("  Max Snapshots", formatQuotaValue(quota.MaxSnapshots, ""))
}

// TenantSummary is a simplified tenant representation for JSON/YAML output
type TenantSummary struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	DisplayName string            `json:"display_name" yaml:"display_name"`
	State       string            `json:"state" yaml:"state"`
	OVSBridge   string            `json:"ovs_bridge" yaml:"ovs_bridge"`
	VLANStart   uint32            `json:"vlan_start" yaml:"vlan_start"`
	VLANEnd     uint32            `json:"vlan_end" yaml:"vlan_end"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	CreatedAt   string            `json:"created_at" yaml:"created_at"`
	UpdatedAt   string            `json:"updated_at" yaml:"updated_at"`
}

// QuotaSummary is a quota representation for JSON/YAML output
type QuotaSummary struct {
	TenantID string         `json:"tenant_id" yaml:"tenant_id"`
	Compute  ComputeSummary `json:"compute" yaml:"compute"`
	Network  NetworkSummary `json:"network" yaml:"network"`
	Storage  StorageSummary `json:"storage" yaml:"storage"`
}

// ComputeSummary is a compute quota representation
type ComputeSummary struct {
	MaxVMs        int64 `json:"max_vms" yaml:"max_vms"`
	MaxContainers int64 `json:"max_containers" yaml:"max_containers"`
	MaxVCPUs      int64 `json:"max_vcpus" yaml:"max_vcpus"`
	MaxMemoryMB   int64 `json:"max_memory_mb" yaml:"max_memory_mb"`
}

// NetworkSummary is a network quota representation
type NetworkSummary struct {
	MaxBridges       int64 `json:"max_bridges" yaml:"max_bridges"`
	MaxPorts         int64 `json:"max_ports" yaml:"max_ports"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps" yaml:"max_bandwidth_mbps"`
}

// StorageSummary is a storage quota representation
type StorageSummary struct {
	MaxVolumesGB int64 `json:"max_volumes_gb" yaml:"max_volumes_gb"`
	MaxSnapshots int64 `json:"max_snapshots" yaml:"max_snapshots"`
}

// toQuotaSummary converts a domain Tenant to QuotaSummary.
func toQuotaSummary(tenantID string, t *sdktenant.Tenant) *QuotaSummary {
	summary := &QuotaSummary{
		TenantID: tenantID,
		Compute:  ComputeSummary{},
		Network:  NetworkSummary{},
		Storage:  StorageSummary{},
	}

	if t.ComputeQuota != nil {
		summary.Compute = ComputeSummary{
			MaxVMs:        t.ComputeQuota.MaxVMs,
			MaxContainers: t.ComputeQuota.MaxContainers,
			MaxVCPUs:      t.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   t.ComputeQuota.MaxMemoryMB,
		}
	}

	if t.NetworkQuota != nil {
		summary.Network = NetworkSummary{
			MaxBridges:       t.NetworkQuota.MaxBridges,
			MaxPorts:         t.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: t.NetworkQuota.MaxBandwidthMbps,
		}
	}

	if t.StorageQuota != nil {
		summary.Storage = StorageSummary{
			MaxVolumesGB: t.StorageQuota.MaxVolumesGB,
			MaxSnapshots: t.StorageQuota.MaxSnapshots,
		}
	}

	return summary
}

// UsageSummary is a usage representation for JSON/YAML output
// Note: Usage is tracked separately from quotas via TenantUsage messages
type UsageSummary struct {
	TenantID string              `json:"tenant_id" yaml:"tenant_id"`
	Compute  ComputeUsageSummary `json:"compute" yaml:"compute"`
	Network  NetworkUsageSummary `json:"network" yaml:"network"`
	Storage  StorageUsageSummary `json:"storage" yaml:"storage"`
}

// ComputeUsageSummary is a compute usage representation
type ComputeUsageSummary struct {
	VMs        UsageItem `json:"vms" yaml:"vms"`
	Containers UsageItem `json:"containers" yaml:"containers"`
	VCPUs      UsageItem `json:"vcpus" yaml:"vcpus"`
	MemoryMB   UsageItem `json:"memory_mb" yaml:"memory_mb"`
}

// NetworkUsageSummary is a network usage representation
type NetworkUsageSummary struct {
	Bridges UsageItem `json:"bridges" yaml:"bridges"`
	Ports   UsageItem `json:"ports" yaml:"ports"`
}

// StorageUsageSummary is a storage usage representation
type StorageUsageSummary struct {
	VolumesGB UsageItem `json:"volumes_gb" yaml:"volumes_gb"`
	Snapshots UsageItem `json:"snapshots" yaml:"snapshots"`
}

// UsageItem represents used/max values
type UsageItem struct {
	Used int64 `json:"used" yaml:"used"`
	Max  int64 `json:"max" yaml:"max"`
}

// toUsageSummary converts a domain Tenant to UsageSummary.
// Note: The quota messages only contain max values, not usage. This returns 0 for used
// values. To get actual usage, you would need to query TenantUsage separately.
func toUsageSummary(tenantID string, t *sdktenant.Tenant) *UsageSummary {
	summary := &UsageSummary{
		TenantID: tenantID,
		Compute:  ComputeUsageSummary{},
		Network:  NetworkUsageSummary{},
		Storage:  StorageUsageSummary{},
	}

	if t.ComputeQuota != nil {
		summary.Compute = ComputeUsageSummary{
			VMs:        UsageItem{Used: 0, Max: t.ComputeQuota.MaxVMs},
			Containers: UsageItem{Used: 0, Max: t.ComputeQuota.MaxContainers},
			VCPUs:      UsageItem{Used: 0, Max: t.ComputeQuota.MaxVCPUs},
			MemoryMB:   UsageItem{Used: 0, Max: t.ComputeQuota.MaxMemoryMB},
		}
	}

	if t.NetworkQuota != nil {
		summary.Network = NetworkUsageSummary{
			Bridges: UsageItem{Used: 0, Max: t.NetworkQuota.MaxBridges},
			Ports:   UsageItem{Used: 0, Max: t.NetworkQuota.MaxPorts},
		}
	}

	if t.StorageQuota != nil {
		summary.Storage = StorageUsageSummary{
			VolumesGB: UsageItem{Used: 0, Max: t.StorageQuota.MaxVolumesGB},
			Snapshots: UsageItem{Used: 0, Max: t.StorageQuota.MaxSnapshots},
		}
	}

	return summary
}

// VLANInfo represents VLAN information for JSON/YAML output
type VLANInfo struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	VLANStart  uint32 `json:"vlan_start" yaml:"vlan_start"`
	VLANEnd    uint32 `json:"vlan_end" yaml:"vlan_end"`
	VLANCount  int    `json:"vlan_count" yaml:"vlan_count"`
}

// toVLANInfo converts a domain Tenant to VLANInfo.
func toVLANInfo(t *sdktenant.Tenant) *VLANInfo {
	count := 0
	if t.VLANStart > 0 && t.VLANEnd > 0 {
		count = int(t.VLANEnd-t.VLANStart) + 1
	}
	return &VLANInfo{
		TenantID:   t.ID,
		TenantName: t.Name,
		VLANStart:  t.VLANStart,
		VLANEnd:    t.VLANEnd,
		VLANCount:  count,
	}
}

// BridgeInfo represents bridge information for JSON/YAML output
type BridgeInfo struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	BridgeName string `json:"bridge_name" yaml:"bridge_name"`
	State      string `json:"state" yaml:"state"`
	VLANStart  uint32 `json:"vlan_start" yaml:"vlan_start"`
	VLANEnd    uint32 `json:"vlan_end" yaml:"vlan_end"`
}

// toBridgeInfo converts a domain Tenant to BridgeInfo.
func toBridgeInfo(t *sdktenant.Tenant) *BridgeInfo {
	return &BridgeInfo{
		TenantID:   t.ID,
		TenantName: t.Name,
		BridgeName: t.OVSBridge,
		State:      string(t.State),
		VLANStart:  t.VLANStart,
		VLANEnd:    t.VLANEnd,
	}
}
