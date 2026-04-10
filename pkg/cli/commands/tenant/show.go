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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// NewShowCommand creates the tenant show subcommand
func NewShowCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <tenant-name>",
		Short: "Show tenant details",
		Long: `Display detailed information about a specific tenant.

Shows tenant configuration, quotas, VLAN allocation, and bridge status.

Examples:
  # Show tenant details
  platformctl tenant show my-tenant

  # Output as JSON
  platformctl tenant show my-tenant -o json

  # Output as YAML
  platformctl tenant show my-tenant -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantShow(flags, args[0])
		},
	}

	return cmd
}

func runTenantShow(flags *cli.CommonFlags, tenantName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	// Get the tenant by name using domain-typed method
	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toTenantDetail(t))

	case cli.OutputFormatTable:
		printTenantDetails(printer, t)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// TenantDetail is a detailed tenant representation for JSON/YAML output
type TenantDetail struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	DisplayName string            `json:"display_name" yaml:"display_name"`
	State       string            `json:"state" yaml:"state"`
	OVSBridge   string            `json:"ovs_bridge" yaml:"ovs_bridge"`
	VLANRange   *VLANRangeDetail  `json:"vlan_range" yaml:"vlan_range"`
	Quotas      *QuotaDetail      `json:"quotas" yaml:"quotas"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	CreatedAt   string            `json:"created_at" yaml:"created_at"`
	UpdatedAt   string            `json:"updated_at" yaml:"updated_at"`
}

// VLANRangeDetail represents VLAN range details
type VLANRangeDetail struct {
	Start uint32 `json:"start" yaml:"start"`
	End   uint32 `json:"end" yaml:"end"`
	Count int    `json:"count" yaml:"count"`
}

// QuotaDetail represents quota details
type QuotaDetail struct {
	Compute *ComputeQuotaDetail `json:"compute" yaml:"compute"`
	Network *NetworkQuotaDetail `json:"network" yaml:"network"`
	Storage *StorageQuotaDetail `json:"storage" yaml:"storage"`
}

// ComputeQuotaDetail represents compute quota details
type ComputeQuotaDetail struct {
	MaxVMs        int64 `json:"max_vms" yaml:"max_vms"`
	MaxContainers int64 `json:"max_containers" yaml:"max_containers"`
	MaxVCPUs      int64 `json:"max_vcpus" yaml:"max_vcpus"`
	MaxMemoryMB   int64 `json:"max_memory_mb" yaml:"max_memory_mb"`
}

// NetworkQuotaDetail represents network quota details
type NetworkQuotaDetail struct {
	MaxBridges       int64 `json:"max_bridges" yaml:"max_bridges"`
	MaxPorts         int64 `json:"max_ports" yaml:"max_ports"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps" yaml:"max_bandwidth_mbps"`
}

// StorageQuotaDetail represents storage quota details
type StorageQuotaDetail struct {
	MaxVolumesGB int64 `json:"max_volumes_gb" yaml:"max_volumes_gb"`
	MaxSnapshots int64 `json:"max_snapshots" yaml:"max_snapshots"`
}

// toTenantDetail converts a domain Tenant to TenantDetail for JSON/YAML output.
func toTenantDetail(t *sdktenant.Tenant) *TenantDetail {
	detail := &TenantDetail{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		State:       string(t.State),
		OVSBridge:   t.OVSBridge,
		Labels:      t.Labels,
		Annotations: t.Annotations,
		CreatedAt:   formatTime(t.CreatedAt),
		UpdatedAt:   formatTime(t.UpdatedAt),
	}

	if t.VLANStart > 0 || t.VLANEnd > 0 {
		detail.VLANRange = &VLANRangeDetail{
			Start: t.VLANStart,
			End:   t.VLANEnd,
			Count: int(t.VLANEnd - t.VLANStart + 1),
		}
	}

	detail.Quotas = &QuotaDetail{
		Compute: &ComputeQuotaDetail{},
		Network: &NetworkQuotaDetail{},
		Storage: &StorageQuotaDetail{},
	}

	if t.ComputeQuota != nil {
		detail.Quotas.Compute = &ComputeQuotaDetail{
			MaxVMs:        t.ComputeQuota.MaxVMs,
			MaxContainers: t.ComputeQuota.MaxContainers,
			MaxVCPUs:      t.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   t.ComputeQuota.MaxMemoryMB,
		}
	}

	if t.NetworkQuota != nil {
		detail.Quotas.Network = &NetworkQuotaDetail{
			MaxBridges:       t.NetworkQuota.MaxBridges,
			MaxPorts:         t.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: t.NetworkQuota.MaxBandwidthMbps,
		}
	}

	if t.StorageQuota != nil {
		detail.Quotas.Storage = &StorageQuotaDetail{
			MaxVolumesGB: t.StorageQuota.MaxVolumesGB,
			MaxSnapshots: t.StorageQuota.MaxSnapshots,
		}
	}

	return detail
}
