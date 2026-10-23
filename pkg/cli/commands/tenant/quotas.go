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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// NewQuotasCommand creates the tenant quotas command group
func NewQuotasCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quotas",
		Short: "Manage tenant quotas",
		Long: `Manage resource quotas for tenants.

Quotas control the maximum resources a tenant can consume across:
  - Compute: VMs, containers, vCPUs, memory
  - Network: bridges, ports, bandwidth
  - Storage: volumes, snapshots

Examples:
  # Get tenant quotas
  platformctl tenant quotas get my-tenant

  # Set compute quotas
  platformctl tenant quotas set my-tenant --max-vms 100 --max-vcpus 400

  # Set all quotas
  platformctl tenant quotas set my-tenant \
    --max-vms 100 --max-containers 200 --max-vcpus 400 --max-memory-gb 512 \
    --max-bridges 10 --max-ports 1000 \
    --max-volumes-gb 5000 --max-snapshots 100`,
	}

	cmd.AddCommand(newQuotasGetCommand(getFlags))
	cmd.AddCommand(newQuotasSetCommand(getFlags))
	cmd.AddCommand(newQuotasCheckCommand(getFlags))

	return cmd
}

// newQuotasGetCommand creates the quotas get subcommand
func newQuotasGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-name>",
		Short: "Get tenant quotas",
		Long: `Display the current quota limits for a tenant.

Examples:
  # Get quotas for a tenant
  platformctl tenant quotas get my-tenant

  # Output as JSON
  platformctl tenant quotas get my-tenant -o json

  # Output as YAML
  platformctl tenant quotas get my-tenant -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runQuotasGet(flags, args[0])
		},
	}

	return cmd
}

func runQuotasGet(flags *cli.CommonFlags, tenantName string) error {
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
		return printer.Print(toQuotaSummary(t.ID, t))

	case cli.OutputFormatTable:
		fmt.Printf("Quotas for tenant: %s\n\n", tenantName)
		if t.ComputeQuota != nil {
			printComputeQuota(printer, t.ComputeQuota)
		}
		fmt.Println()
		if t.NetworkQuota != nil {
			printNetworkQuota(printer, t.NetworkQuota)
		}
		fmt.Println()
		if t.StorageQuota != nil {
			printStorageQuota(printer, t.StorageQuota)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// newQuotasSetCommand creates the quotas set subcommand
func newQuotasSetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		maxVMs           int64
		maxContainers    int64
		maxVCPUs         int64
		maxMemoryGB      int64
		maxBridges       int64
		maxPorts         int64
		maxBandwidthMbps int64
		maxVolumesGB     int64
		maxSnapshots     int64
	)

	cmd := &cobra.Command{
		Use:   "set <tenant-name>",
		Short: "Set tenant quotas",
		Long: `Update quota limits for a tenant.

Only the specified quota values will be updated. Unspecified values
will retain their current limits.

Examples:
  # Set compute quotas
  platformctl tenant quotas set my-tenant --max-vms 100 --max-vcpus 400

  # Set memory quotas
  platformctl tenant quotas set my-tenant --max-memory-gb 512

  # Set network quotas
  platformctl tenant quotas set my-tenant --max-bridges 10 --max-ports 1000

  # Set storage quotas
  platformctl tenant quotas set my-tenant --max-volumes-gb 5000 --max-snapshots 100

  # Set all quotas
  platformctl tenant quotas set my-tenant \
    --max-vms 100 --max-containers 200 --max-vcpus 400 --max-memory-gb 512 \
    --max-bridges 10 --max-ports 1000 --max-bandwidth-mbps 10000 \
    --max-volumes-gb 5000 --max-snapshots 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runQuotasSet(flags, args[0], &quotasSetOptions{
				MaxVMs:           maxVMs,
				MaxContainers:    maxContainers,
				MaxVCPUs:         maxVCPUs,
				MaxMemoryGB:      maxMemoryGB,
				MaxBridges:       maxBridges,
				MaxPorts:         maxPorts,
				MaxBandwidthMbps: maxBandwidthMbps,
				MaxVolumesGB:     maxVolumesGB,
				MaxSnapshots:     maxSnapshots,
				// Track which flags were set
				setMaxVMs:           cmd.Flags().Changed("max-vms"),
				setMaxContainers:    cmd.Flags().Changed("max-containers"),
				setMaxVCPUs:         cmd.Flags().Changed("max-vcpus"),
				setMaxMemoryGB:      cmd.Flags().Changed("max-memory-gb"),
				setMaxBridges:       cmd.Flags().Changed("max-bridges"),
				setMaxPorts:         cmd.Flags().Changed("max-ports"),
				setMaxBandwidthMbps: cmd.Flags().Changed("max-bandwidth-mbps"),
				setMaxVolumesGB:     cmd.Flags().Changed("max-volumes-gb"),
				setMaxSnapshots:     cmd.Flags().Changed("max-snapshots"),
			})
		},
	}

	// Compute quota flags
	cmd.Flags().Int64Var(&maxVMs, "max-vms", 0, "maximum number of VMs")
	cmd.Flags().Int64Var(&maxContainers, "max-containers", 0, "maximum number of containers")
	cmd.Flags().Int64Var(&maxVCPUs, "max-vcpus", 0, "maximum number of vCPUs")
	cmd.Flags().Int64Var(&maxMemoryGB, "max-memory-gb", 0, "maximum memory in GB")

	// Network quota flags
	cmd.Flags().Int64Var(&maxBridges, "max-bridges", 0, "maximum number of bridges")
	cmd.Flags().Int64Var(&maxPorts, "max-ports", 0, "maximum number of network ports")
	cmd.Flags().Int64Var(&maxBandwidthMbps, "max-bandwidth-mbps", 0, "maximum bandwidth in Mbps")

	// Storage quota flags
	cmd.Flags().Int64Var(&maxVolumesGB, "max-volumes-gb", 0, "maximum volume storage in GB")
	cmd.Flags().Int64Var(&maxSnapshots, "max-snapshots", 0, "maximum number of snapshots")

	return cmd
}

type quotasSetOptions struct {
	MaxVMs           int64
	MaxContainers    int64
	MaxVCPUs         int64
	MaxMemoryGB      int64
	MaxBridges       int64
	MaxPorts         int64
	MaxBandwidthMbps int64
	MaxVolumesGB     int64
	MaxSnapshots     int64

	// Track which flags were explicitly set
	setMaxVMs           bool
	setMaxContainers    bool
	setMaxVCPUs         bool
	setMaxMemoryGB      bool
	setMaxBridges       bool
	setMaxPorts         bool
	setMaxBandwidthMbps bool
	setMaxVolumesGB     bool
	setMaxSnapshots     bool
}

func runQuotasSet(flags *cli.CommonFlags, tenantName string, opts *quotasSetOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	// First get the tenant by name using domain-typed method
	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	// Build the update quotas params
	params := &sdktenant.UpdateQuotasParams{
		TenantID: t.ID,
	}

	// Build compute quota update if any flags were set
	if opts.setMaxVMs || opts.setMaxContainers || opts.setMaxVCPUs ||
		opts.setMaxMemoryGB {
		// Start with existing values
		computeQuota := &sdktenant.ComputeQuota{}
		if t.ComputeQuota != nil {
			computeQuota = &sdktenant.ComputeQuota{
				MaxVMs:        t.ComputeQuota.MaxVMs,
				MaxContainers: t.ComputeQuota.MaxContainers,
				MaxVCPUs:      t.ComputeQuota.MaxVCPUs,
				MaxMemoryMB:   t.ComputeQuota.MaxMemoryMB,
			}
		}

		if opts.setMaxVMs {
			computeQuota.MaxVMs = opts.MaxVMs
		}
		if opts.setMaxContainers {
			computeQuota.MaxContainers = opts.MaxContainers
		}
		if opts.setMaxVCPUs {
			computeQuota.MaxVCPUs = opts.MaxVCPUs
		}
		if opts.setMaxMemoryGB {
			computeQuota.MaxMemoryMB = opts.MaxMemoryGB * 1024
		}
		params.ComputeQuota = computeQuota
	}

	// Build network quota update if any flags were set
	if opts.setMaxBridges || opts.setMaxPorts || opts.setMaxBandwidthMbps {
		networkQuota := &sdktenant.NetworkQuota{}
		if t.NetworkQuota != nil {
			networkQuota = &sdktenant.NetworkQuota{
				MaxBridges:       t.NetworkQuota.MaxBridges,
				MaxPorts:         t.NetworkQuota.MaxPorts,
				MaxBandwidthMbps: t.NetworkQuota.MaxBandwidthMbps,
			}
		}

		if opts.setMaxBridges {
			networkQuota.MaxBridges = opts.MaxBridges
		}
		if opts.setMaxPorts {
			networkQuota.MaxPorts = opts.MaxPorts
		}
		if opts.setMaxBandwidthMbps {
			networkQuota.MaxBandwidthMbps = opts.MaxBandwidthMbps
		}
		params.NetworkQuota = networkQuota
	}

	// Build storage quota update if any flags were set
	if opts.setMaxVolumesGB || opts.setMaxSnapshots {
		storageQuota := &sdktenant.StorageQuota{}
		if t.StorageQuota != nil {
			storageQuota = &sdktenant.StorageQuota{
				MaxVolumesGB: t.StorageQuota.MaxVolumesGB,
				MaxSnapshots: t.StorageQuota.MaxSnapshots,
			}
		}

		if opts.setMaxVolumesGB {
			storageQuota.MaxVolumesGB = opts.MaxVolumesGB
		}
		if opts.setMaxSnapshots {
			storageQuota.MaxSnapshots = opts.MaxSnapshots
		}
		params.StorageQuota = storageQuota
	}

	// Update quotas using domain-typed method
	if err := tenantClient.UpdateQuotasDomain(ctx, params); err != nil {
		return ErrOperationFailed{
			Operation: "quotas set",
			TenantID:  t.ID,
			Err:       err,
		}
	}

	// Fetch updated tenant to show results using domain-typed method
	t, err = tenantClient.GetDomain(ctx, params.TenantID)
	if err != nil {
		return ErrOperationFailed{
			Operation: "quotas get",
			TenantID:  params.TenantID,
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toQuotaSummary(t.ID, t))

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Quotas updated for tenant: %s", tenantName))
		fmt.Println()
		if t.ComputeQuota != nil {
			printComputeQuota(printer, t.ComputeQuota)
		}
		fmt.Println()
		if t.NetworkQuota != nil {
			printNetworkQuota(printer, t.NetworkQuota)
		}
		fmt.Println()
		if t.StorageQuota != nil {
			printStorageQuota(printer, t.StorageQuota)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// QuotaCheckResult is the JSON/YAML output of tenant quotas check.
type QuotaCheckResult struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Resource   string `json:"resource" yaml:"resource"`
	Amount     int64  `json:"amount" yaml:"amount"`
	Allowed    bool   `json:"allowed" yaml:"allowed"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
}

// newQuotasCheckCommand creates the quotas check subcommand.
func newQuotasCheckCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		resource string
		amount   int64
	)

	cmd := &cobra.Command{
		Use:   "check <tenant-name>",
		Short: "Check whether a tenant has quota left for a request",
		Long: `Check whether a tenant could allocate an amount of a resource without
going over its quota. Nothing is allocated.

A request over quota is a result, not an error: allowed is false and the
message says which limit it hits.

Resources: vms, containers, vcpus, memory, disk, bridges, ports,
bandwidth, volumes, snapshots.

Examples:
  # Could the tenant start two more VMs?
  platformctl tenant quotas check my-tenant --resource vms --amount 2

  # Output as JSON
  platformctl tenant quotas check my-tenant --resource vcpus --amount 8 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuotasCheck(getFlags(), args[0], resource, amount)
		},
	}

	cmd.Flags().StringVar(&resource, "resource", "", "resource to check (required)")
	cmd.Flags().Int64Var(&amount, "amount", 0, "amount to check; must be positive (required)")

	return cmd
}

func runQuotasCheck(flags *cli.CommonFlags, tenantName, resource string, amount int64) error {
	if resource == "" {
		return ErrInvalidArguments{Reason: "--resource is required"}
	}
	if amount <= 0 {
		return ErrInvalidQuotaValue{Field: "amount", Value: amount, Reason: "must be positive"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	resp, err := tenantClient.CheckQuota(ctx, t.ID, resource, amount)
	if err != nil {
		return ErrOperationFailed{Operation: "quotas check", TenantID: t.ID, Err: err}
	}

	result := &QuotaCheckResult{
		TenantID:   t.ID,
		TenantName: tenantName,
		Resource:   resp.GetResource(),
		Amount:     resp.GetAmount(),
		Allowed:    resp.GetAvailable(),
		Message:    resp.GetMessage(),
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if result.Allowed {
			printer.PrintSuccess(fmt.Sprintf("Tenant %s can allocate %d %s", tenantName, amount, resource))
			return nil
		}
		printer.PrintWarning(fmt.Sprintf("Tenant %s cannot allocate %d %s: %s", tenantName, amount, resource, result.Message))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
