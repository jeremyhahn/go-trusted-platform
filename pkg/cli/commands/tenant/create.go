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

// NewCreateCommand creates the tenant create subcommand
func NewCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		name             string
		displayName      string
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
		Use:   "create",
		Short: "Create a new tenant",
		Long: `Create a new tenant with the specified configuration and quotas.

The tenant will be created with a unique ID and provisioned with:
  - Resource quotas for compute, network, and storage
  - A per-tenant data encryption key and barriers

Examples:
  # Create a basic tenant
  platformctl tenant create --name my-tenant

  # Create with display name
  platformctl tenant create --name my-tenant --display-name "My Tenant"

  # Create with compute quotas
  platformctl tenant create --name my-tenant --max-vms 100 --max-vcpus 400 --max-memory-gb 512

  # Create with all quotas
  platformctl tenant create --name my-tenant \
    --max-vms 100 --max-containers 200 --max-vcpus 400 --max-memory-gb 512 \
    --max-bridges 10 --max-ports 1000 --max-bandwidth-mbps 10000 \
    --max-volumes-gb 5000 --max-snapshots 100`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return ErrMissingTenantName{}
			}

			flags := getFlags()
			return runTenantCreate(flags, &createTenantOptions{
				Name:             name,
				DisplayName:      displayName,
				MaxVMs:           maxVMs,
				MaxContainers:    maxContainers,
				MaxVCPUs:         maxVCPUs,
				MaxMemoryGB:      maxMemoryGB,
				MaxBridges:       maxBridges,
				MaxPorts:         maxPorts,
				MaxBandwidthMbps: maxBandwidthMbps,
				MaxVolumesGB:     maxVolumesGB,
				MaxSnapshots:     maxSnapshots,
			})
		},
	}

	// Required flags
	cmd.Flags().StringVar(&name, "name", "", "unique tenant name (required)")

	// Optional flags
	cmd.Flags().StringVar(&displayName, "display-name", "", "human-readable display name")

	// Compute quota flags
	cmd.Flags().Int64Var(&maxVMs, "max-vms", 0, "maximum number of VMs (0 = use default)")
	cmd.Flags().Int64Var(&maxContainers, "max-containers", 0, "maximum number of containers (0 = use default)")
	cmd.Flags().Int64Var(&maxVCPUs, "max-vcpus", 0, "maximum number of vCPUs (0 = use default)")
	cmd.Flags().Int64Var(&maxMemoryGB, "max-memory-gb", 0, "maximum memory in GB (0 = use default)")

	// Network quota flags
	cmd.Flags().Int64Var(&maxBridges, "max-bridges", 0, "maximum number of bridges (0 = use default)")
	cmd.Flags().Int64Var(&maxPorts, "max-ports", 0, "maximum number of network ports (0 = use default)")
	cmd.Flags().Int64Var(&maxBandwidthMbps, "max-bandwidth-mbps", 0, "maximum bandwidth in Mbps (0 = use default)")

	// Storage quota flags
	cmd.Flags().Int64Var(&maxVolumesGB, "max-volumes-gb", 0, "maximum volume storage in GB (0 = use default)")
	cmd.Flags().Int64Var(&maxSnapshots, "max-snapshots", 0, "maximum number of snapshots (0 = use default)")

	return cmd
}

type createTenantOptions struct {
	Name             string
	DisplayName      string
	MaxVMs           int64
	MaxContainers    int64
	MaxVCPUs         int64
	MaxMemoryGB      int64
	MaxBridges       int64
	MaxPorts         int64
	MaxBandwidthMbps int64
	MaxVolumesGB     int64
	MaxSnapshots     int64
}

func runTenantCreate(flags *cli.CommonFlags, opts *createTenantOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	// Build the create params
	displayName := opts.DisplayName
	if displayName == "" {
		displayName = opts.Name
	}

	params := &sdktenant.CreateParams{
		Name:        opts.Name,
		DisplayName: displayName,
	}

	// Add compute quota if any values specified
	if opts.MaxVMs > 0 || opts.MaxContainers > 0 || opts.MaxVCPUs > 0 ||
		opts.MaxMemoryGB > 0 {
		params.ComputeQuota = &sdktenant.ComputeQuota{
			MaxVMs:        opts.MaxVMs,
			MaxContainers: opts.MaxContainers,
			MaxVCPUs:      opts.MaxVCPUs,
			MaxMemoryMB:   opts.MaxMemoryGB * 1024,
		}
	}

	// Add network quota if any values specified
	if opts.MaxBridges > 0 || opts.MaxPorts > 0 || opts.MaxBandwidthMbps > 0 {
		params.NetworkQuota = &sdktenant.NetworkQuota{
			MaxBridges:       opts.MaxBridges,
			MaxPorts:         opts.MaxPorts,
			MaxBandwidthMbps: opts.MaxBandwidthMbps,
		}
	}

	// Add storage quota if any values specified
	if opts.MaxVolumesGB > 0 || opts.MaxSnapshots > 0 {
		params.StorageQuota = &sdktenant.StorageQuota{
			MaxVolumesGB: opts.MaxVolumesGB,
			MaxSnapshots: opts.MaxSnapshots,
		}
	}

	ctx := context.Background()
	t, err := tenantClient.CreateDomain(ctx, params)
	if err != nil {
		return ErrOperationFailed{
			Operation: "create",
			TenantID:  opts.Name,
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toTenantDetail(t))

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant created successfully: %s", t.Name))
		fmt.Println()
		printTenantDetails(printer, t)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
