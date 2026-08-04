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

package compute

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// migrateOptions holds the options for the migrate command.
type migrateOptions struct {
	destination string
	live        bool
	bandwidth   uint64
}

// newMigrateCommand creates the compute migrate subcommand.
func newMigrateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &migrateOptions{}

	cmd := &cobra.Command{
		Use:   "migrate <vm-id> --destination <host:port>",
		Short: "Migrate a virtual machine to another host",
		Long: `Migrate a running virtual machine to a peer platformd.

Cold migration (the default) pauses the guest and transfers RAM and disks
over a TLS-secured stream; it works without shared storage. Live migration
(--live) keeps the guest running and requires shared storage to be configured
on both hosts. The destination is the peer daemon's mTLS gRPC endpoint
(host:port); the migration channel is always TLS-authenticated.

Examples:
  # Cold-migrate a VM to another host
  platformctl compute migrate myvm --destination node2.example:10443

  # Live-migrate (requires shared storage) with a 500 Mbps bandwidth cap
  platformctl compute migrate myvm --destination node2.example:10443 --live --bandwidth 500

  # JSON output
  platformctl compute migrate myvm --destination node2.example:10443 --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runMigrate(flags, args[0], opts)
		},
	}

	cmd.Flags().StringVarP(&opts.destination, "destination", "d", "", "destination daemon mTLS gRPC endpoint (host:port) (required)")
	cmd.Flags().BoolVar(&opts.live, "live", false, "perform a live migration (requires shared storage)")
	cmd.Flags().Uint64Var(&opts.bandwidth, "bandwidth", 0, "migration bandwidth cap in Mbps (0 = unlimited)")

	return cmd
}

// runMigrate executes the compute migrate command.
func runMigrate(flags *cli.CommonFlags, vmID string, opts *migrateOptions) error {
	if vmID == "" {
		return ErrInvalidVMConfig{Field: "id", Reason: "VM ID is required"}
	}
	if opts.destination == "" {
		return ErrInvalidVMConfig{Field: "destination", Reason: "destination host is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrComputeClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	if err := sdkClient.MigrateVM(ctx, vmID, opts.destination, opts.live, opts.bandwidth); err != nil {
		return ErrVMOperationFailed{Operation: "migrate", ID: vmID, Err: err}
	}

	printer := base.Printer()
	mode := "cold"
	if opts.live {
		mode = "live"
	}
	result := map[string]interface{}{
		"vm_id":            vmID,
		"destination_host": opts.destination,
		"mode":             mode,
		"success":          true,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("VM %s migrated (%s) to %s", vmID, mode, opts.destination))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
