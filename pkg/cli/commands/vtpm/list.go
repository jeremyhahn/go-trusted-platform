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

package vtpm

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newListCommand creates the list subcommand for listing bundles
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		mode   string
		limit  int32
		offset int32
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List vTPM bundles",
		Long: `List all vTPM bundles or filter by mode.

Displays bundle information including ID, mode, hostname, Secure Boot
status, and creation time.

Examples:
  # List all bundles
  platformctl vtpm list

  # List only template bundles
  platformctl vtpm list --mode template

  # List only pre-assigned bundles
  platformctl vtpm list --mode pre-assigned

  # List with pagination
  platformctl vtpm list --limit 10 --offset 0

  # Output as JSON
  platformctl vtpm list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, mode, limit, offset)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "", "filter by mode (template, pre-assigned)")
	cmd.Flags().Int32Var(&limit, "limit", 0, "maximum number of bundles to return (0 = no limit)")
	cmd.Flags().Int32Var(&offset, "offset", 0, "number of bundles to skip")

	return cmd
}

// runList executes the list command
func runList(flags *cli.CommonFlags, mode string, limit, offset int32) error {
	// Validate mode filter first before connecting
	modeFilter := platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	if mode != "" {
		var parseErr error
		modeFilter, parseErr = parseBundleMode(mode)
		if parseErr != nil {
			return parseErr
		}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().VTPM()
	if client == nil {
		return ErrVTPMNotAvailable{}
	}

	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Mode:   modeFilter,
			Limit:  limit,
			Offset: offset,
		},
	}

	ctx := base.Context()
	resp, err := client.ListBundles(ctx, req)
	if err != nil {
		return ErrListBundlesFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Bundles) == 0 {
			printer.PrintInfo("No bundles found")
			return nil
		}

		table := cli.NewTableData("ID", "Mode", "Hostname", "EK Alg", "Secure Boot", "Created")
		for _, bundle := range resp.Bundles {
			hostname := ""
			ekAlg := ""
			secureBoot := ""
			created := ""

			if bundle.Manifest != nil {
				hostname = bundle.Manifest.Hostname
				ekAlg = bundle.Manifest.EkAlgorithm.String()
				secureBoot = formatBool(bundle.Manifest.SecureBootEnabled)
				if bundle.Manifest.CreatedAt != nil {
					created = bundle.Manifest.CreatedAt.AsTime().Format("2006-01-02 15:04")
				}
			}

			if created == "" && bundle.CreatedAt != nil {
				created = bundle.CreatedAt.AsTime().Format("2006-01-02 15:04")
			}

			table.AddRow(
				truncateID(bundle.Id, 12),
				bundle.Mode.String(),
				truncateString(hostname, 25),
				ekAlg,
				secureBoot,
				created,
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total", fmt.Sprintf("%d bundles", len(resp.Bundles)))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseBundleMode parses a mode string to protobuf enum
func parseBundleMode(mode string) (platformv1.BundleMode, error) {
	switch strings.ToLower(mode) {
	case "template":
		return platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, nil
	case "pre-assigned", "preassigned":
		return platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, nil
	default:
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, ErrInvalidBundleMode{Mode: mode}
	}
}

// truncateID truncates an ID for display
func truncateID(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// truncateString truncates a string for display
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
