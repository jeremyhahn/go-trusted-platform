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

package device

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// The read verbs of `platformctl device profile`. They ride the same SDK
// device client as create/update so an operator can confirm a write over the
// transport that made it (the top-level `platformctl profile` reads are
// stubs, #460).

// newProfileGetCommand creates the profile get subcommand.
func newProfileGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get a device profile",
		Long: `Fetch one device profile from the control plane and render it, including
the certificate name the attestation collector verifies its nodes against
(tls_server_name) and the read-only PCR baseline the verifier recorded.

Examples:
  platformctl device profile get 123
  platformctl device profile get 123 --output json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidProfileID{ID: args[0]}
			}
			return runProfileGet(getFlags(), id)
		},
	}
}

// runProfileGet fetches the profile via the SDK device service and renders it.
func runProfileGet(flags *cli.CommonFlags, id uint64) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	profile, err := deviceClient.GetProfile(base.Context(), id)
	if err != nil {
		return ErrProfileGetFailed{ID: id, Cause: err}
	}
	return outputProfile(base, flags, profile)
}

// newProfileListCommand creates the profile list subcommand.
func newProfileListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var page, pageSize int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List device profiles",
		Long: `List device profiles on the control plane with their id, name, role, zone,
the collector's TLS server name and assignment state.

Examples:
  platformctl device profile list
  platformctl device profile list --page 2 --page-size 50 --output json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileList(getFlags(), page, pageSize)
		},
	}
	cmd.Flags().IntVar(&page, "page", 1, "page number (1-based)")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "profiles per page")
	return cmd
}

// runProfileList lists profiles via the SDK device service.
func runProfileList(flags *cli.CommonFlags, page, pageSize int) error {
	if page < 1 || pageSize < 1 {
		return ErrInvalidPagination{Page: page, PageSize: pageSize}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	profiles, pageResult, err := deviceClient.ListProfiles(base.Context(), &common.ListOptions{
		Pagination: common.NewPagination(uint32(page), uint32(pageSize)),
	})
	if err != nil {
		return ErrProfileListFailed{Cause: err}
	}

	var total int
	if pageResult != nil {
		total = int(pageResult.TotalItems)
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printProfileListTable(base.Printer(), profiles, page, pageSize, total)
		return nil
	}
	return base.Output(buildProfileListOutput(page, pageSize, total, profiles))
}

// buildProfileListOutput creates the JSON/YAML output for profile list: the
// same per-profile shape as get, under the list's pagination envelope.
func buildProfileListOutput(page, pageSize, total int, profiles []*platformv1.DeviceProfile) map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(profiles))
	for _, p := range profiles {
		items = append(items, buildProfileOutput(p))
	}
	return map[string]interface{}{
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": (total + pageSize - 1) / pageSize,
		"profiles":    items,
	}
}

// printProfileListTable prints profiles in table format.
func printProfileListTable(printer *cli.Printer, profiles []*platformv1.DeviceProfile, page, pageSize, total int) {
	if len(profiles) == 0 {
		fmt.Println("No profiles found")
		return
	}

	table := cli.NewTableData("ID", "NAME", "ROLE", "ZONE", "TLS SERVER NAME", "ASSIGNED")
	for _, p := range profiles {
		role := ""
		if p.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
			role = profileRoleLabel(p.GetRole())
		}
		table.AddRow(
			strconv.FormatUint(p.GetId(), 10),
			truncate(p.GetName(), 30),
			role,
			truncate(p.GetZone(), 16),
			truncate(p.GetTlsServerName(), 40),
			strconv.FormatBool(p.GetAssigned()),
		)
	}
	if err := printer.Print(*table); err != nil {
		printer.PrintError(err.Error())
		return
	}
	fmt.Printf("\nPage %d of %d (Total: %d profiles)\n", page, (total+pageSize-1)/pageSize, total)
}
