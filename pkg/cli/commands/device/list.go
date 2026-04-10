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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newListCommand creates the list subcommand for listing devices
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var page int
	var pageSize int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List devices",
		Long: `List all devices with pagination support.

Displays registered devices in a paginated table format.
Use --page and --page-size flags to navigate through results.

Examples:
  # List devices (default pagination)
  platformctl device list

  # List with custom pagination
  platformctl device list --page 2 --page-size 50

  # List as JSON output
  platformctl device list -o json

  # List as YAML output
  platformctl device list -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, page, pageSize)
		},
	}

	cmd.Flags().IntVar(&page, "page", 1, "page number (1-indexed)")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "number of items per page")

	return cmd
}

// runList executes the list command using the SDK client
func runList(flags *cli.CommonFlags, page, pageSize int) error {
	// Create base command to get SDK client
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create device service client from the platform client
	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	// Build list options with pagination
	opts := &common.ListOptions{
		Pagination: common.NewPagination(uint32(page), uint32(pageSize)),
	}

	// List devices
	ctx := base.Context()
	devices, pageResult, err := deviceClient.List(ctx, opts)
	if err != nil {
		return ErrListDevicesFailed{Reason: err.Error()}
	}

	// Convert to output format
	deviceList := make([]deviceInfo, 0, len(devices))
	for _, d := range devices {
		deviceList = append(deviceList, deviceInfo{
			ID:     d.Id,
			Serial: d.Serial,
			Model:  d.Model,
		})
	}

	// Get total from page result
	var total int
	if pageResult != nil {
		total = int(pageResult.TotalItems)
	}

	// Output based on format
	if flags.OutputFormat == cli.OutputFormatTable {
		printListTable(base.Printer(), deviceList, page, pageSize, total)
		return nil
	}

	// JSON/YAML output
	output := buildListOutput(page, pageSize, total, deviceList)
	return base.Output(output)
}

// buildListOutput creates the JSON output structure for the list command
func buildListOutput(page, pageSize, total int, devices []deviceInfo) map[string]interface{} {
	totalPages := (total + pageSize - 1) / pageSize

	return map[string]interface{}{
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
		"devices":     devices,
	}
}

// deviceInfo represents device information for output
type deviceInfo struct {
	ID     uint64 `json:"id"`
	Serial string `json:"serial"`
	Model  string `json:"model"`
}

// printListTable prints devices in table format
func printListTable(printer *cli.Printer, devices []deviceInfo, page, pageSize, total int) {
	if len(devices) == 0 {
		fmt.Println("No devices found")
		return
	}

	// Create table data
	table := cli.NewTableData("ID", "SERIAL", "MODEL")
	for _, d := range devices {
		table.AddRow(
			strconv.FormatUint(d.ID, 10),
			truncate(d.Serial, 20),
			truncate(d.Model, 30),
		)
	}

	// Print table
	if err := printer.Print(*table); err != nil {
		printer.PrintError(err.Error())
		return
	}

	// Print pagination info
	totalPages := (total + pageSize - 1) / pageSize
	fmt.Printf("\nPage %d of %d (Total: %d devices)\n", page, totalPages, total)
}
