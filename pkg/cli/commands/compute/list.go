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
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// listOptions holds the options for the list command
type listOptions struct {
	all      bool
	filter   []string
	pageSize int32
}

// newListCommand creates the compute list subcommand
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List virtual machines",
		Long: `List virtual machines with optional filtering.

By default, only running VMs are shown. Use --all to show
all VMs including stopped ones.

Filters can be specified using key=value pairs:
  - state: Filter by VM state (running, stopped, paused, etc.)
  - label: Filter by label (key=value)

Examples:
  # List running VMs
  platformctl compute list

  # List all VMs
  platformctl compute list --all

  # Filter by state
  platformctl compute list --filter state=stopped

  # Filter by label
  platformctl compute list --filter label=env=production

  # List with JSON output
  platformctl compute list --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.all, "all", "a", false, "show all VMs (default shows just running)")
	cmd.Flags().StringArrayVarP(&opts.filter, "filter", "f", nil, "filter VMs (key=value)")
	cmd.Flags().Int32VarP(&opts.pageSize, "limit", "l", 100, "maximum number of VMs to list")

	return cmd
}

// runList executes the compute list command
func runList(flags *cli.CommonFlags, opts *listOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Compute()
	if client == nil {
		return ErrComputeClientNotInitialized{}
	}

	// Build request
	req := &platformv1.ListVMsRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(opts.pageSize),
		},
	}

	// If not showing all, filter to running VMs only
	if !opts.all {
		req.States = []platformv1.VMState{
			platformv1.VMState_VM_STATE_RUNNING,
		}
	}

	// Parse and apply filters
	if len(opts.filter) > 0 {
		selector, states, err := parseVMFilters(opts.filter)
		if err != nil {
			return err
		}
		if selector != nil {
			req.Selector = selector
		}
		if len(states) > 0 {
			req.States = states
		}
	}

	ctx := base.Context()
	resp, err := client.ListVMs(ctx, req)
	if err != nil {
		return ErrVMOperationFailed{Operation: "list", ID: "", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printVMList(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseVMFilters parses filter strings into selector and states
func parseVMFilters(filters []string) (*platformv1.LabelSelector, []platformv1.VMState, error) {
	var selector *platformv1.LabelSelector
	var states []platformv1.VMState

	labels := make(map[string]string)

	for _, f := range filters {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			return nil, nil, ErrInvalidFilter{Filter: f}
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "state":
			state, ok := parseVMState(value)
			if !ok {
				return nil, nil, ErrInvalidVMState{State: value}
			}
			states = append(states, state)
		case "label":
			labelParts := strings.SplitN(value, "=", 2)
			if len(labelParts) == 2 {
				labels[labelParts[0]] = labelParts[1]
			} else {
				labels[value] = ""
			}
		default:
			return nil, nil, ErrInvalidFilter{Filter: f}
		}
	}

	if len(labels) > 0 {
		selector = &platformv1.LabelSelector{
			MatchLabels: labels,
		}
	}

	return selector, states, nil
}

// printVMList prints the VM list in table format
func printVMList(printer *cli.Printer, resp *platformv1.ListVMsResponse) error {
	if len(resp.Vms) == 0 {
		printer.PrintInfo("No virtual machines found")
		return nil
	}

	table := cli.NewTableData("ID", "NAME", "STATE", "CPUS", "MEMORY", "FIRMWARE", "CREATED")

	for _, vm := range resp.Vms {
		id := truncateID(vm.Id)
		name := ""
		cpus := ""
		memory := ""
		firmware := ""

		if vm.Config != nil {
			name = vm.Config.Name
			firmware = formatFirmwareType(vm.Config.Firmware)
			if vm.Config.Cpu != nil {
				cpus = fmt.Sprintf("%d", vm.Config.Cpu.Cores)
			}
			if vm.Config.Memory != nil {
				memory = fmt.Sprintf("%d MB", vm.Config.Memory.SizeMb)
			}
		}

		state := formatVMState(vm.State)
		created := formatTimestamp(vm.CreatedAt)

		table.AddRow(id, name, state, cpus, memory, firmware, created)
	}

	if err := printer.Print(*table); err != nil {
		return err
	}

	fmt.Println()
	printer.PrintKeyValue("Total", fmt.Sprintf("%d VM(s)", len(resp.Vms)))

	return nil
}
