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

package container

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// listOptions holds the options for the list command
type listOptions struct {
	all      bool
	filter   []string
	pageSize int32
}

// newListCommand creates the container list subcommand
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "ps"},
		Short:   "List containers",
		Long: `List containers with optional filtering.

By default, only running containers are shown. Use --all to show
all containers including stopped ones.

Filters can be specified using key=value pairs:
  - state: Filter by container state (running, stopped, created, etc.)
  - name: Filter by container name prefix
  - label: Filter by label (key=value)
  - image: Filter by image name

Examples:
  # List running containers
  platformctl container list

  # List all containers
  platformctl container list --all

  # Filter by state
  platformctl container list --filter state=stopped

  # Filter by label
  platformctl container list --filter label=app=myapp

  # Filter by name prefix
  platformctl container list --all --filter name=web-

  # List with JSON output
  platformctl container list --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.all, "all", "a", false, "show all containers (default shows just running)")
	cmd.Flags().StringArrayVarP(&opts.filter, "filter", "f", nil, "filter containers (key=value)")
	cmd.Flags().Int32VarP(&opts.pageSize, "limit", "l", 100, "maximum number of containers to list")

	return cmd
}

// runList executes the container list command
func runList(flags *cli.CommonFlags, opts *listOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrContainerClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	// Build params
	params := &computesvc.ListContainersParams{
		PageSize: uint32(opts.pageSize),
	}

	// If not showing all, filter to running containers only
	if !opts.all {
		params.States = []computesvc.ContainerState{
			computesvc.ContainerStateRunning,
		}
	}

	// Parse and apply filters
	if len(opts.filter) > 0 {
		selected, err := parseFilters(opts.filter)
		if err != nil {
			return err
		}
		if len(selected.labels) > 0 {
			params.Labels = selected.labels
		}
		if len(selected.states) > 0 {
			params.States = selected.states
		}
		params.NameFilter = selected.namePrefix
	}

	ctx := base.Context()
	result, err := sdkClient.ListContainersDomain(ctx, params)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "list", ID: "", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printContainerList(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// containerFilters is what the --filter flags select.
type containerFilters struct {
	labels     map[string]string
	states     []computesvc.ContainerState
	namePrefix string
}

// parseFilters parses filter strings into label matches, states and a
// name prefix.
func parseFilters(filters []string) (containerFilters, error) {
	selected := containerFilters{labels: make(map[string]string)}

	for _, f := range filters {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			return containerFilters{}, ErrInvalidFilter{Filter: f}
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "state":
			state, ok := parseContainerState(value)
			if !ok {
				return containerFilters{}, ErrInvalidFilter{Filter: f}
			}
			selected.states = append(selected.states, state)
		case "label":
			labelParts := strings.SplitN(value, "=", 2)
			if len(labelParts) == 2 {
				selected.labels[labelParts[0]] = labelParts[1]
			} else {
				selected.labels[value] = ""
			}
		case "name":
			selected.namePrefix = value
		case "image":
			selected.labels[key] = value
		default:
			return containerFilters{}, ErrInvalidFilter{Filter: f}
		}
	}

	return selected, nil
}

// printContainerList prints the container list in table format
func printContainerList(printer *cli.Printer, result *computesvc.ListContainersResult) error {
	if len(result.Containers) == 0 {
		printer.PrintInfo("No containers found")
		return nil
	}

	table := cli.NewTableData("ID", "NAME", "IMAGE", "STATE", "CREATED", "PORTS")

	for _, container := range result.Containers {
		id := truncateID(container.ID)
		name := ""
		image := ""
		ports := ""

		if container.Config != nil {
			name = container.Config.Name
			image = container.Config.Image
			ports = formatPorts(container.Config.Ports)
		}

		state := formatContainerState(container.State)
		created := formatTimestamp(container.CreatedAt)

		table.AddRow(id, name, image, state, created, ports)
	}

	if err := printer.Print(*table); err != nil {
		return err
	}

	fmt.Println()
	printer.PrintKeyValue("Total", fmt.Sprintf("%d container(s)", len(result.Containers)))

	return nil
}

// formatPorts formats port mappings for display
func formatPorts(ports []*computesvc.PortMapping) string {
	if len(ports) == 0 {
		return ""
	}

	var portStrs []string
	for _, p := range ports {
		if p.HostIP != "" {
			portStrs = append(portStrs, fmt.Sprintf("%s:%d->%d/%s",
				p.HostIP, p.HostPort, p.ContainerPort, p.Protocol))
		} else {
			portStrs = append(portStrs, fmt.Sprintf("%d->%d/%s",
				p.HostPort, p.ContainerPort, p.Protocol))
		}
	}

	return strings.Join(portStrs, ", ")
}
