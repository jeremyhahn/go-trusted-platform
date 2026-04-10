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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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
  - name: Filter by container name (supports wildcards)
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

	client := base.Client().Compute()
	if client == nil {
		return ErrContainerClientNotInitialized{}
	}

	// Build request
	req := &platformv1.ListContainersRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(opts.pageSize),
		},
	}

	// If not showing all, filter to running containers only
	if !opts.all {
		req.States = []platformv1.ContainerState{
			platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		}
	}

	// Parse and apply filters
	if len(opts.filter) > 0 {
		selector, states, err := parseFilters(opts.filter)
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
	resp, err := client.ListContainers(ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "list", ID: "", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printContainerList(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseFilters parses filter strings into selector and states
func parseFilters(filters []string) (*platformv1.LabelSelector, []platformv1.ContainerState, error) {
	var selector *platformv1.LabelSelector
	var states []platformv1.ContainerState

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
			state, ok := parseContainerState(value)
			if !ok {
				return nil, nil, ErrInvalidFilter{Filter: f}
			}
			states = append(states, state)
		case "label":
			labelParts := strings.SplitN(value, "=", 2)
			if len(labelParts) == 2 {
				labels[labelParts[0]] = labelParts[1]
			} else {
				labels[value] = ""
			}
		case "name", "image":
			// These could be used for additional filtering
			labels[key] = value
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

// printContainerList prints the container list in table format
func printContainerList(printer *cli.Printer, resp *platformv1.ListContainersResponse) error {
	if len(resp.Containers) == 0 {
		printer.PrintInfo("No containers found")
		return nil
	}

	table := cli.NewTableData("ID", "NAME", "IMAGE", "STATE", "CREATED", "PORTS")

	for _, container := range resp.Containers {
		id := truncateID(container.Id)
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
	printer.PrintKeyValue("Total", fmt.Sprintf("%d container(s)", len(resp.Containers)))

	return nil
}

// formatPorts formats port mappings for display
func formatPorts(ports []*platformv1.PortMapping) string {
	if len(ports) == 0 {
		return ""
	}

	var portStrs []string
	for _, p := range ports {
		if p.HostIp != "" {
			portStrs = append(portStrs, fmt.Sprintf("%s:%d->%d/%s",
				p.HostIp, p.HostPort, p.ContainerPort, p.Protocol))
		} else {
			portStrs = append(portStrs, fmt.Sprintf("%d->%d/%s",
				p.HostPort, p.ContainerPort, p.Protocol))
		}
	}

	return strings.Join(portStrs, ", ")
}
