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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// createOptions holds the options for the create command
type createOptions struct {
	name        string
	image       string
	env         []string
	label       []string
	port        []string
	mount       []string
	privileged  bool
	networkMode string
	memory      string
	cpu         string
	command     []string
	workDir     string
	tpmAccess   bool
	start       bool
}

// newCreateCommand creates the container create subcommand
func newCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &createOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new container",
		Long: `Create a new container with the specified configuration.

The container is created but not started unless --start is specified.

Examples:
  # Create a basic container
  platformctl container create --name myapp --image nginx:latest

  # Create container with environment variables
  platformctl container create --name myapp --image myimage \
    --env "DB_HOST=localhost" --env "DB_PORT=5432"

  # Create container with port mappings
  platformctl container create --name myapp --image nginx:latest \
    --port 8080:80 --port 8443:443

  # Create container with volume mounts
  platformctl container create --name myapp --image nginx:latest \
    --mount /host/data:/container/data --mount /host/config:/container/config:ro

  # Create container with resource limits
  platformctl container create --name myapp --image nginx:latest \
    --memory 512m --cpu 0.5

  # Create container with TPM access
  platformctl container create --name myapp --image myimage \
    --tpm-access --privileged

  # Create and start container immediately
  platformctl container create --name myapp --image nginx:latest --start`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCreate(flags, opts)
		},
	}

	// Required flags
	cmd.Flags().StringVarP(&opts.name, "name", "n", "", "container name (required)")
	cmd.Flags().StringVarP(&opts.image, "image", "i", "", "container image (required)")

	// Optional flags
	cmd.Flags().StringArrayVarP(&opts.env, "env", "e", nil, "environment variables (KEY=value)")
	cmd.Flags().StringArrayVarP(&opts.label, "label", "l", nil, "labels (key=value)")
	cmd.Flags().StringArrayVarP(&opts.port, "port", "p", nil, "port mappings (hostPort:containerPort[/protocol])")
	cmd.Flags().StringArrayVarP(&opts.mount, "mount", "m", nil, "volume mounts (hostPath:containerPath[:ro])")
	cmd.Flags().BoolVar(&opts.privileged, "privileged", false, "run container in privileged mode")
	cmd.Flags().StringVar(&opts.networkMode, "network-mode", "", "network mode (bridge, host, none)")
	cmd.Flags().StringVar(&opts.memory, "memory", "", "memory limit (e.g., 512m, 1g)")
	cmd.Flags().StringVar(&opts.cpu, "cpu", "", "CPU limit (e.g., 1, 2, 4)")
	cmd.Flags().StringArrayVar(&opts.command, "cmd", nil, "command to run in container")
	cmd.Flags().StringVarP(&opts.workDir, "workdir", "w", "", "working directory inside container")
	cmd.Flags().BoolVar(&opts.tpmAccess, "tpm-access", false, "mount host TPM device into container")
	cmd.Flags().BoolVar(&opts.start, "start", false, "start container immediately after creation")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "name", "image")

	return cmd
}

// runCreate executes the container create command
func runCreate(flags *cli.CommonFlags, opts *createOptions) error {
	// Validate options
	if opts.name == "" {
		return ErrInvalidContainerConfig{Field: "name", Reason: "name is required"}
	}
	if opts.image == "" {
		return ErrInvalidContainerConfig{Field: "image", Reason: "image is required"}
	}

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

	// Parse environment variables
	envVars, err := parseEnvVars(opts.env)
	if err != nil {
		return err
	}

	// Parse labels
	labels, err := parseLabels(opts.label)
	if err != nil {
		return err
	}

	// Parse port mappings
	ports, err := parsePortMappings(opts.port)
	if err != nil {
		return err
	}

	// Parse volume mounts
	volumes, err := parseMountSpecs(opts.mount)
	if err != nil {
		return err
	}

	// Parse resource limits
	memoryMB, err := parseMemory(opts.memory)
	if err != nil {
		return err
	}

	cpuLimit, err := parseCPUCount(opts.cpu)
	if err != nil {
		return err
	}

	// Build create params
	params := &computesvc.CreateContainerParams{
		Name:       opts.name,
		Image:      opts.image,
		Env:        envVars,
		Labels:     labels,
		Ports:      ports,
		Volumes:    volumes,
		Privileged: opts.privileged,
		Network:    opts.networkMode,
		Command:    opts.command,
		WorkingDir: opts.workDir,
		TpmAccess:  opts.tpmAccess,
		Start:      opts.start,
	}

	// Set resource limits if specified
	if memoryMB > 0 || cpuLimit > 0 {
		params.Resources = &computesvc.ResourceLimits{
			MaxMemoryMB: memoryMB,
			MaxCPUs:     cpuLimit,
		}
	}

	ctx := base.Context()
	container, err := sdkClient.CreateContainerDomain(ctx, params)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "create", ID: opts.name, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(container)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Container created successfully: %s", container.ID))
		fmt.Println()
		printContainerDetails(printer, container)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printContainerDetails prints container details in a formatted way
func printContainerDetails(printer *cli.Printer, container *computesvc.Container) {
	if container == nil {
		return
	}

	printer.PrintKeyValue("ID", container.ID)
	if container.Config != nil {
		printer.PrintKeyValue("Name", container.Config.Name)
		printer.PrintKeyValue("Image", container.Config.Image)
		if container.Config.WorkingDir != "" {
			printer.PrintKeyValue("Working Dir", container.Config.WorkingDir)
		}
		if len(container.Config.Command) > 0 {
			printer.PrintKeyValue("Command", fmt.Sprintf("%v", container.Config.Command))
		}
		printer.PrintKeyValue("Privileged", formatBool(container.Config.Privileged))
		printer.PrintKeyValue("TPM Access", formatBool(container.Config.TpmAccess))
		if container.Config.Network != "" {
			printer.PrintKeyValue("Network", container.Config.Network)
		}
	}
	printer.PrintKeyValue("State", formatContainerState(container.State))
	printer.PrintKeyValue("Created At", formatTimestamp(container.CreatedAt))
	if !container.StartedAt.IsZero() {
		printer.PrintKeyValue("Started At", formatTimestamp(container.StartedAt))
	}
	if container.HostID != "" {
		printer.PrintKeyValue("Host ID", container.HostID)
	}
}

// parseCPUCount parses a CPU count specification (e.g., 1, 2, 4)
func parseCPUCount(spec string) (uint32, error) {
	if spec == "" {
		return 0, nil
	}

	value, err := parseCPU(spec)
	if err != nil {
		return 0, err
	}

	return uint32(value), nil
}
