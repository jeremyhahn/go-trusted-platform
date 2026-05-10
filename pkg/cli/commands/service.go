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

package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// serviceActionResponse is the structured response for service action commands
// (start, stop, restart) when JSON or YAML output format is requested.
type serviceActionResponse struct {
	Service string `json:"service" yaml:"service"`
	Action  string `json:"action" yaml:"action"`
	Success bool   `json:"success" yaml:"success"`
	Message string `json:"message" yaml:"message"`
}

// NewServiceCommand creates the service management command
func NewServiceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage platform services",
		Long:  "Start, stop, restart, and query platform services",
	}

	cmd.AddCommand(newServiceListCommand(getFlags))
	cmd.AddCommand(newServiceStartCommand(getFlags))
	cmd.AddCommand(newServiceStopCommand(getFlags))
	cmd.AddCommand(newServiceRestartCommand(getFlags))
	cmd.AddCommand(newServiceStatusCommand(getFlags))

	return cmd
}

// newServiceListCommand creates the service list subcommand
func newServiceListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all services",
		Long:  "Display a list of all platform services and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runServiceList(flags)
		},
	}
}

// newServiceStartCommand creates the service start subcommand
func newServiceStartCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "start <service-type>",
		Short: "Start a service",
		Long:  "Start a platform service (tpm, sdn, compute, dns, acme, webservice, attestation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runServiceStart(flags, args[0])
		},
	}
}

// newServiceStopCommand creates the service stop subcommand
func newServiceStopCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	var timeout uint32

	cmd := &cobra.Command{
		Use:   "stop <service-type>",
		Short: "Stop a service",
		Long:  "Stop a platform service (tpm, sdn, compute, dns, acme, webservice, attestation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runServiceStop(flags, args[0], force, timeout)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "force stop the service")
	cmd.Flags().Uint32VarP(&timeout, "timeout", "t", 30, "timeout in seconds")

	return cmd
}

// newServiceRestartCommand creates the service restart subcommand
func newServiceRestartCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var timeout uint32

	cmd := &cobra.Command{
		Use:   "restart <service-type>",
		Short: "Restart a service",
		Long:  "Restart a platform service (tpm, sdn, compute, dns, acme, webservice, attestation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runServiceRestart(flags, args[0], timeout)
		},
	}

	cmd.Flags().Uint32VarP(&timeout, "timeout", "t", 30, "timeout in seconds")

	return cmd
}

// newServiceStatusCommand creates the service status subcommand
func newServiceStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status <service-type>",
		Short: "Get service status",
		Long:  "Display the status of a specific platform service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runServiceStatus(flags, args[0])
		},
	}
}

func runServiceList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	services, err := daemonClient.ListServicesDomain(ctx)
	if err != nil {
		return err
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(services)

	case cli.OutputFormatTable:
		table := cli.NewTableData("Name", "Type", "Status", "Health", "Uptime", "Version")
		for _, svc := range services {
			table.AddRow(
				svc.Name,
				string(svc.Type),
				string(svc.Status),
				string(svc.Health),
				fmt.Sprintf("%ds", svc.UptimeSeconds),
				svc.Version,
			)
		}
		return printer.Print(*table)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runServiceStart(flags *cli.CommonFlags, serviceType string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	_, err = daemonClient.StartServiceDomain(ctx, serviceType)
	if err != nil {
		return err
	}

	printer := base.Printer()
	message := fmt.Sprintf("Service %s started successfully", serviceType)
	return printServiceAction(printer, flags.OutputFormat, serviceType, "start", message)
}

func runServiceStop(flags *cli.CommonFlags, serviceType string, force bool, timeout uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	err = daemonClient.StopServiceDomain(ctx, serviceType, force, timeout)
	if err != nil {
		return err
	}

	printer := base.Printer()
	message := fmt.Sprintf("Service %s stopped successfully", serviceType)
	return printServiceAction(printer, flags.OutputFormat, serviceType, "stop", message)
}

func runServiceRestart(flags *cli.CommonFlags, serviceType string, timeout uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	_, err = daemonClient.RestartServiceDomain(ctx, serviceType, timeout)
	if err != nil {
		return err
	}

	printer := base.Printer()
	message := fmt.Sprintf("Service %s restarted successfully", serviceType)
	return printServiceAction(printer, flags.OutputFormat, serviceType, "restart", message)
}

// printServiceAction outputs a service action result in the requested format.
// For JSON/YAML, it prints a structured serviceActionResponse. For table
// format, it prints a human-readable success message.
func printServiceAction(printer *cli.Printer, format cli.OutputFormat, service, action, message string) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(serviceActionResponse{
			Service: service,
			Action:  action,
			Success: true,
			Message: message,
		})

	case cli.OutputFormatTable:
		printer.PrintSuccess(message)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

func runServiceStatus(flags *cli.CommonFlags, serviceType string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	svc, err := daemonClient.GetServiceStatusDomain(ctx, serviceType)
	if err != nil {
		return err
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(svc)

	case cli.OutputFormatTable:
		if svc != nil {
			printer.PrintKeyValue("Name", svc.Name)
			printer.PrintKeyValue("Type", string(svc.Type))
			printer.PrintKeyValue("Status", string(svc.Status))
			printer.PrintKeyValue("Health", string(svc.Health))
			printer.PrintKeyValue("Version", svc.Version)
			printer.PrintKeyValue("Uptime", fmt.Sprintf("%d seconds", svc.UptimeSeconds))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
