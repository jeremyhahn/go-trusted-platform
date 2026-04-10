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
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

	ctx := base.Context()
	resp, err := base.Client().Daemon().ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		table := cli.NewTableData("Name", "Type", "Status", "Health", "Uptime", "Version")
		for _, svc := range resp.Services {
			table.AddRow(
				svc.Name,
				formatServiceType(svc.Type),
				formatServiceStatus(svc.Status),
				formatHealthStatus(svc.Health),
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

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := base.Client().Daemon().StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	printer := base.Printer()

	if resp.Status != nil && resp.Status.Success {
		return printServiceAction(printer, flags.OutputFormat, serviceType, "start",
			fmt.Sprintf("Service %s started successfully", serviceType))
	}

	if resp.Status != nil && resp.Status.Error != nil {
		return fmt.Errorf("failed to start service: %s", resp.Status.Error.Message)
	}

	return fmt.Errorf("failed to start service: unknown error")
}

func runServiceStop(flags *cli.CommonFlags, serviceType string, force bool, timeout uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := base.Client().Daemon().StopService(ctx, &platformv1.StopServiceRequest{
		Service:        svcType,
		Force:          force,
		TimeoutSeconds: timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	printer := base.Printer()

	if resp.Status != nil && resp.Status.Success {
		return printServiceAction(printer, flags.OutputFormat, serviceType, "stop",
			fmt.Sprintf("Service %s stopped successfully", serviceType))
	}

	if resp.Status != nil && resp.Status.Error != nil {
		return fmt.Errorf("failed to stop service: %s", resp.Status.Error.Message)
	}

	return fmt.Errorf("failed to stop service: unknown error")
}

func runServiceRestart(flags *cli.CommonFlags, serviceType string, timeout uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := base.Client().Daemon().RestartService(ctx, &platformv1.RestartServiceRequest{
		Service:        svcType,
		TimeoutSeconds: timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	printer := base.Printer()

	if resp.Status != nil && resp.Status.Success {
		return printServiceAction(printer, flags.OutputFormat, serviceType, "restart",
			fmt.Sprintf("Service %s restarted successfully", serviceType))
	}

	if resp.Status != nil && resp.Status.Error != nil {
		return fmt.Errorf("failed to restart service: %s", resp.Status.Error.Message)
	}

	return fmt.Errorf("failed to restart service: unknown error")
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

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := base.Client().Daemon().GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		return fmt.Errorf("failed to get service status: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Service != nil {
			printer.PrintKeyValue("Name", resp.Service.Name)
			printer.PrintKeyValue("Type", formatServiceType(resp.Service.Type))
			printer.PrintKeyValue("Status", formatServiceStatus(resp.Service.Status))
			printer.PrintKeyValue("Health", formatHealthStatus(resp.Service.Health))
			printer.PrintKeyValue("Version", resp.Service.Version)
			printer.PrintKeyValue("Uptime", fmt.Sprintf("%d seconds", resp.Service.UptimeSeconds))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func parseServiceType(s string) (platformv1.ServiceType, error) {
	switch strings.ToLower(s) {
	case "tpm":
		return platformv1.ServiceType_SERVICE_TYPE_TPM, nil
	case "sdn":
		return platformv1.ServiceType_SERVICE_TYPE_SDN, nil
	case "compute":
		return platformv1.ServiceType_SERVICE_TYPE_COMPUTE, nil
	case "dns":
		return platformv1.ServiceType_SERVICE_TYPE_DNS, nil
	case "acme":
		return platformv1.ServiceType_SERVICE_TYPE_ACME, nil
	case "webservice", "web":
		return platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, nil
	case "attestation":
		return platformv1.ServiceType_SERVICE_TYPE_ATTESTATION, nil
	default:
		return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, cli.ErrInvalidServiceType{Type: s}
	}
}
