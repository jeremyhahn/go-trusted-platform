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

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newRunCommand creates the run subcommand for executing a full PXE bootstrap.
func newRunCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string
	var dryRun bool
	var skipVirtualMediaMount bool

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run full PXE bootstrap",
		Long: `Execute the complete PXE bootstrap flow.

This command performs all bootstrap phases:
  Phase 0: Discover MAC addresses from BMCs (or use manual MACs)
  Phase 1: Configure physical switch (optional)
  Phase 2: Deploy bootstrap container to target host
  Phase 3: PXE boot control-plane nodes
  Phase 4: Seed device templates and create profiles
  Phase 5: PXE boot gateway and worker nodes
  Phase 6: Teardown bootstrap container

Use --dry-run to validate configuration and test BMC connectivity
without making any changes to real infrastructure.

Examples:
  # Run full bootstrap
  platformctl bootstrap run --config bootstrap.yaml

  # Validate config and test connectivity only
  platformctl bootstrap run --config bootstrap.yaml --dry-run

  # Run with verbose logging
  platformctl bootstrap run --config bootstrap.yaml --verbose`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			if dryRun {
				return runBootstrapDryRun(configPath, commonFlags)
			}
			return runBootstrap(configPath, commonFlags, skipVirtualMediaMount)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate config and test BMC connectivity without making changes")
	cmd.Flags().BoolVar(&skipVirtualMediaMount, "skip-virtual-media-mount", false,
		"for boot_method: virtual-media nodes, assume operator inserted media out-of-band; "+
			"orchestrator runs SetBootDevice + power reset + wait health + best-effort unmount only. "+
			"Use as a documented escape hatch on Supermicro DCMS-licensed boards until smc-cgi backend is implemented.")

	return cmd
}

// runBootstrap loads config, creates the orchestrator, executes the full run,
// and prints per-node results. skipVirtualMediaMount lets the operator
// bypass MountVirtualMedia for boot_method: virtual-media nodes when the
// orchestrator's BMC backends can't reach the vendor mount API (e.g.
// Supermicro DCMS-licensed Redfish endpoints).
func runBootstrap(configPath string, commonFlags *cli.CommonFlags, skipVirtualMediaMount bool) error {
	config, err := loadAndValidateConfig(configPath)
	if err != nil {
		return err
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr).Slog()

	orch, err := createOrchestrator(config, configPath, logger)
	if err != nil {
		return err
	}
	orch.SkipVirtualMediaMount = skipVirtualMediaMount

	ctx := context.Background()
	result, err := orch.Run(ctx)
	if err != nil {
		printBootstrapResult(result)
		return ErrPXERunFailed{Cause: err}
	}

	printBootstrapResult(result)
	return nil
}

// runBootstrapDryRun loads config, creates the orchestrator, executes a dry-run
// validation, and prints the execution plan.
func runBootstrapDryRun(configPath string, commonFlags *cli.CommonFlags) error {
	config, err := loadAndValidateConfig(configPath)
	if err != nil {
		return err
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr).Slog()

	orch, err := createOrchestrator(config, configPath, logger)
	if err != nil {
		return err
	}

	ctx := context.Background()
	result, err := orch.DryRun(ctx)

	// If the deployer target is Cisco, render the CLI commands for inspection.
	if result != nil && result.DeployerTarget == string(deployer.TargetCisco) {
		provisioningVLAN := deployer.DefaultCiscoProvisioningVLAN
		cmds, renderErr := deployer.RenderCiscoDeployPlan(
			config.ProvisioningNetwork.Gateway, provisioningVLAN)
		if renderErr != nil {
			result.Warnings = append(result.Warnings,
				"could not render cisco commands: "+renderErr.Error())
		} else {
			result.CiscoCommands = cmds
		}
	}

	printDryRunResult(result)
	if err != nil {
		return ErrPXEDryRunFailed{Cause: err}
	}
	return nil
}

// printBootstrapResult prints the bootstrap result summary to stdout.
func printBootstrapResult(result *bootstrap.BootstrapResult) {
	if result == nil {
		return
	}

	fmt.Fprintf(os.Stdout, "\nBootstrap Result\n")
	fmt.Fprintf(os.Stdout, "  Phase:     %s\n", result.Phase)
	fmt.Fprintf(os.Stdout, "  Duration:  %s\n", result.Duration)
	fmt.Fprintf(os.Stdout, "  Switch:    %s\n", boolStatus(result.SwitchConfigured))
	fmt.Fprintf(os.Stdout, "  Container: %s\n", boolStatus(result.ContainerDeployed))
	fmt.Fprintf(os.Stdout, "  Control:   %s\n", boolStatus(result.ControlPlaneReady))
	fmt.Fprintf(os.Stdout, "  Gateways:  %s\n", boolStatus(result.GatewaysReady))
	fmt.Fprintf(os.Stdout, "  Workers:   %s\n", boolStatus(result.WorkersReady))
	fmt.Fprintf(os.Stdout, "  Teardown:  %s\n", boolStatus(result.ContainerTornDown))

	if len(result.Nodes) > 0 {
		fmt.Fprintf(os.Stdout, "\n  %-20s %-15s %-18s %-10s %-12s %s\n",
			"HOSTNAME", "ROLE", "MAC", "BMC", "STATUS", "ERROR")
		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %-12s %s\n",
			"--------", "----", "---", "---", "------", "-----")
		for i := range result.Nodes {
			n := &result.Nodes[i]
			bmcStr := "no"
			if n.BMCManaged {
				bmcStr = "yes"
			}
			fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %-12s %s\n",
				n.Hostname, n.Role, joinMACs(n.MACs), bmcStr, n.Status, n.Error)
		}
	}
	fmt.Fprintln(os.Stdout)
}

// printDryRunResult prints a formatted dry-run execution plan to stdout.
func printDryRunResult(result *bootstrap.DryRunResult) {
	if result == nil {
		return
	}

	configStatus := "valid"
	if !result.ConfigValid {
		configStatus = "INVALID"
	}

	fmt.Fprintf(os.Stdout, "\nDry Run Result\n")
	fmt.Fprintf(os.Stdout, "  Config:     %s\n", configStatus)
	fmt.Fprintf(os.Stdout, "  Deployer:   %s @ %s\n", result.DeployerTarget, result.DeployerHost)

	if result.SwitchConfigured {
		fmt.Fprintf(os.Stdout, "  Switch:     %s\n", result.SwitchVendor)
	} else {
		fmt.Fprintf(os.Stdout, "  Switch:     not configured\n")
	}

	fmt.Fprintf(os.Stdout, "  Duration:   %s\n", result.Duration)

	// Execution plan.
	fmt.Fprintf(os.Stdout, "\n  Execution Plan:\n")

	bmcCount := 0
	for i := range result.Nodes {
		if result.Nodes[i].BMCManaged {
			bmcCount++
		}
	}

	fmt.Fprintf(os.Stdout, "    Phase 0: Discover MACs from %d BMC-managed nodes\n", bmcCount)

	if result.SwitchConfigured {
		fmt.Fprintf(os.Stdout, "    Phase 1: Configure switch (%s)\n", result.SwitchVendor)
	} else {
		fmt.Fprintf(os.Stdout, "    Phase 1: Skip switch configuration (not configured)\n")
	}

	fmt.Fprintf(os.Stdout, "    Phase 2: Deploy bootstrap container to %s (%s)\n",
		result.DeployerHost, result.DeployerTarget)
	fmt.Fprintf(os.Stdout, "    Phase 3: PXE boot %d control-plane node(s), wait for health\n",
		result.ControlPlaneCount)
	fmt.Fprintf(os.Stdout, "    Phase 4: Seed device templates and create profiles\n")

	remainingCount := result.GatewayCount + result.WorkerCount
	fmt.Fprintf(os.Stdout, "    Phase 5: PXE boot %d remaining nodes (%d gateway, %d worker)\n",
		remainingCount, result.GatewayCount, result.WorkerCount)
	fmt.Fprintf(os.Stdout, "    Phase 6: Teardown bootstrap container\n")

	// Switch plan.
	printSwitchPlan(result.SwitchPlan)

	// Cisco app-hosting commands.
	printCiscoCommands(result)

	// Node table.
	if len(result.Nodes) > 0 {
		fmt.Fprintf(os.Stdout, "\n  Nodes:\n")
		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %-10s %-18s %s\n",
			"HOSTNAME", "ROLE", "BMC ADDRESS", "PROTOCOL", "REACHABLE", "MAC", "STATUS")
		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %-10s %-18s %s\n",
			"--------", "----", "-----------", "--------", "---------", "---", "------")
		for i := range result.Nodes {
			n := &result.Nodes[i]
			reachable := "n/a"
			if n.BMCManaged {
				reachable = "no"
				if n.BMCReachable {
					reachable = "yes"
				}
			}
			macs := joinMACs(n.MACs)
			if discovered := joinMACs(n.DiscoveredMACs); discovered != "" {
				macs = discovered
			}
			fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %-10s %-18s %s\n",
				n.Hostname, n.Role, n.BMCAddress, n.BMCProtocol, reachable, macs, n.Status)
		}
	}

	// Resolved device configs.
	printResolvedConfigs(result.Nodes)

	// Warnings.
	fmt.Fprintf(os.Stdout, "\n  Warnings:")
	if len(result.Warnings) == 0 {
		fmt.Fprintf(os.Stdout, " (none)\n")
	} else {
		fmt.Fprintln(os.Stdout)
		for _, w := range result.Warnings {
			fmt.Fprintf(os.Stdout, "    - %s\n", w)
		}
	}

	// Errors.
	fmt.Fprintf(os.Stdout, "  Errors:")
	if len(result.Errors) == 0 {
		fmt.Fprintf(os.Stdout, " (none)\n")
	} else {
		fmt.Fprintln(os.Stdout)
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stdout, "    - %s\n", e)
		}
	}

	fmt.Fprintln(os.Stdout)
}

// printSwitchPlan prints the switch configuration plan to stdout.
func printSwitchPlan(plan *bootstrap.SwitchPlan) {
	if plan == nil {
		return
	}

	fmt.Fprintf(os.Stdout, "\n  Switch Plan (%s @ %s):\n", plan.Vendor, plan.Host)

	if len(plan.VLANs) > 0 {
		fmt.Fprintf(os.Stdout, "    VLANs to configure:\n")
		for i := range plan.VLANs {
			v := &plan.VLANs[i]
			fmt.Fprintf(os.Stdout, "      VLAN %-5d %-15s %s\n", v.ID, v.Name, v.Subnet)
		}
	}

	if len(plan.Ports) > 0 {
		fmt.Fprintf(os.Stdout, "    Ports to configure:\n")
		for i := range plan.Ports {
			p := &plan.Ports[i]
			vlanStrs := make([]string, len(p.VLANs))
			for j, vid := range p.VLANs {
				vlanStrs[j] = strconv.Itoa(vid)
			}
			fmt.Fprintf(os.Stdout, "      %-10s %-6s VLANs [%s]  %s\n",
				p.Port, p.Mode, strings.Join(vlanStrs, ","), p.Description)
		}
	}
}

// printCiscoCommands prints the Cisco IOS-XE app-hosting CLI commands when
// the deployer target is Cisco.
func printCiscoCommands(result *bootstrap.DryRunResult) {
	if result.CiscoCommands == "" {
		return
	}

	fmt.Fprintf(os.Stdout, "\n  Cisco App-Hosting Commands (%s @ %s):\n",
		result.DeployerTarget, result.DeployerHost)
	fmt.Fprintf(os.Stdout, "  %s\n", strings.Repeat("=", 55))

	lines := strings.Split(strings.TrimRight(result.CiscoCommands, "\n"), "\n")
	for _, line := range lines {
		fmt.Fprintf(os.Stdout, "  %s\n", line)
	}
}

// printResolvedConfigs prints resolved device configurations per node.
func printResolvedConfigs(nodes []bootstrap.DryRunNodeResult) {
	hasConfig := false
	for i := range nodes {
		if nodes[i].ResolvedConfig != "" {
			hasConfig = true
			break
		}
	}
	if !hasConfig {
		return
	}

	fmt.Fprintf(os.Stdout, "\n  Resolved Device Configs:\n")
	fmt.Fprintf(os.Stdout, "  ========================\n")

	for i := range nodes {
		n := &nodes[i]
		if n.ResolvedConfig == "" {
			continue
		}
		fmt.Fprintf(os.Stdout, "\n  --- %s (%s) ---\n", n.Hostname, n.Role)
		// Indent each line of the resolved config for readability.
		lines := strings.Split(strings.TrimRight(n.ResolvedConfig, "\n"), "\n")
		for _, line := range lines {
			fmt.Fprintf(os.Stdout, "  %s\n", line)
		}
	}
}

// boolStatus returns a human-readable status string for a boolean.
func boolStatus(b bool) string {
	if b {
		return "done"
	}
	return "pending"
}
