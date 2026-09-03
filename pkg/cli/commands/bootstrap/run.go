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
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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

	// Listen for SIGINT/SIGTERM. Before this the command ran under
	// context.Background(), so an operator could not interrupt it at all —
	// #135 run 10 "survived SIGTERM, needed SIGKILL". A run that ignores
	// SIGTERM cannot be stopped cleanly and cannot be asked for diagnostics.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := runOrchestratorWithShutdownWatchdog(ctx, orch)
	if err != nil {
		printBootstrapResult(result)
		return ErrPXERunFailed{Cause: err}
	}

	printBootstrapResult(result)
	return nil
}

// shutdownGrace is how long Run may take to unwind after its context is
// cancelled before the watchdog treats it as stuck and dumps goroutines.
const shutdownGrace = 30 * time.Second

// runOrchestratorWithShutdownWatchdog runs the orchestrator and, if it fails to
// return after its context is cancelled, dumps every goroutine's stack to
// stderr before giving up.
//
// #135: run 10 completed every phase, logged "tearing down bootstrap
// container", and then never returned — stuck in futex_do_wait for 20+ minutes
// with zero output, surviving SIGTERM. A fully successful deploy reported
// nothing, because the result table prints only after Run returns. The cause is
// a goroutine that never drains after teardown (SOL/console session, SSH
// channel, or an undrained WaitGroup) and it is not diagnosable after the fact.
//
// The watchdog is armed ONLY by context cancellation, never by elapsed run
// time: a healthy deploy legitimately runs for a long time, so a blanket timer
// would fire on good runs. This way an operator who sees a hang sends SIGTERM
// and gets a full goroutine dump naming the stuck stack, instead of SIGKILL and
// nothing.
func runOrchestratorWithShutdownWatchdog(ctx context.Context, orch *bootstrap.Orchestrator) (*bootstrap.BootstrapResult, error) {
	return runWithShutdownWatchdog(ctx, shutdownGrace, os.Stderr, orch.Run)
}

// runWithShutdownWatchdog is the watchdog policy itself, with the orchestrator,
// the grace period and the diagnostic sink all injected.
//
// This is deliberately the ONLY implementation: an earlier version kept the
// policy inline here and a lookalike in the test, so the tests passed over a
// duplicate while the production path — the wiring to orch.Run, the grace
// value, and whether a dump was emitted at all — went unexercised. A test that
// re-implements the code under test verifies the copy (test doubles that lie).
func runWithShutdownWatchdog(
	ctx context.Context,
	grace time.Duration,
	dumpTo io.Writer,
	run func(context.Context) (*bootstrap.BootstrapResult, error),
) (*bootstrap.BootstrapResult, error) {
	type outcome struct {
		result *bootstrap.BootstrapResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := run(ctx)
		done <- outcome{result: r, err: err}
	}()

	select {
	case out := <-done:
		return out.result, out.err
	case <-ctx.Done():
		// Cancelled (signal or parent). Give the run a bounded chance to unwind.
		select {
		case out := <-done:
			return out.result, out.err
		case <-time.After(grace):
			dumpGoroutines(dumpTo, grace)
			return nil, ErrBootstrapShutdownStuck{Grace: grace}
		}
	}
}

// diagnosticWriteTimeout bounds how long the watchdog will wait for its own
// diagnostic to reach the writer.
//
// This exists because the diagnostic can hang the very shutdown it reports on.
// A blocked write to stderr — a pipe whose reader has stopped consuming, a
// terminal that went away — blocks forever, and by then signal.NotifyContext
// has already consumed SIGTERM, so the command needs SIGKILL and prints
// nothing. That is #135 reproduced by the code written to diagnose #135.
var diagnosticWriteTimeout = 5 * time.Second

// diagnosticWriteTimeoutForTest shortens the bound so a regression fails fast
// instead of stalling the package until go test's own timeout.
func diagnosticWriteTimeoutForTest(d time.Duration) (restore func()) {
	prev := diagnosticWriteTimeout
	diagnosticWriteTimeout = d
	return func() { diagnosticWriteTimeout = prev }
}

// dumpGoroutines writes every goroutine's stack to w, giving up if the write
// does not complete within diagnosticWriteTimeout.
//
// The stack is rendered into memory FIRST and the write is then attempted in a
// goroutine, so a writer that never drains costs a bounded delay instead of the
// process. A dropped diagnostic is a bad outcome; an unkillable process is a
// worse one, and the caller is already on its way to failing.
func dumpGoroutines(w io.Writer, grace time.Duration) {
	buf := make([]byte, 1<<20)
	var stack []byte
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			stack = buf[:n]
			break
		}
		// Stack did not fit; grow and retry so the dump is never truncated
		// at exactly the point that matters.
		buf = make([]byte, 2*len(buf))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		fmt.Fprintf(w, "\nbootstrap: did not shut down within %s after cancellation — dumping goroutines (#135)\n", grace)
		w.Write(stack)
	}()

	select {
	case <-done:
	case <-time.After(diagnosticWriteTimeout):
		// The goroutine stays blocked on the writer; it holds only the stack
		// buffer and the process is exiting anyway. Returning is the point.
	}
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
		provSubnetGateway := ""
		if ps := config.ProvisioningSubnet(); ps != nil {
			provSubnetGateway = ps.Gateway
		}
		cmds, renderErr := deployer.RenderCiscoDeployPlan(
			provSubnetGateway, provisioningVLAN)
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
