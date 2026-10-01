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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newDeployCommand creates the deploy subcommand for deploying the bootstrap container.
func newDeployCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy bootstrap container",
		Long: `Deploy the PXE bootstrap container to the deployer host.

This runs the first phases of "bootstrap run" and stops once the container
is serving: discovery of the nodes' MACs (Phase 0), switch configuration
when bootstrap.yaml has a switch section (Phase 1), and the container
deploy with the manifest built from discovery and the netboot media build
(Phase 2).

Examples:
  # Deploy the bootstrap container
  platformctl bootstrap deploy --config bootstrap.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runDeploy(configPath, commonFlags)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")

	return cmd
}

// runDeploy brings the bootstrap container up through the orchestrator,
// exactly as the first phases of bootstrap run do.
func runDeploy(configPath string, commonFlags *cli.CommonFlags) error {
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

	result, err := orch.Deploy(context.Background())
	if err != nil {
		return ErrPXEDeployFailed{Cause: err}
	}

	fmt.Fprintf(os.Stdout, "Bootstrap container deployed\n")
	fmt.Fprintf(os.Stdout, "  Host:        %s\n", config.Deployer.Host)
	fmt.Fprintf(os.Stdout, "  Nodes:       %d\n", len(result.Nodes))
	fmt.Fprintf(os.Stdout, "  Switch:      %t\n", result.SwitchConfigured)
	fmt.Fprintf(os.Stdout, "  Duration:    %s\n", result.Duration)
	return nil
}
