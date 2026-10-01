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

// newTeardownCommand creates the teardown subcommand for removing the bootstrap container.
func newTeardownCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "teardown",
		Short: "Teardown bootstrap container",
		Long: `Teardown the PXE bootstrap container on the deployer host.

This stops and removes the bootstrap container and its data from the
deployer host. Use this to clean up after bootstrap completes
or to reset before a re-run.

Examples:
  # Teardown the bootstrap container
  platformctl bootstrap teardown --config bootstrap.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runTeardown(configPath, commonFlags)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")

	return cmd
}

// runTeardown tears the bootstrap container down through the orchestrator,
// as the last phase of bootstrap run does.
func runTeardown(configPath string, commonFlags *cli.CommonFlags) error {
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

	if err := orch.Teardown(context.Background()); err != nil {
		return ErrPXETeardownFailed{Cause: err}
	}

	fmt.Fprintf(os.Stdout, "Bootstrap container torn down on %s\n", config.Deployer.Host)
	return nil
}
