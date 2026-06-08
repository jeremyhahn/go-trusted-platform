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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newDeployCommand creates the deploy subcommand for deploying the bootstrap container.
func newDeployCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy bootstrap container",
		Long: `Deploy the PXE bootstrap container to the configured target host.

This runs Phase 2 of the bootstrap flow: it discovers node MACs,
builds the container manifest, and deploys the bootstrap container
via SSH to the target host (Linux or Cisco IOS-XE guestshell).

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

// runDeploy loads config, discovers nodes, builds a manifest, and deploys the container.
func runDeploy(configPath string, commonFlags *cli.CommonFlags) error {
	config, err := loadAndValidateConfig(configPath)
	if err != nil {
		return err
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr).Slog()

	// Create deployer for the configured target.
	target := deployer.DeployTarget(config.Deployer.Target)
	dep, err := deployer.NewDeployer(target, logger)
	if err != nil {
		return ErrDeployerCreationFailed{Target: config.Deployer.Target, Cause: err}
	}

	ctx := context.Background()

	// Build deploy config from bootstrap config.
	deployConfig := buildDeployConfig(config, configPath)

	// Deploy the container.
	result, err := dep.Deploy(ctx, deployConfig)
	if err != nil {
		return ErrPXEDeployFailed{Cause: err}
	}

	fmt.Fprintf(os.Stdout, "Bootstrap container deployed\n")
	fmt.Fprintf(os.Stdout, "  Host:        %s\n", result.Host)
	fmt.Fprintf(os.Stdout, "  Container:   %s\n", result.ContainerID)
	fmt.Fprintf(os.Stdout, "  Running:     %t\n", result.Running)

	return nil
}

// buildDeployConfig converts a BootstrapConfig into a deployer.DeployConfig.
// configPath is the path to the bootstrap YAML, used to resolve relative paths.
func buildDeployConfig(config *bootstrap.BootstrapConfig, configPath string) *deployer.DeployConfig {
	configDir := ""
	if configPath != "" {
		configDir = filepath.Dir(configPath)
	}

	// Expand ~ in SSH key path.
	sshKey := config.Deployer.SSHKey
	if strings.HasPrefix(sshKey, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			sshKey = filepath.Join(home, sshKey[2:])
		}
	}

	dc := &deployer.DeployConfig{
		Target:           deployer.DeployTarget(config.Deployer.Target),
		Host:             config.Deployer.Host,
		User:             config.Deployer.User,
		SSHKeyPath:       sshKey,
		ContainerRuntime: config.Deployer.ContainerRuntime,
		ContainerImage:   config.Deployer.ContainerImage,
		// DataDir is required by teardown so the root cleanup container
		// targets the configured staging directory rather than the
		// package default; EffectiveDataDir falls back to that default
		// when unset.
		DataDir:            config.Deployer.EffectiveDataDir(),
		TransferProtocol:   config.Deployer.TransferProtocol,
		TransferServer:     config.Deployer.TransferServer,
		CiscoAppID:         config.Deployer.AppID,
		CiscoImageFile:     config.Deployer.ImageFile,
		ProvisioningSubnet: config.ProvisioningSubnet(),
	}

	// Resolve relative config file path against bootstrap.yaml directory.
	if config.Deployer.ConfigFile != "" {
		cfgPath := config.Deployer.ConfigFile
		if !filepath.IsAbs(cfgPath) && configDir != "" {
			cfgPath = filepath.Join(configDir, cfgPath)
		}
		dc.CiscoConfigFile = cfgPath
	}

	dc.ApplyDefaults()
	return dc
}
