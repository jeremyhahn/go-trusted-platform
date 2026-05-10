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
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// loadAndValidateConfig loads, parses, and validates a PXE bootstrap configuration file.
func loadAndValidateConfig(path string) (*bootstrap.BootstrapConfig, error) {
	if path == "" {
		return nil, ErrPXEConfigRequired{}
	}
	config, err := bootstrap.LoadBootstrapConfig(path)
	if err != nil {
		return nil, ErrPXEConfigLoadFailed{Path: path, Cause: err}
	}
	if err := config.Validate(); err != nil {
		return nil, ErrPXEConfigValidationFailed{Cause: err}
	}
	return config, nil
}

// createOrchestrator builds an Orchestrator from a validated bootstrap
// config. configPath is the path to the bootstrap YAML file, used to
// resolve relative template paths.
//
// When `deployer.host` and `deployer.container_image` are both set in
// the bootstrap config, this constructor wires a real deployer adapter
// so Phase 2 (deploy bootstrap container) actually runs. Earlier
// versions left the orchestrator's Deployer nil and silently skipped
// Phase 2, which broke virtual-media boot whenever the deployer
// host's bootstrap container was stale or absent.
//
// When `container_image` is empty the adapter is omitted (Phase 2
// remains a no-op) — useful for debugging flows where the operator has
// already started the bootstrap container manually.
func createOrchestrator(config *bootstrap.BootstrapConfig, configPath string, logger *slog.Logger) (*bootstrap.Orchestrator, error) {
	bmcFactory := bmc.NewDefaultClientFactory(logger)

	var dep bootstrap.Deployer
	if config.Deployer.Host != "" && config.Deployer.ContainerImage != "" {
		d, err := bootstrap.NewLinuxDeployerAdapter(&config.Deployer, logger)
		if err != nil {
			return nil, ErrDeployerCreationFailed{Target: config.Deployer.Target, Cause: err}
		}
		dep = d
	}

	orch, err := bootstrap.NewOrchestrator(bootstrap.OrchestratorParams{
		Config:     config,
		ConfigPath: configPath,
		BMCFactory: bmcFactory,
		Logger:     logger,
		Deployer:   dep,
	})
	if err != nil {
		return nil, ErrOrchestratorCreationFailed{Cause: err}
	}
	return orch, nil
}
