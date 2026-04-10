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

// createOrchestrator builds an Orchestrator from a validated bootstrap config.
// configPath is the path to the bootstrap YAML file, used to resolve relative
// template paths.
func createOrchestrator(config *bootstrap.BootstrapConfig, configPath string, logger *slog.Logger) (*bootstrap.Orchestrator, error) {
	bmcFactory := bmc.NewDefaultClientFactory(logger)
	orch, err := bootstrap.NewOrchestrator(bootstrap.OrchestratorParams{
		Config:     config,
		ConfigPath: configPath,
		BMCFactory: bmcFactory,
		Logger:     logger,
	})
	if err != nil {
		return nil, ErrOrchestratorCreationFailed{Cause: err}
	}
	return orch, nil
}
