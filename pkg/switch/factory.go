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

package switchmgmt

import "log/slog"

// ConfiguratorFactory creates a Configurator for a given vendor.
type ConfiguratorFactory func(config *Config, logger *slog.Logger) (Configurator, error)

// configuratorRegistry maps vendor identifiers to their factory functions.
var configuratorRegistry = map[SwitchVendor]ConfiguratorFactory{
	VendorCiscoNexus: newCiscoNexusConfigurator,
	VendorNoop:       newNoopConfiguratorFactory,
}

// NewConfigurator creates a switch configurator for the given vendor.
// Returns a no-op configurator if config is nil.
func NewConfigurator(config *Config, logger *slog.Logger) (Configurator, error) {
	if config == nil {
		return NewNoopConfigurator(), nil
	}
	factory, ok := configuratorRegistry[config.Vendor]
	if !ok {
		return nil, ErrUnsupportedVendor{Vendor: config.Vendor}
	}
	return factory(config, logger)
}

func newNoopConfiguratorFactory(_ *Config, _ *slog.Logger) (Configurator, error) {
	return NewNoopConfigurator(), nil
}
