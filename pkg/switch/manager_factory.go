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

// ManagerFactory creates a Manager for a given switch Config.
type ManagerFactory func(config *Config, logger *slog.Logger) (Manager, error)

// managerRegistry maps vendor identifiers to their Manager factory functions.
var managerRegistry = map[SwitchVendor]ManagerFactory{
	VendorCiscoNexus: newSSHManager,
	VendorNoop:       newNoopManagerFactory,
}

// NewManager creates a Manager for the switch identified by the given config.
// Returns a no-op Manager if config is nil.
func NewManager(config *Config, logger *slog.Logger) (Manager, error) {
	if config == nil {
		return NewNoopManager(), nil
	}
	factory, ok := managerRegistry[config.Vendor]
	if !ok {
		return nil, ErrUnsupportedVendor{Vendor: config.Vendor}
	}
	return factory(config, logger)
}

func newNoopManagerFactory(_ *Config, _ *slog.Logger) (Manager, error) {
	return NewNoopManager(), nil
}
