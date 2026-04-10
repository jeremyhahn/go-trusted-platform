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

import "context"

type noopConfigurator struct{}

// NewNoopConfigurator returns a Configurator that performs no operations.
// Used when no switch configuration is provided, or for testing.
func NewNoopConfigurator() Configurator {
	return &noopConfigurator{}
}

func (n *noopConfigurator) ConfigureVLANs(_ context.Context, _ []VLANConfig) error {
	return nil
}

func (n *noopConfigurator) ConfigurePorts(_ context.Context, _ []PortConfig) error {
	return nil
}

func (n *noopConfigurator) Configure(_ context.Context, _ *Config) error {
	return nil
}

func (n *noopConfigurator) Verify(_ context.Context, _ *Config) error {
	return nil
}

func (n *noopConfigurator) Close() error {
	return nil
}
