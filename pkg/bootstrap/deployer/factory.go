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

package deployer

import "log/slog"

// DeployerFactory is the function signature for deployer constructors.
type DeployerFactory func(logger *slog.Logger) Deployer

// deployers is a map-based dispatch table for deployer targets.
var deployers = map[DeployTarget]DeployerFactory{
	TargetLinux: func(logger *slog.Logger) Deployer {
		return &LinuxDeployer{logger: logger}
	},
	TargetCisco: func(logger *slog.Logger) Deployer {
		return &CiscoDeployer{logger: logger}
	},
}

// NewDeployer creates a Deployer for the given target using map-based dispatch.
func NewDeployer(target DeployTarget, logger *slog.Logger) (Deployer, error) {
	factory, ok := deployers[target]
	if !ok {
		return nil, ErrUnknownTarget{Target: target}
	}
	return factory(logger), nil
}
