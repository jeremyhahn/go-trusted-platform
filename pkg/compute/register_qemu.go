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

package compute

import "context"

// init registers the always-compiled local QEMU orchestrator with the
// provider factory so unified provider selection can resolve "local-qemu"
// (and its "qemu"/"vm" aliases).
func init() {
	RegisterOrchestrator(ProviderLocalQEMU, newQEMUOrchestratorForConfig)
}

// newQEMUOrchestratorForConfig is the factory adapter for the local QEMU
// orchestrator. It forces the compute type to VM (QEMU never runs
// containers) and constructs the orchestrator from the shared config.
func newQEMUOrchestratorForConfig(_ context.Context, cfg *OrchestratorConfig, deps *Deps) (Orchestrator, error) {
	if cfg == nil {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidConfiguration,
			Cause:    &MessageError{Msg: "config is required"},
		}
	}
	local := *cfg
	local.Type = ComputeTypeVM
	local.Provider = ProviderLocalQEMU
	return NewQEMUOrchestrator(&local, deps.logger())
}
