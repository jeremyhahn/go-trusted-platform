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

package container

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// init registers the consolidated container orchestrator with the compute
// provider factory so unified provider selection can resolve
// "local-container" (and its "container"/"local"/empty aliases). The
// registration lives in this package — rather than in pkg/compute — because
// the container orchestrator lives here and pkg/compute must not import it
// (that would be an import cycle). Importing pkg/compute/container anywhere
// in the build triggers this registration.
func init() {
	compute.RegisterOrchestrator(compute.ProviderLocalContainer, newContainerOrchestratorForConfig)
}

// newContainerOrchestratorForConfig is the factory adapter for the container
// orchestrator. It forces the compute type to container and, when a host TPM
// is supplied via Deps, enables workload measurement + quote attestation by
// building a host TPM provider (mirroring the daemon's historical wiring).
func newContainerOrchestratorForConfig(_ context.Context, cfg *compute.OrchestratorConfig, deps *compute.Deps) (compute.Orchestrator, error) {
	if cfg == nil {
		return nil, &compute.SentinelCauseError{
			Sentinel: compute.ErrInvalidConfiguration,
			Cause:    &compute.MessageError{Msg: "config is required"},
		}
	}

	local := *cfg
	local.Type = compute.ComputeTypeContainer
	local.Provider = compute.ProviderLocalContainer

	var logger *logging.Logger
	var opts []ComputeOrchestratorOption
	if deps != nil {
		logger = deps.Logger
		if logger == nil {
			logger = logging.DefaultLogger()
		}
		if deps.HostTPM != nil {
			tpmProvider, err := NewHostTPMProvider(deps.HostTPM)
			if err != nil {
				logger.Warn("container attestation unavailable: failed to create host TPM provider",
					"error", err)
			} else {
				opts = append(opts, WithComputeTPMProvider(tpmProvider))
			}
		}
	}

	return NewComputeOrchestrator(&local, logger, opts...)
}
