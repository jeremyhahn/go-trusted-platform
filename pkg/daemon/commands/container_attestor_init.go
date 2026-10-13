// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// The platform fleet container attestor (#704): the attestor the embedded
// QuicBaaS server answers Security().Attestation().AttestContainer with.
// It quotes this host's TPM against the golden PCRs of the host's device
// profile, and quarantines and re-attests the host when they drift. The
// adapter is registered when the embedded server starts; this file installs
// the attestor into it once the device registry, the attestation service
// and this node's own device record exist.

// runtimeAttestorFunc builds the attestor that quotes the host TPM.
type runtimeAttestorFunc func(tpm orchestration.HostTPM, logger *slog.Logger) (service.ContainerAttestor, error)

// containerAttestorDeps is what the fleet attestor is composed from.
type containerAttestorDeps struct {
	TPM       orchestration.HostTPM
	Devices   container.FleetDeviceRegistry
	Baselines container.FleetBaselineResolver
	Verdicts  container.FleetVerdictRecorder
	// Reattest is optional: without it a drifted host is quarantined but
	// not re-attested.
	Reattest container.FleetReattestationRequester
	// Self is this node's own device record; only this host is attested.
	Self *controlPlaneSelfDevice
	// NewRuntimeAttestor is container.NewSDKContainerAttestor in
	// production.
	NewRuntimeAttestor runtimeAttestorFunc
}

// wireContainerAttestor installs the fleet attestor into the embedded
// QuicBaaS server. A node without an embedded server, or without what the
// attestor needs, keeps refusing AttestContainer with a typed error.
func wireContainerAttestor(logger *slog.Logger, a *app.App, cfg *daemon.Config, svcs *attestationServices, self *controlPlaneSelfDevice) {
	if a == nil || cfg == nil {
		return
	}
	factory, ok := a.DAOFactory().(*platformquicbaas.Factory)
	if !ok {
		logger.Info("container attestation: no embedded QuicBaaS server on this node; the platform attestor is not installed")
		return
	}
	deps := containerAttestorDepsFrom(a, cfg, svcs, self)
	if err := installContainerAttestor(logger, factory.ContainerAttestor(), deps); err != nil {
		var prerequisite ErrContainerAttestorPrerequisite
		if errors.As(err, &prerequisite) {
			logger.Info("container attestation: the platform attestor is not installed; AttestContainer refuses on this node", "reason", err.Error())
			return
		}
		logger.Warn("container attestation: the platform attestor could not be built; AttestContainer refuses on this node", "error", err)
	}
}

// containerAttestorDepsFrom collects the attestor's dependencies from the
// running daemon. A missing one stays a nil interface, never a typed nil,
// so the constructors report it by name.
func containerAttestorDepsFrom(a *app.App, cfg *daemon.Config, svcs *attestationServices, self *controlPlaneSelfDevice) containerAttestorDeps {
	deps := containerAttestorDeps{
		Self:               self,
		NewRuntimeAttestor: container.NewSDKContainerAttestor,
	}
	if a != nil && a.TPM != nil {
		deps.TPM = a.TPM
	}
	if cfg != nil {
		if cfg.DeviceService != nil {
			deps.Devices = cfg.DeviceService
		}
		if cfg.DeviceProfileService != nil {
			deps.Baselines = cfg.DeviceProfileService
		}
		if refresher := reportingRefresher(cfg); refresher != nil {
			deps.Reattest = refresher
		}
	}
	if svcs != nil && svcs.Service != nil {
		deps.Verdicts = svcs.Service
	}
	return deps
}

// installContainerAttestor builds the fleet attestor and installs it into
// the adapter the embedded server registered.
func installContainerAttestor(logger *slog.Logger, target *platformquicbaas.ContainerAttestorAdapter, deps containerAttestorDeps) error {
	if target == nil {
		return ErrContainerAttestorPrerequisite{Missing: "the embedded QuicBaaS server's container attestor seam"}
	}
	fleet, err := newFleetContainerAttestor(logger, deps)
	if err != nil {
		return err
	}
	target.SetAttestor(fleet)
	logger.Info("container attestation: platform fleet attestor installed", "device_id", deps.Self.DeviceID)
	return nil
}

// newFleetContainerAttestor composes the runtime attestor and the fleet
// policy around it for this node's own device record.
func newFleetContainerAttestor(logger *slog.Logger, deps containerAttestorDeps) (*container.FleetContainerAttestor, error) {
	if deps.Self == nil {
		return nil, ErrContainerAttestorPrerequisite{Missing: "this node's own device record (attestation.reporting.enabled)"}
	}
	if deps.TPM == nil {
		return nil, ErrContainerAttestorPrerequisite{Missing: "a host TPM"}
	}
	if deps.NewRuntimeAttestor == nil {
		return nil, ErrContainerAttestorPrerequisite{Missing: "a runtime attestor"}
	}
	localID, err := strconv.ParseUint(strings.TrimSpace(deps.Self.DeviceID), 10, 64)
	if err != nil {
		return nil, ErrCollectorDeviceID{DeviceID: deps.Self.DeviceID}
	}
	runtime, err := deps.NewRuntimeAttestor(deps.TPM, logger)
	if err != nil {
		return nil, ErrContainerAttestorRuntime{Cause: err}
	}
	return container.NewFleetContainerAttestor(container.FleetAttestorConfig{
		Attestor:      runtime,
		Devices:       deps.Devices,
		Baselines:     deps.Baselines,
		Verdicts:      deps.Verdicts,
		Reattest:      deps.Reattest,
		LocalDeviceID: localID,
		Logger:        logger,
	})
}

// ErrContainerAttestorPrerequisite reports that this node lacks something
// the fleet attestor needs. It is a configuration state, not a fault.
type ErrContainerAttestorPrerequisite struct {
	Missing string
}

func (e ErrContainerAttestorPrerequisite) Error() string {
	return "container attestation: no " + e.Missing
}

// ErrContainerAttestorRuntime reports that the attestor quoting the host
// TPM could not be built, typically because no container runtime is
// installed.
type ErrContainerAttestorRuntime struct {
	Cause error
}

func (e ErrContainerAttestorRuntime) Error() string {
	return "container attestation: runtime attestor unavailable: " + e.Cause.Error()
}

func (e ErrContainerAttestorRuntime) Unwrap() error { return e.Cause }
