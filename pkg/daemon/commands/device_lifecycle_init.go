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
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// wireDeviceLifecycle gives the daemon config the operator Enable/Disable
// Device flow (#250). The flow enforces through the quarantine manager the
// attestation observer registered, because only that observer restores a
// re-enabled device once it re-attests. Without a manager the config keeps a
// nil lifecycle and every transport refuses the transition.
//
// refresher, when non-nil, is asked to re-attest a re-enabled device at once
// rather than on the collector's next sweep.
func wireDeviceLifecycle(cfg *daemon.Config, manager *policy.QuarantineManager, refresher device.ReattestationRequester, logger *slog.Logger) {
	if cfg == nil || manager == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	opts := []device.LifecycleOption{device.WithLifecycleLogger(logger)}
	if refresher != nil {
		opts = append(opts, device.WithLifecycleReattestation(refresher))
	}
	lifecycle, err := device.NewLifecycleService(cfg.DeviceService, manager, opts...)
	if err != nil {
		logger.Error("device lifecycle: operator enable/disable not configured",
			slog.String("error", err.Error()))
		return
	}
	cfg.DeviceLifecycle = lifecycle
	logger.Info("device lifecycle: operator enable/disable configured",
		slog.Bool("reattestation", refresher != nil))
}

// reportingRefresher returns the reporting collector's re-attestation hook,
// or nil when this node runs no collector.
func reportingRefresher(cfg *daemon.Config) device.ReattestationRequester {
	if cfg == nil || cfg.AttestationReporting == nil || cfg.AttestationReporting.Refresher == nil {
		return nil
	}
	return cfg.AttestationReporting.Refresher
}
