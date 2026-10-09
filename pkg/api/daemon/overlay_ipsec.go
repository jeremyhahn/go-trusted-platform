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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayIPsec is overlay IPsec as the daemon drives it (ipsec.Service).
type overlayIPsec interface {
	Install(ctx context.Context) error
	Run(ctx context.Context)
	Close()
}

// overlayStarters build the two halves of the overlay that startOverlay
// brings up in order.
type overlayStarters struct {
	ipsec      func(cfg *ipsec.Config) (overlayIPsec, error)
	controller func(ctx context.Context) (*overlay.Controller, error)
}

// newOverlayStarters are the production starters: ipsec.Service and
// buildOverlayController.
func newOverlayStarters(config *Config, logger *logging.Logger) overlayStarters {
	return overlayStarters{
		ipsec: func(cfg *ipsec.Config) (overlayIPsec, error) {
			return ipsec.NewService(cfg, logger.Slog())
		},
		controller: func(ctx context.Context) (*overlay.Controller, error) {
			return buildOverlayController(ctx, config.App, config.OVSSocketPath, logger)
		},
	}
}

// startOverlay brings up the overlay in order. With overlay.ipsec enabled,
// the IPsec fail-closed floor goes in first; a floor that cannot be built
// or installed is returned and nothing after it starts, so platformd never
// runs a VTEP with the fabric open to cleartext. Then, with the overlay
// enabled, the overlay controller registers the local VTEP. A controller
// that fails to start is logged, and the overlay endpoints report it
// unavailable.
func startOverlay(ctx context.Context, cfg *sdn.OverlayConfig, start overlayStarters, logger *logging.Logger) (overlayIPsec, *overlay.Controller, error) {
	if cfg == nil {
		return nil, nil, nil
	}
	var sec overlayIPsec
	if cfg.IPsec != nil && cfg.IPsec.Enabled {
		s, err := start.ipsec(cfg.IPsec)
		if err != nil {
			return nil, nil, err
		}
		if err := s.Install(ctx); err != nil {
			s.Close()
			return nil, nil, err
		}
		logger.Info("overlay IPsec fail-closed floor installed",
			"fabric_interface", cfg.IPsec.FabricInterface,
			"local_address", cfg.IPsec.LocalAddress)
		sec = s
	}
	if !cfg.Enabled {
		return sec, nil, nil
	}
	ctrl, err := start.controller(ctx)
	if err != nil {
		logger.Warn("overlay controller init failed; overlay endpoints will return unavailable",
			"error", err)
		return sec, nil, nil
	}
	return sec, ctrl, nil
}

// overlayIPsecRun runs overlay IPsec in the background between start and
// stop. A nil run does nothing.
type overlayIPsecRun struct {
	svc    overlayIPsec
	cancel context.CancelFunc
	done   chan struct{}
}

// start runs the service unless it is running already.
func (r *overlayIPsecRun) start() {
	if r == nil || r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.cancel, r.done = cancel, done
	go func() {
		defer close(done)
		r.svc.Run(ctx)
	}()
}

// stop ends the run and waits for it. The floor stays installed, and a
// later start runs the service again.
func (r *overlayIPsecRun) stop() {
	if r == nil || r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
	r.cancel, r.done = nil, nil
}
