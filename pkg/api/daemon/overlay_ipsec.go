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
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayIPsec is overlay IPsec as the daemon drives it (ipsec.Service).
type overlayIPsec interface {
	Install(ctx context.Context) error
	Run(ctx context.Context)
	Close()
}

// overlayStarters build the overlay's parts that startOverlay brings up in
// order: the IPsec service, the local VTEP, and the controller on that VTEP.
type overlayStarters struct {
	ipsec      func(cfg *ipsecconfig.Config) (overlayIPsec, error)
	vtep       func(cfg *sdn.OverlayConfig) (overlayVTEP, error)
	controller func(ctx context.Context, vtep overlayVTEP) (*overlay.Controller, error)
}

// newOverlayStarters are the production starters: ipsec.Service,
// resolveOverlayVTEP on the host's interfaces, and buildOverlayController.
func newOverlayStarters(config *Config, logger *logging.Logger) overlayStarters {
	return overlayStarters{
		ipsec: func(cfg *ipsecconfig.Config) (overlayIPsec, error) {
			if config.App == nil {
				return nil, ipsec.ErrMissingDependency
			}
			anchor, err := config.App.PlatformAnchor()
			if err != nil {
				return nil, err
			}
			return ipsec.NewService(cfg, anchor, logger.Slog())
		},
		vtep: func(cfg *sdn.OverlayConfig) (overlayVTEP, error) {
			return resolveOverlayVTEP(config.App.PublicIPv4, cfg, interfaceAddrs)
		},
		controller: func(ctx context.Context, vtep overlayVTEP) (*overlay.Controller, error) {
			return buildOverlayController(ctx, config.App, vtep, config.OVSSocketPath, logger)
		},
	}
}

// startOverlay brings up the overlay in order. With overlay.ipsec enabled,
// the IPsec service is built first. With the overlay enabled, the local VTEP
// is resolved next (resolveOverlayVTEP): with IPsec it is the IPsec local
// endpoint on the fabric interface, and a VTEP the floor would not protect
// is refused. Then the fail-closed floor goes in. A service, VTEP or floor
// that cannot be had is returned and nothing after it starts, so platformd
// never runs a VTEP with the fabric open to cleartext, or one whose VXLAN
// the floor drops. Last, the overlay controller registers the local VTEP. A
// controller that fails to start is logged, and the overlay endpoints
// report it unavailable.
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
		sec = s
	}
	var vtep overlayVTEP
	if cfg.Enabled {
		v, err := start.vtep(cfg)
		if err != nil {
			if sec != nil {
				sec.Close()
			}
			return nil, nil, err
		}
		vtep = v
	}
	if sec != nil {
		if err := sec.Install(ctx); err != nil {
			sec.Close()
			return nil, nil, err
		}
		logger.Info("overlay IPsec fail-closed floor installed",
			"fabric_interface", cfg.IPsec.FabricInterface,
			"local_address", cfg.IPsec.LocalAddress)
	}
	if !cfg.Enabled {
		return sec, nil, nil
	}
	ctrl, err := start.controller(ctx, vtep)
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
