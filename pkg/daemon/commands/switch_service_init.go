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

package commands

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

// newSwitchService builds the switch service from the `switches:` config
// block parsed into a.SwitchConfigs, one manager per configured switch.
// A nil App or an empty block returns a nil service and no error: the node
// has no switch, and every switch surface stays dark. A config that
// switchmgmt refuses (an unsupported vendor, an invalid connection config)
// returns the wrapped error, so errors.As still finds the cause and serve
// refuses to start.
func newSwitchService(logger *logging.Logger, a *app.App) (*switchmgmt.Service, error) {
	if a == nil || len(a.SwitchConfigs) == 0 {
		return nil, nil
	}
	svc, err := switchmgmt.NewService(a.SwitchConfigs, logger.Slog())
	if err != nil {
		return nil, fmt.Errorf("switch service: %w", err)
	}
	logger.Info("Switch service built from the switches config block", "switches", len(a.SwitchConfigs))
	return svc, nil
}

// switchServiceProvider returns svc as the provider the REST router takes.
// A nil svc returns a nil interface, not a typed nil inside one, so the
// router's nil check still reports the switch surface as not configured.
func switchServiceProvider(svc *switchmgmt.Service) device.SwitchServiceProvider {
	if svc == nil {
		return nil
	}
	return svc
}

// wireSwitchService hands svc to the SwitchService gRPC servicer, which the
// QUIC opcodes, the MCP tools and the embedded transport share. It does
// nothing when either is nil, so a node with no switch keeps answering
// Unavailable.
func wireSwitchService(grpcSvc *daemon.SwitchGRPCService, svc *switchmgmt.Service) {
	if grpcSvc == nil || svc == nil {
		return
	}
	grpcSvc.SetSwitchService(svc)
}
