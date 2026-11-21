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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// TestWirePXEOnConfig_CarriesTheSectionAndFlowManager checks the helper
// both run paths call (runWithWebservices and runDaemonOnly): the pxe:
// section and the SDN zone flow manager reach the daemon config, so an
// enabled section is validated at daemon start on either path (#1694).
func TestWirePXEOnConfig_CarriesTheSectionAndFlowManager(t *testing.T) {
	section := &pxe.DaemonConfig{Enabled: true, BridgeName: "br-pxe"}
	flows := &policy.ZoneFlowManager{}
	cfg := daemon.DefaultConfig()

	wirePXEOnConfig(&app.App{PXEConfig: section}, cfg, &sdnPolicyComponents{ZoneFlowManager: flows})

	assert.Same(t, section, cfg.PXE)
	assert.Same(t, flows, cfg.PXEFlowManager)
}

// TestWirePXEOnConfig_NoSDNPolicyLeavesNoFlowManager checks that without
// an SDN policy the section still reaches the config with no flow
// manager, so daemon start refuses an enabled section instead of
// serving PXE RPCs that answer SERVICE_NOT_CONFIGURED.
func TestWirePXEOnConfig_NoSDNPolicyLeavesNoFlowManager(t *testing.T) {
	section := &pxe.DaemonConfig{Enabled: true, BridgeName: "br-pxe"}
	cfg := daemon.DefaultConfig()

	wirePXEOnConfig(&app.App{PXEConfig: section}, cfg, nil)

	assert.Same(t, section, cfg.PXE)
	assert.Nil(t, cfg.PXEFlowManager)
}

func TestWirePXEOnConfig_NilAppOrConfigIsANoOp(t *testing.T) {
	cfg := daemon.DefaultConfig()

	assert.NotPanics(t, func() { wirePXEOnConfig(nil, cfg, nil) })
	assert.NotPanics(t, func() { wirePXEOnConfig(&app.App{}, nil, nil) })
	assert.Nil(t, cfg.PXE)
}
