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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// pxeApp is an App with an enabled pxe: section on loopback ports and an
// environment-4 sdn: section on bridge br-pxe. Validating the sdn: section
// checks the OVS socket path is set; nothing dials it.
func pxeApp() *app.App {
	return &app.App{
		SDNConfig: &sdn.Config{
			Enabled:     true,
			Environment: &netplan.Environment{ID: 4},
			OVS:         &sdn.OVSConfig{Socket: "/run/openvswitch/db.sock", Bridge: "br-pxe"},
		},
		PXEConfig: &pxe.Config{
			Enabled:  true,
			BindHost: "127.0.0.1",
			HTTPPort: 18081,
			TFTPPort: 16969,
			BootEntries: []ipxe.BootEntry{{
				Name:        "platform",
				Description: "Platform installer",
				Kernel:      "/data/vmlinuz",
				Initrd:      "/data/initramfs",
			}},
		},
	}
}

func TestWireDaemonPXEService_HandsTheConfiguredServiceToTheDaemon(t *testing.T) {
	// Every transport's PXE handler serves the backend the pxe: section
	// built; without it each answers SERVICE_NOT_CONFIGURED.
	cfg := daemon.DefaultConfig()

	require.NoError(t, wireDaemonPXEService(context.Background(), logging.NewLogger(0, nil), pxeApp(), cfg))

	require.NotNil(t, cfg.PXEService)
	status := cfg.PXEService.Status()
	assert.False(t, status.Running, "wiring binds no port; StartService starts the servers")
	assert.Equal(t, uint16(404), status.QuarantineVLAN)
	assert.Equal(t, uint16(405), status.ProvisioningVLAN)
	assert.Equal(t, "127.0.0.1", status.IPXEServerAddr)
}

func TestWireDaemonPXEService_NoSectionLeavesTheDaemonWithout(t *testing.T) {
	logger := logging.NewLogger(0, nil)
	disabled := pxeApp()
	disabled.PXEConfig.Enabled = false

	for name, a := range map[string]*app.App{
		"nil app":          nil,
		"no pxe section":   {},
		"section disabled": disabled,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := daemon.DefaultConfig()
			require.NoError(t, wireDaemonPXEService(context.Background(), logger, a, cfg))
			assert.Nil(t, cfg.PXEService)
		})
	}
	assert.NoError(t, wireDaemonPXEService(context.Background(), logger, pxeApp(), nil))
}

func TestWireDaemonPXEService_RefusesASectionItCannotServe(t *testing.T) {
	// An enabled section that cannot be built fails startup instead of
	// leaving a node that was asked for PXE silently without it.
	noSDN := pxeApp()
	noSDN.SDNConfig = nil
	noEntries := pxeApp()
	noEntries.PXEConfig.BootEntries = nil
	badSDN := pxeApp()
	badSDN.SDNConfig.Environment = nil

	tests := []struct {
		name  string
		app   *app.App
		phase string
		check func(t *testing.T, err error)
	}{
		{
			name:  "no network plan",
			app:   noSDN,
			phase: "PXE service",
			check: func(t *testing.T, err error) {
				var target pxe.ErrNetworkPlanRequired
				assert.True(t, errors.As(err, &target), "got %v", err)
			},
		},
		{
			name:  "no boot entries",
			app:   noEntries,
			phase: "PXE service",
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, ipxe.ErrNoBootEntries)
			},
		},
		{
			name:  "invalid sdn section",
			app:   badSDN,
			phase: "PXE service network plan",
			check: func(t *testing.T, err error) {
				var target app.ErrSDNConfigValidation
				assert.True(t, errors.As(err, &target), "got %v", err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := daemon.DefaultConfig()
			err := wireDaemonPXEService(context.Background(), logging.NewLogger(0, nil), tt.app, cfg)

			var startup ErrServeStartup
			require.True(t, errors.As(err, &startup), "got %v", err)
			assert.Equal(t, tt.phase, startup.Phase)
			tt.check(t, err)
			assert.Nil(t, cfg.PXEService)
		})
	}
}
