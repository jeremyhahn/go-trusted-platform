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

package pxe

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSection is a pxe: section on unprivileged loopback ports, as the
// integration platformd runs it.
func testSection() *Config {
	return &Config{
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
	}
}

func TestNewConfiguredService_ServesTheSection(t *testing.T) {
	ctx := context.Background()
	svc, err := NewConfiguredService(ctx, testSection(), testNetPlan, "br-test", nil)
	require.NoError(t, err)

	status := svc.Status()
	assert.False(t, status.Running, "initializing binds nothing; StartService starts the servers")
	assert.Equal(t, uint16(testQuarantineVLAN), status.QuarantineVLAN)
	assert.Equal(t, uint16(testProvisioningVLAN), status.ProvisioningVLAN)
	assert.Equal(t, "127.0.0.1", status.IPXEServerAddr)

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	assert.Equal(t, uint16(testQuarantineVLAN), device.CurrentVLAN)
	assert.Equal(t, 1, svc.Status().DeviceCount)
}

func TestNewConfiguredService_Refusals(t *testing.T) {
	noEntries := testSection()
	noEntries.BootEntries = nil
	badPort := testSection()
	badPort.HTTPPort = 70000

	tests := []struct {
		name   string
		cfg    *Config
		bridge string
		check  func(t *testing.T, err error)
	}{
		{
			name:   "nil section",
			cfg:    nil,
			bridge: "br-test",
			check: func(t *testing.T, err error) {
				var target ErrInvalidConfiguration
				assert.True(t, errors.As(err, &target), "got %v", err)
			},
		},
		{
			name:   "no bridge",
			cfg:    testSection(),
			bridge: "",
			check: func(t *testing.T, err error) {
				var target ErrInvalidConfiguration
				assert.True(t, errors.As(err, &target), "got %v", err)
			},
		},
		{
			name:   "no boot entries",
			cfg:    noEntries,
			bridge: "br-test",
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, ipxe.ErrNoBootEntries)
			},
		},
		{
			name:   "port out of range",
			cfg:    badPort,
			bridge: "br-test",
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, ipxe.ErrInvalidPort)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewConfiguredService(context.Background(), tt.cfg, testNetPlan, tt.bridge, nil)
			require.Error(t, err)
			assert.Nil(t, svc)
			tt.check(t, err)
		})
	}
}

func TestNewConfiguredService_RequiresNetworkPlan(t *testing.T) {
	svc, err := NewConfiguredService(context.Background(), testSection(), nil, "br-test", nil)
	require.Error(t, err)
	assert.Nil(t, svc)
	var target ErrNetworkPlanRequired
	assert.True(t, errors.As(err, &target), "got %v", err)
}
