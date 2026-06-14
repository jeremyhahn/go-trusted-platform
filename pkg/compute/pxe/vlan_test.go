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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func TestNewNoopVLANIntegration(t *testing.T) {
	vi := NewNoopVLANIntegration()

	assert.NotNil(t, vi)
}

func TestNoopVLANIntegration_ApplyQuarantineVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, uint16(100), vlan)
}

func TestNoopVLANIntegration_ApplyQuarantineVLAN_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyQuarantineVLAN(ctx, "", 100)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "portID", configErr.Field)
}

func TestNoopVLANIntegration_ApplyQuarantineVLAN_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_ApplyProvisioningVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyProvisioningVLAN(ctx, "port-1", 200)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, uint16(200), vlan)
}

func TestNoopVLANIntegration_ApplyProvisioningVLAN_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyProvisioningVLAN(ctx, "", 200)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_ApplyProvisioningVLAN_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProvisioningVLAN(ctx, "port-1", 200)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_ApplyZoneVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "port-1", zone.ZoneTrusted)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, DefaultTrustedVLAN, vlan)
}

func TestNoopVLANIntegration_ApplyZoneVLAN_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "", zone.ZoneTrusted)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_ApplyZoneVLAN_EmptyZone(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "port-1", "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "zone", configErr.Field)
}

func TestNoopVLANIntegration_ApplyZoneVLAN_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyZoneVLAN(ctx, "port-1", zone.ZoneTrusted)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_GetCurrentVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	// Store a VLAN first
	err := vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	require.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, uint16(100), vlan)
}

func TestNoopVLANIntegration_GetCurrentVLAN_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	_, err := vi.GetCurrentVLAN(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_GetCurrentVLAN_NotFound(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	_, err := vi.GetCurrentVLAN(ctx, "nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestNoopVLANIntegration_GetCurrentVLAN_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	_, err = vi.GetCurrentVLAN(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_ApplyQuarantineFlows(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyQuarantineFlows(ctx, "port-1", mac)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, DefaultQuarantineVLAN, vlan)
}

func TestNoopVLANIntegration_ApplyQuarantineFlows_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyQuarantineFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_ApplyQuarantineFlows_NilMAC(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyQuarantineFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestNoopVLANIntegration_ApplyQuarantineFlows_EmptyMAC(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyQuarantineFlows(ctx, "port-1", net.HardwareAddr{})
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestNoopVLANIntegration_ApplyQuarantineFlows_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyQuarantineFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_ApplyProvisioningFlows(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProvisioningFlows(ctx, "port-1", mac)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, DefaultProvisioningVLAN, vlan)
}

func TestNoopVLANIntegration_ApplyProvisioningFlows_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProvisioningFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_ApplyProvisioningFlows_NilMAC(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyProvisioningFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestNoopVLANIntegration_ApplyProvisioningFlows_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProvisioningFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_ApplyProductionFlows(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, DefaultTrustedVLAN, vlan)
}

func TestNoopVLANIntegration_ApplyProductionFlows_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_ApplyProductionFlows_NilMAC(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.ApplyProductionFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestNoopVLANIntegration_ApplyProductionFlows_StoresTrustedVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.NoError(t, err)

	vlan, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, DefaultTrustedVLAN, vlan)
}

func TestNoopVLANIntegration_ApplyProductionFlows_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_BlockPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	err := vi.BlockPort(ctx, "port-1")
	assert.NoError(t, err)

	assert.True(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_BlockPort_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.BlockPort(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_BlockPort_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.BlockPort(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_UnblockPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	// Block first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Unblock
	err = vi.UnblockPort(ctx, "port-1")
	assert.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_UnblockPort_EmptyPortID(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.UnblockPort(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestNoopVLANIntegration_UnblockPort_AfterClose(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.UnblockPort(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestNoopVLANIntegration_GetPortVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration()
	ctx := context.Background()

	// Store a VLAN first
	err := vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	require.NoError(t, err)

	vlan, err := vi.GetPortVLAN(ctx, "port-1")
	assert.NoError(t, err)
	assert.Equal(t, uint16(100), vlan)
}

func TestNoopVLANIntegration_Close(t *testing.T) {
	vi := NewNoopVLANIntegration()

	err := vi.Close()
	assert.NoError(t, err)
}

func TestNoopVLANIntegration_Close_Idempotent(t *testing.T) {
	vi := NewNoopVLANIntegration()

	err := vi.Close()
	assert.NoError(t, err)

	err = vi.Close()
	assert.NoError(t, err)
}

func TestNoopVLANIntegration_IsPortBlocked(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	// Not blocked initially
	assert.False(t, vi.IsPortBlocked("port-1"))

	// Block
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Unblock
	err = vi.UnblockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_VLANTransitionsRemoveBlockedStatus(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Block port
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply quarantine flows should unblock
	err = vi.ApplyQuarantineFlows(ctx, "port-1", mac)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_ApplyQuarantineVLAN_UnblocksPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	// Block port first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply quarantine VLAN should unblock
	err = vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_ApplyProvisioningVLAN_UnblocksPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	// Block port first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply provisioning VLAN should unblock
	err = vi.ApplyProvisioningVLAN(ctx, "port-1", 200)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_ApplyZoneVLAN_UnblocksPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()

	// Block port first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply zone VLAN should unblock
	err = vi.ApplyZoneVLAN(ctx, "port-1", zone.ZoneTrusted)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_ApplyProvisioningFlows_UnblocksPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Block port first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply provisioning flows should unblock
	err = vi.ApplyProvisioningFlows(ctx, "port-1", mac)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNoopVLANIntegration_ApplyProductionFlows_UnblocksPort(t *testing.T) {
	vi := NewNoopVLANIntegration().(*noopVLANIntegration)
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Block port first
	err := vi.BlockPort(ctx, "port-1")
	require.NoError(t, err)
	assert.True(t, vi.IsPortBlocked("port-1"))

	// Apply production flows should unblock
	err = vi.ApplyProductionFlows(ctx, "port-1", mac)
	require.NoError(t, err)
	assert.False(t, vi.IsPortBlocked("port-1"))
}

func TestNewVLANIntegrationWrapper(t *testing.T) {
	vi := NewVLANIntegrationWrapper()

	assert.NotNil(t, vi)
}

func TestNewVLANIntegrationWrapper_WithOptions(t *testing.T) {
	vi := NewVLANIntegrationWrapper(
		WithBridgeName("br-custom"),
		WithQuarantineVLAN(10),
		WithProvisioningVLAN(20),
	)

	assert.NotNil(t, vi)

	// Check the wrapper was configured
	wrapper := vi.(*vlanIntegrationWrapper)
	assert.Equal(t, "br-custom", wrapper.bridgeName)
	assert.Equal(t, uint16(10), wrapper.quarantineVLAN)
	assert.Equal(t, uint16(20), wrapper.provisioningVLAN)
}

func TestVLANIntegrationWrapper_ApplyQuarantineVLAN_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	// Without a flow manager, this should be a no-op (succeeds silently)
	err := vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyQuarantineVLAN_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyQuarantineVLAN(ctx, "", 100)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyQuarantineVLAN_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyQuarantineVLAN(ctx, "port-1", 100)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningVLAN_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProvisioningVLAN(ctx, "port-1", 200)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyProvisioningVLAN_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProvisioningVLAN(ctx, "", 200)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningVLAN_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProvisioningVLAN(ctx, "port-1", 200)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_ApplyZoneVLAN_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "port-1", zone.ZoneTrusted)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyZoneVLAN_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "", zone.ZoneTrusted)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyZoneVLAN_EmptyZone(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyZoneVLAN(ctx, "port-1", "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyZoneVLAN_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyZoneVLAN(ctx, "port-1", zone.ZoneTrusted)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_GetCurrentVLAN_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	_, err := vi.GetCurrentVLAN(ctx, "port-1")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestVLANIntegrationWrapper_GetCurrentVLAN_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	_, err := vi.GetCurrentVLAN(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_GetCurrentVLAN_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	_, err = vi.GetCurrentVLAN(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_ApplyQuarantineFlows_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyQuarantineFlows(ctx, "port-1", mac)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyQuarantineFlows_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyQuarantineFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyQuarantineFlows_NilMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyQuarantineFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestVLANIntegrationWrapper_ApplyQuarantineFlows_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyQuarantineFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningFlows_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProvisioningFlows(ctx, "port-1", mac)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyProvisioningFlows_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProvisioningFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningFlows_NilMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProvisioningFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningFlows_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProvisioningFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "", mac)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_NilMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProductionFlows(ctx, "port-1", nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_StoresTrustedZone(t *testing.T) {
	// ApplyProductionFlows transitions to zone.ZoneTrusted; VLAN is resolved by ZoneFlowManager.
	// Without a flow manager, this is a no-op.
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := vi.Close()
	require.NoError(t, err)

	err = vi.ApplyProductionFlows(ctx, "port-1", mac)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_BlockPort_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.BlockPort(ctx, "port-1")
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_BlockPort_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.BlockPort(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_BlockPort_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.BlockPort(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_UnblockPort_NoFlowManager(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.UnblockPort(ctx, "port-1")
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_UnblockPort_EmptyPortID(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.UnblockPort(ctx, "")
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestVLANIntegrationWrapper_UnblockPort_AfterClose(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.Close()
	require.NoError(t, err)

	err = vi.UnblockPort(ctx, "port-1")
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestVLANIntegrationWrapper_GetPortVLAN(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	// Without flow manager, should return not found
	_, err := vi.GetPortVLAN(ctx, "port-1")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestVLANIntegrationWrapper_Close(t *testing.T) {
	vi := NewVLANIntegrationWrapper()

	err := vi.Close()
	assert.NoError(t, err)
}

func TestVLANIntegrationWrapper_Close_Idempotent(t *testing.T) {
	vi := NewVLANIntegrationWrapper()

	err := vi.Close()
	assert.NoError(t, err)

	err = vi.Close()
	assert.NoError(t, err)
}

func TestWithFlowManager_Option(t *testing.T) {
	vi := NewVLANIntegrationWrapper(
		WithFlowManager(nil),
	)

	assert.NotNil(t, vi)
}

func TestWithVLANLogger_Option(t *testing.T) {
	vi := NewVLANIntegrationWrapper(
		WithVLANLogger(nil),
	)

	assert.NotNil(t, vi)
}

func TestDefaultBridgeName(t *testing.T) {
	assert.Equal(t, "br-int", DefaultBridgeName)
}

func TestVLANIntegrationWrapper_ApplyQuarantineFlows_EmptyMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyQuarantineFlows(ctx, "port-1", net.HardwareAddr{})
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestVLANIntegrationWrapper_ApplyProvisioningFlows_EmptyMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProvisioningFlows(ctx, "port-1", net.HardwareAddr{})
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestVLANIntegrationWrapper_ApplyProductionFlows_EmptyMAC(t *testing.T) {
	vi := NewVLANIntegrationWrapper()
	ctx := context.Background()

	err := vi.ApplyProductionFlows(ctx, "port-1", net.HardwareAddr{})
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}
