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

package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// bmcStubProvider is a minimal BMCProvider that records the last invoked
// method so tests can assert dispatch.
type bmcStubProvider struct {
	lastCall string
}

func (s *bmcStubProvider) BMCPowerOn(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "power_on"
	return map[string]interface{}{"profile_id": profileID, "previous_state": "off", "current_state": "on"}, nil
}

func (s *bmcStubProvider) BMCPowerOff(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "power_off"
	return map[string]interface{}{"profile_id": profileID}, nil
}

func (s *bmcStubProvider) BMCPowerReset(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "power_reset"
	return map[string]interface{}{"profile_id": profileID}, nil
}

func (s *bmcStubProvider) BMCPowerCycle(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "power_cycle"
	return map[string]interface{}{"profile_id": profileID}, nil
}

func (s *bmcStubProvider) BMCPowerStatus(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "power_status"
	return map[string]interface{}{"profile_id": profileID, "state": "on"}, nil
}

func (s *bmcStubProvider) BMCSetBootDevice(_ context.Context, profileID uint64, device string, persistent bool) (interface{}, error) {
	s.lastCall = "set_boot_device:" + device
	return map[string]interface{}{"profile_id": profileID, "device": device, "persistent": persistent}, nil
}

func (s *bmcStubProvider) BMCGetBootDevice(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "get_boot_device"
	return map[string]interface{}{"profile_id": profileID, "device": "pxe"}, nil
}

func (s *bmcStubProvider) BMCMountISO(_ context.Context, profileID uint64, isoURL string) (interface{}, error) {
	s.lastCall = "mount_iso:" + isoURL
	return map[string]interface{}{"profile_id": profileID, "mounted": true}, nil
}

func (s *bmcStubProvider) BMCUnmountISO(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "unmount_iso"
	return map[string]interface{}{"profile_id": profileID, "mounted": false}, nil
}

func (s *bmcStubProvider) BMCVirtualMediaStatus(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "vmedia_status"
	return map[string]interface{}{"profile_id": profileID, "mounted": false}, nil
}

func (s *bmcStubProvider) BMCGetSensors(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "sensors"
	return map[string]interface{}{"profile_id": profileID, "sensors": []map[string]interface{}{}}, nil
}

func (s *bmcStubProvider) BMCGetSystemInfo(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "system_info"
	return map[string]interface{}{"profile_id": profileID, "manufacturer": "ACME"}, nil
}

func (s *bmcStubProvider) BMCGetWebCertificate(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "web_cert"
	return map[string]interface{}{"profile_id": profileID, "subject": "CN=bmc.example"}, nil
}

func (s *bmcStubProvider) BMCListUsers(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "list_users"
	return map[string]interface{}{"profile_id": profileID, "users": []map[string]interface{}{}}, nil
}

func (s *bmcStubProvider) BMCEnrollBMC(_ context.Context, profileID uint64, replaceCertificate, rotatePassword, dnsRegister, danePublish *bool) (interface{}, error) {
	s.lastCall = "enroll_bmc"
	return map[string]interface{}{"profile_id": profileID, "device_id": "42", "endpoint": "10.0.0.1:443"}, nil
}

// BMCRestoreFactoryCert satisfies the BMCProvider interface. It records
// the last call for dispatch verification.
func (s *bmcStubProvider) BMCRestoreFactoryCert(_ context.Context, profileID uint64) (interface{}, error) {
	s.lastCall = "restore_factory_cert"
	return map[string]interface{}{
		"device_id": profileID,
		"endpoint":  "10.0.0.1:443",
		"hostname":  "bmc.example",
		"steps":     []map[string]interface{}{},
		"new_cert_meta": map[string]interface{}{
			"subject": "CN=bmc.example",
		},
	}, nil
}

// bmcCombinedProvider satisfies both ServiceProvider (via mockServiceProvider)
// and BMCProvider (via bmcStubProvider). The two types contribute disjoint
// method sets so embedding is collision-free.
type bmcCombinedProvider struct {
	*mockServiceProvider
	*bmcStubProvider
}

// Compile-time assertions: combined provider satisfies both interfaces.
var (
	_ ServiceProvider = (*bmcCombinedProvider)(nil)
	_ BMCProvider     = (*bmcCombinedProvider)(nil)
)

// =============================================================================
// Tests
// =============================================================================

// TestToolRegistry_ExecuteTool_BMC_RoutesToProvider verifies that the
// ExecuteTool dispatcher routes platform_bmc_* tools through the
// optional BMCProvider interface.
func TestToolRegistry_ExecuteTool_BMC_RoutesToProvider(t *testing.T) {
	stub := &bmcStubProvider{}
	svc := &bmcCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		bmcStubProvider:     stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]interface{}
		wantCall string
	}{
		{name: "platform_bmc_power_on", args: map[string]interface{}{"profile_id": 1}, wantCall: "power_on"},
		{name: "platform_bmc_power_off", args: map[string]interface{}{"profile_id": 1}, wantCall: "power_off"},
		{name: "platform_bmc_power_reset", args: map[string]interface{}{"profile_id": 1}, wantCall: "power_reset"},
		{name: "platform_bmc_power_cycle", args: map[string]interface{}{"profile_id": 1}, wantCall: "power_cycle"},
		{name: "platform_bmc_power_status", args: map[string]interface{}{"profile_id": 1}, wantCall: "power_status"},
		{name: "platform_bmc_set_boot_device", args: map[string]interface{}{"profile_id": 1, "device": "pxe"}, wantCall: "set_boot_device:pxe"},
		{name: "platform_bmc_get_boot_device", args: map[string]interface{}{"profile_id": 1}, wantCall: "get_boot_device"},
		{name: "platform_bmc_mount_iso", args: map[string]interface{}{"profile_id": 1, "iso_url": "http://x/iso"}, wantCall: "mount_iso:http://x/iso"},
		{name: "platform_bmc_unmount_iso", args: map[string]interface{}{"profile_id": 1}, wantCall: "unmount_iso"},
		{name: "platform_bmc_virtual_media_status", args: map[string]interface{}{"profile_id": 1}, wantCall: "vmedia_status"},
		{name: "platform_bmc_get_sensors", args: map[string]interface{}{"profile_id": 1}, wantCall: "sensors"},
		{name: "platform_bmc_get_system_info", args: map[string]interface{}{"profile_id": 1}, wantCall: "system_info"},
		{name: "platform_bmc_get_web_certificate", args: map[string]interface{}{"profile_id": 1}, wantCall: "web_cert"},
		{name: "platform_bmc_list_users", args: map[string]interface{}{"profile_id": 1}, wantCall: "list_users"},
		{name: "platform_bmc_enroll", args: map[string]interface{}{"profile_id": 1}, wantCall: "enroll_bmc"},
		{name: "platform_bmc_cert_restore", args: map[string]interface{}{"profile_id": 1}, wantCall: "restore_factory_cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if result == nil {
				t.Errorf("%s: result should not be nil", tc.name)
			}
			if stub.lastCall != tc.wantCall {
				t.Errorf("%s: lastCall = %q, want %q", tc.name, stub.lastCall, tc.wantCall)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_BMC_NoProvider verifies that BMC tools
// return ErrBMCNotConfigured when the ServiceProvider does not also
// satisfy BMCProvider.
func TestToolRegistry_ExecuteTool_BMC_NoProvider(t *testing.T) {
	// Plain mockServiceProvider does NOT satisfy BMCProvider.
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	bmcTools := []string{
		"platform_bmc_power_on",
		"platform_bmc_power_off",
		"platform_bmc_power_status",
		"platform_bmc_set_boot_device",
		"platform_bmc_get_sensors",
		"platform_bmc_get_system_info",
		"platform_bmc_get_web_certificate",
		"platform_bmc_list_users",
		"platform_bmc_enroll",
		"platform_bmc_cert_restore",
	}
	for _, name := range bmcTools {
		t.Run(name, func(t *testing.T) {
			args := map[string]interface{}{"profile_id": 1, "device": "pxe", "iso_url": "http://x"}
			_, err := registry.ExecuteTool(ctx, name, args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
			if !errors.Is(err, ErrBMCNotConfigured) {
				t.Errorf("%s: expected ErrBMCNotConfigured, got %v", name, err)
			}
		})
	}
}
