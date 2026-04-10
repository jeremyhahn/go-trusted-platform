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

package bmc

import "testing"

func TestPowerState_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		state PowerState
		want  bool
	}{
		{"on is valid", PowerStateOn, true},
		{"off is valid", PowerStateOff, true},
		{"unknown is valid", PowerStateUnknown, true},
		{"empty is invalid", PowerState(""), false},
		{"arbitrary is invalid", PowerState("sleeping"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.want {
				t.Errorf("PowerState(%q).IsValid() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestBootDevice_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		device BootDevice
		want   bool
	}{
		{"pxe is valid", BootDevicePXE, true},
		{"disk is valid", BootDeviceDisk, true},
		{"cdrom is valid", BootDeviceCDROM, true},
		{"virtual_media is valid", BootDeviceVirtualMedia, true},
		{"none is valid", BootDeviceNone, true},
		{"empty is invalid", BootDevice(""), false},
		{"usb is invalid", BootDevice("usb"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.device.IsValid(); got != tt.want {
				t.Errorf("BootDevice(%q).IsValid() = %v, want %v", tt.device, got, tt.want)
			}
		})
	}
}

func TestProtocol_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     bool
	}{
		{"ipmi is valid", ProtocolIPMI, true},
		{"redfish is valid", ProtocolRedfish, true},
		{"empty is invalid", Protocol(""), false},
		{"ssh is invalid", Protocol("ssh"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.protocol.IsValid(); got != tt.want {
				t.Errorf("Protocol(%q).IsValid() = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}
