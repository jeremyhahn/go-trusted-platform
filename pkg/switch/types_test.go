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

package switchmgmt

import (
	"errors"
	"testing"
)

func TestValidateVLANConfig_Valid(t *testing.T) {
	vlan := VLANConfig{ID: 10, Name: "production", Subnet: "10.0.10.0/24"}
	if err := ValidateVLANConfig(vlan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVLANConfig_IDTooLow(t *testing.T) {
	vlan := VLANConfig{ID: 0, Name: "bad"}
	err := ValidateVLANConfig(vlan)
	if err == nil {
		t.Fatal("expected error for VLAN ID 0")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T", err)
	}
}

func TestValidateVLANConfig_IDTooHigh(t *testing.T) {
	vlan := VLANConfig{ID: 4095, Name: "bad"}
	err := ValidateVLANConfig(vlan)
	if err == nil {
		t.Fatal("expected error for VLAN ID 4095")
	}
}

func TestValidateVLANConfig_EmptyName(t *testing.T) {
	vlan := VLANConfig{ID: 10, Name: ""}
	err := ValidateVLANConfig(vlan)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T", err)
	}
	if invalidCfg.Field != "vlan.name" {
		t.Fatalf("expected field 'vlan.name', got: %s", invalidCfg.Field)
	}
}

func TestValidateVLANConfig_BoundaryIDs(t *testing.T) {
	// ID 1 is valid (minimum)
	if err := ValidateVLANConfig(VLANConfig{ID: 1, Name: "min"}); err != nil {
		t.Fatalf("VLAN ID 1 should be valid: %v", err)
	}
	// ID 4094 is valid (maximum)
	if err := ValidateVLANConfig(VLANConfig{ID: 4094, Name: "max"}); err != nil {
		t.Fatalf("VLAN ID 4094 should be valid: %v", err)
	}
}

func TestValidatePortConfig_ValidTrunk(t *testing.T) {
	port := PortConfig{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10, 20}}
	if err := ValidatePortConfig(port); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePortConfig_ValidAccess(t *testing.T) {
	port := PortConfig{Port: "Eth1/2", Mode: "access", AccessVLAN: 10}
	if err := ValidatePortConfig(port); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePortConfig_EmptyPort(t *testing.T) {
	port := PortConfig{Port: "", Mode: "trunk", VLANs: []int{10}}
	err := ValidatePortConfig(port)
	if err == nil {
		t.Fatal("expected error for empty port")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T", err)
	}
}

func TestValidatePortConfig_InvalidMode(t *testing.T) {
	port := PortConfig{Port: "Eth1/1", Mode: "hybrid"}
	err := ValidatePortConfig(port)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T", err)
	}
}

func TestValidatePortConfig_AccessMissingVLAN(t *testing.T) {
	port := PortConfig{Port: "Eth1/1", Mode: "access"}
	err := ValidatePortConfig(port)
	if err == nil {
		t.Fatal("expected error for access mode without vlan")
	}
}

func TestValidatePortConfig_TrunkMissingVLANs(t *testing.T) {
	port := PortConfig{Port: "Eth1/1", Mode: "trunk"}
	err := ValidatePortConfig(port)
	if err == nil {
		t.Fatal("expected error for trunk mode without vlans")
	}
}

func TestConfigureResult_Fields(t *testing.T) {
	result := ConfigureResult{
		VLANsCreated:    3,
		PortsConfigured: 5,
		Warnings:        []string{"port Eth1/5 already configured"},
	}
	if result.VLANsCreated != 3 {
		t.Fatalf("expected 3 VLANs created, got %d", result.VLANsCreated)
	}
	if result.PortsConfigured != 5 {
		t.Fatalf("expected 5 ports configured, got %d", result.PortsConfigured)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestSwitchVendorConstants(t *testing.T) {
	if VendorCiscoNexus != "cisco-nexus" {
		t.Fatalf("expected 'cisco-nexus', got: %s", VendorCiscoNexus)
	}
	if VendorNoop != "noop" {
		t.Fatalf("expected 'noop', got: %s", VendorNoop)
	}
}
