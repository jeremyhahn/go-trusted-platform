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

package gateway

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUplinkConfig_PCIAddressYAML(t *testing.T) {
	input := "name: eth0\nmtu: 1500\npci-address: \"0000:03:00.0\"\n"

	var cfg UplinkConfig
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}
	if cfg.PCIAddress != "0000:03:00.0" {
		t.Fatalf("PCIAddress = %q, want %q", cfg.PCIAddress, "0000:03:00.0")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestUplinkConfig_PCIAddressYAMLOmitted(t *testing.T) {
	input := "name: eth0\nmtu: 1500\n"

	var cfg UplinkConfig
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}
	if cfg.PCIAddress != "" {
		t.Fatalf("PCIAddress = %q, want empty", cfg.PCIAddress)
	}

	// omitempty: the key must not appear when unset.
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal() error: %v", err)
	}
	if string(out) == "" {
		t.Fatal("yaml.Marshal() produced empty output")
	}
	var round map[string]interface{}
	if err := yaml.Unmarshal(out, &round); err != nil {
		t.Fatalf("yaml.Unmarshal(round) error: %v", err)
	}
	if _, ok := round["pci-address"]; ok {
		t.Fatal("pci-address must be omitted from YAML when empty")
	}
}

func TestUplinkConfig_PCIAddressJSON(t *testing.T) {
	cfg := UplinkConfig{Name: "eth0", MTU: 9000, PCIAddress: "0000:81:00.1"}

	data, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var round map[string]interface{}
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if got := round["pci_address"]; got != "0000:81:00.1" {
		t.Fatalf("pci_address = %v, want %q", got, "0000:81:00.1")
	}
}
