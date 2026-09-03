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

package app

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// miniFleetIdentity is the mini fleet's ATEN firmware identity: a
// placeholder Model with the board named only by PartNumber. It resolves a
// board-specific entry, so a test built on it fails if any field is dropped
// in transit.
var miniFleetIdentity = quirks.Identity{
	Manufacturer: "Supermicro",
	Model:        "Super Server",
	PartNumber:   "SYS-5018D-FN8T-AS001",
}

// TestApp_CarriesHardwareIdentityFromConfigFile closes the last hop of the
// path the bootstrap orchestrator opens. Every on-disk installer config
// reaches the installer through App — loadUnifiedConfig unmarshals the file
// into App and hands back GetInstallerConfig() — so an identity App does
// not carry is an identity the installer never sees, and the orchestrator's
// work is silently discarded.
//
// The document is produced by marshalling installer.Config itself, so the
// test is driven by that type's YAML tags rather than by key strings copied
// into the test: if App's tags drift from installer.Config's, this fails.
func TestApp_CarriesHardwareIdentityFromConfigFile(t *testing.T) {
	document, err := yaml.Marshal(&installer.Config{
		HardwareManufacturer: miniFleetIdentity.Manufacturer,
		HardwareModel:        miniFleetIdentity.Model,
		HardwarePartNumber:   miniFleetIdentity.PartNumber,
	})
	if err != nil {
		t.Fatalf("marshal installer.Config: %v", err)
	}

	var loaded App
	if err := yaml.Unmarshal(document, &loaded); err != nil {
		t.Fatalf("unmarshal into App: %v", err)
	}

	got := loaded.GetInstallerConfig().HardwareIdentity()
	if got != miniFleetIdentity {
		t.Errorf("identity through App = %+v, want %+v\ndocument:\n%s", got, miniFleetIdentity, document)
	}
	if key := quirks.ResolveIdentity(got).Key; key != "supermicro/x10sdv" {
		t.Errorf("installer resolves %q, want supermicro/x10sdv", key)
	}
}

// TestApp_SetInstallerConfigRoundTripsHardwareIdentity keeps the two
// directions symmetric, so a config loaded as installer.Config and pushed
// into App is not quietly stripped of its identity.
func TestApp_SetInstallerConfigRoundTripsHardwareIdentity(t *testing.T) {
	var a App
	a.SetInstallerConfig(&installer.Config{
		HardwareManufacturer: miniFleetIdentity.Manufacturer,
		HardwareModel:        miniFleetIdentity.Model,
		HardwarePartNumber:   miniFleetIdentity.PartNumber,
	})

	if got := a.GetInstallerConfig().HardwareIdentity(); got != miniFleetIdentity {
		t.Errorf("identity after round trip = %+v, want %+v", got, miniFleetIdentity)
	}
}
