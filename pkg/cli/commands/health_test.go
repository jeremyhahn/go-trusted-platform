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
	"bytes"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

func TestNewHealthCommand(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewHealthCommand returned nil")
	}

	if cmd.Use != "health" {
		t.Errorf("expected Use to be 'health', got %s", cmd.Use)
	}

	if cmd.Short != "Show platform health status" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestHealthCommandFlags(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	detailedFlag := cmd.Flags().Lookup("detailed")
	if detailedFlag == nil {
		t.Fatal("detailed flag not found")
	}

	if detailedFlag.Shorthand != "d" {
		t.Errorf("expected detailed flag shorthand to be 'd', got %s", detailedFlag.Shorthand)
	}

	if detailedFlag.DefValue != "false" {
		t.Errorf("expected detailed flag default to be false, got %s", detailedFlag.DefValue)
	}
}

func TestHealthCommandStructure(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestHealthRunEWithNoConnection(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestHealthCommandLongDescription(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Display the health status of the Trusted Platform and its components"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestHealthDetailedFlagUsage(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	detailedFlag := cmd.Flags().Lookup("detailed")
	if detailedFlag == nil {
		t.Fatal("detailed flag should exist")
	}

	if detailedFlag.Usage != "show detailed component health" {
		t.Errorf("unexpected detailed flag usage: %s", detailedFlag.Usage)
	}
}

// Surfacing a degraded component (#509) ----------------------------------------
//
// A fleet ran time-unsynced from enrolment because "Overall Health: degraded"
// named nothing, and the component that WAS naming it was one flag away from
// being read. The default view now names every component that is not healthy.

// healthPrinter returns a printer writing to buf with colour off, so the
// output is the deterministic [LEVEL] form.
func healthPrinter(buf *bytes.Buffer) *cli.Printer {
	return cli.NewPrinterWithWriter(cli.OutputFormatTable, true, buf)
}

func TestPrintUnhealthyComponents_NamesTheDegradedComponent(t *testing.T) {
	var buf bytes.Buffer
	printUnhealthyComponents(healthPrinter(&buf), &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusDegraded,
		Components: []*daemonsvc.ComponentHealth{
			{Name: "ca", Status: daemonsvc.HealthStatusHealthy, Message: "issuing"},
			{Name: "ntp", Status: daemonsvc.HealthStatusDegraded, Message: "time-unsynced"},
		},
	})

	out := buf.String()
	if !strings.Contains(out, "[WARNING] ntp: DEGRADED — time-unsynced") {
		t.Errorf("degraded component not named in the default view: %q", out)
	}
	if strings.Contains(out, "ca") {
		t.Errorf("healthy components must not be listed: %q", out)
	}
	if !strings.Contains(out, "--detailed") {
		t.Errorf("the pointer to the full table is missing: %q", out)
	}
}

func TestPrintUnhealthyComponents_UnhealthyIsAnError(t *testing.T) {
	var buf bytes.Buffer
	printUnhealthyComponents(healthPrinter(&buf), &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusUnhealthy,
		Components: []*daemonsvc.ComponentHealth{
			{Name: "ntp", Status: daemonsvc.HealthStatusUnhealthy, Message: "time-unsynced: control socket unreachable"},
		},
	})

	out := buf.String()
	if !strings.Contains(out, "[ERROR] ntp: UNHEALTHY — time-unsynced: control socket unreachable") {
		t.Errorf("unhealthy component not reported as an error: %q", out)
	}
}

// TestPrintUnhealthyComponents_SilentWhenEverythingIsHealthy covers the
// other half: a healthy platform prints no component noise, and neither a
// nil component nor an empty message can produce a stray line.
func TestPrintUnhealthyComponents_SilentWhenEverythingIsHealthy(t *testing.T) {
	var buf bytes.Buffer
	printUnhealthyComponents(healthPrinter(&buf), &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusHealthy,
		Components: []*daemonsvc.ComponentHealth{
			nil,
			{Name: "ca", Status: daemonsvc.HealthStatusHealthy},
		},
	})
	if buf.Len() != 0 {
		t.Errorf("a healthy platform must print nothing here, got %q", buf.String())
	}

	buf.Reset()
	printUnhealthyComponents(healthPrinter(&buf), &daemonsvc.HealthInfo{})
	if buf.Len() != 0 {
		t.Errorf("a health report with no components must print nothing, got %q", buf.String())
	}
}

// TestPrintUnhealthyComponents_MessagelessComponentStillNamed asserts a
// component that reports no message is still named with its status: the
// operator must learn WHICH component is wrong even when it says nothing.
func TestPrintUnhealthyComponents_MessagelessComponentStillNamed(t *testing.T) {
	var buf bytes.Buffer
	printUnhealthyComponents(healthPrinter(&buf), &daemonsvc.HealthInfo{
		Components: []*daemonsvc.ComponentHealth{
			{Name: "sdn", Status: daemonsvc.HealthStatusUnspecified},
		},
	})
	out := buf.String()
	if !strings.Contains(out, "sdn: UNKNOWN") {
		t.Errorf("component with no message not named: %q", out)
	}
	if strings.Contains(out, "—") {
		t.Errorf("no message means no separator: %q", out)
	}
}

// TestPrintHealthTable_DefaultViewNamesTheFailingComponent asserts the
// DEFAULT rendering — no `--detailed` — names the component that is wrong.
// This is the assertion that pins the wiring, not just the helper: the
// failure #509 records is precisely that the information existed and the
// default view did not print it.
func TestPrintHealthTable_DefaultViewNamesTheFailingComponent(t *testing.T) {
	var buf bytes.Buffer
	health := &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusDegraded,
		Components: []*daemonsvc.ComponentHealth{
			{Name: "ca", Status: daemonsvc.HealthStatusHealthy, Message: "issuing"},
			{Name: "ntp", Status: daemonsvc.HealthStatusDegraded, Message: "time-unsynced"},
		},
	}
	if err := printHealthTable(healthPrinter(&buf), health, false); err != nil {
		t.Fatalf("printHealthTable: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Overall Health: DEGRADED") {
		t.Errorf("overall verdict missing: %q", out)
	}
	if !strings.Contains(out, "ntp: DEGRADED — time-unsynced") {
		t.Errorf("the degraded component is not named without --detailed: %q", out)
	}
	if strings.Contains(out, "COMPONENT") {
		t.Errorf("the full table belongs to --detailed: %q", out)
	}
}

// TestPrintHealthTable_DetailedShowsEveryComponentOnce asserts `--detailed`
// still renders the full table, and does not ALSO print the per-component
// warning lines — the same row twice would read as two findings.
func TestPrintHealthTable_DetailedShowsEveryComponentOnce(t *testing.T) {
	var buf bytes.Buffer
	health := &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusDegraded,
		Components: []*daemonsvc.ComponentHealth{
			{Name: "ca", Status: daemonsvc.HealthStatusHealthy, Message: "issuing"},
			{Name: "ntp", Status: daemonsvc.HealthStatusDegraded, Message: "time-unsynced"},
		},
	}
	if err := printHealthTable(healthPrinter(&buf), health, true); err != nil {
		t.Fatalf("printHealthTable: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ca") || !strings.Contains(out, "ntp") {
		t.Errorf("the detailed table must list every component: %q", out)
	}
	if strings.Contains(out, "[WARNING] ntp:") {
		t.Errorf("--detailed must not repeat the component as a warning line: %q", out)
	}
}

// TestPrintHealthTable_HealthyPlatformPrintsOnlyTheVerdict covers the other
// side: nothing is added when there is nothing wrong.
func TestPrintHealthTable_HealthyPlatformPrintsOnlyTheVerdict(t *testing.T) {
	var buf bytes.Buffer
	health := &daemonsvc.HealthInfo{
		Status: daemonsvc.HealthStatusHealthy,
		Components: []*daemonsvc.ComponentHealth{
			{Name: "ca", Status: daemonsvc.HealthStatusHealthy, Message: "issuing"},
		},
	}
	if err := printHealthTable(healthPrinter(&buf), health, false); err != nil {
		t.Fatalf("printHealthTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Overall Health: HEALTHY") {
		t.Errorf("overall verdict missing: %q", out)
	}
	if strings.Contains(out, "[WARNING]") || strings.Contains(out, "--detailed") {
		t.Errorf("a healthy platform must print only the verdict: %q", out)
	}
}
