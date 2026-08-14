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

package sdn

import (
	"errors"
	"testing"
)

func TestNewGatewayPerfCommand(t *testing.T) {
	cmd := newGatewayPerfCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("newGatewayPerfCommand returned nil")
	}
	if cmd.Use != "perf" {
		t.Errorf("expected Use 'perf', got %s", cmd.Use)
	}

	expectedSubs := map[string]bool{
		"flows": false, "datapath": false, "conntrack": false,
	}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
	for _, subcmd := range commands {
		if _, ok := expectedSubs[subcmd.Name()]; ok {
			expectedSubs[subcmd.Name()] = true
		}
	}
	for name, found := range expectedSubs {
		if !found {
			t.Errorf("missing subcommand %s", name)
		}
	}
}

func TestGatewayPerfFlowsCommandFlags(t *testing.T) {
	cmd := newGatewayPerfFlowsCommand(testGetFlags())

	for _, flag := range []string{"count", "batch", "bridge"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing --%s flag", flag)
		}
	}
	if def := cmd.Flags().Lookup("count").DefValue; def != "1000" {
		t.Errorf("--count default = %s, want 1000", def)
	}
	if def := cmd.Flags().Lookup("batch").DefValue; def != "false" {
		t.Errorf("--batch default = %s, want false", def)
	}
}

func TestGatewayPerfDatapathCommandFlags(t *testing.T) {
	cmd := newGatewayPerfDatapathCommand(testGetFlags())

	if cmd.Flags().Lookup("bridge") == nil {
		t.Error("missing --bridge flag")
	}
	if cmd.Use != "datapath" {
		t.Errorf("Use = %s", cmd.Use)
	}
}

func TestGatewayPerfConntrackCommandFlags(t *testing.T) {
	cmd := newGatewayPerfConntrackCommand(testGetFlags())

	if cmd.Flags().Lookup("zone") == nil {
		t.Error("missing --zone flag")
	}
	if cmd.Use != "conntrack" {
		t.Errorf("Use = %s", cmd.Use)
	}
}

func TestGatewayPerfConntrackInvalidZone(t *testing.T) {
	cmd := newGatewayPerfConntrackCommand(testGetFlags())
	cmd.SetArgs([]string{"--zone", "70000"})

	err := cmd.Execute()
	var zoneErr *ErrInvalidConntrackZone
	if !errors.As(err, &zoneErr) {
		t.Fatalf("err = %v, want ErrInvalidConntrackZone", err)
	}
	if zoneErr.Zone != 70000 {
		t.Errorf("Zone = %d, want 70000", zoneErr.Zone)
	}
}

func TestGatewayPerfRegisteredUnderGateway(t *testing.T) {
	cmd := NewGatewayCommand(testGetFlags())

	found := false
	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "perf" {
			found = true
			break
		}
	}
	if !found {
		t.Error("perf subcommand not registered under gateway")
	}
}
