package sdn

import (
	"testing"
)

func TestNewIPAMCommand(t *testing.T) {
	cmd := NewIPAMCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewIPAMCommand returned nil")
	}
	if cmd.Use != "ipam" {
		t.Errorf("expected Use 'ipam', got %s", cmd.Use)
	}
}

func TestIPAMCommandSubcommands(t *testing.T) {
	cmd := NewIPAMCommand(testGetFlags())

	expectedSubs := []string{"pool", "allocate", "release", "allocations"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}

	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}
}

func TestIPAMPoolSubcommands(t *testing.T) {
	cmd := newIPAMPoolCommand(testGetFlags())
	commands := cmd.Commands()
	if len(commands) != 5 {
		t.Errorf("expected 5 subcommands (create, get, update, delete, list), got %d", len(commands))
	}
	found := make(map[string]bool, len(commands))
	for _, sub := range commands {
		found[sub.Name()] = true
	}
	for _, expected := range []string{"create", "get", "update", "delete", "list"} {
		if !found[expected] {
			t.Errorf("expected %q subcommand not found", expected)
		}
	}
}

func TestIPAMAllocateCommandFlags(t *testing.T) {
	cmd := newIPAMAllocateCommand(testGetFlags())
	requiredFlags := []string{"pool-id", "device-id"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}

	// Optional hostname flag
	flag := cmd.Flags().Lookup("hostname")
	if flag == nil {
		t.Error("hostname flag should exist")
	}
}

func TestIPAMReleaseCommandFlags(t *testing.T) {
	cmd := newIPAMReleaseCommand(testGetFlags())
	flag := cmd.Flags().Lookup("ip")
	if flag == nil {
		t.Error("ip flag should exist")
	}
}

func TestIPAMAllocationsCommandFlags(t *testing.T) {
	cmd := newIPAMAllocationsCommand(testGetFlags())
	flag := cmd.Flags().Lookup("pool-id")
	if flag == nil {
		t.Error("pool-id flag should exist")
	}
}
