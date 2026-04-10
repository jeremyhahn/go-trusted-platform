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
	if len(commands) != 1 {
		t.Errorf("expected 1 subcommand (list), got %d", len(commands))
	}
	if len(commands) > 0 && commands[0].Name() != "list" {
		t.Errorf("expected 'list' subcommand, got %s", commands[0].Name())
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
