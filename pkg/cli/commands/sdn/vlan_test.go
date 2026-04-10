package sdn

import (
	"testing"
)

func TestErrInvalidVLANID(t *testing.T) {
	err := ErrInvalidVLANID{Value: "abc"}
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
	if !containsStr(msg, "abc") {
		t.Errorf("error should contain the invalid value, got: %s", msg)
	}
	if !containsStr(msg, "1-4094") {
		t.Errorf("error should mention valid range, got: %s", msg)
	}
}

func TestErrInvalidVLANIDEmptyValue(t *testing.T) {
	err := ErrInvalidVLANID{Value: ""}
	msg := err.Error()
	if !containsStr(msg, "invalid VLAN ID") {
		t.Errorf("error should contain 'invalid VLAN ID', got: %s", msg)
	}
}

func TestNewVLANCommand(t *testing.T) {
	cmd := NewVLANCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewVLANCommand returned nil")
	}
	if cmd.Use != "vlan" {
		t.Errorf("expected Use 'vlan', got %s", cmd.Use)
	}
}

func TestVLANCommandSubcommands(t *testing.T) {
	cmd := NewVLANCommand(testGetFlags())

	expectedSubs := []string{"create", "delete", "list"}
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

func TestVLANCreateCommandFlags(t *testing.T) {
	cmd := newVLANCreateCommand(testGetFlags())
	requiredFlags := []string{"id", "name"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}

	optionalFlags := []string{"description", "bridge"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestVLANDeleteCommandArgs(t *testing.T) {
	cmd := newVLANDeleteCommand(testGetFlags())
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
	flag := cmd.Flags().Lookup("bridge")
	if flag == nil {
		t.Error("bridge flag should exist")
	}
}

func TestVLANListCommandFlags(t *testing.T) {
	cmd := newVLANListCommand(testGetFlags())
	optionalFlags := []string{"bridge", "limit", "cursor"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}
