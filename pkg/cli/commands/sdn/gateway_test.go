package sdn

import (
	"testing"
)

func TestNewGatewayCommand(t *testing.T) {
	cmd := NewGatewayCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewGatewayCommand returned nil")
	}
	if cmd.Use != "gateway" {
		t.Errorf("expected Use 'gateway', got %s", cmd.Use)
	}
}

func TestGatewayCommandSubcommands(t *testing.T) {
	cmd := NewGatewayCommand(testGetFlags())

	expectedSubs := []string{"status", "mode", "bgp"}
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

func TestGatewayModeCommand(t *testing.T) {
	cmd := newGatewayModeCommand(testGetFlags())
	if cmd.Use != "mode" {
		t.Errorf("expected Use 'mode', got %s", cmd.Use)
	}

	// Should have "set" subcommand
	commands := cmd.Commands()
	if len(commands) != 1 {
		t.Errorf("expected 1 subcommand (set), got %d", len(commands))
	}
	if len(commands) > 0 && commands[0].Name() != "set" {
		t.Errorf("expected 'set' subcommand, got %s", commands[0].Name())
	}
}

func TestGatewayModeSetCommandFlags(t *testing.T) {
	cmd := newGatewayModeCommand(testGetFlags())
	commands := cmd.Commands()
	if len(commands) == 0 {
		t.Fatal("expected set subcommand")
	}
	setCmd := commands[0]
	flag := setCmd.Flags().Lookup("modes")
	if flag == nil {
		t.Error("modes flag should exist")
	}
}

func TestGatewayBGPCommand(t *testing.T) {
	cmd := newGatewayBGPCommand(testGetFlags())
	if cmd.Use != "bgp" {
		t.Errorf("expected Use 'bgp', got %s", cmd.Use)
	}

	expectedSubs := []string{"status", "peers", "announce", "withdraw", "routes"}
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

func TestGatewayBGPAnnounceCommandFlags(t *testing.T) {
	cmd := newGatewayBGPCommand(testGetFlags())
	var announceCmd *interface{}
	_ = announceCmd

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "announce" {
			flag := subcmd.Flags().Lookup("prefix")
			if flag == nil {
				t.Error("prefix flag should exist on announce command")
			}
			nextHopFlag := subcmd.Flags().Lookup("next-hop")
			if nextHopFlag == nil {
				t.Error("next-hop flag should exist on announce command")
			}
			return
		}
	}
	t.Error("announce subcommand not found")
}

func TestGatewayStatusCommand(t *testing.T) {
	cmd := newGatewayStatusCommand(testGetFlags())
	if cmd.Use != "status" {
		t.Errorf("expected Use 'status', got %s", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}
