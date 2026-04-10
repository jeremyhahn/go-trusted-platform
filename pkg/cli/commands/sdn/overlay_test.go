package sdn

import (
	"testing"
)

func TestNewOverlayCommand(t *testing.T) {
	cmd := NewOverlayCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewOverlayCommand returned nil")
	}
	if cmd.Use != "overlay" {
		t.Errorf("expected Use 'overlay', got %s", cmd.Use)
	}
}

func TestOverlayCommandSubcommands(t *testing.T) {
	cmd := NewOverlayCommand(testGetFlags())

	expectedSubs := []string{"status", "vtep", "vni", "tunnel", "mac"}
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

func TestOverlayVTEPSubcommands(t *testing.T) {
	cmd := newOverlayVTEPCommand(testGetFlags())
	expectedSubs := []string{"list", "get"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
}

func TestOverlayVNISubcommands(t *testing.T) {
	cmd := newOverlayVNICommand(testGetFlags())
	expectedSubs := []string{"list", "create", "delete"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
}

func TestOverlayTunnelSubcommands(t *testing.T) {
	cmd := newOverlayTunnelCommand(testGetFlags())
	expectedSubs := []string{"list"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
}

func TestOverlayMACSubcommands(t *testing.T) {
	cmd := newOverlayMACCommand(testGetFlags())
	expectedSubs := []string{"list", "forget"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
}

func TestOverlayStatusCommand(t *testing.T) {
	cmd := newOverlayStatusCommand(testGetFlags())
	if cmd.Use != "status" {
		t.Errorf("expected Use 'status', got %s", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}
