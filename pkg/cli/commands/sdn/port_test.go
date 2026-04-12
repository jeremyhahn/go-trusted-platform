package sdn

import (
	"testing"

	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

func TestParsePortType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected sdnsvc.PortType
		wantErr  bool
	}{
		{"Internal", "internal", sdnsvc.PortTypeInternal, false},
		{"Physical", "physical", sdnsvc.PortTypePhysical, false},
		{"Tap", "tap", sdnsvc.PortTypeTap, false},
		{"Veth", "veth", sdnsvc.PortTypeVeth, false},
		{"VXLAN", "vxlan", sdnsvc.PortTypeVXLAN, false},
		{"GRE", "gre", sdnsvc.PortTypeGRE, false},
		{"Uppercase", "INTERNAL", sdnsvc.PortTypeInternal, false},
		{"Mixed case", "Vxlan", sdnsvc.PortTypeVXLAN, false},
		{"Invalid", "invalid", sdnsvc.PortTypeUnspecified, true},
		{"Empty", "", sdnsvc.PortTypeUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := sdnsvc.ParsePortType(tt.input)
			if tt.wantErr {
				if ok {
					t.Errorf("ParsePortType(%q) expected not ok, got ok", tt.input)
				}
				return
			}
			if !ok {
				t.Errorf("ParsePortType(%q) expected ok, got not ok", tt.input)
				return
			}
			if result != tt.expected {
				t.Errorf("ParsePortType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrInvalidPortType(t *testing.T) {
	err := ErrInvalidPortType{Type: "badtype"}
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
	if !containsStr(msg, "badtype") {
		t.Errorf("error should contain the invalid type, got: %s", msg)
	}
	if !containsStr(msg, "internal") {
		t.Errorf("error should list valid types, got: %s", msg)
	}
}

func TestNewPortCommand(t *testing.T) {
	cmd := NewPortCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewPortCommand returned nil")
	}
	if cmd.Use != "port" {
		t.Errorf("expected Use 'port', got %s", cmd.Use)
	}
}

func TestPortCommandSubcommands(t *testing.T) {
	cmd := NewPortCommand(testGetFlags())

	expectedSubs := []string{"add", "delete", "state", "set-state", "stats"}
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

func TestPortAddCommandRequiredFlags(t *testing.T) {
	cmd := newPortAddCommand(testGetFlags())
	requiredFlags := []string{"bridge", "id", "name", "type"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestPortDeleteCommandRequiredFlags(t *testing.T) {
	cmd := newPortDeleteCommand(testGetFlags())
	flag := cmd.Flags().Lookup("bridge")
	if flag == nil {
		t.Error("bridge flag should exist")
	}
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestStringToPortTypeMapCompleteness(t *testing.T) {
	expectedTypes := []string{"internal", "physical", "tap", "veth", "vxlan", "gre"}
	for _, expected := range expectedTypes {
		if _, ok := sdnsvc.StringToPortType[expected]; !ok {
			t.Errorf("StringToPortType missing entry for %s", expected)
		}
	}
}

func TestPortSetStateCommandFlags(t *testing.T) {
	cmd := newPortSetStateCommand(testGetFlags())

	flags := []string{"bridge", "admin-state", "ingress-rate", "egress-rate"}
	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}

	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestPortStatsCommandRequiredFlags(t *testing.T) {
	cmd := newPortStatsCommand(testGetFlags())
	flag := cmd.Flags().Lookup("bridge")
	if flag == nil {
		t.Error("bridge flag should exist")
	}
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}
