package sdn

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestParsePortType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected platformv1.PortType
		wantErr  bool
	}{
		{"Internal", "internal", platformv1.PortType_PORT_TYPE_INTERNAL, false},
		{"Physical", "physical", platformv1.PortType_PORT_TYPE_PHYSICAL, false},
		{"Tap", "tap", platformv1.PortType_PORT_TYPE_TAP, false},
		{"Veth", "veth", platformv1.PortType_PORT_TYPE_VETH, false},
		{"VXLAN", "vxlan", platformv1.PortType_PORT_TYPE_VXLAN, false},
		{"GRE", "gre", platformv1.PortType_PORT_TYPE_GRE, false},
		{"Uppercase", "INTERNAL", platformv1.PortType_PORT_TYPE_INTERNAL, false},
		{"Mixed case", "Vxlan", platformv1.PortType_PORT_TYPE_VXLAN, false},
		{"Invalid", "invalid", platformv1.PortType_PORT_TYPE_UNSPECIFIED, true},
		{"Empty", "", platformv1.PortType_PORT_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePortType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parsePortType(%q) = %v, want %v", tt.input, result, tt.expected)
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

func TestPortTypeMapCompleteness(t *testing.T) {
	expectedTypes := []string{"internal", "physical", "tap", "veth", "vxlan", "gre"}
	for _, expected := range expectedTypes {
		if _, ok := portTypeMap[expected]; !ok {
			t.Errorf("portTypeMap missing entry for %s", expected)
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
