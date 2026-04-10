package sdn

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestParseBridgeType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected platformv1.BridgeType
		wantErr  bool
	}{
		{"OVS lowercase", "ovs", platformv1.BridgeType_BRIDGE_TYPE_OVS, false},
		{"OVS uppercase", "OVS", platformv1.BridgeType_BRIDGE_TYPE_OVS, false},
		{"OVS mixed case", "Ovs", platformv1.BridgeType_BRIDGE_TYPE_OVS, false},
		{"Linux", "linux", platformv1.BridgeType_BRIDGE_TYPE_LINUX, false},
		{"VXLAN", "vxlan", platformv1.BridgeType_BRIDGE_TYPE_VXLAN, false},
		{"Invalid type", "invalid", platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED, true},
		{"Empty string", "", platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseBridgeType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBridgeType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parseBridgeType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrInvalidBridgeType(t *testing.T) {
	err := ErrInvalidBridgeType{Type: "bogus"}
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
	if !containsStr(msg, "bogus") {
		t.Errorf("error message should contain the invalid type, got: %s", msg)
	}
	if !containsStr(msg, "ovs") {
		t.Errorf("error message should list valid types, got: %s", msg)
	}
}

func TestNewBridgeCommand(t *testing.T) {
	cmd := NewBridgeCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewBridgeCommand returned nil")
	}
	if cmd.Use != "bridge" {
		t.Errorf("expected Use 'bridge', got %s", cmd.Use)
	}
}

func TestBridgeCommandSubcommands(t *testing.T) {
	cmd := NewBridgeCommand(testGetFlags())

	expectedSubs := []string{"create", "get", "list", "delete"}

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

func TestBridgeCreateCommandRequiredFlags(t *testing.T) {
	cmd := newBridgeCreateCommand(testGetFlags())

	requiredFlags := []string{"id", "name", "type"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
			continue
		}
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestBridgeGetCommandRequiresExactArgs(t *testing.T) {
	cmd := newBridgeGetCommand(testGetFlags())
	if cmd.Args == nil {
		t.Error("Args validation should not be nil (expects ExactArgs(1))")
	}
}

func TestBridgeDeleteCommandFlags(t *testing.T) {
	cmd := newBridgeDeleteCommand(testGetFlags())

	optionalFlags := []string{"force", "delete-ports", "delete-flows"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestBridgeListCommandFlags(t *testing.T) {
	cmd := newBridgeListCommand(testGetFlags())

	optionalFlags := []string{"type", "status", "limit", "cursor"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestBridgeTypeMapCompleteness(t *testing.T) {
	expectedTypes := []string{"ovs", "linux", "vxlan"}
	for _, expected := range expectedTypes {
		if _, ok := bridgeTypeMap[expected]; !ok {
			t.Errorf("bridgeTypeMap missing entry for %s", expected)
		}
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
