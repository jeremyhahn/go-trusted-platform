package sdn

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestParseFlowActionType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected platformv1.FlowActionType
		wantErr  bool
	}{
		{"Output", "output", platformv1.FlowActionType_FLOW_ACTION_OUTPUT, false},
		{"Drop", "drop", platformv1.FlowActionType_FLOW_ACTION_DROP, false},
		{"Set VLAN", "set_vlan", platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, false},
		{"Strip VLAN", "strip_vlan", platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN, false},
		{"Set field", "set_field", platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, false},
		{"Goto table", "goto_table", platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, false},
		{"Controller", "controller", platformv1.FlowActionType_FLOW_ACTION_CONTROLLER, false},
		{"Normal", "normal", platformv1.FlowActionType_FLOW_ACTION_OUTPUT, false},
		{"Flood", "flood", platformv1.FlowActionType_FLOW_ACTION_OUTPUT, false},
		{"Uppercase", "OUTPUT", platformv1.FlowActionType_FLOW_ACTION_OUTPUT, false},
		{"Invalid", "invalid", platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED, true},
		{"Empty", "", platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseFlowActionType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlowActionType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parseFlowActionType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrInvalidFlowActionType(t *testing.T) {
	err := ErrInvalidFlowActionType{Type: "bogus"}
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
	if !containsStr(msg, "bogus") {
		t.Errorf("error should contain the invalid type, got: %s", msg)
	}
	if !containsStr(msg, "output") {
		t.Errorf("error should list valid types, got: %s", msg)
	}
}

func TestParseFlowTable(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected platformv1.FlowTable
	}{
		{"Table 0", 0, platformv1.FlowTable_FLOW_TABLE_0},
		{"Table 1", 1, platformv1.FlowTable_FLOW_TABLE_1},
		{"Table 2", 2, platformv1.FlowTable_FLOW_TABLE_2},
		{"Table 3", 3, platformv1.FlowTable_FLOW_TABLE_3},
		{"Table 255 (drop)", 255, platformv1.FlowTable_FLOW_TABLE_DROP},
		{"Unknown table", 99, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED},
		{"Negative table", -1, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFlowTable(tt.input)
			if result != tt.expected {
				t.Errorf("parseFlowTable(%d) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewFlowCommand(t *testing.T) {
	cmd := NewFlowCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewFlowCommand returned nil")
	}
	if cmd.Use != "flow" {
		t.Errorf("expected Use 'flow', got %s", cmd.Use)
	}
}

func TestFlowCommandSubcommands(t *testing.T) {
	cmd := NewFlowCommand(testGetFlags())

	expectedSubs := []string{"add", "delete", "list"}
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

func TestFlowAddCommandRequiredFlags(t *testing.T) {
	cmd := newFlowAddCommand(testGetFlags())
	requiredFlags := []string{"bridge", "id", "table", "priority"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestFlowDeleteCommandRequiredFlags(t *testing.T) {
	cmd := newFlowDeleteCommand(testGetFlags())
	flag := cmd.Flags().Lookup("bridge")
	if flag == nil {
		t.Error("bridge flag should exist")
	}
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestFlowListCommandFlags(t *testing.T) {
	cmd := newFlowListCommand(testGetFlags())
	optionalFlags := []string{"bridge", "table", "limit", "cursor"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestFlowActionTypeMapCompleteness(t *testing.T) {
	expectedTypes := []string{"output", "drop", "set_vlan", "strip_vlan", "set_field", "goto_table", "controller", "normal", "flood"}
	for _, expected := range expectedTypes {
		if _, ok := flowActionTypeMap[expected]; !ok {
			t.Errorf("flowActionTypeMap missing entry for %s", expected)
		}
	}
}

func TestFlowTableMapCompleteness(t *testing.T) {
	expectedTables := []int{0, 1, 2, 3, 255}
	for _, expected := range expectedTables {
		if _, ok := flowTableMap[expected]; !ok {
			t.Errorf("flowTableMap missing entry for %d", expected)
		}
	}
}
