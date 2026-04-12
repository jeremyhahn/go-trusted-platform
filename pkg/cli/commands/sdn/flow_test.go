package sdn

import (
	"testing"

	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

func TestParseFlowActionType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected sdnsvc.FlowActionType
		wantErr  bool
	}{
		{"Output", "output", sdnsvc.FlowActionOutput, false},
		{"Drop", "drop", sdnsvc.FlowActionDrop, false},
		{"Set VLAN", "set_vlan", sdnsvc.FlowActionSetVLAN, false},
		{"Strip VLAN", "strip_vlan", sdnsvc.FlowActionStripVLAN, false},
		{"Set field", "set_field", sdnsvc.FlowActionSetField, false},
		{"Goto table", "goto_table", sdnsvc.FlowActionGotoTable, false},
		{"Controller", "controller", sdnsvc.FlowActionController, false},
		{"Normal", "normal", sdnsvc.FlowActionOutput, false},
		{"Flood", "flood", sdnsvc.FlowActionOutput, false},
		{"Uppercase", "OUTPUT", sdnsvc.FlowActionOutput, false},
		{"Invalid", "invalid", sdnsvc.FlowActionUnspecified, true},
		{"Empty", "", sdnsvc.FlowActionUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := sdnsvc.ParseFlowActionType(tt.input)
			if tt.wantErr {
				if ok {
					t.Errorf("ParseFlowActionType(%q) expected not ok, got ok", tt.input)
				}
				return
			}
			if !ok {
				t.Errorf("ParseFlowActionType(%q) expected ok, got not ok", tt.input)
				return
			}
			if result != tt.expected {
				t.Errorf("ParseFlowActionType(%q) = %v, want %v", tt.input, result, tt.expected)
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
		expected sdnsvc.FlowTable
	}{
		{"Table 0", 0, sdnsvc.FlowTable0},
		{"Table 1", 1, sdnsvc.FlowTable1},
		{"Table 2", 2, sdnsvc.FlowTable2},
		{"Table 3", 3, sdnsvc.FlowTable3},
		{"Table 255 (drop)", 255, sdnsvc.FlowTableDrop},
		{"Unknown table", 99, sdnsvc.FlowTableUnspecified},
		{"Negative table", -1, sdnsvc.FlowTableUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sdnsvc.ParseFlowTable(tt.input)
			if result != tt.expected {
				t.Errorf("ParseFlowTable(%d) = %v, want %v", tt.input, result, tt.expected)
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

func TestStringToFlowActionTypeMapCompleteness(t *testing.T) {
	expectedTypes := []string{"output", "drop", "set_vlan", "strip_vlan", "set_field", "goto_table", "controller", "normal", "flood"}
	for _, expected := range expectedTypes {
		if _, ok := sdnsvc.StringToFlowActionType[expected]; !ok {
			t.Errorf("StringToFlowActionType missing entry for %s", expected)
		}
	}
}

func TestFlowTableMapCompleteness(t *testing.T) {
	expectedTables := []int{0, 1, 2, 3, 255}
	for _, expected := range expectedTables {
		result := sdnsvc.ParseFlowTable(expected)
		if result == sdnsvc.FlowTableUnspecified {
			t.Errorf("ParseFlowTable(%d) returned unspecified", expected)
		}
	}
}
