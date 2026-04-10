package sdn

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestParsePolicyType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected platformv1.PolicyType
		wantErr  bool
	}{
		{"ACL", "acl", platformv1.PolicyType_POLICY_TYPE_ACL, false},
		{"QoS", "qos", platformv1.PolicyType_POLICY_TYPE_QOS, false},
		{"NAT", "nat", platformv1.PolicyType_POLICY_TYPE_NAT, false},
		{"Firewall", "firewall", platformv1.PolicyType_POLICY_TYPE_FIREWALL, false},
		{"Routing", "routing", platformv1.PolicyType_POLICY_TYPE_ROUTING, false},
		{"Invalid", "invalid", platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED, true},
		{"Empty", "", platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePolicyType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePolicyType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parsePolicyType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrInvalidPolicyType(t *testing.T) {
	err := ErrInvalidPolicyType{Type: "bogus"}
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
	if !containsStr(msg, "bogus") {
		t.Errorf("error should contain the invalid type, got: %s", msg)
	}
	if !containsStr(msg, "acl") {
		t.Errorf("error should list valid types, got: %s", msg)
	}
}

func TestNewPolicyCommand(t *testing.T) {
	cmd := NewPolicyCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewPolicyCommand returned nil")
	}
	if cmd.Use != "policy" {
		t.Errorf("expected Use 'policy', got %s", cmd.Use)
	}
}

func TestPolicyCommandSubcommands(t *testing.T) {
	cmd := NewPolicyCommand(testGetFlags())

	expectedSubs := []string{"apply", "get", "list"}
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

func TestPolicyApplyCommandRequiredFlags(t *testing.T) {
	cmd := newPolicyApplyCommand(testGetFlags())
	requiredFlags := []string{"id", "name", "type", "priority", "bridge"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestPolicyGetCommandArgs(t *testing.T) {
	cmd := newPolicyGetCommand(testGetFlags())
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestPolicyListCommandFlags(t *testing.T) {
	cmd := newPolicyListCommand(testGetFlags())
	optionalFlags := []string{"type", "target", "limit", "cursor"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestPolicyApplyCommandOptionalFlags(t *testing.T) {
	cmd := newPolicyApplyCommand(testGetFlags())
	optionalFlags := []string{"description", "enabled"}
	for _, flagName := range optionalFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}
