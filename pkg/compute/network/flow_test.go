// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package network

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlowRuleType_String(t *testing.T) {
	tests := []struct {
		name     string
		ruleType FlowRuleType
		expected string
	}{
		{"quarantine", FlowRuleTypeQuarantine, "quarantine"},
		{"production", FlowRuleTypeProduction, "production"},
		{"drop", FlowRuleTypeDrop, "drop"},
		{"redirect", FlowRuleTypeRedirect, "redirect"},
		{"rate_limit", FlowRuleTypeRateLimit, "rate_limit"},
		{"monitor", FlowRuleTypeMonitor, "monitor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ruleType.String())
		})
	}
}

func TestFlowRuleType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		ruleType FlowRuleType
		expected bool
	}{
		{"quarantine valid", FlowRuleTypeQuarantine, true},
		{"production valid", FlowRuleTypeProduction, true},
		{"drop valid", FlowRuleTypeDrop, true},
		{"redirect valid", FlowRuleTypeRedirect, true},
		{"rate_limit valid", FlowRuleTypeRateLimit, true},
		{"monitor valid", FlowRuleTypeMonitor, true},
		{"invalid type", FlowRuleType("invalid"), false},
		{"empty type", FlowRuleType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ruleType.IsValid())
		})
	}
}

func TestFlowRule_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		rule    FlowRule
		expired bool
	}{
		{
			name:    "no expiration",
			rule:    FlowRule{ExpiresAt: time.Time{}},
			expired: false,
		},
		{
			name:    "not expired",
			rule:    FlowRule{ExpiresAt: time.Now().Add(time.Hour)},
			expired: false,
		},
		{
			name:    "expired",
			rule:    FlowRule{ExpiresAt: time.Now().Add(-time.Hour)},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expired, tt.rule.IsExpired())
		})
	}
}

func TestFlowConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  FlowConfig
		wantErr bool
	}{
		{
			name:    "valid minimal config",
			config:  FlowConfig{BridgeName: "br0"},
			wantErr: false,
		},
		{
			name: "valid full config",
			config: FlowConfig{
				BridgeName:         "br0",
				ControllerAddress:  "tcp:127.0.0.1:6653",
				DefaultPriority:    100,
				QuarantinePriority: 200,
				ProductionPriority: 300,
				RuleTimeout:        time.Hour,
			},
			wantErr: false,
		},
		{
			name:    "empty bridge name",
			config:  FlowConfig{BridgeName: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFlowConfig_DefaultPriorities(t *testing.T) {
	config := FlowConfig{BridgeName: "br0"}
	err := config.Validate()
	require.NoError(t, err)

	// Default priorities should be set
	assert.Equal(t, uint16(100), config.DefaultPriority)
	assert.Equal(t, uint16(200), config.QuarantinePriority)
	assert.Equal(t, uint16(300), config.ProductionPriority)
}

func TestFlowManager_Initialize(t *testing.T) {
	ctx := context.Background()

	t.Run("successful initialization", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}

		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		// Re-initialization should fail
		err = manager.Initialize(ctx, config)
		assert.Error(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.Initialize(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("invalid config", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: ""}
		err := manager.Initialize(ctx, config)
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(cancelCtx, config)
		assert.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)
	})
}

func TestFlowManager_InstallQuarantineRules(t *testing.T) {
	ctx := context.Background()

	t.Run("successful installation", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallQuarantineRules(ctx, "eth0", 1)
		require.NoError(t, err)

		// Verify rules were created
		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Len(t, rules, 2) // ingress + egress
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.InstallQuarantineRules(ctx, "eth0", 1)
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
	})

	t.Run("empty port ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallQuarantineRules(ctx, "", 1)
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = manager.InstallQuarantineRules(cancelCtx, "eth0", 1)
		assert.Error(t, err)
	})
}

func TestFlowManager_InstallProductionRules(t *testing.T) {
	ctx := context.Background()

	t.Run("successful installation", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallProductionRules(ctx, "eth0", 100)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Len(t, rules, 2)

		for _, rule := range rules {
			assert.Equal(t, FlowRuleTypeProduction, rule.Type)
			assert.Equal(t, uint16(100), rule.VLAN)
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.InstallProductionRules(ctx, "eth0", 100)
		assert.Error(t, err)
	})

	t.Run("empty port ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallProductionRules(ctx, "", 100)
		assert.Error(t, err)
	})
}

func TestFlowManager_RemoveRules(t *testing.T) {
	ctx := context.Background()

	t.Run("remove existing rules", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallQuarantineRules(ctx, "eth0", 1)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.NotEmpty(t, rules)

		err = manager.RemoveRules(ctx, "eth0")
		require.NoError(t, err)

		rules, err = manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("remove non-existent rules", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.RemoveRules(ctx, "eth0")
		assert.NoError(t, err) // Should not error
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.RemoveRules(ctx, "eth0")
		assert.Error(t, err)
	})

	t.Run("empty port ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.RemoveRules(ctx, "")
		assert.Error(t, err)
	})
}

func TestFlowManager_GetRules(t *testing.T) {
	ctx := context.Background()

	t.Run("get rules for port with rules", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallQuarantineRules(ctx, "eth0", 1)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Len(t, rules, 2)
	})

	t.Run("get rules for port without rules", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		rules, err := manager.GetRules(ctx, "eth0")
		assert.Error(t, err)
		assert.Nil(t, rules)
	})

	t.Run("empty port ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, rules)
	})
}

func TestFlowManager_InstallRule(t *testing.T) {
	ctx := context.Background()

	t.Run("install custom rule", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		rule := &FlowRule{
			ID:       "custom-rule-1",
			PortID:   "eth0",
			Type:     FlowRuleTypeDrop,
			Priority: 500,
			VLAN:     0,
			Match:    &FlowMatch{IPSrc: "10.0.0.1/32"},
			Actions:  []FlowAction{{Type: FlowActionTypeDrop}},
		}

		err = manager.InstallRule(ctx, rule)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Len(t, rules, 1)
		assert.Equal(t, "custom-rule-1", rules[0].ID)
	})

	t.Run("nil rule", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.InstallRule(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("empty rule ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		rule := &FlowRule{ID: "", PortID: "eth0"}
		err = manager.InstallRule(ctx, rule)
		assert.Error(t, err)
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		rule := &FlowRule{ID: "rule-1", PortID: "eth0"}
		err := manager.InstallRule(ctx, rule)
		assert.Error(t, err)
	})
}

func TestFlowManager_RemoveRule(t *testing.T) {
	ctx := context.Background()

	t.Run("remove existing rule", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		rule := &FlowRule{ID: "rule-1", PortID: "eth0", Type: FlowRuleTypeDrop}
		err = manager.InstallRule(ctx, rule)
		require.NoError(t, err)

		err = manager.RemoveRule(ctx, "rule-1")
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("remove non-existent rule", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.RemoveRule(ctx, "non-existent")
		assert.NoError(t, err) // Should not error
	})

	t.Run("empty rule ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.RemoveRule(ctx, "")
		assert.Error(t, err)
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.RemoveRule(ctx, "rule-1")
		assert.Error(t, err)
	})
}

func TestFlowManager_TransitionVLAN(t *testing.T) {
	ctx := context.Background()

	t.Run("successful VLAN transition", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		// Install initial quarantine rules
		err = manager.InstallQuarantineRules(ctx, "eth0", 1)
		require.NoError(t, err)

		// Transition to production VLAN
		err = manager.TransitionVLAN(ctx, "eth0", 1, 100)
		require.NoError(t, err)

		rules, err := manager.GetRules(ctx, "eth0")
		require.NoError(t, err)
		assert.NotEmpty(t, rules)
	})

	t.Run("same VLAN transition (no-op)", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.TransitionVLAN(ctx, "eth0", 100, 100)
		assert.NoError(t, err)
	})

	t.Run("empty port ID", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.TransitionVLAN(ctx, "", 1, 100)
		assert.Error(t, err)
	})

	t.Run("not initialized", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.TransitionVLAN(ctx, "eth0", 1, 100)
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = manager.TransitionVLAN(cancelCtx, "eth0", 1, 100)
		assert.Error(t, err)
	})
}

func TestFlowManager_Close(t *testing.T) {
	ctx := context.Background()

	t.Run("close initialized manager", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.Close()
		assert.NoError(t, err)

		// Second close should be no-op
		err = manager.Close()
		assert.NoError(t, err)
	})

	t.Run("close uninitialized manager", func(t *testing.T) {
		manager := NewFlowManager()
		err := manager.Close()
		assert.NoError(t, err)
	})

	t.Run("operations after close", func(t *testing.T) {
		manager := NewFlowManager()
		config := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, config)
		require.NoError(t, err)

		err = manager.Close()
		require.NoError(t, err)

		err = manager.InstallQuarantineRules(ctx, "eth0", 1)
		assert.Error(t, err)
	})
}

func TestGenerateRuleID(t *testing.T) {
	t.Run("generates unique IDs with no time between them", func(t *testing.T) {
		id1 := generateRuleID()
		id2 := generateRuleID()

		assert.NotEqual(t, id1, id2, "rule IDs must not depend on the clock advancing")
	})

	t.Run("generates a UUID", func(t *testing.T) {
		_, err := uuid.Parse(generateRuleID())
		assert.NoError(t, err)
	})
}

func TestFlowMatch(t *testing.T) {
	match := &FlowMatch{
		InPort:  1,
		EthSrc:  "00:11:22:33:44:55",
		EthDst:  "66:77:88:99:AA:BB",
		EthType: 0x0800,
		VLANID:  100,
		IPSrc:   "10.0.0.1/24",
		IPDst:   "192.168.1.0/24",
		IPProto: 6,
		SrcPort: 12345,
		DstPort: 80,
	}

	assert.Equal(t, uint32(1), match.InPort)
	assert.Equal(t, "00:11:22:33:44:55", match.EthSrc)
	assert.Equal(t, uint16(100), match.VLANID)
	assert.Equal(t, uint8(6), match.IPProto)
	assert.Equal(t, uint16(80), match.DstPort)
}

func TestFlowAction(t *testing.T) {
	tests := []struct {
		name   string
		action FlowAction
	}{
		{
			name: "output action",
			action: FlowAction{
				Type: FlowActionTypeOutput,
				Port: 2,
			},
		},
		{
			name: "drop action",
			action: FlowAction{
				Type: FlowActionTypeDrop,
			},
		},
		{
			name: "set VLAN action",
			action: FlowAction{
				Type: FlowActionTypeSetVLAN,
				VLAN: 100,
			},
		},
		{
			name: "set field action",
			action: FlowAction{
				Type:  FlowActionTypeSetField,
				Field: "eth_src",
				Value: "00:11:22:33:44:55",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.action.Type)
		})
	}
}

// mockFlowController implements FlowController for testing
type mockFlowController struct {
	addFlowCalled    bool
	deleteFlowCalled bool
	setVLANCalled    bool
	shouldFail       bool
}

func (m *mockFlowController) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	m.addFlowCalled = true
	if m.shouldFail {
		return ErrFlowRule{Operation: "AddFlow", Reason: "mock error"}
	}
	return nil
}

func (m *mockFlowController) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	m.deleteFlowCalled = true
	if m.shouldFail {
		return ErrFlowRule{Operation: "DeleteFlow", Reason: "mock error"}
	}
	return nil
}

func (m *mockFlowController) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowController) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowController) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	m.setVLANCalled = true
	if m.shouldFail {
		return ErrFlowRule{Operation: "SetPortVLAN", Reason: "mock error"}
	}
	return nil
}

func TestFlowManager_WithController(t *testing.T) {
	ctx := context.Background()
	controller := &mockFlowController{}

	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	t.Run("controller called on install", func(t *testing.T) {
		err := manager.InstallQuarantineRules(ctx, "eth0", 1)
		require.NoError(t, err)
		assert.True(t, controller.addFlowCalled)
		assert.True(t, controller.setVLANCalled)
	})
}

func TestFlowManager_WithControllerFailure(t *testing.T) {
	ctx := context.Background()
	controller := &mockFlowController{shouldFail: true}

	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	t.Run("controller failure returns error", func(t *testing.T) {
		rule := &FlowRule{ID: "rule-1", PortID: "eth0", Type: FlowRuleTypeDrop}
		err := manager.InstallRule(ctx, rule)
		assert.Error(t, err)
		assert.IsType(t, ErrFlowRule{}, err)
	})
}
