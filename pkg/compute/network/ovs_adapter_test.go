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
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ovsControllerInterface defines the methods used by OVSFlowControllerAdapter.
// This interface matches the methods of *policy.OVSFlowController used by the adapter.
type ovsControllerInterface interface {
	InstallFlow(bridgeName string, priority int, match string, actions string) error
	DeleteFlow(bridgeName string, match string) error
	ListFlows(bridgeName string) ([]string, error)
	SetPortVLAN(ctx context.Context, portName string, vlan int64) error
}

// mockOVSController is a mock implementation of the OVS controller interface.
type mockOVSController struct {
	installFlowCalled   bool
	installFlowBridge   string
	installFlowPriority int
	installFlowMatch    string
	installFlowActions  string
	installFlowErr      error

	deleteFlowCalled bool
	deleteFlowBridge string
	deleteFlowMatch  string
	deleteFlowErr    error

	listFlowsCalled bool
	listFlowsBridge string
	listFlowsResult []string
	listFlowsErr    error

	setPortVLANCalled bool
	setPortVLANPort   string
	setPortVLANValue  int64
	setPortVLANErr    error
}

func (m *mockOVSController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	m.installFlowCalled = true
	m.installFlowBridge = bridgeName
	m.installFlowPriority = priority
	m.installFlowMatch = match
	m.installFlowActions = actions
	return m.installFlowErr
}

func (m *mockOVSController) DeleteFlow(bridgeName string, match string) error {
	m.deleteFlowCalled = true
	m.deleteFlowBridge = bridgeName
	m.deleteFlowMatch = match
	return m.deleteFlowErr
}

func (m *mockOVSController) ListFlows(bridgeName string) ([]string, error) {
	m.listFlowsCalled = true
	m.listFlowsBridge = bridgeName
	return m.listFlowsResult, m.listFlowsErr
}

func (m *mockOVSController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	m.setPortVLANCalled = true
	m.setPortVLANPort = portName
	m.setPortVLANValue = vlan
	return m.setPortVLANErr
}

// testableOVSAdapter is a test version of OVSFlowControllerAdapter that uses an interface
// for the controller, allowing us to inject mocks for testing.
type testableOVSAdapter struct {
	controller ovsControllerInterface
	ruleIndex  sync.Map
	logger     *slog.Logger
}

// newTestableAdapter creates a testable adapter with a mock controller.
func newTestableAdapter(mock *mockOVSController) *testableOVSAdapter {
	return &testableOVSAdapter{
		controller: mock,
		logger:     slog.Default(),
	}
}

// AddFlow implements the same logic as OVSFlowControllerAdapter.AddFlow.
func (a *testableOVSAdapter) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "AddFlow"}
	default:
	}

	if rule == nil {
		return ErrInvalidConfig{Field: "rule", Reason: "rule cannot be nil"}
	}

	if rule.ID == "" {
		return ErrInvalidConfig{Field: "ID", Reason: "rule ID cannot be empty"}
	}

	matchStr := a.buildMatchString(rule)
	actionsStr := a.buildActionsString(rule)

	if err := a.controller.InstallFlow(bridge, int(rule.Priority), matchStr, actionsStr); err != nil {
		return ErrFlowRule{
			PortID:    rule.PortID,
			RuleID:    rule.ID,
			Operation: "AddFlow",
			Reason:    "failed to install flow",
			Cause:     err,
		}
	}

	a.ruleIndex.Store(rule.ID, matchStr)

	a.logger.Debug("added flow rule",
		"rule_id", rule.ID,
		"port_id", rule.PortID,
		"bridge", bridge,
		"match", matchStr,
		"actions", actionsStr,
	)

	return nil
}

// DeleteFlow implements the same logic as OVSFlowControllerAdapter.DeleteFlow.
func (a *testableOVSAdapter) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "DeleteFlow"}
	default:
	}

	if ruleID == "" {
		return ErrInvalidConfig{Field: "ruleID", Reason: "rule ID cannot be empty"}
	}

	matchVal, ok := a.ruleIndex.Load(ruleID)
	if !ok {
		return nil
	}

	matchStr := matchVal.(string)

	if err := a.controller.DeleteFlow(bridge, matchStr); err != nil {
		return ErrFlowRule{
			RuleID:    ruleID,
			Operation: "DeleteFlow",
			Reason:    "failed to delete flow",
			Cause:     err,
		}
	}

	a.ruleIndex.Delete(ruleID)

	a.logger.Debug("deleted flow rule",
		"rule_id", ruleID,
		"bridge", bridge,
	)

	return nil
}

// ModifyFlow implements the same logic as OVSFlowControllerAdapter.ModifyFlow.
func (a *testableOVSAdapter) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "ModifyFlow"}
	default:
	}

	if rule == nil {
		return ErrInvalidConfig{Field: "rule", Reason: "rule cannot be nil"}
	}

	if err := a.DeleteFlow(ctx, bridge, rule.ID); err != nil {
		a.logger.Debug("delete during modify failed (may not exist)",
			"rule_id", rule.ID,
			"error", err,
		)
	}

	return a.AddFlow(ctx, bridge, rule)
}

// GetFlows implements the same logic as OVSFlowControllerAdapter.GetFlows.
func (a *testableOVSAdapter) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetFlows"}
	default:
	}

	flowStrings, err := a.controller.ListFlows(bridge)
	if err != nil {
		return nil, ErrFlowRule{
			Operation: "GetFlows",
			Reason:    "failed to list flows",
			Cause:     err,
		}
	}

	rules := make([]*FlowRule, 0, len(flowStrings))
	for _, flowStr := range flowStrings {
		rule := a.parseFlowString(flowStr)
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// SetPortVLAN implements the same logic as OVSFlowControllerAdapter.SetPortVLAN.
func (a *testableOVSAdapter) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "SetPortVLAN"}
	default:
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	if err := a.controller.SetPortVLAN(ctx, portID, int64(vlan)); err != nil {
		return ErrVLANFailed{
			PortID: portID,
			ToVLAN: vlan,
			Reason: "failed to set port VLAN",
			Cause:  err,
		}
	}

	a.logger.Debug("set port VLAN",
		"port_id", portID,
		"vlan", vlan,
	)

	return nil
}

// buildMatchString mirrors OVSFlowControllerAdapter.buildMatchString.
func (a *testableOVSAdapter) buildMatchString(rule *FlowRule) string {
	adapter := &OVSFlowControllerAdapter{}
	return adapter.buildMatchString(rule)
}

// buildActionsString mirrors OVSFlowControllerAdapter.buildActionsString.
func (a *testableOVSAdapter) buildActionsString(rule *FlowRule) string {
	adapter := &OVSFlowControllerAdapter{}
	return adapter.buildActionsString(rule)
}

// parseFlowString mirrors OVSFlowControllerAdapter.parseFlowString.
func (a *testableOVSAdapter) parseFlowString(flowStr string) *FlowRule {
	adapter := &OVSFlowControllerAdapter{}
	return adapter.parseFlowString(flowStr)
}

// Ensure testableOVSAdapter implements FlowController.
var _ FlowController = (*testableOVSAdapter)(nil)

// TestNewOVSFlowControllerAdapter_NilController tests constructor with nil controller.
func TestNewOVSFlowControllerAdapter_NilController(t *testing.T) {
	adapter, err := NewOVSFlowControllerAdapter(nil)
	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.IsType(t, ErrInvalidConfig{}, err)

	configErr := err.(ErrInvalidConfig)
	assert.Equal(t, "controller", configErr.Field)
	assert.Contains(t, configErr.Reason, "nil")
}

// TestWithOVSAdapterLogger tests the logger option function.
func TestWithOVSAdapterLogger(t *testing.T) {
	t.Run("sets logger on adapter", func(t *testing.T) {
		customLogger := slog.Default().With("component", "test")
		opt := WithOVSAdapterLogger(customLogger)

		adapter := &OVSFlowControllerAdapter{}
		opt(adapter)

		assert.Equal(t, customLogger, adapter.logger)
	})

	t.Run("option function is not nil", func(t *testing.T) {
		logger := slog.Default()
		opt := WithOVSAdapterLogger(logger)
		assert.NotNil(t, opt)
	})
}

// TestOVSFlowControllerAdapter_AddFlow tests the AddFlow method.
func TestOVSFlowControllerAdapter_AddFlow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:       "test-rule-1",
			PortID:   "eth0",
			Priority: 100,
			Match: &FlowMatch{
				InPort:  1,
				EthSrc:  "00:11:22:33:44:55",
				IPSrc:   "10.0.0.1/32",
				IPProto: 6,
				DstPort: 80,
			},
			Actions: []FlowAction{
				{Type: FlowActionTypeOutput, Port: 2},
			},
		}

		err := adapter.AddFlow(ctx, "br0", rule)
		require.NoError(t, err)

		assert.True(t, mock.installFlowCalled)
		assert.Equal(t, "br0", mock.installFlowBridge)
		assert.Equal(t, 100, mock.installFlowPriority)

		matchVal, ok := adapter.ruleIndex.Load(rule.ID)
		require.True(t, ok)
		assert.NotEmpty(t, matchVal.(string))
	})

	t.Run("nil rule", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.AddFlow(ctx, "br0", nil)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "rule", configErr.Field)
	})

	t.Run("empty rule ID", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:     "",
			PortID: "eth0",
		}

		err := adapter.AddFlow(ctx, "br0", rule)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "ID", configErr.Field)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rule := &FlowRule{
			ID:     "test-rule",
			PortID: "eth0",
		}

		err := adapter.AddFlow(ctx, "br0", rule)
		require.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "AddFlow", cancelErr.Operation)
	})

	t.Run("controller error", func(t *testing.T) {
		mock := &mockOVSController{
			installFlowErr: errors.New("install failed"),
		}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:     "test-rule",
			PortID: "eth0",
		}

		err := adapter.AddFlow(ctx, "br0", rule)
		require.Error(t, err)
		assert.IsType(t, ErrFlowRule{}, err)

		flowErr := err.(ErrFlowRule)
		assert.Equal(t, "AddFlow", flowErr.Operation)
		assert.Equal(t, "eth0", flowErr.PortID)
		assert.Equal(t, "test-rule", flowErr.RuleID)
	})
}

// TestOVSFlowControllerAdapter_DeleteFlow tests the DeleteFlow method.
func TestOVSFlowControllerAdapter_DeleteFlow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:     "test-rule-delete",
			PortID: "eth0",
		}
		err := adapter.AddFlow(ctx, "br0", rule)
		require.NoError(t, err)

		_, ok := adapter.ruleIndex.Load(rule.ID)
		require.True(t, ok)

		err = adapter.DeleteFlow(ctx, "br0", rule.ID)
		require.NoError(t, err)

		_, ok = adapter.ruleIndex.Load(rule.ID)
		assert.False(t, ok)
	})

	t.Run("not found should not error", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.DeleteFlow(ctx, "br0", "non-existent-rule")
		require.NoError(t, err)
	})

	t.Run("empty rule ID", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.DeleteFlow(ctx, "br0", "")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "ruleID", configErr.Field)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := adapter.DeleteFlow(ctx, "br0", "test-rule")
		require.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "DeleteFlow", cancelErr.Operation)
	})

	t.Run("controller error", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:     "test-rule-fail",
			PortID: "eth0",
		}
		err := adapter.AddFlow(ctx, "br0", rule)
		require.NoError(t, err)

		mock.deleteFlowErr = errors.New("delete failed")

		err = adapter.DeleteFlow(ctx, "br0", rule.ID)
		require.Error(t, err)
		assert.IsType(t, ErrFlowRule{}, err)

		flowErr := err.(ErrFlowRule)
		assert.Equal(t, "DeleteFlow", flowErr.Operation)
	})
}

// TestOVSFlowControllerAdapter_ModifyFlow tests the ModifyFlow method.
func TestOVSFlowControllerAdapter_ModifyFlow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:       "test-rule-modify",
			PortID:   "eth0",
			Priority: 100,
		}
		err := adapter.AddFlow(ctx, "br0", rule)
		require.NoError(t, err)

		rule.Priority = 200
		err = adapter.ModifyFlow(ctx, "br0", rule)
		require.NoError(t, err)

		_, ok := adapter.ruleIndex.Load(rule.ID)
		assert.True(t, ok)
	})

	t.Run("nil rule", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.ModifyFlow(ctx, "br0", nil)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rule := &FlowRule{
			ID:     "test-rule",
			PortID: "eth0",
		}

		err := adapter.ModifyFlow(ctx, "br0", rule)
		require.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "ModifyFlow", cancelErr.Operation)
	})

	t.Run("modify non-existent rule succeeds", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rule := &FlowRule{
			ID:     "new-rule",
			PortID: "eth0",
		}

		err := adapter.ModifyFlow(ctx, "br0", rule)
		require.NoError(t, err)

		_, ok := adapter.ruleIndex.Load(rule.ID)
		assert.True(t, ok)
	})
}

// TestOVSFlowControllerAdapter_GetFlows tests the GetFlows method.
func TestOVSFlowControllerAdapter_GetFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockOVSController{
			listFlowsResult: []string{
				"priority=100,in_port=1,dl_src=00:11:22:33:44:55,nw_src=10.0.0.1,nw_dst=10.0.0.2",
				"priority=200,dl_vlan=100,nw_proto=6,tp_src=12345,tp_dst=80",
			},
		}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rules, err := adapter.GetFlows(ctx, "br0")
		require.NoError(t, err)
		assert.Len(t, rules, 2)

		assert.Equal(t, uint16(100), rules[0].Priority)
		assert.Equal(t, uint32(1), rules[0].Match.InPort)
		assert.Equal(t, "00:11:22:33:44:55", rules[0].Match.EthSrc)
		assert.Equal(t, "10.0.0.1", rules[0].Match.IPSrc)
		assert.Equal(t, "10.0.0.2", rules[0].Match.IPDst)

		assert.Equal(t, uint16(200), rules[1].Priority)
		assert.Equal(t, uint16(100), rules[1].Match.VLANID)
		assert.Equal(t, uint8(6), rules[1].Match.IPProto)
		assert.Equal(t, uint16(12345), rules[1].Match.SrcPort)
		assert.Equal(t, uint16(80), rules[1].Match.DstPort)
	})

	t.Run("empty result", func(t *testing.T) {
		mock := &mockOVSController{
			listFlowsResult: []string{},
		}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rules, err := adapter.GetFlows(ctx, "br0")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("controller error", func(t *testing.T) {
		mock := &mockOVSController{
			listFlowsErr: errors.New("list failed"),
		}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		rules, err := adapter.GetFlows(ctx, "br0")
		require.Error(t, err)
		assert.Nil(t, rules)
		assert.IsType(t, ErrFlowRule{}, err)

		flowErr := err.(ErrFlowRule)
		assert.Equal(t, "GetFlows", flowErr.Operation)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rules, err := adapter.GetFlows(ctx, "br0")
		require.Error(t, err)
		assert.Nil(t, rules)
		assert.IsType(t, ErrContextCanceled{}, err)
	})
}

// TestOVSFlowControllerAdapter_SetPortVLAN tests the SetPortVLAN method.
func TestOVSFlowControllerAdapter_SetPortVLAN(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.SetPortVLAN(ctx, "br0", "eth0", 100)
		require.NoError(t, err)

		assert.True(t, mock.setPortVLANCalled)
		assert.Equal(t, "eth0", mock.setPortVLANPort)
		assert.Equal(t, int64(100), mock.setPortVLANValue)
	})

	t.Run("empty port ID", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.SetPortVLAN(ctx, "br0", "", 100)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "portID", configErr.Field)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mock := &mockOVSController{}
		adapter := newTestableAdapter(mock)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := adapter.SetPortVLAN(ctx, "br0", "eth0", 100)
		require.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "SetPortVLAN", cancelErr.Operation)
	})

	t.Run("controller error", func(t *testing.T) {
		mock := &mockOVSController{
			setPortVLANErr: errors.New("set vlan failed"),
		}
		adapter := newTestableAdapter(mock)
		ctx := context.Background()

		err := adapter.SetPortVLAN(ctx, "br0", "eth0", 100)
		require.Error(t, err)
		assert.IsType(t, ErrVLANFailed{}, err)

		vlanErr := err.(ErrVLANFailed)
		assert.Equal(t, "eth0", vlanErr.PortID)
		assert.Equal(t, uint16(100), vlanErr.ToVLAN)
	})
}

// TestOVSFlowControllerAdapter_buildMatchString tests the buildMatchString helper.
func TestOVSFlowControllerAdapter_buildMatchString(t *testing.T) {
	adapter := &OVSFlowControllerAdapter{}

	t.Run("nil match", func(t *testing.T) {
		rule := &FlowRule{Match: nil}
		result := adapter.buildMatchString(rule)
		assert.Empty(t, result)
	})

	t.Run("empty match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{}}
		result := adapter.buildMatchString(rule)
		assert.Empty(t, result)
	})

	t.Run("in_port only", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{InPort: 1}}
		result := adapter.buildMatchString(rule)
		assert.Equal(t, "in_port=1", result)
	})

	t.Run("ethernet match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{
			EthSrc:  "00:11:22:33:44:55",
			EthDst:  "66:77:88:99:aa:bb",
			EthType: 0x0800,
		}}
		result := adapter.buildMatchString(rule)
		assert.Contains(t, result, "dl_src=00:11:22:33:44:55")
		assert.Contains(t, result, "dl_dst=66:77:88:99:aa:bb")
		assert.Contains(t, result, "dl_type=0x0800")
	})

	t.Run("VLAN match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{VLANID: 100}}
		result := adapter.buildMatchString(rule)
		assert.Equal(t, "dl_vlan=100", result)
	})

	t.Run("IP match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{
			IPSrc:   "10.0.0.1/24",
			IPDst:   "192.168.1.0/24",
			IPProto: 6,
		}}
		result := adapter.buildMatchString(rule)
		assert.Contains(t, result, "nw_src=10.0.0.1/24")
		assert.Contains(t, result, "nw_dst=192.168.1.0/24")
		assert.Contains(t, result, "nw_proto=6")
	})

	t.Run("TCP UDP port match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{
			SrcPort: 12345,
			DstPort: 80,
		}}
		result := adapter.buildMatchString(rule)
		assert.Contains(t, result, "tp_src=12345")
		assert.Contains(t, result, "tp_dst=80")
	})

	t.Run("full match", func(t *testing.T) {
		rule := &FlowRule{Match: &FlowMatch{
			InPort:  1,
			EthSrc:  "00:11:22:33:44:55",
			EthDst:  "66:77:88:99:aa:bb",
			EthType: 0x0800,
			VLANID:  100,
			IPSrc:   "10.0.0.1/32",
			IPDst:   "10.0.0.2/32",
			IPProto: 6,
			SrcPort: 12345,
			DstPort: 443,
		}}
		result := adapter.buildMatchString(rule)

		assert.Contains(t, result, "in_port=1")
		assert.Contains(t, result, "dl_src=00:11:22:33:44:55")
		assert.Contains(t, result, "dl_dst=66:77:88:99:aa:bb")
		assert.Contains(t, result, "dl_type=0x0800")
		assert.Contains(t, result, "dl_vlan=100")
		assert.Contains(t, result, "nw_src=10.0.0.1/32")
		assert.Contains(t, result, "nw_dst=10.0.0.2/32")
		assert.Contains(t, result, "nw_proto=6")
		assert.Contains(t, result, "tp_src=12345")
		assert.Contains(t, result, "tp_dst=443")
	})
}

// TestOVSFlowControllerAdapter_buildActionsString tests the buildActionsString helper.
func TestOVSFlowControllerAdapter_buildActionsString(t *testing.T) {
	adapter := &OVSFlowControllerAdapter{}

	t.Run("no actions returns drop", func(t *testing.T) {
		rule := &FlowRule{Actions: nil}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "drop", result)
	})

	t.Run("empty actions returns drop", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "drop", result)
	})

	t.Run("output action with port", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeOutput, Port: 2},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "output:2", result)
	})

	t.Run("output action without port", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeOutput, Port: 0},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "normal", result)
	})

	t.Run("drop action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeDrop},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "drop", result)
	})

	t.Run("set VLAN action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: 100},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "mod_vlan_vid:100", result)
	})

	t.Run("strip VLAN action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeStripVLAN},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "strip_vlan", result)
	})

	t.Run("set field action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeSetField, Field: "eth_src", Value: "00:11:22:33:44:55"},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "set_field:00:11:22:33:44:55->eth_src", result)
	})

	t.Run("controller action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeController},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "controller", result)
	})

	t.Run("flood action", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeFlood},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "flood", result)
	})

	t.Run("multiple actions", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: 100},
			{Type: FlowActionTypeOutput, Port: 2},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "mod_vlan_vid:100,output:2", result)
	})

	t.Run("unknown action type returns normal", func(t *testing.T) {
		rule := &FlowRule{Actions: []FlowAction{
			{Type: FlowActionType("unknown")},
		}}
		result := adapter.buildActionsString(rule)
		assert.Equal(t, "normal", result)
	})
}

// TestOVSFlowControllerAdapter_parseFlowString tests the parseFlowString helper.
func TestOVSFlowControllerAdapter_parseFlowString(t *testing.T) {
	adapter := &OVSFlowControllerAdapter{}

	t.Run("empty string", func(t *testing.T) {
		rule := adapter.parseFlowString("")
		require.NotNil(t, rule)
		assert.NotNil(t, rule.Match)
		assert.NotNil(t, rule.Metadata)
	})

	t.Run("priority only", func(t *testing.T) {
		rule := adapter.parseFlowString("priority=100")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(100), rule.Priority)
	})

	t.Run("in_port", func(t *testing.T) {
		rule := adapter.parseFlowString("in_port=1")
		require.NotNil(t, rule)
		assert.Equal(t, uint32(1), rule.Match.InPort)
	})

	t.Run("dl_vlan", func(t *testing.T) {
		rule := adapter.parseFlowString("dl_vlan=100")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(100), rule.Match.VLANID)
		assert.Equal(t, uint16(100), rule.VLAN)
	})

	t.Run("ethernet addresses", func(t *testing.T) {
		rule := adapter.parseFlowString("dl_src=00:11:22:33:44:55,dl_dst=66:77:88:99:aa:bb")
		require.NotNil(t, rule)
		assert.Equal(t, "00:11:22:33:44:55", rule.Match.EthSrc)
		assert.Equal(t, "66:77:88:99:aa:bb", rule.Match.EthDst)
	})

	t.Run("IP addresses", func(t *testing.T) {
		rule := adapter.parseFlowString("nw_src=10.0.0.1/24,nw_dst=192.168.1.0/24")
		require.NotNil(t, rule)
		assert.Equal(t, "10.0.0.1/24", rule.Match.IPSrc)
		assert.Equal(t, "192.168.1.0/24", rule.Match.IPDst)
	})

	t.Run("IP protocol", func(t *testing.T) {
		rule := adapter.parseFlowString("nw_proto=6")
		require.NotNil(t, rule)
		assert.Equal(t, uint8(6), rule.Match.IPProto)
	})

	t.Run("TCP UDP ports", func(t *testing.T) {
		rule := adapter.parseFlowString("tp_src=12345,tp_dst=80")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(12345), rule.Match.SrcPort)
		assert.Equal(t, uint16(80), rule.Match.DstPort)
	})

	t.Run("full flow string", func(t *testing.T) {
		flowStr := "priority=200,in_port=1,dl_vlan=100,dl_src=00:11:22:33:44:55,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_proto=6,tp_src=12345,tp_dst=443"
		rule := adapter.parseFlowString(flowStr)
		require.NotNil(t, rule)

		assert.Equal(t, uint16(200), rule.Priority)
		assert.Equal(t, uint32(1), rule.Match.InPort)
		assert.Equal(t, uint16(100), rule.Match.VLANID)
		assert.Equal(t, "00:11:22:33:44:55", rule.Match.EthSrc)
		assert.Equal(t, "10.0.0.1", rule.Match.IPSrc)
		assert.Equal(t, "10.0.0.2", rule.Match.IPDst)
		assert.Equal(t, uint8(6), rule.Match.IPProto)
		assert.Equal(t, uint16(12345), rule.Match.SrcPort)
		assert.Equal(t, uint16(443), rule.Match.DstPort)
	})

	t.Run("with whitespace", func(t *testing.T) {
		rule := adapter.parseFlowString(" priority = 100 , in_port = 1 ")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(100), rule.Priority)
		assert.Equal(t, uint32(1), rule.Match.InPort)
	})

	t.Run("invalid numeric values are ignored", func(t *testing.T) {
		rule := adapter.parseFlowString("priority=invalid,in_port=abc")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(0), rule.Priority)
		assert.Equal(t, uint32(0), rule.Match.InPort)
	})

	t.Run("parts without equals are ignored", func(t *testing.T) {
		rule := adapter.parseFlowString("priority=100,actions,drop")
		require.NotNil(t, rule)
		assert.Equal(t, uint16(100), rule.Priority)
	})
}

// TestOVSFlowControllerAdapter_InterfaceCompliance verifies the adapter implements FlowController.
func TestOVSFlowControllerAdapter_InterfaceCompliance(t *testing.T) {
	var _ FlowController = (*OVSFlowControllerAdapter)(nil)
}

// TestOVSFlowControllerAdapter_ConcurrentAccess tests concurrent access to the adapter.
func TestOVSFlowControllerAdapter_ConcurrentAccess(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				rule := &FlowRule{
					ID:     generateRuleID("eth0", "test", string(rune(id))+string(rune(j))),
					PortID: "eth0",
				}
				_ = adapter.AddFlow(ctx, "br0", rule)
				_ = adapter.DeleteFlow(ctx, "br0", rule.ID)
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestOVSFlowControllerAdapter_AddFlow_MatchBuilding verifies match string is built correctly.
func TestOVSFlowControllerAdapter_AddFlow_MatchBuilding(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rule := &FlowRule{
		ID:       "match-test-rule",
		PortID:   "eth0",
		Priority: 150,
		Match: &FlowMatch{
			InPort:  3,
			VLANID:  200,
			IPSrc:   "192.168.1.0/24",
			DstPort: 8080,
		},
		Actions: []FlowAction{
			{Type: FlowActionTypeOutput, Port: 4},
		},
	}

	err := adapter.AddFlow(ctx, "br0", rule)
	require.NoError(t, err)

	assert.True(t, mock.installFlowCalled)
	assert.Equal(t, "br0", mock.installFlowBridge)
	assert.Equal(t, 150, mock.installFlowPriority)
	assert.Contains(t, mock.installFlowMatch, "in_port=3")
	assert.Contains(t, mock.installFlowMatch, "dl_vlan=200")
	assert.Contains(t, mock.installFlowMatch, "nw_src=192.168.1.0/24")
	assert.Contains(t, mock.installFlowMatch, "tp_dst=8080")
	assert.Equal(t, "output:4", mock.installFlowActions)
}

// TestOVSFlowControllerAdapter_DeleteFlow_MatchLookup verifies the match string is looked up.
func TestOVSFlowControllerAdapter_DeleteFlow_MatchLookup(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rule := &FlowRule{
		ID:     "lookup-test-rule",
		PortID: "eth0",
		Match: &FlowMatch{
			InPort: 5,
		},
	}

	err := adapter.AddFlow(ctx, "br0", rule)
	require.NoError(t, err)

	mock.deleteFlowCalled = false

	err = adapter.DeleteFlow(ctx, "br0", rule.ID)
	require.NoError(t, err)

	assert.True(t, mock.deleteFlowCalled)
	assert.Equal(t, "br0", mock.deleteFlowBridge)
	assert.Contains(t, mock.deleteFlowMatch, "in_port=5")
}

// TestOVSFlowControllerAdapter_RuleIndexTracking tests that rules are properly tracked.
func TestOVSFlowControllerAdapter_RuleIndexTracking(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rules := []*FlowRule{
		{ID: "rule-1", PortID: "eth0", Match: &FlowMatch{InPort: 1}},
		{ID: "rule-2", PortID: "eth0", Match: &FlowMatch{InPort: 2}},
		{ID: "rule-3", PortID: "eth1", Match: &FlowMatch{InPort: 3}},
	}

	for _, rule := range rules {
		err := adapter.AddFlow(ctx, "br0", rule)
		require.NoError(t, err)
	}

	for _, rule := range rules {
		_, ok := adapter.ruleIndex.Load(rule.ID)
		assert.True(t, ok, "rule %s should be tracked", rule.ID)
	}

	err := adapter.DeleteFlow(ctx, "br0", "rule-2")
	require.NoError(t, err)

	_, ok := adapter.ruleIndex.Load("rule-1")
	assert.True(t, ok)
	_, ok = adapter.ruleIndex.Load("rule-2")
	assert.False(t, ok)
	_, ok = adapter.ruleIndex.Load("rule-3")
	assert.True(t, ok)
}

// TestOVSFlowControllerAdapter_GetFlows_ParseErrors tests handling of parse errors.
func TestOVSFlowControllerAdapter_GetFlows_ParseErrors(t *testing.T) {
	mock := &mockOVSController{
		listFlowsResult: []string{
			"priority=100,in_port=1",
			"invalid-format-no-equals",
			"priority=abc",
			"priority=200,nw_proto=6",
			"",
			"key_without_value=",
			"   ",
			"priority=300,tp_dst=invalid_port",
		},
	}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rules, err := adapter.GetFlows(ctx, "br0")
	require.NoError(t, err)

	assert.Len(t, rules, len(mock.listFlowsResult))

	assert.Equal(t, uint16(100), rules[0].Priority)
	assert.Equal(t, uint32(1), rules[0].Match.InPort)
	assert.Equal(t, uint16(200), rules[3].Priority)
	assert.Equal(t, uint8(6), rules[3].Match.IPProto)
}

// TestOVSFlowControllerAdapter_ModifyFlow_DeleteError tests modify continues on delete error.
func TestOVSFlowControllerAdapter_ModifyFlow_DeleteError(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rule := &FlowRule{
		ID:     "modify-delete-error",
		PortID: "eth0",
	}
	err := adapter.AddFlow(ctx, "br0", rule)
	require.NoError(t, err)

	mock.deleteFlowErr = errors.New("delete failed")

	rule.Priority = 300
	err = adapter.ModifyFlow(ctx, "br0", rule)
	require.NoError(t, err)
}

// TestOVSFlowControllerAdapter_AddFlow_NilMatch tests adding flow with nil match.
func TestOVSFlowControllerAdapter_AddFlow_NilMatch(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	rule := &FlowRule{
		ID:     "nil-match-rule",
		PortID: "eth0",
		Match:  nil,
		Actions: []FlowAction{
			{Type: FlowActionTypeDrop},
		},
	}

	err := adapter.AddFlow(ctx, "br0", rule)
	require.NoError(t, err)

	assert.Empty(t, mock.installFlowMatch)
	assert.Equal(t, "drop", mock.installFlowActions)
}

// TestOVSFlowControllerAdapter_AddFlow_AllActions tests all action types.
func TestOVSFlowControllerAdapter_AddFlow_AllActions(t *testing.T) {
	tests := []struct {
		name            string
		actions         []FlowAction
		expectedActions string
	}{
		{
			name:            "output with port",
			actions:         []FlowAction{{Type: FlowActionTypeOutput, Port: 5}},
			expectedActions: "output:5",
		},
		{
			name:            "output without port",
			actions:         []FlowAction{{Type: FlowActionTypeOutput}},
			expectedActions: "normal",
		},
		{
			name:            "drop",
			actions:         []FlowAction{{Type: FlowActionTypeDrop}},
			expectedActions: "drop",
		},
		{
			name:            "set vlan",
			actions:         []FlowAction{{Type: FlowActionTypeSetVLAN, VLAN: 200}},
			expectedActions: "mod_vlan_vid:200",
		},
		{
			name:            "strip vlan",
			actions:         []FlowAction{{Type: FlowActionTypeStripVLAN}},
			expectedActions: "strip_vlan",
		},
		{
			name:            "controller",
			actions:         []FlowAction{{Type: FlowActionTypeController}},
			expectedActions: "controller",
		},
		{
			name:            "flood",
			actions:         []FlowAction{{Type: FlowActionTypeFlood}},
			expectedActions: "flood",
		},
		{
			name:            "set field",
			actions:         []FlowAction{{Type: FlowActionTypeSetField, Field: "eth_dst", Value: "ff:ff:ff:ff:ff:ff"}},
			expectedActions: "set_field:ff:ff:ff:ff:ff:ff->eth_dst",
		},
		{
			name: "chain of actions",
			actions: []FlowAction{
				{Type: FlowActionTypeStripVLAN},
				{Type: FlowActionTypeSetVLAN, VLAN: 50},
				{Type: FlowActionTypeOutput, Port: 10},
			},
			expectedActions: "strip_vlan,mod_vlan_vid:50,output:10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockOVSController{}
			adapter := newTestableAdapter(mock)
			ctx := context.Background()

			rule := &FlowRule{
				ID:      "action-test-" + tt.name,
				PortID:  "eth0",
				Actions: tt.actions,
			}

			err := adapter.AddFlow(ctx, "br0", rule)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedActions, mock.installFlowActions)
		})
	}
}

// TestOVSFlowControllerAdapter_SetPortVLAN_ZeroVLAN tests setting VLAN to zero.
func TestOVSFlowControllerAdapter_SetPortVLAN_ZeroVLAN(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	err := adapter.SetPortVLAN(ctx, "br0", "eth0", 0)
	require.NoError(t, err)

	assert.True(t, mock.setPortVLANCalled)
	assert.Equal(t, int64(0), mock.setPortVLANValue)
}

// TestOVSFlowControllerAdapter_SetPortVLAN_MaxVLAN tests setting maximum VLAN value.
func TestOVSFlowControllerAdapter_SetPortVLAN_MaxVLAN(t *testing.T) {
	mock := &mockOVSController{}
	adapter := newTestableAdapter(mock)
	ctx := context.Background()

	err := adapter.SetPortVLAN(ctx, "br0", "eth0", 4095)
	require.NoError(t, err)

	assert.True(t, mock.setPortVLANCalled)
	assert.Equal(t, int64(4095), mock.setPortVLANValue)
}
