package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/require"
)

// ofPortController is a port controller whose ports have OpenFlow numbers
// distinct from their names, as on a real switch.
type ofPortController struct {
	mu        sync.Mutex
	ofPorts   map[string]int32
	ofPortErr error
	deleted   []string
	vlanPorts []string
	trunks    []string
	installed []zoneflows.FlowRule
}

func (c *ofPortController) InstallFlow(string, int, string, string) error { return nil }

func (c *ofPortController) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installed = append(c.installed, rules...)
	return nil
}

func (c *ofPortController) DeleteFlow(string, string) error { return nil }

func (c *ofPortController) DeleteFlowsByPort(_ string, portID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleted = append(c.deleted, portID)
	return nil
}

func (c *ofPortController) ListFlows(string) ([]string, error) { return nil, nil }

func (c *ofPortController) SetPortVLAN(_ context.Context, portName string, _ int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vlanPorts = append(c.vlanPorts, portName)
	return nil
}

func (c *ofPortController) SetPortTrunk(_ context.Context, portName string, _ []uint16, _ uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trunks = append(c.trunks, portName)
	return nil
}

func (c *ofPortController) SetPortState(context.Context, string, ovs.PortState) error { return nil }

func (c *ofPortController) GetOFPort(_ context.Context, portName string) (int32, error) {
	if c.ofPortErr != nil {
		return 0, c.ofPortErr
	}
	n, ok := c.ofPorts[portName]
	if !ok {
		return -1, nil
	}
	return n, nil
}

func newOFPortZFM(t *testing.T, ctrl *ofPortController) *ZoneFlowManager {
	t.Helper()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	return m
}

// assertPortRules checks every installed rule that names an input port
// names OpenFlow port 7 and never the interface name.
func assertPortRules(t *testing.T, rules []zoneflows.FlowRule) {
	t.Helper()
	require.NotEmpty(t, rules)
	var portRules int
	for _, r := range rules {
		require.NotContains(t, r.Match, "in_port=tap0", "rule %q", r.Match)
		if strings.Contains(r.Match, "in_port=") {
			require.Contains(t, r.Match, "in_port=7", "rule %q", r.Match)
			portRules++
		}
	}
	require.NotZero(t, portRules)
}

func TestZoneFlowManager_ApplyZoneFlows_UsesOpenFlowPortNumber(t *testing.T) {
	for _, z := range []zone.Zone{zone.ZoneQuarantine, zone.ZoneProvisioning, zone.ZoneControlPlane} {
		t.Run(string(z), func(t *testing.T) {
			ctrl := &ofPortController{ofPorts: map[string]int32{"tap0": 7}}
			m := newOFPortZFM(t, ctrl)

			require.NoError(t, m.ApplyZoneFlows(context.Background(), "tap0", z))

			require.Equal(t, []string{"7"}, ctrl.deleted)
			require.Equal(t, []string{"tap0"}, ctrl.vlanPorts)
			assertPortRules(t, ctrl.installed)
			got, err := m.GetPortZone("tap0")
			require.NoError(t, err)
			require.Equal(t, z, got)
		})
	}
}

func TestZoneFlowManager_ApplyPortClassFlows_UsesOpenFlowPortNumber(t *testing.T) {
	ctrl := &ofPortController{ofPorts: map[string]int32{"tap0": 7}}
	m := newOFPortZFM(t, ctrl)

	require.NoError(t, m.ApplyPortClassFlows(context.Background(), "tap0", zone.PortClassHypervisor))

	require.Equal(t, []string{"7"}, ctrl.deleted)
	require.Equal(t, []string{"tap0"}, ctrl.trunks)
	assertPortRules(t, ctrl.installed)
}

func TestZoneFlowManager_RemoveFlows_UsesOpenFlowPortNumber(t *testing.T) {
	ctrl := &ofPortController{ofPorts: map[string]int32{"tap0": 7}}
	m := newOFPortZFM(t, ctrl)
	require.NoError(t, m.ApplyZoneFlows(context.Background(), "tap0", zone.ZoneQuarantine))
	ctrl.deleted = nil

	require.NoError(t, m.RemoveFlows("tap0"))

	require.Equal(t, []string{"7"}, ctrl.deleted)
	_, err := m.GetPortZone("tap0")
	require.Error(t, err)
}

func TestZoneFlowManager_NoOpenFlowPort_Errors(t *testing.T) {
	lookupErr := errors.New("no such interface")
	cases := map[string]*ofPortController{
		"lookup error": {ofPortErr: lookupErr},
		"unassigned":   {ofPorts: map[string]int32{}},
		"zero":         {ofPorts: map[string]int32{"tap0": 0}},
	}
	for name, ctrl := range cases {
		t.Run(name, func(t *testing.T) {
			m := newOFPortZFM(t, ctrl)
			ctx := context.Background()

			require.Error(t, m.ApplyZoneFlows(ctx, "tap0", zone.ZoneQuarantine))
			require.Error(t, m.ApplyPortClassFlows(ctx, "tap0", zone.PortClassHypervisor))
			require.Error(t, m.RemoveFlows("tap0"))
			require.Empty(t, ctrl.deleted)
			require.Empty(t, ctrl.installed)
			require.Empty(t, ctrl.vlanPorts)
		})
	}
}

// partialInstallController is an ofPortController whose switch state is
// tracked: the port's VLAN and the live flows. With failInstall set, a
// batch install leaves its first rule on the switch and then fails, as the
// real OpenFlow client allows partial batch success.
type partialInstallController struct {
	*ofPortController
	vlans        map[string]int64
	live         []zoneflows.FlowRule
	failInstalls int // fail the next n non-empty InstallFlows batches
	failVLANAt   int // fail the n-th SetPortVLAN call (1-based); 0 never
	vlanCalls    int
	partial      *zoneflows.FlowRule
}

func (c *partialInstallController) InstallFlows(bridge string, rules []zoneflows.FlowRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failInstalls > 0 && len(rules) > 0 {
		c.failInstalls--
		r := rules[0]
		c.partial = &r
		c.live = append(c.live, r)
		return errors.New("batch rejected after the first flow mod")
	}
	c.live = append(c.live, rules...)
	return nil
}

func (c *partialInstallController) DeleteFlow(_ string, match string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.live[:0]
	for _, r := range c.live {
		if r.Match != match {
			kept = append(kept, r)
		}
	}
	c.live = kept
	return nil
}

// DeleteFlowsByPort removes every live flow that matches on the port, as
// ovs-ofctl del-flows in_port=N does: the move really deletes the port's
// earlier rules, so a rollback that does not reinstall them leaves none.
func (c *partialInstallController) DeleteFlowsByPort(_ string, ofPort string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.live[:0]
	for _, r := range c.live {
		if !matchesInPort(r.Match, ofPort) {
			kept = append(kept, r)
		}
	}
	c.live = kept
	return nil
}

func matchesInPort(match, ofPort string) bool {
	for _, field := range strings.Split(match, ",") {
		if strings.TrimSpace(field) == "in_port="+ofPort {
			return true
		}
	}
	return false
}

// portDropRules answers the live drop rules that match on OpenFlow port 7.
func portDropRules(c *partialInstallController) []zoneflows.FlowRule {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []zoneflows.FlowRule
	for _, r := range c.live {
		if r.Actions == "drop" && matchesInPort(r.Match, "7") {
			out = append(out, r)
		}
	}
	return out
}

func (c *partialInstallController) SetPortVLAN(_ context.Context, portName string, vlan int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vlanCalls++
	if c.failVLANAt != 0 && c.vlanCalls == c.failVLANAt {
		return errors.New("ovsdb unavailable")
	}
	c.vlans[portName] = vlan
	return nil
}

func newPartialInstallZFM(t *testing.T) (*partialInstallController, *ZoneFlowManager) {
	t.Helper()
	ctrl := &partialInstallController{
		ofPortController: &ofPortController{ofPorts: map[string]int32{"tap0": 7}},
		vlans:            map[string]int64{},
	}
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	return ctrl, m
}

func TestZoneFlowManager_ApplyZoneFlows_InstallFailureRestoresPort(t *testing.T) {
	ctx := context.Background()
	ctrl, m := newPartialInstallZFM(t)
	require.NoError(t, m.ApplyZoneFlows(ctx, "tap0", zone.ZoneQuarantine))
	prevVLAN := ctrl.vlans["tap0"]
	prevLive := append([]zoneflows.FlowRule(nil), ctrl.live...)

	ctrl.failInstalls = 1
	err := m.ApplyZoneFlows(ctx, "tap0", zone.ZoneProvisioning)
	require.Error(t, err)

	require.Equal(t, prevVLAN, ctrl.vlans["tap0"], "the port is back on its previous VLAN")
	require.NotNil(t, ctrl.partial)
	// The rollback reinstalls the previous zone's rules, which may share a
	// rule with the failed batch: every live rule is a previous-zone rule.
	for _, r := range ctrl.live {
		require.Contains(t, prevLive, r, "a flow of the failed batch is still installed")
	}
	got, err := m.GetPortZone("tap0")
	require.NoError(t, err)
	require.Equal(t, zone.ZoneQuarantine, got)
	gotVLAN, err := m.GetPortVLAN("tap0")
	require.NoError(t, err)
	require.Equal(t, prevVLAN, int64(gotVLAN))
}

func TestZoneFlowManager_ApplyZoneFlows_RestoreFailureIsUnknownState(t *testing.T) {
	ctx := context.Background()
	ctrl, m := newPartialInstallZFM(t)
	require.NoError(t, m.ApplyZoneFlows(ctx, "tap0", zone.ZoneProvisioning))

	ctrl.failInstalls = 1
	ctrl.failVLANAt = 3 // 1: first apply, 2: the move, 3: the restore
	err := m.ApplyZoneFlows(ctx, "tap0", zone.ZoneControlPlane)
	require.ErrorIs(t, err, ErrPortStateUnknown)
	for _, r := range ctrl.live {
		require.NotEqual(t, *ctrl.partial, r, "a flow of the failed batch is still installed")
	}
	got, err := m.GetPortZone("tap0")
	require.NoError(t, err)
	require.Equal(t, zone.ZoneQuarantine, got, "the manager records the most restrictive zone")
}

// TestZoneFlowManager_ApplyZoneFlows_RollbackReinstallsPreviousZone pins
// #1896 Codex P1: the move deletes the port's rules before it installs the
// new template, so when that install fails part-way the rollback must
// reinstall the previous zone's rules; a quarantined port must not be left
// on its restricted VLAN with no drop rules.
func TestZoneFlowManager_ApplyZoneFlows_RollbackReinstallsPreviousZone(t *testing.T) {
	for _, prev := range []zone.Zone{zone.ZoneQuarantine, zone.ZoneProvisioning} {
		t.Run(string(prev), func(t *testing.T) {
			ctx := context.Background()
			ctrl, m := newPartialInstallZFM(t)
			require.NoError(t, m.ApplyZoneFlows(ctx, "tap0", prev))
			before := portDropRules(ctrl)
			require.NotEmpty(t, before, "the %s zone installs drop rules for the port", prev)

			ctrl.failInstalls = 1
			err := m.ApplyZoneFlows(ctx, "tap0", zone.ZoneControlPlane)
			require.ErrorIs(t, err, ErrFlowInstallFailed)
			require.NotErrorIs(t, err, ErrPortStateUnknown)

			after := portDropRules(ctrl)
			for _, r := range before {
				require.Contains(t, after, r, "the previous zone's drop rule is reinstalled")
			}
			got, err := m.GetPortZone("tap0")
			require.NoError(t, err)
			require.Equal(t, prev, got)
		})
	}
}

// TestZoneFlowManager_ApplyZoneFlows_FailedRestoreBlocksPort: when the
// previous zone's rules cannot be reinstalled either, the port is blocked by
// a drop-all that outranks every other rule, and the error is returned.
func TestZoneFlowManager_ApplyZoneFlows_FailedRestoreBlocksPort(t *testing.T) {
	ctx := context.Background()
	ctrl, m := newPartialInstallZFM(t)
	require.NoError(t, m.ApplyZoneFlows(ctx, "tap0", zone.ZoneQuarantine))

	ctrl.failInstalls = 2 // the new template, then the restore of the old one
	err := m.ApplyZoneFlows(ctx, "tap0", zone.ZoneControlPlane)
	require.ErrorIs(t, err, ErrFlowInstallFailed)
	require.ErrorIs(t, err, ErrPortStateUnknown)

	var block *zoneflows.FlowRule
	maxOther := 0
	for _, r := range portDropRules(ctrl) {
		if r.Match == "in_port=7" {
			r := r
			block = &r
		}
	}
	require.NotNil(t, block, "a drop-all for the port is installed")
	ctrl.mu.Lock()
	for _, r := range ctrl.live {
		if r != *block && r.Priority > maxOther {
			maxOther = r.Priority
		}
	}
	ctrl.mu.Unlock()
	require.Greater(t, block.Priority, maxOther, "the drop-all outranks every other rule")
	require.Equal(t, 0, block.Table)

	got, err := m.GetPortZone("tap0")
	require.NoError(t, err)
	require.Equal(t, zone.ZoneQuarantine, got)
}
