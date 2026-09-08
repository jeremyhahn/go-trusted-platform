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

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// The bridge-level calls the pipeline makes, recorded on the shared fake so
// the firewall/NAT/LB handler tests keep working unchanged.

func (f *fakeOVSClient) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeErr != nil {
		return nil, f.bridgeErr
	}
	return &ovs.Bridge{Name: name, FailMode: f.failMode, ExternalIDs: copyIDs(f.externalIDs)}, nil
}

func (f *fakeOVSClient) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failModeErr != nil {
		return f.failModeErr
	}
	f.failModes = append(f.failModes, failMode)
	f.failMode = failMode
	return nil
}

func (f *fakeOVSClient) SetBridgeExternalIDs(ctx context.Context, name string, ids map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.externalIDsErr != nil {
		return f.externalIDsErr
	}
	if f.externalIDs == nil {
		f.externalIDs = map[string]string{}
	}
	for k, v := range ids {
		f.externalIDs[k] = v
	}
	return nil
}

func (f *fakeOVSClient) GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeErr != nil {
		return nil, f.bridgeErr
	}
	return copyIDs(f.externalIDs), nil
}

func copyIDs(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (f *fakeFlowController) allRules() []zoneflows.FlowRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []zoneflows.FlowRule
	for _, batch := range f.installs {
		out = append(out, batch...)
	}
	return out
}

func pipelineRules(rules []zoneflows.FlowRule) []zoneflows.FlowRule {
	want := fmt.Sprintf("0x%x", CookiePipeline)
	var out []zoneflows.FlowRule
	for _, r := range rules {
		if r.Cookie == want {
			out = append(out, r)
		}
	}
	return out
}

func TestBasePipelineRules_Normal(t *testing.T) {
	rules, err := BasePipelineRules(TerminalNormal)
	require.NoError(t, err)
	require.Len(t, rules, 3)
	assert.Equal(t, int(modes.TableIngress), rules[0].Table)
	assert.Equal(t, "goto_table:10", rules[0].Actions)
	assert.Equal(t, int(modes.TableVXLANDecap), rules[1].Table)
	assert.Equal(t, "goto_table:30", rules[1].Actions)
	assert.Equal(t, int(modes.TableMACLearning), rules[2].Table)
	assert.Equal(t, "normal", rules[2].Actions)
	for _, r := range rules {
		assert.Equal(t, 0, r.Priority, "the pipeline never outranks a platformd flow or a service gate")
		assert.Empty(t, r.Match, "the pipeline is a table default, not a match")
		assert.Equal(t, fmt.Sprintf("0x%x", CookiePipeline), r.Cookie)
	}

	empty, err := BasePipelineRules("")
	require.NoError(t, err)
	assert.Equal(t, rules, empty, "the empty terminal is NORMAL")
}

func TestBasePipelineRules_OverlayIsRefusedUntilEgressExists(t *testing.T) {
	_, err := BasePipelineRules(TerminalOverlay)
	var unavailable *ErrPipelineTerminalUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, TerminalOverlay, unavailable.Terminal)
	assert.Contains(t, err.Error(), "encap")
}

func TestBasePipelineRules_UnknownTerminal(t *testing.T) {
	_, err := BasePipelineRules("bogus")
	var unknown *ErrPipelineTerminalUnknown
	require.True(t, errors.As(err, &unknown), "got %v", err)
}

func TestEnsurePipeline_InstallsRecordsAndSecures(t *testing.T) {
	rt := newTestRuntime()
	ovsFake := rt.OVS.(*fakeOVSClient)
	ovsFake.failMode = "standalone"

	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal))
	assert.True(t, rt.PipelineInstalled())

	installed := pipelineRules(rt.Controller.(*fakeFlowController).allRules())
	require.Len(t, installed, 3)
	assert.Equal(t, "secure", ovsFake.failMode)
	assert.Equal(t, "gatewayd:gw-1", ovsFake.externalIDs[PipelineOwnerKey])
	assert.Equal(t, "normal", ovsFake.externalIDs[PipelineTerminalKey])

	// Idempotent for the same owner: no second install.
	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal))
	assert.Len(t, pipelineRules(rt.Controller.(*fakeFlowController).allRules()), 3)

	// Another owner on the same runtime is refused.
	err := rt.EnsurePipeline(context.Background(), "gw-2", TerminalNormal)
	var owned *ErrPipelineOwned
	require.True(t, errors.As(err, &owned), "got %v", err)
	assert.Equal(t, "gw-1", owned.Owner)

	require.NoError(t, rt.RemovePipeline(context.Background()))
	assert.False(t, rt.PipelineInstalled())
	assert.Contains(t, ovsFake.cookieDeletes, CookiePipeline)
	assert.Equal(t, "standalone", ovsFake.failMode, "the bridge gets its previous fail_mode back")
	assert.Equal(t, "", ovsFake.externalIDs[PipelineOwnerKey])

	// Removing twice is a no-op.
	require.NoError(t, rt.RemovePipeline(context.Background()))
}

func TestEnsurePipeline_RefusesABridgeAnotherGatewayHolds(t *testing.T) {
	rt := newTestRuntime()
	rt.OVS.(*fakeOVSClient).externalIDs = map[string]string{PipelineOwnerKey: "gatewayd:other"}
	err := rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal)
	var owned *ErrPipelineOwned
	require.True(t, errors.As(err, &owned), "got %v", err)
	assert.Equal(t, "gatewayd:other", owned.Owner)
	assert.Empty(t, pipelineRules(rt.Controller.(*fakeFlowController).allRules()))
}

func TestEnsurePipeline_ReclaimsItsOwnStaleRecord(t *testing.T) {
	// A crashed gatewayd left its own owner record behind; the same id
	// takes the bridge back rather than locking itself out.
	rt := newTestRuntime()
	rt.OVS.(*fakeOVSClient).externalIDs = map[string]string{PipelineOwnerKey: "gatewayd:gw-1"}
	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal))
	assert.True(t, rt.PipelineInstalled())
}

func TestEnsurePipeline_MissingDependencies(t *testing.T) {
	var nilRuntime *GatewayRuntime
	var missing *ErrRuntimeMissing
	require.True(t, errors.As(nilRuntime.EnsurePipeline(context.Background(), "gw", TerminalNormal), &missing))

	rt := newTestRuntime()
	rt.OVS = nil
	require.True(t, errors.As(rt.EnsurePipeline(context.Background(), "gw", TerminalNormal), &missing))

	rt = newTestRuntime()
	rt.Bridge = ""
	var noBridge *ErrPipelineBridgeMissing
	require.True(t, errors.As(rt.EnsurePipeline(context.Background(), "gw", TerminalNormal), &noBridge))

	rt = newTestRuntime()
	var unavailable *ErrPipelineTerminalUnavailable
	require.True(t, errors.As(rt.EnsurePipeline(context.Background(), "gw", TerminalOverlay), &unavailable))
	assert.False(t, rt.PipelineInstalled())

	require.NoError(t, nilRuntime.RemovePipeline(context.Background()))
	assert.False(t, nilRuntime.PipelineInstalled())
}

func TestEnsurePipeline_RollsBackWhenALaterStepFails(t *testing.T) {
	rt := newTestRuntime()
	ovsFake := rt.OVS.(*fakeOVSClient)
	ovsFake.failMode = "standalone"
	ovsFake.externalIDsErr = errors.New("ovsdb write refused")

	err := rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal)
	var install *ErrPipelineInstallFailed
	require.True(t, errors.As(err, &install), "got %v", err)
	assert.Equal(t, "record owner", install.Step)
	assert.Contains(t, ovsFake.cookieDeletes, CookiePipeline, "the flows are rolled back")
	assert.Equal(t, "standalone", ovsFake.failMode, "the fail_mode is restored")
	assert.False(t, rt.PipelineInstalled())

	rt = newTestRuntime()
	rt.OVS.(*fakeOVSClient).failModeErr = errors.New("fail_mode refused")
	err = rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal)
	require.True(t, errors.As(err, &install), "got %v", err)
	assert.Equal(t, "set fail_mode", install.Step)

	rt = newTestRuntime()
	rt.OVS.(*fakeOVSClient).bridgeErr = errors.New("no such bridge")
	err = rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal)
	require.True(t, errors.As(err, &install), "got %v", err)
	assert.Equal(t, "read external_ids", install.Step)
}

func TestRemovePipeline_ReportsAFailedDelete(t *testing.T) {
	rt := newTestRuntime()
	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal))
	rt.OVS.(*fakeOVSClient).cookieDeleteErr = errors.New("openflow down")
	err := rt.RemovePipeline(context.Background())
	var remove *ErrPipelineRemoveFailed
	require.True(t, errors.As(err, &remove), "got %v", err)
	assert.Equal(t, "delete flows", remove.Step)
	assert.True(t, rt.PipelineInstalled(), "a failed removal keeps the record so a retry can finish it")
}

func TestReadPipelineOwner(t *testing.T) {
	client := &fakeOVSClient{}
	_, held, err := ReadPipelineOwner(context.Background(), client, "br0")
	require.NoError(t, err)
	assert.False(t, held)

	client.externalIDs = map[string]string{PipelineOwnerKey: "gatewayd:gw-1", PipelineTerminalKey: "normal"}
	owner, held, err := ReadPipelineOwner(context.Background(), client, "br0")
	require.NoError(t, err)
	require.True(t, held)
	assert.Equal(t, "gatewayd:gw-1", owner.Owner)
	assert.Equal(t, TerminalNormal, owner.Terminal)

	client.externalIDs = map[string]string{PipelineOwnerKey: ""}
	_, held, err = ReadPipelineOwner(context.Background(), client, "br0")
	require.NoError(t, err)
	assert.False(t, held, "a cleared owner is no owner")

	client.bridgeErr = errors.New("ovsdb unavailable")
	_, _, err = ReadPipelineOwner(context.Background(), client, "br0")
	var readErr *ErrPipelineOwnerReadFailed
	require.True(t, errors.As(err, &readErr), "got %v", err)

	_, _, err = ReadPipelineOwner(context.Background(), nil, "br0")
	var missing *ErrRuntimeMissing
	require.True(t, errors.As(err, &missing), "got %v", err)
}

// TestGatewayStart_InstallsThePipelineBeforeTheFirstGate is the keystone
// assertion: with the firewall enabled, the table-0 hand-off is installed
// in an earlier batch than the firewall's table-10 gate, and it is gone
// again after Stop.
func TestGatewayStart_InstallsThePipelineBeforeTheFirstGate(t *testing.T) {
	cfg := firewallGatewayConfig()
	gw := startGateway(t, cfg)

	ctrl := cfg.Runtime.Controller.(*fakeFlowController)
	ctrl.mu.Lock()
	batches := ctrl.installs
	ctrl.mu.Unlock()
	require.NotEmpty(t, batches)
	assert.Equal(t, fmt.Sprintf("0x%x", CookiePipeline), batches[0][0].Cookie, "the pipeline batch comes first")
	assert.Equal(t, int(modes.TableIngress), batches[0][0].Table)
	assert.True(t, cfg.Runtime.PipelineInstalled())
	assert.Equal(t, "secure", cfg.Runtime.OVS.(*fakeOVSClient).failMode)

	require.NoError(t, gw.Stop(context.Background()))
	assert.False(t, cfg.Runtime.PipelineInstalled())
}

func TestGatewayStart_NoDatapathServiceInstallsNoPipeline(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "telemetry-only",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Runtime:       newTestRuntime(),
	}
	gw := startGateway(t, cfg)
	assert.False(t, cfg.Runtime.PipelineInstalled())
	assert.Empty(t, pipelineRules(cfg.Runtime.Controller.(*fakeFlowController).allRules()))
	require.NoError(t, gw.Stop(context.Background()))
}

// TestGatewayStart_OverlayAloneNeedsNoPipeline pins the review finding on
// #577: the overlay handler programs no flows today, so enabling it must not
// request a pipeline terminal that is refused and turn a startable gateway
// into a startup failure.
// TestEnsurePipeline_ReinstallsAfterRemove pins the review finding on
// #577: RemovePipeline leaves the owner key present and empty, and the next
// EnsurePipeline must treat that as unowned, or every stop/start cycle
// refuses with ErrPipelineOwned{Owner: ""}.
func TestEnsurePipeline_ReinstallsAfterRemove(t *testing.T) {
	rt := newTestRuntime()
	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal))
	require.NoError(t, rt.RemovePipeline(context.Background()))
	assert.False(t, rt.PipelineInstalled())
	assert.Equal(t, "", rt.OVS.(*fakeOVSClient).externalIDs[PipelineOwnerKey])

	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-1", TerminalNormal), "re-install after a clean remove")
	assert.True(t, rt.PipelineInstalled())
	assert.Equal(t, "gatewayd:gw-1", rt.OVS.(*fakeOVSClient).externalIDs[PipelineOwnerKey])

	// A different gateway may also take a bridge nobody owns.
	require.NoError(t, rt.RemovePipeline(context.Background()))
	require.NoError(t, rt.EnsurePipeline(context.Background(), "gw-2", TerminalNormal))
}

// TestGatewayStopStart_RoundTrip drives the same cycle through the gateway.
func TestGatewayStopStart_RoundTrip(t *testing.T) {
	cfg := firewallGatewayConfig()
	gw := startGateway(t, cfg)
	require.NoError(t, gw.Stop(context.Background()))
	assert.False(t, cfg.Runtime.PipelineInstalled())
	require.NoError(t, gw.Start(context.Background()), "a stopped gateway must start again")
	assert.True(t, cfg.Runtime.PipelineInstalled())
	require.NoError(t, gw.Stop(context.Background()))
}

func TestErrRollbackIncomplete_UnwrapsBothBranches(t *testing.T) {
	cause := &ErrServiceStartFailed{Service: "firewall", Cause: errors.New("boom")}
	rollback := &ErrPipelineRemoveFailed{Bridge: "br0", Step: "delete", Cause: errors.New("ovs")}
	err := &ErrRollbackIncomplete{Cause: cause, Rollback: rollback}
	var gotStart *ErrServiceStartFailed
	var gotRemove *ErrPipelineRemoveFailed
	assert.True(t, errors.As(err, &gotStart))
	assert.True(t, errors.As(err, &gotRemove))
	assert.Contains(t, err.Error(), "rollback incomplete")
}

// TestGatewayStart_OverlayAloneInstallsNoPipeline: the overlay section is a
// refused service (#568) and never a pipeline owner. A gateway that enables
// only overlay installs nothing and fails Start with the typed refusal.
func TestGatewayStart_OverlayAloneInstallsNoPipeline(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "overlay-only",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Runtime:       newTestRuntime(),
		Overlay:       &OverlayServiceConfig{Enabled: true},
	}
	assert.False(t, cfg.needsPipeline())
	assert.Equal(t, TerminalNormal, cfg.pipelineTerminal())
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.False(t, cfg.Runtime.PipelineInstalled())
}

// TestGatewayStart_OverlayBesideFirewallRollsThePipelineBack: the firewall
// installs the pipeline on NORMAL, the refused overlay section fails the
// start, and the rollback removes the pipeline again.
func TestGatewayStart_OverlayBesideFirewallRollsThePipelineBack(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.Overlay = &OverlayServiceConfig{Enabled: true}
	assert.True(t, cfg.needsPipeline())
	assert.Equal(t, TerminalNormal, cfg.pipelineTerminal())
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, ServiceOverlay, unavailable.Service)
	assert.False(t, cfg.Runtime.PipelineInstalled(), "the pipeline is rolled back with the failed start")
}

func TestGatewayStart_PipelineFailureIsAStartupFailure(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.Runtime.OVS.(*fakeOVSClient).failModeErr = errors.New("refused")
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var startup *ErrStartupFailed
	require.True(t, errors.As(err, &startup), "got %v", err)
	assert.Equal(t, "pipeline", startup.Phase)
	assert.Equal(t, GatewayStateError, GatewayState(gw.state.Load()))
}

// TestPipelineInvariant_EveryGotoTargetIsRouted is the general form of the
// bug #567 fixes: for every rule set the gateway compiles, each
// goto_table:N target must be a table the base pipeline routes into or a
// table a service gate routes into from one the pipeline reaches.
func TestPipelineInvariant_EveryGotoTargetIsRouted(t *testing.T) {
	base, err := BasePipelineRules(TerminalNormal)
	require.NoError(t, err)

	cfg := lbGatewayConfig()
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.Uplinks = []UplinkConfig{{Name: "eth0", MTU: 1500}}
	cfg.NAT = natGatewayConfig().NAT
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	rules := cfg.Runtime.Controller.(*fakeFlowController).allRules()
	assertEveryGotoTargetIsRouted(t, append(base, rules...))
}

// assertEveryGotoTargetIsRouted walks the table graph from table 0 along
// goto_table edges and fails on any goto whose source table is not
// reachable — a rule in an unreachable table is a verdict nobody sees.
func assertEveryGotoTargetIsRouted(t *testing.T, rules []zoneflows.FlowRule) {
	t.Helper()
	edges := map[int]map[int]bool{}
	for _, r := range rules {
		for _, target := range gotoTargets(r.Actions) {
			if edges[r.Table] == nil {
				edges[r.Table] = map[int]bool{}
			}
			edges[r.Table][target] = true
		}
	}
	reachable := map[int]bool{int(modes.TableIngress): true}
	queue := []int{int(modes.TableIngress)}
	for len(queue) > 0 {
		table := queue[0]
		queue = queue[1:]
		for target := range edges[table] {
			if !reachable[target] {
				reachable[target] = true
				queue = append(queue, target)
			}
		}
	}
	for _, r := range rules {
		assert.True(t, reachable[r.Table],
			"rule in table %d (%s -> %s) is unreachable from table 0: no pipeline or gate routes into it", r.Table, r.Match, r.Actions)
	}
}

// gotoTargets extracts every table a rule's actions can send a packet to:
// goto_table:N, and the recirculation table of a ct(...,table=N,...) action.
func gotoTargets(actions string) []int {
	var out []int
	for _, token := range strings.FieldsFunc(actions, func(r rune) bool { return r == ',' || r == ' ' || r == '(' || r == ')' }) {
		for _, prefix := range []string{"goto_table:", "table="} {
			if n, ok := strings.CutPrefix(token, prefix); ok {
				if v, err := strconv.Atoi(n); err == nil {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

func TestGotoTargets(t *testing.T) {
	assert.Equal(t, []int{10}, gotoTargets("goto_table:10"))
	assert.Equal(t, []int{21}, gotoTargets("ct(table=21,zone=5)"))
	assert.Equal(t, []int{30}, gotoTargets("ct(commit,zone=7,nat(dst=10.0.0.1:80)),goto_table:30"))
	assert.Empty(t, gotoTargets("normal"))
	assert.Empty(t, gotoTargets("drop"))
}
