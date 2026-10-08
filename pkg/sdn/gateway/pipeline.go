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
	"fmt"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// The base OpenFlow pipeline is the runtime's, not a service's (#567).
//
// Every datapath service gates traffic out of table 10 — the firewall into
// the conntrack tables, NAT into table 25, the load balancer into table 26
// — and relies on something having routed table 0 into table 10 first.
// Until #567 that something was the overlay mode handler, which nothing in
// a running binary constructs, so a bridge carried no table-0 flow at all:
// OVS's implicit table-0 miss is NORMAL, every gate was dead, and a gateway
// reporting `firewall: healthy` forwarded every packet it claimed to drop.
//
// EnsurePipeline installs the hand-off flows once, before any service
// handler starts, and RemovePipeline tears them down after the last stops.
// It is not a ServiceHandler on purpose: handler iteration order is
// map-random and the pipeline must exist before the first gate.

// CookiePipeline tags every flow of the base pipeline. It shares the
// gateway's 0xF1BE owner prefix with the firewall (…0001), NAT (…0002),
// load balancer (…0003), NAT64 (…0004) and perf (…00FF) services under
// CookieMask.
const CookiePipeline uint64 = 0xF1BE000000000000

// CookiePipelineMask selects the owner prefix of CookiePipeline.
const CookiePipelineMask uint64 = 0xFFFFFFFF00000000

// PipelineTerminal is the disposition of a packet that reaches table 30
// with no service having claimed it.
type PipelineTerminal string

const (
	// TerminalNormal hands the packet to OVS's built-in L2 learning — the
	// behaviour a bridge had before the pipeline existed, so installing
	// the pipeline changes nothing for traffic no service touches.
	TerminalNormal PipelineTerminal = "normal"

	// TerminalOverlay leaves table 30 to the overlay handler
	// (modes.OverlayModeHandler), whose MAC, ARP and egress tables forward
	// over the flow-based VXLAN port. It is refused while gatewayd cannot
	// build that handler: the overlay config carries no VTEP or access port
	// (#709), so nothing would install those tables and the chain would be
	// a drop funnel.
	TerminalOverlay PipelineTerminal = "overlay"
)

// Bridge external_ids keys through which platformd reads who owns the
// pipeline on a bridge it shares with gatewayd; the definitions live in
// zoneflows so both daemons share one.
const (
	PipelineOwnerKey    = zoneflows.PipelineOwnerKey
	PipelineTerminalKey = zoneflows.PipelineTerminalKey

	// pipelineOwnerPrefix is the owner value prefix.
	pipelineOwnerPrefix = "gatewayd:"
)

// PipelineFailMode is the bridge fail_mode held while the pipeline is
// installed: a controller loss must not fall back to NORMAL forwarding
// around the firewall.
const PipelineFailMode = "secure"

// PipelineOwner is what a bridge's external_ids say about its pipeline.
type PipelineOwner struct {
	// Owner is the gateway id that installed the pipeline.
	Owner string
	// Terminal is the disposition in force.
	Terminal PipelineTerminal
}

// BasePipelineRules returns the flows the runtime installs: table 0 at
// priority 0 hands every packet to table 10, table 10 at priority 0 hands
// it to table 30, table 20 at priority 0 hands it to table 30, and table 30
// at priority 0 applies the terminal. Priority 0 everywhere, so a platformd
// flow in table 0 still wins its match and a service gate or divert still
// outranks the miss.
//
// The table-20 miss is the pipeline's, not a service's. Every datapath
// service gates table 10 into the conntrack gate (table 20) with an
// empty-match flow and then claims only the frames it handles there, so
// whatever none of them claims needs a disposition that no single service
// owns. When each service carried its own, a service that forgot it (NAT,
// NAT64) black-holed every unclaimed frame on a gateway running it alone,
// and two that carried it at one priority were one OpenFlow flow, which
// either service's cookie-scoped Stop removed from under the other.
// OVS's own table miss is a drop, so this flow is load-bearing (owner
// ruling on #614, 2026-09-25).
func BasePipelineRules(terminal PipelineTerminal) ([]zoneflows.FlowRule, error) {
	cookie := fmt.Sprintf("0x%x", CookiePipeline)
	rules := []zoneflows.FlowRule{
		{
			Table:    int(modes.TableIngress),
			Priority: 0,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableVXLANDecap),
			Cookie:   cookie,
		},
		{
			Table:    int(modes.TableVXLANDecap),
			Priority: 0,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
			Cookie:   cookie,
		},
		{
			Table:    int(modes.TableCTGate),
			Priority: 0,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
			Cookie:   cookie,
		},
	}
	switch terminal {
	case TerminalNormal, "":
		rules = append(rules, zoneflows.FlowRule{
			Table:    int(modes.TableMACLearning),
			Priority: 0,
			Actions:  "normal",
			Cookie:   cookie,
		})
	case TerminalOverlay:
		return nil, &ErrPipelineTerminalUnavailable{
			Terminal: terminal,
			Reason:   "the overlay service is not built: the overlay config carries no VTEP or access port, so nothing installs the overlay tables",
		}
	default:
		return nil, &ErrPipelineTerminalUnknown{Terminal: terminal}
	}
	return rules, nil
}

// pipelineState is what EnsurePipeline recorded so RemovePipeline can put
// the bridge back exactly as it found it.
type pipelineState struct {
	bridge       string
	prevFailMode string
	owner        string
	terminal     PipelineTerminal
}

// PipelineStatus is what the runtime holds on its bridge, for the telemetry
// snapshot (#594). Installed is false when this runtime holds no pipeline,
// and the other fields are then zero.
type PipelineStatus struct {
	Installed bool
	Bridge    string
	Owner     string
	Terminal  PipelineTerminal
	FailMode  string
}

// PipelineStatus reports the base pipeline this runtime installed.
func (r *GatewayRuntime) PipelineStatus() PipelineStatus {
	if r == nil {
		return PipelineStatus{}
	}
	r.pipelineMu.Lock()
	defer r.pipelineMu.Unlock()
	if r.pipeline == nil {
		return PipelineStatus{}
	}
	return PipelineStatus{
		Installed: true,
		Bridge:    r.pipeline.bridge,
		Owner:     r.pipeline.owner,
		Terminal:  r.pipeline.terminal,
		FailMode:  PipelineFailMode,
	}
}

// EnsurePipeline installs the base pipeline on the runtime's bridge for the
// gateway named by ownerID, records the owner and terminal in the bridge's
// external_ids, and holds the bridge in fail_mode secure. It is idempotent
// for the same owner and refuses to take a bridge another owner holds.
func (r *GatewayRuntime) EnsurePipeline(ctx context.Context, ownerID string, terminal PipelineTerminal) error {
	if r == nil {
		return &ErrRuntimeMissing{Service: "pipeline"}
	}
	if r.Controller == nil || r.OVS == nil {
		return &ErrRuntimeMissing{Service: "pipeline"}
	}
	if r.Bridge == "" {
		return &ErrPipelineBridgeMissing{}
	}
	if terminal == "" {
		terminal = TerminalNormal
	}
	rules, err := BasePipelineRules(terminal)
	if err != nil {
		return err
	}

	r.pipelineMu.Lock()
	defer r.pipelineMu.Unlock()

	if r.pipeline != nil {
		if r.pipeline.owner == ownerID {
			return nil
		}
		return &ErrPipelineOwned{Bridge: r.Bridge, Owner: r.pipeline.owner}
	}

	current, err := r.OVS.GetBridgeExternalIDs(ctx, r.Bridge)
	if err != nil {
		return &ErrPipelineInstallFailed{Bridge: r.Bridge, Step: "read external_ids", Cause: err}
	}
	// RemovePipeline leaves the key present with an empty value; an empty
	// owner is nobody, not a rival, so a stop/start cycle re-installs.
	if owner, held := current[PipelineOwnerKey]; held && owner != "" && owner != pipelineOwnerPrefix+ownerID {
		return &ErrPipelineOwned{Bridge: r.Bridge, Owner: owner}
	}

	bridge, err := r.OVS.GetBridge(ctx, r.Bridge)
	if err != nil {
		return &ErrPipelineInstallFailed{Bridge: r.Bridge, Step: "read bridge", Cause: err}
	}

	// fail_mode goes first, and only when it changes. On a bridge with no
	// configured controller OVS flushes EVERY flow when fail_mode changes
	// (connmgr_set_fail_mode -> ofproto_flush_flows), so setting it after
	// the install wiped the pipeline it had just written and left a secure
	// bridge with no flows: every frame dropped, by every gateway, while
	// the services reported healthy (#614, measured on Open vSwitch 3.5).
	changedFailMode := bridge.FailMode != PipelineFailMode
	if changedFailMode {
		if err := r.OVS.SetBridgeFailMode(ctx, r.Bridge, PipelineFailMode); err != nil {
			return &ErrPipelineInstallFailed{Bridge: r.Bridge, Step: "set fail_mode", Cause: err}
		}
	}
	if err := r.Controller.InstallFlows(r.Bridge, rules); err != nil {
		if changedFailMode {
			r.restoreFailMode(ctx, bridge.FailMode)
		}
		return &ErrPipelineInstallFailed{Bridge: r.Bridge, Step: "install flows", Cause: err}
	}
	if err := r.OVS.SetBridgeExternalIDs(ctx, r.Bridge, map[string]string{
		PipelineOwnerKey:    pipelineOwnerPrefix + ownerID,
		PipelineTerminalKey: string(terminal),
	}); err != nil {
		r.rollbackPipelineFlows(ctx)
		if changedFailMode {
			r.restoreFailMode(ctx, bridge.FailMode)
		}
		return &ErrPipelineInstallFailed{Bridge: r.Bridge, Step: "record owner", Cause: err}
	}

	r.pipeline = &pipelineState{bridge: r.Bridge, prevFailMode: bridge.FailMode, owner: ownerID, terminal: terminal}
	r.logf(slog.LevelInfo, "base pipeline installed",
		slog.String("bridge", r.Bridge),
		slog.String("owner", ownerID),
		slog.String("terminal", string(terminal)),
		slog.Int("flows", len(rules)))
	return nil
}

// RemovePipeline deletes the base pipeline flows, clears the owner from the
// bridge's external_ids and restores the fail_mode the bridge had before
// EnsurePipeline. It is a no-op when no pipeline is installed.
func (r *GatewayRuntime) RemovePipeline(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.pipelineMu.Lock()
	defer r.pipelineMu.Unlock()
	if r.pipeline == nil {
		return nil
	}
	state := r.pipeline

	if err := r.OVS.DeleteFlowsByCookie(ctx, state.bridge, CookiePipeline, CookiePipelineMask); err != nil {
		return &ErrPipelineRemoveFailed{Bridge: state.bridge, Step: "delete flows", Cause: err}
	}
	if err := r.OVS.SetBridgeExternalIDs(ctx, state.bridge, map[string]string{
		PipelineOwnerKey:    "",
		PipelineTerminalKey: "",
	}); err != nil {
		return &ErrPipelineRemoveFailed{Bridge: state.bridge, Step: "clear owner", Cause: err}
	}
	// Restoring a different fail_mode flushes the bridge (see
	// EnsurePipeline); every gateway service has stopped by now, so the
	// flush takes nothing that is still in use by this gateway.
	if state.prevFailMode != PipelineFailMode {
		r.restoreFailMode(ctx, state.prevFailMode)
	}
	r.pipeline = nil
	r.logf(slog.LevelInfo, "base pipeline removed",
		slog.String("bridge", state.bridge),
		slog.String("owner", state.owner))
	return nil
}

// PipelineInstalled reports whether this runtime holds the pipeline.
func (r *GatewayRuntime) PipelineInstalled() bool {
	if r == nil {
		return false
	}
	r.pipelineMu.Lock()
	defer r.pipelineMu.Unlock()
	return r.pipeline != nil
}

// rollbackPipelineFlows removes the flows after a later install step
// failed; a failure here is logged because the original error is what
// the caller needs.
func (r *GatewayRuntime) rollbackPipelineFlows(ctx context.Context) {
	if err := r.OVS.DeleteFlowsByCookie(ctx, r.Bridge, CookiePipeline, CookiePipelineMask); err != nil {
		r.logf(slog.LevelWarn, "base pipeline rollback failed", slog.String("bridge", r.Bridge), slog.String("error", err.Error()))
	}
}

// restoreFailMode puts the bridge's fail_mode back; the empty string is
// OVS's default (standalone behaviour), which SetBridgeFailMode accepts.
func (r *GatewayRuntime) restoreFailMode(ctx context.Context, failMode string) {
	if err := r.OVS.SetBridgeFailMode(ctx, r.Bridge, failMode); err != nil {
		r.logf(slog.LevelWarn, "base pipeline fail_mode restore failed", slog.String("bridge", r.Bridge), slog.String("error", err.Error()))
	}
}

func (r *GatewayRuntime) logf(level slog.Level, msg string, attrs ...slog.Attr) {
	if r.Logger == nil {
		return
	}
	r.Logger.LogAttrs(context.Background(), level, msg, attrs...)
}

// ReadPipelineOwner is the seam platformd uses on a bridge it shares with
// gatewayd: it reports who holds the base pipeline, so platformd's own
// flow compilers can hand off to table 10 instead of terminating in
// `normal` and punching through the gatewayd firewall. ok is false when no
// gatewayd owns the bridge.
func ReadPipelineOwner(ctx context.Context, client ovs.ClientInterface, bridge string) (PipelineOwner, bool, error) {
	if client == nil {
		return PipelineOwner{}, false, &ErrRuntimeMissing{Service: "pipeline"}
	}
	ids, err := client.GetBridgeExternalIDs(ctx, bridge)
	if err != nil {
		return PipelineOwner{}, false, &ErrPipelineOwnerReadFailed{Bridge: bridge, Cause: err}
	}
	owner, ok := ids[PipelineOwnerKey]
	if !ok || owner == "" {
		return PipelineOwner{}, false, nil
	}
	terminal := PipelineTerminal(ids[PipelineTerminalKey])
	if terminal == "" {
		terminal = TerminalNormal
	}
	return PipelineOwner{Owner: owner, Terminal: terminal}, true, nil
}

// pipelineGuard is embedded in GatewayRuntime; it lives here so the
// runtime struct declaration in runtime.go stays a plain dependency bag.
type pipelineGuard struct {
	pipelineMu sync.Mutex
	pipeline   *pipelineState
}

// ErrPipelineBridgeMissing is returned when the runtime names no bridge.
type ErrPipelineBridgeMissing struct{}

// Error implements the error interface.
func (e *ErrPipelineBridgeMissing) Error() string {
	return "gateway: base pipeline requires a runtime bridge"
}

// ErrPipelineOwned is returned when another gateway holds the bridge's
// pipeline. Two owners on one bridge would replace each other's table-0
// flow silently, so the second one is refused.
type ErrPipelineOwned struct {
	Bridge string
	Owner  string
}

// Error implements the error interface.
func (e *ErrPipelineOwned) Error() string {
	return fmt.Sprintf("gateway: bridge %s pipeline is owned by %s", e.Bridge, e.Owner)
}

// ErrPipelineTerminalUnavailable is returned for a terminal the runtime
// cannot honour yet.
type ErrPipelineTerminalUnavailable struct {
	Terminal PipelineTerminal
	Reason   string
}

// Error implements the error interface.
func (e *ErrPipelineTerminalUnavailable) Error() string {
	return fmt.Sprintf("gateway: pipeline terminal %q is unavailable: %s", e.Terminal, e.Reason)
}

// ErrPipelineTerminalUnknown is returned for a terminal the runtime does
// not define.
type ErrPipelineTerminalUnknown struct {
	Terminal PipelineTerminal
}

// Error implements the error interface.
func (e *ErrPipelineTerminalUnknown) Error() string {
	return fmt.Sprintf("gateway: unknown pipeline terminal %q (want %q or %q)", e.Terminal, TerminalNormal, TerminalOverlay)
}

// ErrPipelineInstallFailed wraps a failed EnsurePipeline step.
type ErrPipelineInstallFailed struct {
	Bridge string
	Step   string
	Cause  error
}

// Error implements the error interface.
func (e *ErrPipelineInstallFailed) Error() string {
	return fmt.Sprintf("gateway: base pipeline install on %s failed at %s: %v", e.Bridge, e.Step, e.Cause)
}

// Unwrap returns the cause.
func (e *ErrPipelineInstallFailed) Unwrap() error { return e.Cause }

// ErrPipelineRemoveFailed wraps a failed RemovePipeline step.
type ErrPipelineRemoveFailed struct {
	Bridge string
	Step   string
	Cause  error
}

// Error implements the error interface.
func (e *ErrPipelineRemoveFailed) Error() string {
	return fmt.Sprintf("gateway: base pipeline removal on %s failed at %s: %v", e.Bridge, e.Step, e.Cause)
}

// Unwrap returns the cause.
func (e *ErrPipelineRemoveFailed) Unwrap() error { return e.Cause }

// ErrPipelineOwnerReadFailed wraps a failed ReadPipelineOwner.
type ErrPipelineOwnerReadFailed struct {
	Bridge string
	Cause  error
}

// Error implements the error interface.
func (e *ErrPipelineOwnerReadFailed) Error() string {
	return fmt.Sprintf("gateway: reading pipeline owner of %s failed: %v", e.Bridge, e.Cause)
}

// Unwrap returns the cause.
func (e *ErrPipelineOwnerReadFailed) Unwrap() error { return e.Cause }
