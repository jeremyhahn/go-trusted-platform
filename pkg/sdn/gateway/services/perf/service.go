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

// Package perf implements the gateway performance verification service.
// It measures REAL datapath state only: flow-programming throughput is
// timed against a live OVS bridge with a monotonic clock, and datapath /
// conntrack numbers come straight from ovs-vswitchd's unixctl counters.
// No synthetic values are produced anywhere in this package.
package perf

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

const (
	// FlowTable is the dedicated OpenFlow table used for ephemeral
	// flow-programming measurements. It sits far above the last table of
	// the gateway pipeline (modes.TableLocalDelivery), and no pipeline
	// table resubmits to it, so perf flows never intersect production
	// traffic.
	FlowTable = 250

	// FlowPriority is the priority of ephemeral perf flows.
	FlowPriority = 1

	// FlowCookie stamps every ephemeral perf flow so teardown is a
	// single cookie-scoped delete. The 0xF1BE prefix matches the
	// gateway service cookie family (firewall 0xF1BE0001/0002, load
	// balancer 0xF1BE0003, NAT64 0xF1BE0004); 0x00FF marks the perf
	// sub-range.
	FlowCookie uint64 = 0xF1BE00FF00000000

	// MaxFlowCount bounds one measurement run to keep the ephemeral
	// table and the teardown delete cheap.
	MaxFlowCount = 100000

	// DefaultFlowCount is used when a caller passes count <= 0 at the
	// API boundary (the service itself rejects non-positive counts).
	DefaultFlowCount = 1000
)

// FlowClient is the narrow OVS surface the perf service needs. The
// concrete *ovs.Client satisfies it.
type FlowClient interface {
	AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	AddFlows(ctx context.Context, bridgeName string, flows []*ovs.FlowMod) error
	DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error
	ListBridges(ctx context.Context) ([]*ovs.Bridge, error)
	GetBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	GetOVSOtherConfig(ctx context.Context) (map[string]string, error)
}

// Compile-time check: the concrete OVS client provides the flow surface.
var _ FlowClient = (*ovs.Client)(nil)

// Deps carries the service dependencies.
type Deps struct {
	// OVS programs and deletes flows and reads OVSDB state (required).
	OVS FlowClient

	// AppCtl issues unixctl commands against ovs-vswitchd (optional).
	// Datapath and Conntrack return ErrAppCtlUnavailable without it;
	// Flows works with OVS alone.
	AppCtl ovs.AppCtlRunner

	// Bridge is the default bridge for flow measurements when the
	// caller does not name one. When empty, the first bridge (sorted
	// by name) is used.
	Bridge string
}

// Service measures gateway datapath performance characteristics.
type Service struct {
	ovs    FlowClient
	appctl ovs.AppCtlRunner
	bridge string
}

// New creates a perf service. OVS is required; AppCtl is optional (see
// Deps).
func New(deps Deps) (*Service, error) {
	if deps.OVS == nil {
		return nil, ErrOVSRequired
	}
	return &Service{ovs: deps.OVS, appctl: deps.AppCtl, bridge: deps.Bridge}, nil
}

// FlowsResult reports one measured flow-programming run.
type FlowsResult struct {
	// Installed is the number of flows actually installed.
	Installed int

	// Duration is the measured wall time of the install phase
	// (monotonic clock).
	Duration time.Duration

	// FlowsPerSecond is Installed divided by Duration.
	FlowsPerSecond float64

	// Batched reports whether the flows were installed with a single
	// batched barrier (AddFlows) or one-by-one (AddFlow).
	Batched bool

	// Bridge is the bridge the flows were installed on.
	Bridge string
}

// DatapathResult reports the datapath counters relevant to hardware
// offload verification. All values are read from ovs-vswitchd; none are
// computed synthetically.
type DatapathResult struct {
	// Hits is the datapath flow-cache hit counter.
	Hits uint64

	// Missed is the upcall (cache miss) counter.
	Missed uint64

	// Lost is the dropped-upcall counter.
	Lost uint64

	// OffloadedFlowCount is the number of datapath flows currently
	// offloaded to hardware (dpctl/dump-flows type=offloaded).
	OffloadedFlowCount int

	// HWOffloadEnabled reports the Open_vSwitch other_config
	// hw-offload switch.
	HWOffloadEnabled bool

	// DatapathType is the bridge's datapath_type ("" or "system" for
	// the kernel datapath, "netdev" for userspace/DPDK).
	DatapathType string

	// Bridge is the bridge whose datapath_type was inspected.
	Bridge string
}

// ConntrackResult summarizes the connection tracking table.
type ConntrackResult struct {
	// TotalEntries is the number of conntrack entries in the dump.
	TotalEntries int

	// PerZone maps conntrack zone ID to entry count.
	PerZone map[int]int
}

// Flows installs count ephemeral drop flows into the dedicated perf
// table on the target bridge, measures the install time with a monotonic
// clock, and tears the flows down again with a cookie-scoped delete. The
// teardown runs even when the install fails part-way (deferred), so a
// failed run never leaks flows.
func (s *Service) Flows(ctx context.Context, bridge string, count int, batch bool) (result FlowsResult, err error) {
	if count <= 0 || count > MaxFlowCount {
		return FlowsResult{}, &ErrInvalidFlowCount{Count: count, Max: MaxFlowCount}
	}

	bridge, err = s.resolveBridge(ctx, bridge)
	if err != nil {
		return FlowsResult{}, err
	}

	flows := buildPerfFlows(count)

	// Teardown must run even on error: the non-batch path may have
	// installed a prefix of the flows before failing.
	defer func() {
		// Use a context detached from the caller's cancellation so a
		// canceled measurement still cleans up its flows, bounded to
		// keep teardown from hanging.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if delErr := s.ovs.DeleteFlowsByCookie(cleanupCtx, bridge, FlowCookie, ^uint64(0)); delErr != nil && err == nil {
			err = &ErrFlowTeardownFailed{Bridge: bridge, Cause: delErr}
		}
	}()

	start := time.Now()
	if batch {
		if installErr := s.ovs.AddFlows(ctx, bridge, flows); installErr != nil {
			return FlowsResult{}, &ErrFlowInstallFailed{Bridge: bridge, Cause: installErr}
		}
	} else {
		for _, flow := range flows {
			if installErr := s.ovs.AddFlow(ctx, bridge, flow); installErr != nil {
				return FlowsResult{}, &ErrFlowInstallFailed{Bridge: bridge, Cause: installErr}
			}
		}
	}
	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}

	return FlowsResult{
		Installed:      count,
		Duration:       duration,
		FlowsPerSecond: float64(count) / duration.Seconds(),
		Batched:        batch,
		Bridge:         bridge,
	}, nil
}

// Datapath reads the live datapath lookup counters, the offloaded flow
// count, the hw-offload switch, and the bridge datapath type.
func (s *Service) Datapath(ctx context.Context, bridge string) (DatapathResult, error) {
	if s.appctl == nil {
		return DatapathResult{}, ErrAppCtlUnavailable
	}

	bridge, err := s.resolveBridge(ctx, bridge)
	if err != nil {
		return DatapathResult{}, err
	}

	statsOut, err := s.appctl.DatapathStats(ctx)
	if err != nil {
		return DatapathResult{}, err
	}
	counters, err := ovs.ParseDatapathStats(statsOut)
	if err != nil {
		return DatapathResult{}, err
	}

	offloadedDump, err := s.appctl.DumpDatapathFlows(ctx, "type=offloaded")
	if err != nil {
		return DatapathResult{}, err
	}

	otherConfig, err := s.ovs.GetOVSOtherConfig(ctx)
	if err != nil {
		return DatapathResult{}, err
	}

	bridgeRow, err := s.ovs.GetBridge(ctx, bridge)
	if err != nil {
		return DatapathResult{}, err
	}
	datapathType := bridgeRow.DatapathType
	if datapathType == "" {
		datapathType = "system"
	}

	return DatapathResult{
		Hits:               counters.Hits,
		Missed:             counters.Missed,
		Lost:               counters.Lost,
		OffloadedFlowCount: ovs.CountOffloadedFlows(offloadedDump),
		HWOffloadEnabled:   otherConfig["hw-offload"] == "true",
		DatapathType:       datapathType,
		Bridge:             bridge,
	}, nil
}

// Conntrack summarizes the connection tracking table. A negative zone
// dumps every zone; zone >= 0 restricts the dump to that zone.
func (s *Service) Conntrack(ctx context.Context, zone int) (ConntrackResult, error) {
	if s.appctl == nil {
		return ConntrackResult{}, ErrAppCtlUnavailable
	}

	dump, err := s.appctl.DumpConntrack(ctx, zone)
	if err != nil {
		return ConntrackResult{}, err
	}

	summary := ovs.ParseConntrackSummary(dump)
	return ConntrackResult{TotalEntries: summary.Total, PerZone: summary.PerZone}, nil
}

// resolveBridge picks the measurement bridge: the caller's explicit
// bridge, then the configured default, then the first bridge sorted by
// name. Explicit bridges are validated against OVSDB.
func (s *Service) resolveBridge(ctx context.Context, bridge string) (string, error) {
	if bridge == "" {
		bridge = s.bridge
	}
	if bridge != "" {
		if _, err := s.ovs.GetBridge(ctx, bridge); err != nil {
			return "", &ErrBridgeUnavailable{Bridge: bridge, Cause: err}
		}
		return bridge, nil
	}

	bridges, err := s.ovs.ListBridges(ctx)
	if err != nil {
		return "", &ErrBridgeUnavailable{Cause: err}
	}
	if len(bridges) == 0 {
		return "", ErrNoBridgeAvailable
	}

	names := make([]string, 0, len(bridges))
	for _, b := range bridges {
		names = append(names, b.Name)
	}
	sort.Strings(names)
	return names[0], nil
}

// buildPerfFlows constructs count unique drop flows in the perf table.
// Uniqueness comes from a locally-administered destination MAC derived
// from the flow index, so every FlowMod is a distinct table entry.
func buildPerfFlows(count int) []*ovs.FlowMod {
	cookie := fmt.Sprintf("0x%x", FlowCookie)
	flows := make([]*ovs.FlowMod, 0, count)
	for i := 0; i < count; i++ {
		flows = append(flows, &ovs.FlowMod{
			Table:    FlowTable,
			Priority: FlowPriority,
			Cookie:   cookie,
			Match: fmt.Sprintf("dl_dst=0e:bf:%02x:%02x:%02x:%02x",
				(i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			Actions: "drop",
		})
	}
	return flows
}
