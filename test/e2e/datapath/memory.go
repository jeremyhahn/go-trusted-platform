package main

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// node is the running gateway the IPC server reports. It holds no state:
// the harness only drives the service verbs.
type node struct{}

func (node) GetState() gateway.GatewayState                      { return gateway.GatewayStateRunning }
func (node) ServiceReports() []gateway.ServiceReport             { return nil }
func (node) Snapshot() *gwstate.Snapshot                         { return &gwstate.Snapshot{} }
func (node) Apply(context.Context, *gwstate.DesiredConfig) error { return nil }
func (node) DesiredConfigState() gwstate.DesiredConfigState {
	var state gwstate.DesiredConfigState
	return state
}

// vipKey identifies a VIP the way the load balancer does: protocol plus
// address:port.
type vipKey struct {
	protocol string
	addr     netip.AddrPort
}

// memoryLB is a mutex-guarded in-memory ipc.LoadBalancer. It validates a
// VIP the way the datapath service does and reports every backend healthy;
// it programs no flows.
type memoryLB struct {
	mu   sync.Mutex
	vips map[vipKey]loadbalancer.VIP
	last time.Time
}

func newMemoryLB() *memoryLB {
	return &memoryLB{vips: map[vipKey]loadbalancer.VIP{}, last: time.Now()}
}

func keyOf(protocol string, addr netip.AddrPort) vipKey {
	return vipKey{protocol: protocol, addr: addr}
}

func cloneVIP(v loadbalancer.VIP) loadbalancer.VIP {
	v.Backends = slices.Clone(v.Backends)
	return v
}

func statusOf(v loadbalancer.VIP) loadbalancer.VIPStatus {
	st := loadbalancer.VIPStatus{VIP: cloneVIP(v)}
	for _, b := range v.Backends {
		st.Backends = append(st.Backends, loadbalancer.BackendStatus{Backend: b, Healthy: true})
	}
	return st
}

func (m *memoryLB) AddVIP(_ context.Context, vip loadbalancer.VIP) error {
	if err := vip.Validate(loadbalancer.DefaultMaxBackends); err != nil {
		return err
	}
	key := keyOf(vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port))
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.vips[key]; ok {
		return loadbalancer.ErrVIPExists
	}
	m.vips[key] = cloneVIP(vip)
	m.last = time.Now()
	return nil
}

func (m *memoryLB) RemoveVIP(_ context.Context, protocol string, addr netip.AddrPort) error {
	key := keyOf(protocol, addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.vips[key]; !ok {
		return loadbalancer.ErrVIPNotFound
	}
	delete(m.vips, key)
	m.last = time.Now()
	return nil
}

func (m *memoryLB) GetVIP(_ context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vips[keyOf(protocol, addr)]
	if !ok {
		return loadbalancer.VIPStatus{}, loadbalancer.ErrVIPNotFound
	}
	return statusOf(v), nil
}

func (m *memoryLB) ListVIPs(context.Context) ([]loadbalancer.VIPStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]loadbalancer.VIPStatus, 0, len(m.vips))
	for _, v := range m.vips {
		out = append(out, statusOf(v))
	}
	slices.SortFunc(out, func(a, b loadbalancer.VIPStatus) int {
		ka := netip.AddrPortFrom(a.VIP.Address, a.VIP.Port)
		kb := netip.AddrPortFrom(b.VIP.Address, b.VIP.Port)
		if c := ka.Compare(kb); c != 0 {
			return c
		}
		switch {
		case a.VIP.Protocol < b.VIP.Protocol:
			return -1
		case a.VIP.Protocol > b.VIP.Protocol:
			return 1
		}
		return 0
	})
	return out, nil
}

func (m *memoryLB) SetVIPBackends(_ context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error {
	key := keyOf(protocol, addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vips[key]
	if !ok {
		return loadbalancer.ErrVIPNotFound
	}
	v.Backends = slices.Clone(backends)
	if err := v.Validate(loadbalancer.DefaultMaxBackends); err != nil {
		return err
	}
	m.vips[key] = v
	m.last = time.Now()
	return nil
}

func (m *memoryLB) LBStatus(context.Context) (loadbalancer.Health, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := loadbalancer.Health{Active: true, VIPCount: len(m.vips), LastReconcile: m.last}
	for _, v := range m.vips {
		h.TotalBackends += len(v.Backends)
	}
	h.HealthyBackends = h.TotalBackends
	return h, nil
}

// memoryNAT64 answers a fixed, idle NAT64 status.
type memoryNAT64 struct{ started time.Time }

func (n memoryNAT64) NAT64Status(context.Context) (nat64.Health, error) {
	return nat64.Health{
		Active:          true,
		InstancePresent: true,
		Prefix:          "64:ff9b::/96",
		Instance:        "e2e",
		LastReconcile:   n.started,
	}, nil
}

// memoryPerf answers fixed perf reads: an empty datapath and conntrack
// table, and a flow run that installs what it is asked to.
type memoryPerf struct{}

func (memoryPerf) Flows(_ context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error) {
	d := time.Millisecond
	return perf.FlowsResult{
		Installed:      count,
		Duration:       d,
		FlowsPerSecond: float64(count) / d.Seconds(),
		Batched:        batch,
		Bridge:         bridge,
	}, nil
}

func (memoryPerf) Datapath(_ context.Context, bridge string) (perf.DatapathResult, error) {
	return perf.DatapathResult{DatapathType: "system", Bridge: bridge}, nil
}

func (memoryPerf) Conntrack(context.Context, int) (perf.ConntrackResult, error) {
	return perf.ConntrackResult{PerZone: map[int]int{}}, nil
}

// services is the in-memory datapath's service set.
func services() ipc.Services {
	return ipc.Services{
		LoadBalancer: newMemoryLB(),
		NAT64:        memoryNAT64{started: time.Now()},
		Perf:         memoryPerf{},
	}
}
