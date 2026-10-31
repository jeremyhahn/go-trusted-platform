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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// reconcileGatewayConfig runs the load balancer and NAT together on the
// fake runtime so Apply has both sections' services to drive.
func reconcileGatewayConfig() *GatewayConfig {
	cfg := lbGatewayConfig()
	cfg.ID = "reconcile-gw"
	cfg.Uplinks = []UplinkConfig{{Name: "eth0", MTU: 1500}}
	cfg.NAT = &NATConfig{
		Enabled:        true,
		ExternalIP:     "203.0.113.10",
		PortRangeStart: 1024,
		PortRangeEnd:   65535,
		MaxSessions:    1000,
		InternalCIDR:   "10.0.100.0/24",
	}
	return cfg
}

func desiredDoc(version string) *gwstate.DesiredConfig {
	return &gwstate.DesiredConfig{
		GatewayID: "reconcile-gw",
		Version:   version,
		LoadBalancer: &gwstate.DesiredLoadBalancer{VIPs: []gwstate.DesiredVIP{
			{Address: "10.100.0.10", Port: 443, Protocol: "tcp",
				Backends: []gwstate.DesiredBackend{{Address: "10.0.1.5", Port: 8443, Weight: 2}, {Address: "10.0.1.6", Port: 8443}}},
			{Address: "10.100.0.20", Port: 80, Protocol: "tcp",
				Backends: []gwstate.DesiredBackend{{Address: "10.0.1.7", Port: 8080}}},
		}},
		NAT: &gwstate.DesiredNAT{
			SNATInternalCIDR: "10.0.100.0/24",
			DNAT:             []gwstate.DesiredDNAT{{Protocol: "tcp", External: "203.0.113.10:2222", Internal: "10.0.100.5:22"}},
		},
	}
}

func vipAddrs(gw *Gateway) map[string]int {
	out := map[string]int{}
	svc, ok := gw.LBService()
	if !ok {
		return out
	}
	for _, s := range svc.ListVIPs() {
		out[netip.AddrPortFrom(s.VIP.Address, s.VIP.Port).String()] = len(s.VIP.Backends)
	}
	return out
}

func TestApply_BringsServicesToTheDesiredState(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	gw.desired.now = func() time.Time { return now }

	require.NoError(t, gw.Apply(context.Background(), desiredDoc("rev-1")))

	state := gw.DesiredConfigState()
	assert.Equal(t, "rev-1", state.Version)
	assert.Equal(t, now, state.AppliedAt)
	assert.Empty(t, state.LastError)
	assert.Equal(t, map[string]int{"10.100.0.10:443": 2, "10.100.0.20:80": 1}, vipAddrs(gw))

	nat, ok := gw.NATService()
	require.True(t, ok)
	prefix, enabled := nat.SNATPrefix()
	assert.True(t, enabled)
	assert.Equal(t, "10.0.100.0/24", prefix.String())
	rules := nat.DNATRules()
	require.Len(t, rules, 1)
	assert.Equal(t, "10.0.100.5:22", rules[0].Internal.String())

	// The snapshot carries the state.
	assert.Equal(t, "rev-1", gw.Snapshot().DesiredConfig.Version)
}

func TestApply_SameVersionIsANoOp(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	require.NoError(t, gw.Apply(context.Background(), desiredDoc("rev-1")))
	applied := gw.DesiredConfigState().AppliedAt

	// A document with the same version but different content is not
	// re-applied: the version is the control plane's contract.
	changed := desiredDoc("rev-1")
	changed.LoadBalancer.VIPs = changed.LoadBalancer.VIPs[:1]
	require.NoError(t, gw.Apply(context.Background(), changed))
	assert.Equal(t, applied, gw.DesiredConfigState().AppliedAt)
	assert.Len(t, vipAddrs(gw), 2, "the same version must not be re-applied")
}

func TestApply_ContentVersionDrivesReapplyWhenUnset(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	first := desiredDoc("")
	require.NoError(t, gw.Apply(context.Background(), first))
	assert.Equal(t, first.ContentVersion(), gw.DesiredConfigState().Version)

	second := desiredDoc("")
	second.LoadBalancer.VIPs = second.LoadBalancer.VIPs[:1]
	require.NoError(t, gw.Apply(context.Background(), second))
	assert.Equal(t, second.ContentVersion(), gw.DesiredConfigState().Version)
	assert.Equal(t, map[string]int{"10.100.0.10:443": 2}, vipAddrs(gw), "the removed VIP is gone")
}

func TestApply_ChangesBackendsAlgorithmAndNAT(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	require.NoError(t, gw.Apply(context.Background(), desiredDoc("rev-1")))

	next := desiredDoc("rev-2")
	next.LoadBalancer.VIPs[0].Backends = []gwstate.DesiredBackend{{Address: "10.0.1.9", Port: 8443}}
	next.LoadBalancer.VIPs[1].Algorithm = "round-robin"
	next.NAT.SNATInternalCIDR = "10.0.101.0/24"
	next.NAT.DNAT = []gwstate.DesiredDNAT{
		{Protocol: "tcp", External: "203.0.113.10:2222", Internal: "10.0.100.6:22"}, // retargeted
		{Protocol: "udp", External: "203.0.113.10:5353", Internal: "10.0.100.7:53"}, // new
	}
	require.NoError(t, gw.Apply(context.Background(), next))

	assert.Equal(t, map[string]int{"10.100.0.10:443": 1, "10.100.0.20:80": 1}, vipAddrs(gw))
	svc, _ := gw.LBService()
	status, err := svc.GetVIP("tcp", netip.MustParseAddrPort("10.100.0.20:80"))
	require.NoError(t, err)
	assert.Equal(t, "round-robin", status.VIP.Algorithm)

	nat, _ := gw.NATService()
	prefix, enabled := nat.SNATPrefix()
	assert.True(t, enabled)
	assert.Equal(t, "10.0.101.0/24", prefix.String())
	targets := map[string]string{}
	for _, r := range nat.DNATRules() {
		targets[r.Protocol+"/"+r.External.String()] = r.Internal.String()
	}
	assert.Equal(t, map[string]string{"tcp/203.0.113.10:2222": "10.0.100.6:22", "udp/203.0.113.10:5353": "10.0.100.7:53"}, targets)

	// Disabling SNAT and clearing DNAT is a state too.
	off := desiredDoc("rev-3")
	off.NAT = &gwstate.DesiredNAT{}
	require.NoError(t, gw.Apply(context.Background(), off))
	_, enabled = nat.SNATPrefix()
	assert.False(t, enabled)
	assert.Empty(t, nat.DNATRules())
}

func TestApply_SectionForAnInactiveServiceIsATypedError(t *testing.T) {
	cfg := reconcileGatewayConfig()
	cfg.NAT = nil
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	err := gw.Apply(context.Background(), desiredDoc("rev-1"))
	var failed *ErrDesiredApplyFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, gwstate.SectionNAT, failed.Section)
	var inactive *ErrServiceNotActive
	assert.True(t, errors.As(err, &inactive))

	state := gw.DesiredConfigState()
	assert.Empty(t, state.Version, "a partially applied version is not recorded as applied")
	assert.Contains(t, state.LastError, "nat")
	assert.False(t, state.AttemptedAt.IsZero())
	// The section that could be applied was applied.
	assert.Len(t, vipAddrs(gw), 2)
}

// TestApply_AChildAppliesOnlyTheSectionsOfItsServices: the supervisor sends
// the vpn child the whole document (#557); the load-balancer and NAT sections
// belong to the datapath child, so the vpn child leaves them alone rather than
// failing them as inactive services.
func TestApply_AChildAppliesOnlyTheSectionsOfItsServices(t *testing.T) {
	cfg := reconcileGatewayConfig()
	cfg.HostedServices = []string{ServiceManagementVPN}
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	require.NoError(t, gw.Apply(context.Background(), desiredDoc("rev-1")))
	state := gw.DesiredConfigState()
	assert.Equal(t, "rev-1", state.Version)
	assert.Empty(t, state.LastError)
	assert.Empty(t, vipAddrs(gw), "no load balancer runs in this child")
	_, natActive := gw.NATService()
	assert.False(t, natActive, "no NAT runs in this child")
}

func TestApply_RejectsAnInvalidDocument(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	bad := desiredDoc("rev-1")
	bad.NAT.DNAT[0].External = "nope"
	err := gw.Apply(context.Background(), bad)
	require.True(t, gwstate.IsDesiredConfigRejection(err), "got %v", err)
	assert.Contains(t, gw.DesiredConfigState().LastError, "nat.dnat[0].external")
	assert.Empty(t, gw.DesiredConfigState().Version)
}

func TestApply_EmptyDocumentTouchesNothing(t *testing.T) {
	gw := startGateway(t, reconcileGatewayConfig())
	defer gw.Stop(context.Background())
	before := vipAddrs(gw)
	require.NoError(t, gw.Apply(context.Background(), &gwstate.DesiredConfig{GatewayID: "reconcile-gw", Version: "empty"}))
	assert.Equal(t, before, vipAddrs(gw))
	assert.Equal(t, "empty", gw.DesiredConfigState().Version)
}
