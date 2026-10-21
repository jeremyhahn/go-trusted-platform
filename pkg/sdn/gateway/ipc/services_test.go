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

package ipc

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// fakeServices stands in for the datapath child's load balancer, NAT64
// and perf services; err, when set, is every call's refusal.
type fakeServices struct {
	err error

	addedVIP    loadbalancer.VIP
	removedVIP  netip.AddrPort
	setBackends []loadbalancer.Backend
	flowsCount  int
	ctZone      int
}

func (f *fakeServices) AddVIP(_ context.Context, vip loadbalancer.VIP) error {
	f.addedVIP = vip
	return f.err
}

func (f *fakeServices) RemoveVIP(_ context.Context, _ string, addr netip.AddrPort) error {
	f.removedVIP = addr
	return f.err
}

func (f *fakeServices) GetVIP(_ context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error) {
	if f.err != nil {
		return loadbalancer.VIPStatus{}, f.err
	}
	return loadbalancer.VIPStatus{VIP: loadbalancer.VIP{Address: addr.Addr(), Port: addr.Port(), Protocol: protocol}, CTZone: 7}, nil
}

func (f *fakeServices) ListVIPs(context.Context) ([]loadbalancer.VIPStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []loadbalancer.VIPStatus{{GroupID: 3}}, nil
}

func (f *fakeServices) SetVIPBackends(_ context.Context, _ string, _ netip.AddrPort, backends []loadbalancer.Backend) error {
	f.setBackends = backends
	return f.err
}

func (f *fakeServices) LBStatus(context.Context) (loadbalancer.Health, error) {
	if f.err != nil {
		return loadbalancer.Health{}, f.err
	}
	return loadbalancer.Health{Active: true, VIPCount: 2, TotalBackends: 4}, nil
}

func (f *fakeServices) NAT64Status(context.Context) (nat64.Health, error) {
	if f.err != nil {
		return nat64.Health{}, f.err
	}
	return nat64.Health{Active: true, Prefix: "64:ff9b::/96", Sessions: 9,
		LastReconcile: time.Unix(1700000000, 0).UTC(), LastError: errors.New("reconcile: module busy")}, nil
}

func (f *fakeServices) Flows(_ context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error) {
	f.flowsCount = count
	if f.err != nil {
		return perf.FlowsResult{}, f.err
	}
	return perf.FlowsResult{Installed: count, Batched: batch, Bridge: bridge}, nil
}

func (f *fakeServices) Datapath(_ context.Context, bridge string) (perf.DatapathResult, error) {
	if f.err != nil {
		return perf.DatapathResult{}, f.err
	}
	return perf.DatapathResult{Bridge: bridge}, nil
}

func (f *fakeServices) Conntrack(_ context.Context, zone int) (perf.ConntrackResult, error) {
	f.ctZone = zone
	if f.err != nil {
		return perf.ConntrackResult{}, f.err
	}
	return perf.ConntrackResult{}, nil
}

func serveServices(t *testing.T, fake *fakeServices, policy Policy) *Client {
	t.Helper()
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, policy)
	srv.SetServices(Services{LoadBalancer: fake, NAT64: fake, Perf: fake})
	return client
}

var testVIP = netip.MustParseAddrPort("10.0.0.10:443")

func TestServices_LiveReadsRoundTrip(t *testing.T) {
	client := serveServices(t, &fakeServices{}, selfPolicy())
	ctx := testContext(t)

	health, err := client.LBStatus(ctx)
	if err != nil || !health.Active || health.VIPCount != 2 || health.TotalBackends != 4 {
		t.Fatalf("LBStatus = %+v, %v", health, err)
	}
	vips, err := client.ListVIPs(ctx)
	if err != nil || len(vips) != 1 || vips[0].GroupID != 3 {
		t.Fatalf("ListVIPs = %+v, %v", vips, err)
	}
	vip, err := client.GetVIP(ctx, "tcp", testVIP)
	if err != nil || vip.VIP.Address != testVIP.Addr() || vip.VIP.Port != 443 || vip.CTZone != 7 {
		t.Fatalf("GetVIP = %+v, %v", vip, err)
	}
	nat, err := client.NAT64Status(ctx)
	if err != nil || !nat.Active || nat.Prefix != "64:ff9b::/96" || nat.Sessions != 9 {
		t.Fatalf("NAT64Status = %+v, %v", nat, err)
	}
	if nat.LastError == nil || nat.LastError.Error() != "reconcile: module busy" {
		t.Fatalf("NAT64Status LastError = %v, want the child's text", nat.LastError)
	}
	if !nat.LastReconcile.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("NAT64Status LastReconcile = %v", nat.LastReconcile)
	}
	flows, err := client.Flows(ctx, "br-test", 50, true)
	if err != nil || flows.Installed != 50 || !flows.Batched || flows.Bridge != "br-test" {
		t.Fatalf("Flows = %+v, %v", flows, err)
	}
	dp, err := client.Datapath(ctx, "br-test")
	if err != nil || dp.Bridge != "br-test" {
		t.Fatalf("Datapath = %+v, %v", dp, err)
	}
	if _, err := client.Conntrack(ctx, 12); err != nil {
		t.Fatalf("Conntrack: %v", err)
	}
}

func TestServices_ControlActionsReachTheService(t *testing.T) {
	fake := &fakeServices{}
	client := serveServices(t, fake, selfPolicy())
	ctx := testContext(t)
	backend := loadbalancer.Backend{Address: netip.MustParseAddr("10.0.1.5"), Port: 8443, Weight: 2}

	add := loadbalancer.VIP{Address: testVIP.Addr(), Port: testVIP.Port(), Protocol: "tcp", Backends: []loadbalancer.Backend{backend}}
	if err := client.AddVIP(ctx, add); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if fake.addedVIP.Address != add.Address || len(fake.addedVIP.Backends) != 1 || fake.addedVIP.Backends[0] != backend {
		t.Fatalf("AddVIP reached the service as %+v", fake.addedVIP)
	}
	if err := client.SetVIPBackends(ctx, "tcp", testVIP, []loadbalancer.Backend{backend}); err != nil {
		t.Fatalf("SetVIPBackends: %v", err)
	}
	if len(fake.setBackends) != 1 || fake.setBackends[0] != backend {
		t.Fatalf("SetVIPBackends reached the service as %+v", fake.setBackends)
	}
	if err := client.RemoveVIP(ctx, "tcp", testVIP); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
	if fake.removedVIP != testVIP {
		t.Fatalf("RemoveVIP reached the service as %v", fake.removedVIP)
	}
}

func TestServices_TheServiceRefusalKeepsItsType(t *testing.T) {
	fake := &fakeServices{err: &perf.ErrBridgeUnavailable{Bridge: "br-x", Cause: errors.New("no such bridge")}}
	client := serveServices(t, fake, selfPolicy())

	_, err := client.Datapath(testContext(t), "br-x")
	var bridge *perf.ErrBridgeUnavailable
	if !errors.As(err, &bridge) || bridge.Bridge != "br-x" {
		t.Fatalf("Datapath err = %v, want *perf.ErrBridgeUnavailable for br-x", err)
	}

	fake.err = loadbalancer.ErrVIPNotFound
	if err := client.RemoveVIP(testContext(t), "tcp", testVIP); !errors.Is(err, loadbalancer.ErrVIPNotFound) {
		t.Fatalf("RemoveVIP err = %v, want ErrVIPNotFound", err)
	}
	if _, err := client.LBStatus(testContext(t)); !errors.Is(err, loadbalancer.ErrVIPNotFound) {
		t.Fatalf("LBStatus err = %v, want ErrVIPNotFound", err)
	}
}

func TestServices_AProcessHostingNoneRefusesNotActive(t *testing.T) {
	_, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	ctx := testContext(t)

	checks := map[string]error{}
	_, checks[gateway.ServiceLoadBalancer] = client.LBStatus(ctx)
	_, checks[gateway.ServiceNAT64] = client.NAT64Status(ctx)
	_, checks[PerfService] = client.Conntrack(ctx, 0)
	for service, err := range checks {
		var notActive *gateway.ErrServiceNotActive
		if !errors.As(err, &notActive) || notActive.Service != service {
			t.Errorf("%s err = %v, want *gateway.ErrServiceNotActive{%s}", service, err, service)
		}
	}
}

func TestServices_AMalformedVIPKeyIsRefused(t *testing.T) {
	client := serveServices(t, &fakeServices{}, selfPolicy())

	resp, err := client.services.GetVIP(testContext(t), &ipcv1.GetVIPRequest{Vip: &ipcv1.VIPKey{Protocol: "tcp", Address: "not-an-address"}})
	if err != nil {
		t.Fatalf("GetVIP RPC: %v", err)
	}
	var remote *ErrRemoteService
	if !errors.As(errorForRefusal(resp.GetRefusal()), &remote) || remote.Message == "" {
		t.Fatalf("GetVIP refusal = %v, want the VIP key error", resp.GetRefusal())
	}
}

func TestServices_AMalformedDocumentIsRefused(t *testing.T) {
	fake := &fakeServices{}
	client := serveServices(t, fake, selfPolicy())

	resp, err := client.services.AddVIP(testContext(t), &ipcv1.AddVIPRequest{VipJson: []byte("{")})
	if err != nil {
		t.Fatalf("AddVIP RPC: %v", err)
	}
	if resp.GetRefusal() == nil {
		t.Fatal("AddVIP accepted a malformed VIP document")
	}
	if fake.addedVIP.Address.IsValid() {
		t.Fatal("a malformed VIP document reached the service")
	}
}

func TestServices_AnUnreachableChildIsServiceNotActive(t *testing.T) {
	client := serveServices(t, &fakeServices{}, selfPolicy())
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := client.LBStatus(context.Background())
	var unreachable *ErrServiceUnreachable
	if !errors.As(err, &unreachable) || unreachable.Socket == "" {
		t.Fatalf("LBStatus err = %v, want *ErrServiceUnreachable naming the socket", err)
	}
	var notActive *gateway.ErrServiceNotActive
	if !errors.As(err, &notActive) || notActive.Service != gateway.ServiceLoadBalancer {
		t.Fatalf("LBStatus err = %v, want it to read as the load balancer not active", err)
	}
}

func TestServices_ValuesTheWireCannotCarryAreRefusedLocally(t *testing.T) {
	fake := &fakeServices{}
	client := serveServices(t, fake, selfPolicy())

	var count *perf.ErrInvalidFlowCount
	if _, err := client.Flows(testContext(t), "", math.MaxInt32+1, false); !errors.As(err, &count) {
		t.Fatalf("Flows err = %v, want *perf.ErrInvalidFlowCount", err)
	}
	var zone *ErrConntrackZone
	if _, err := client.Conntrack(testContext(t), math.MinInt32-1); !errors.As(err, &zone) {
		t.Fatalf("Conntrack err = %v, want *ErrConntrackZone", err)
	}
	if fake.flowsCount != 0 || fake.ctZone != 0 {
		t.Fatal("an out-of-range value reached the service")
	}
}

func TestPolicy_APlatformUIDReachesOnlyTheGatewayServices(t *testing.T) {
	uid := uint32(os.Getuid())
	policy := Policy{ControlUIDs: []uint32{4294967000}, DatapathUIDs: []uint32{4294967001}, PlatformUIDs: []uint32{uid}}
	client := serveServices(t, &fakeServices{}, policy)

	if _, err := client.LBStatus(testContext(t)); err != nil {
		t.Fatalf("LBStatus: %v", err)
	}
	if _, err := client.Status(testContext(t)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Status err = %v, want PermissionDenied", err)
	}
	if _, err := client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("InstallVPNPeer err = %v, want PermissionDenied", err)
	}
}

func TestPolicy_TheGatewayServicesRefuseAnUnlistedUID(t *testing.T) {
	policy := Policy{ControlUIDs: []uint32{4294967000}, DatapathUIDs: []uint32{uint32(os.Getuid())}}
	client := serveServices(t, &fakeServices{}, policy)

	_, err := client.LBStatus(testContext(t))
	var unreachable *ErrServiceUnreachable
	if !errors.As(err, &unreachable) || status.Code(unreachable.Cause) != codes.PermissionDenied {
		t.Fatalf("LBStatus err = %v, want PermissionDenied for a parser uid", err)
	}
}

func TestRefusal_EveryClassRoundTrips(t *testing.T) {
	cases := map[string]error{
		"not active":    &gateway.ErrServiceNotActive{Service: gateway.ServiceNAT64},
		"module":        &nat64.ErrNAT64ModuleUnavailable{Instance: "gw0", Err: errors.New("modprobe failed")},
		"flow count":    &perf.ErrInvalidFlowCount{Count: 0, Max: perf.MaxFlowCount},
		"bridge":        &perf.ErrBridgeUnavailable{Bridge: "br0", Cause: errors.New("gone")},
		"vip not found": loadbalancer.ErrVIPNotFound,
		"nat64 stopped": nat64.ErrNotStarted,
		"appctl":        perf.ErrAppCtlUnavailable,
	}
	for name, sent := range cases {
		got := errorForRefusal(refusalFor(sent))
		if got == nil || got.Error() == "" {
			t.Errorf("%s: rebuilt %v", name, got)
		}
	}

	var module *nat64.ErrNAT64ModuleUnavailable
	if !errors.As(errorForRefusal(refusalFor(cases["module"])), &module) || module.Instance != "gw0" || module.Err.Error() != "modprobe failed" {
		t.Errorf("module refusal rebuilt as %+v", module)
	}
	var count *perf.ErrInvalidFlowCount
	if !errors.As(errorForRefusal(refusalFor(cases["flow count"])), &count) || count.Max != perf.MaxFlowCount {
		t.Errorf("flow count refusal rebuilt as %+v", count)
	}
	for _, s := range sentinelRefusals {
		if !errors.Is(errorForRefusal(refusalFor(s.err)), s.err) {
			t.Errorf("sentinel %v did not survive the wire", s.err)
		}
	}
}

func TestRefusal_NilAndUnknownErrors(t *testing.T) {
	if refusalFor(nil) != nil || errorForRefusal(nil) != nil {
		t.Fatal("no error must encode and decode to none")
	}
	r := refusalFor(errors.New("disk on fire"))
	if r.GetClass() != ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_UNSPECIFIED {
		t.Fatalf("an unclassified error got class %v", r.GetClass())
	}
	var remote *ErrRemoteService
	if err := errorForRefusal(r); !errors.As(err, &remote) || remote.Sentinel != nil || err.Error() != "disk on fire" {
		t.Fatalf("an unclassified refusal rebuilt as %v", err)
	}
}

func TestClampInt32(t *testing.T) {
	cases := map[int]int32{5: 5, math.MaxInt32 + 1: math.MaxInt32, math.MinInt32 - 1: math.MinInt32}
	for in, want := range cases {
		if got := clampInt32(in); got != want {
			t.Errorf("clampInt32(%d) = %d, want %d", in, got, want)
		}
	}
}
