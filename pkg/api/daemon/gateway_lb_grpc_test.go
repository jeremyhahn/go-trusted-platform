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

package daemon

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeGatewayLB is an in-memory GatewayLoadBalancerInterface.
type fakeGatewayLB struct {
	vips   map[string]loadbalancer.VIPStatus
	health loadbalancer.Health
	err    error
}

func newFakeGatewayLB() *fakeGatewayLB {
	return &fakeGatewayLB{
		vips: make(map[string]loadbalancer.VIPStatus),
		health: loadbalancer.Health{
			Active:        true,
			LastReconcile: time.Now(),
		},
	}
}

func lbKey(protocol string, addr netip.AddrPort) string {
	return protocol + "/" + addr.String()
}

func (f *fakeGatewayLB) AddVIP(ctx context.Context, vip loadbalancer.VIP) error {
	if f.err != nil {
		return f.err
	}
	key := lbKey(vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port))
	if _, exists := f.vips[key]; exists {
		return loadbalancer.ErrVIPExists
	}
	statusEntry := loadbalancer.VIPStatus{VIP: vip, CTZone: 9, GroupID: 0x4C420001}
	for _, b := range vip.Backends {
		statusEntry.Backends = append(statusEntry.Backends, loadbalancer.BackendStatus{Backend: b, Healthy: true})
	}
	f.vips[key] = statusEntry
	return nil
}

func (f *fakeGatewayLB) RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error {
	if f.err != nil {
		return f.err
	}
	key := lbKey(protocol, addr)
	if _, exists := f.vips[key]; !exists {
		return loadbalancer.ErrVIPNotFound
	}
	delete(f.vips, key)
	return nil
}

func (f *fakeGatewayLB) GetVIP(ctx context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error) {
	if f.err != nil {
		return loadbalancer.VIPStatus{}, f.err
	}
	vip, exists := f.vips[lbKey(protocol, addr)]
	if !exists {
		return loadbalancer.VIPStatus{}, loadbalancer.ErrVIPNotFound
	}
	return vip, nil
}

func (f *fakeGatewayLB) ListVIPs(ctx context.Context) ([]loadbalancer.VIPStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]loadbalancer.VIPStatus, 0, len(f.vips))
	for _, vip := range f.vips {
		out = append(out, vip)
	}
	return out, nil
}

func (f *fakeGatewayLB) SetVIPBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error {
	if f.err != nil {
		return f.err
	}
	key := lbKey(protocol, addr)
	vip, exists := f.vips[key]
	if !exists {
		return loadbalancer.ErrVIPNotFound
	}
	vip.VIP.Backends = backends
	vip.Backends = nil
	for _, b := range backends {
		vip.Backends = append(vip.Backends, loadbalancer.BackendStatus{Backend: b, Healthy: true})
	}
	f.vips[key] = vip
	return nil
}

func (f *fakeGatewayLB) LBStatus(ctx context.Context) (loadbalancer.Health, error) {
	if f.err != nil {
		return loadbalancer.Health{}, f.err
	}
	health := f.health
	health.VIPCount = len(f.vips)
	for _, vip := range f.vips {
		health.TotalBackends += len(vip.VIP.Backends)
		health.HealthyBackends += len(vip.VIP.Backends)
	}
	return health, nil
}

// newLBGatewayService builds a GatewayService with a fake LB backend.
func newLBGatewayService() (*GatewayService, *fakeGatewayLB) {
	lb := newFakeGatewayLB()
	return NewGatewayService(WithLoadBalancer(lb)), lb
}

// testVIPProto builds a valid proto VIP config.
func testVIPProto() *platformv1.VIPConfig {
	return &platformv1.VIPConfig{
		Address:  "10.100.0.10",
		Port:     443,
		Protocol: "tcp",
		Backends: []*platformv1.VIPBackend{
			{Address: "10.0.1.5", Port: 8443, Weight: 2},
			{Address: "10.0.1.6", Port: 8443},
		},
	}
}

// wantCode asserts a gRPC status code.
func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error %v is not a gRPC status", err)
	}
	if st.Code() != want {
		t.Fatalf("code = %v, want %v (%v)", st.Code(), want, err)
	}
}

func TestGRPCAddVIP(t *testing.T) {
	svc, lb := newLBGatewayService()
	ctx := context.Background()

	resp, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()})
	if err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("Success = false")
	}
	if resp.GetVip().GetVip().GetAddress() != "10.100.0.10" {
		t.Errorf("vip = %+v", resp.GetVip())
	}
	if len(lb.vips) != 1 {
		t.Errorf("stored vips = %d", len(lb.vips))
	}

	// Duplicate maps to AlreadyExists.
	_, err = svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()})
	wantCode(t, err, codes.AlreadyExists)
}

func TestGRPCAddVIPValidation(t *testing.T) {
	svc, _ := newLBGatewayService()
	ctx := context.Background()

	tests := []struct {
		name   string
		mutate func(*platformv1.VIPConfig)
	}{
		{"missing protocol", func(v *platformv1.VIPConfig) { v.Protocol = "" }},
		{"missing address", func(v *platformv1.VIPConfig) { v.Address = "" }},
		{"invalid address", func(v *platformv1.VIPConfig) { v.Address = "bogus" }},
		{"zero port", func(v *platformv1.VIPConfig) { v.Port = 0 }},
		{"port overflow", func(v *platformv1.VIPConfig) { v.Port = 70000 }},
		{"bad backend address", func(v *platformv1.VIPConfig) { v.Backends[0].Address = "bogus" }},
		{"bad backend port", func(v *platformv1.VIPConfig) { v.Backends[0].Port = 0 }},
		{"backend weight overflow", func(v *platformv1.VIPConfig) { v.Backends[0].Weight = 70000 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vip := testVIPProto()
			tt.mutate(vip)
			_, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: vip})
			wantCode(t, err, codes.InvalidArgument)
		})
	}

	t.Run("nil vip", func(t *testing.T) {
		_, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{})
		wantCode(t, err, codes.InvalidArgument)
	})
}

func TestGRPCAddVIPNoBackend(t *testing.T) {
	svc := NewGatewayService()
	_, err := svc.AddVIP(context.Background(), &platformv1.AddVIPRequest{Vip: testVIPProto()})
	wantCode(t, err, codes.Unavailable)
}

func TestGRPCRemoveVIP(t *testing.T) {
	svc, _ := newLBGatewayService()
	ctx := context.Background()

	if _, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()}); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	resp, err := svc.RemoveVIP(ctx, &platformv1.RemoveVIPRequest{
		Protocol: "tcp", Address: "10.100.0.10", Port: 443,
	})
	if err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("Success = false")
	}

	_, err = svc.RemoveVIP(ctx, &platformv1.RemoveVIPRequest{
		Protocol: "tcp", Address: "10.100.0.10", Port: 443,
	})
	wantCode(t, err, codes.NotFound)

	_, err = svc.RemoveVIP(ctx, &platformv1.RemoveVIPRequest{Protocol: "tcp"})
	wantCode(t, err, codes.InvalidArgument)
}

func TestGRPCGetVIPAndList(t *testing.T) {
	svc, _ := newLBGatewayService()
	ctx := context.Background()

	if _, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()}); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}

	get, err := svc.GetVIP(ctx, &platformv1.GetVIPRequest{
		Protocol: "tcp", Address: "10.100.0.10", Port: 443,
	})
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if get.GetVip().GetCtZone() != 9 || get.GetVip().GetGroupId() != 0x4C420001 {
		t.Errorf("vip = %+v", get.GetVip())
	}
	if len(get.GetVip().GetBackends()) != 2 {
		t.Errorf("backends = %d", len(get.GetVip().GetBackends()))
	}

	list, err := svc.ListVIPs(ctx, &platformv1.ListVIPsRequest{})
	if err != nil {
		t.Fatalf("ListVIPs: %v", err)
	}
	if len(list.GetVips()) != 1 {
		t.Errorf("vips = %d", len(list.GetVips()))
	}

	_, err = svc.GetVIP(ctx, &platformv1.GetVIPRequest{
		Protocol: "tcp", Address: "10.9.9.9", Port: 1,
	})
	wantCode(t, err, codes.NotFound)
}

func TestGRPCSetVIPBackends(t *testing.T) {
	svc, _ := newLBGatewayService()
	ctx := context.Background()

	if _, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()}); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}

	resp, err := svc.SetVIPBackends(ctx, &platformv1.SetVIPBackendsRequest{
		Protocol: "tcp", Address: "10.100.0.10", Port: 443,
		Backends: []*platformv1.VIPBackend{{Address: "10.0.1.9", Port: 9000, Weight: 3}},
	})
	if err != nil {
		t.Fatalf("SetVIPBackends: %v", err)
	}
	if len(resp.GetVip().GetVip().GetBackends()) != 1 {
		t.Errorf("backends = %+v", resp.GetVip().GetVip().GetBackends())
	}

	_, err = svc.SetVIPBackends(ctx, &platformv1.SetVIPBackendsRequest{
		Protocol: "tcp", Address: "10.100.0.10", Port: 443,
		Backends: []*platformv1.VIPBackend{{Address: "bogus", Port: 9000}},
	})
	wantCode(t, err, codes.InvalidArgument)

	_, err = svc.SetVIPBackends(ctx, &platformv1.SetVIPBackendsRequest{
		Protocol: "tcp", Address: "10.9.9.9", Port: 1,
		Backends: []*platformv1.VIPBackend{{Address: "10.0.1.9", Port: 9000}},
	})
	wantCode(t, err, codes.NotFound)
}

func TestGRPCGetLBStatus(t *testing.T) {
	svc, _ := newLBGatewayService()
	ctx := context.Background()

	if _, err := svc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: testVIPProto()}); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}

	resp, err := svc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	if err != nil {
		t.Fatalf("GetLBStatus: %v", err)
	}
	if !resp.GetStatus().GetActive() || resp.GetStatus().GetVipCount() != 1 ||
		resp.GetStatus().GetTotalBackends() != 2 {
		t.Errorf("status = %+v", resp.GetStatus())
	}
	if resp.GetStatus().GetLastReconcile() == nil {
		t.Error("LastReconcile not set")
	}
}

func TestGRPCLBServiceNotActive(t *testing.T) {
	svc, lb := newLBGatewayService()
	lb.err = loadbalancer.ErrNotStarted
	ctx := context.Background()

	_, err := svc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	wantCode(t, err, codes.Unavailable)

	_, err = svc.ListVIPs(ctx, &platformv1.ListVIPsRequest{})
	wantCode(t, err, codes.Unavailable)
}
