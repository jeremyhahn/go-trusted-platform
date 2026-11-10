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

//go:build linux

package ipc

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// cov964NAT64 is a translator that answers with a fixed health or error,
// as nat64's own NAT64Status does.
type cov964NAT64 struct {
	health nat64.Health
	err    error
}

func (f *cov964NAT64) NAT64Status(context.Context) (nat64.Health, error) {
	if f.err != nil {
		return nat64.Health{}, f.err
	}
	return f.health, nil
}

// cov964ServiceCall is one GatewayServicesService call through the client.
type cov964ServiceCall struct {
	name    string
	service string
	call    func(ctx context.Context, c *Client) error
}

func cov964LoadBalancerAndPerfCalls() []cov964ServiceCall {
	return []cov964ServiceCall{
		{"ListVIPs", gateway.ServiceLoadBalancer, func(ctx context.Context, c *Client) error {
			_, err := c.ListVIPs(ctx)
			return err
		}},
		{"GetVIP", gateway.ServiceLoadBalancer, func(ctx context.Context, c *Client) error {
			_, err := c.GetVIP(ctx, "tcp", testVIP)
			return err
		}},
		{"AddVIP", gateway.ServiceLoadBalancer, func(ctx context.Context, c *Client) error {
			return c.AddVIP(ctx, loadbalancer.VIP{Protocol: "tcp", Address: testVIP.Addr(), Port: testVIP.Port()})
		}},
		{"RemoveVIP", gateway.ServiceLoadBalancer, func(ctx context.Context, c *Client) error {
			return c.RemoveVIP(ctx, "tcp", testVIP)
		}},
		{"SetVIPBackends", gateway.ServiceLoadBalancer, func(ctx context.Context, c *Client) error {
			return c.SetVIPBackends(ctx, "tcp", testVIP, nil)
		}},
		{"Flows", PerfService, func(ctx context.Context, c *Client) error {
			_, err := c.Flows(ctx, "br-int", 10, false)
			return err
		}},
		{"Datapath", PerfService, func(ctx context.Context, c *Client) error {
			_, err := c.Datapath(ctx, "br-int")
			return err
		}},
	}
}

func TestCov964_AProcessHostingNoServiceRefusesEveryCallNotActive(t *testing.T) {
	_, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())

	for _, tc := range cov964LoadBalancerAndPerfCalls() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(testContext(t), client)
			var notActive *gateway.ErrServiceNotActive
			if !errors.As(err, &notActive) || notActive.Service != tc.service {
				t.Fatalf("%s err = %v, want *gateway.ErrServiceNotActive for %s", tc.name, err, tc.service)
			}
			var unreachable *ErrServiceUnreachable
			if errors.As(err, &unreachable) {
				t.Fatalf("%s err = %v, a refusal must not read as an unreachable child", tc.name, err)
			}
		})
	}
}

func TestCov964_AClosedClientReportsEveryServiceUnreachable(t *testing.T) {
	client := serveServices(t, &fakeServices{}, selfPolicy())
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	calls := append(cov964LoadBalancerAndPerfCalls(),
		cov964ServiceCall{"NAT64Status", gateway.ServiceNAT64, func(ctx context.Context, c *Client) error {
			_, err := c.NAT64Status(ctx)
			return err
		}},
		cov964ServiceCall{"Conntrack", PerfService, func(ctx context.Context, c *Client) error {
			_, err := c.Conntrack(ctx, 0)
			return err
		}},
	)
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(context.Background(), client)
			var unreachable *ErrServiceUnreachable
			if !errors.As(err, &unreachable) || unreachable.Service != tc.service || unreachable.Socket == "" {
				t.Fatalf("%s err = %v, want *ErrServiceUnreachable for %s naming the socket", tc.name, err, tc.service)
			}
		})
	}
}

func TestCov964_AMalformedVIPKeyNeverReachesTheLoadBalancer(t *testing.T) {
	fake := &fakeServices{}
	client := serveServices(t, fake, selfPolicy())
	// The zero AddrPort travels as "invalid AddrPort", which the server
	// cannot parse back.
	var invalid netip.AddrPort

	tests := []struct {
		name    string
		call    func() error
		reached func() bool
	}{
		{"RemoveVIP", func() error { return client.RemoveVIP(testContext(t), "tcp", invalid) },
			func() bool { return fake.removedVIP.IsValid() }},
		{"SetVIPBackends", func() error {
			return client.SetVIPBackends(testContext(t), "tcp", invalid, []loadbalancer.Backend{{Address: testVIP.Addr(), Port: testVIP.Port()}})
		}, func() bool { return fake.setBackends != nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			var remote *ErrRemoteService
			if !errors.As(err, &remote) || !strings.Contains(remote.Message, `VIP address "invalid AddrPort"`) {
				t.Fatalf("%s err = %v, want the VIP key refusal", tc.name, err)
			}
			if tc.reached() {
				t.Fatalf("%s: a malformed VIP key reached the load balancer", tc.name)
			}
		})
	}
}

func TestCov964_AMalformedBackendsDocumentIsRefused(t *testing.T) {
	fake := &fakeServices{}
	client := serveServices(t, fake, selfPolicy())

	resp, err := client.services.SetVIPBackends(testContext(t), &ipcv1.SetVIPBackendsRequest{
		Vip:          vipKey("tcp", testVIP),
		BackendsJson: []byte("[{"),
	})
	if err != nil {
		t.Fatalf("SetVIPBackends RPC: %v", err)
	}
	var remote *ErrRemoteService
	if !errors.As(errorForRefusal(resp.GetRefusal()), &remote) || !strings.Contains(remote.Message, "VIP backends document") {
		t.Fatalf("SetVIPBackends refusal = %v, want the VIP backends document error", resp.GetRefusal())
	}
	if fake.setBackends != nil {
		t.Fatal("a malformed backends document reached the load balancer")
	}
}

func TestCov964_NAT64StatusCarriesTheRefusalAndAHealthyStatus(t *testing.T) {
	translator := &cov964NAT64{}
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	srv.SetServices(Services{NAT64: translator})

	translator.err = &gateway.ErrServiceNotActive{Service: gateway.ServiceNAT64}
	_, err := client.NAT64Status(testContext(t))
	var notActive *gateway.ErrServiceNotActive
	if !errors.As(err, &notActive) || notActive.Service != gateway.ServiceNAT64 {
		t.Fatalf("NAT64Status err = %v, want the translator's *gateway.ErrServiceNotActive", err)
	}
	var unreachable *ErrServiceUnreachable
	if errors.As(err, &unreachable) {
		t.Fatalf("NAT64Status err = %v, a refusal must not read as an unreachable child", err)
	}

	translator.err = nil
	translator.health = nat64.Health{Active: true, Prefix: "64:ff9b::/96", Sessions: 3}
	health, err := client.NAT64Status(testContext(t))
	if err != nil {
		t.Fatalf("NAT64Status: %v", err)
	}
	if !health.Active || health.Prefix != "64:ff9b::/96" || health.Sessions != 3 {
		t.Fatalf("NAT64Status = %+v, want the translator's health", health)
	}
	if health.LastError != nil {
		t.Fatalf("NAT64Status LastError = %v, want nil for a health without an error", health.LastError)
	}
}

func TestCov964_ResultDocumentsThatCannotBeCodedAreTypedErrors(t *testing.T) {
	body, refusal := encodeResult(math.NaN(), nil)
	if body != nil {
		t.Fatalf("encodeResult(NaN) body = %q, want none", body)
	}
	var remote *ErrRemoteService
	if !errors.As(errorForRefusal(refusal), &remote) || !strings.Contains(remote.Message, "service result document") {
		t.Fatalf("encodeResult(NaN) refusal = %v, want the service result document error", refusal)
	}

	_, err := decodeResult[loadbalancer.VIPStatus]([]byte("{"), nil, "VIP status")
	var document *ErrDocument
	if !errors.As(err, &document) || document.Document != "VIP status" {
		t.Fatalf("decodeResult err = %v, want *ErrDocument for the VIP status", err)
	}
}

func TestCov964_ControlCallsOnAClosedClientCarryTheTransportError(t *testing.T) {
	node := &fakeNode{state: gateway.GatewayStateRunning}
	_, client := serve(t, node, selfPolicy())
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := client.Snapshot(context.Background()); status.Code(err) != codes.Canceled {
		t.Fatalf("Snapshot err = %v, want the closed connection's Canceled", err)
	}
	if _, err := client.ApplyDesired(context.Background(), &gwstate.DesiredConfig{}); status.Code(err) != codes.Canceled {
		t.Fatalf("ApplyDesired err = %v, want the closed connection's Canceled", err)
	}
	if node.applied != nil {
		t.Fatal("ApplyDesired reached the node over a closed connection")
	}
}

func TestCov964_ApplyDesiredRefusesAMalformedDocument(t *testing.T) {
	node := &fakeNode{state: gateway.GatewayStateRunning}
	srv := NewServer(node, selfPolicy())

	_, err := srv.ApplyDesired(context.Background(), &ipcv1.ApplyDesiredRequest{DesiredJson: []byte("{")})
	var document *ErrDocument
	if !errors.As(err, &document) || document.Document != "desired config" {
		t.Fatalf("ApplyDesired err = %v, want *ErrDocument for the desired config", err)
	}
	if node.applied != nil {
		t.Fatal("a malformed desired config reached the node")
	}
}

func TestCov964_AddrNamesTheListeningSocket(t *testing.T) {
	if addr := NewServer(&fakeNode{}, selfPolicy()).Addr(); addr != "" {
		t.Fatalf("Addr before Listen = %q, want empty", addr)
	}

	srv, _ := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	if addr := srv.Addr(); filepath.Base(addr) != "p.sock" {
		t.Fatalf("Addr = %q, want the listening socket path", addr)
	}
}

func TestCov964_ServeReturnsTheListenerFailure(t *testing.T) {
	dir, err := os.MkdirTemp("", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	srv := NewServer(&fakeNode{}, selfPolicy())
	if err := srv.Listen(filepath.Join(dir, "p.sock"), 0o600, -1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(srv.Stop)
	if err := srv.listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	err = srv.Serve()
	var notListening *ErrServerNotListening
	if err == nil || errors.As(err, &notListening) {
		t.Fatalf("Serve err = %v, want the closed listener's accept error", err)
	}
}
