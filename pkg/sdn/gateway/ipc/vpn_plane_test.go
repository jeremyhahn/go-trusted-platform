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
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// childPlane is the datapath child's MASQUE plane: it records the peers the
// supervisor side installs and refuses with installErr.
type childPlane struct {
	installErr error
	installed  map[vpn.LeaseID]vpn.Lease
	removed    []vpn.LeaseID
}

func (p *childPlane) Kind() vpn.DataPlaneKind { return vpn.DataPlaneMASQUE }

func (p *childPlane) InstallPeer(_ context.Context, lease *vpn.Lease) error {
	if p.installErr != nil {
		return p.installErr
	}
	p.installed[lease.ID] = *lease
	return nil
}

func (p *childPlane) RemovePeer(_ context.Context, id vpn.LeaseID) error {
	delete(p.installed, id)
	p.removed = append(p.removed, id)
	return nil
}

func (p *childPlane) Start(context.Context) error { return nil }
func (p *childPlane) Stop(context.Context) error  { return nil }

// datapathPlaneOver is a MASQUE vpn.DatapathPlane reaching plane through a
// real gateway socket, the way the supervisor reaches the datapath child.
func datapathPlaneOver(t *testing.T, plane *childPlane, policy Policy) *vpn.DatapathPlane {
	t.Helper()
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, policy)
	host, err := vpn.NewPlaneHost(plane)
	if err != nil {
		t.Fatalf("NewPlaneHost: %v", err)
	}
	srv.SetVPNPlanes(host)
	p, err := vpn.NewDatapathPlane(vpn.DataPlaneMASQUE, client)
	if err != nil {
		t.Fatalf("NewDatapathPlane: %v", err)
	}
	return p
}

func testLease() *vpn.Lease {
	return &vpn.Lease{
		ID:        "l1",
		DataPlane: vpn.DataPlaneMASQUE,
		Address:   netip.MustParsePrefix("100.64.0.7/32"),
		Keys:      vpn.PeerKeys{ClientCertificateSHA256: []byte{0xab, 0xcd}},
	}
}

func TestDatapathPlane_RoundTripsThroughTheChild(t *testing.T) {
	plane := &childPlane{installed: map[vpn.LeaseID]vpn.Lease{}}
	p := datapathPlaneOver(t, plane, selfPolicy())

	if err := p.InstallPeer(testContext(t), testLease()); err != nil {
		t.Fatalf("InstallPeer: %v", err)
	}
	got, ok := plane.installed["l1"]
	if !ok || got.Address != testLease().Address || string(got.Keys.ClientCertificateSHA256) != "\xab\xcd" {
		t.Fatalf("child plane saw %+v (installed %v)", got, ok)
	}
	if err := p.RemovePeer(testContext(t), "l1"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if len(plane.removed) != 1 || plane.removed[0] != "l1" {
		t.Fatalf("child plane removed %v", plane.removed)
	}
}

func TestDatapathPlane_ChildRefusalComesBackTyped(t *testing.T) {
	plane := &childPlane{
		installed:  map[vpn.LeaseID]vpn.Lease{},
		installErr: &vpn.ErrPeerConflict{Kind: vpn.DataPlaneMASQUE, LeaseID: "l1", Existing: "l0", Reason: "the address is already bound"},
	}
	p := datapathPlaneOver(t, plane, selfPolicy())

	var conflict *vpn.ErrPeerConflict
	err := p.InstallPeer(testContext(t), testLease())
	if !errors.As(err, &conflict) || conflict.Existing != "l0" || conflict.LeaseID != "l1" {
		t.Fatalf("InstallPeer = %v, want the child's ErrPeerConflict", err)
	}
}

// A socket nobody listens on is a refusal, never an admit.
func TestDatapathPlane_UnreachableChildRefuses(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	client, err := Dial(filepath.Join(dir, "absent.sock"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	p, err := vpn.NewDatapathPlane(vpn.DataPlaneMASQUE, client)
	if err != nil {
		t.Fatalf("NewDatapathPlane: %v", err)
	}

	var unavailable *vpn.ErrDataPlaneUnavailable
	if err := p.InstallPeer(testContext(t), testLease()); !errors.As(err, &unavailable) || unavailable.Cause == nil {
		t.Fatalf("InstallPeer = %v, want ErrDataPlaneUnavailable with the RPC cause", err)
	}
	if err := p.RemovePeer(testContext(t), "l1"); !errors.As(err, &unavailable) {
		t.Fatalf("RemovePeer = %v, want ErrDataPlaneUnavailable", err)
	}
}

// A caller the policy does not admit is refused the same way.
func TestDatapathPlane_UnadmittedCallerRefuses(t *testing.T) {
	plane := &childPlane{installed: map[vpn.LeaseID]vpn.Lease{}}
	p := datapathPlaneOver(t, plane, Policy{ControlUIDs: []uint32{4294967000}, DatapathUIDs: []uint32{4294967000}})

	var unavailable *vpn.ErrDataPlaneUnavailable
	if err := p.InstallPeer(testContext(t), testLease()); !errors.As(err, &unavailable) {
		t.Fatalf("InstallPeer = %v, want ErrDataPlaneUnavailable", err)
	}
	if len(plane.installed) != 0 {
		t.Fatalf("child plane installed %v for an unadmitted caller", plane.installed)
	}
}
