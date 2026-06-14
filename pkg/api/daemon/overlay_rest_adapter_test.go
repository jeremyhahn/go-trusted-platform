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
	"errors"
	"net/netip"
	"testing"
	"time"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// stubOverlayController is defined in overlay_quic_adapter_test.go and shared
// across both REST and QUIC adapter tests in this package.

// =============================================================================
// Status
// =============================================================================

func TestOverlayRESTAdapter_GetOverlayStatus(t *testing.T) {
	t.Run("happy path returns populated status", func(t *testing.T) {
		vtepIP := netip.MustParseAddr("10.0.0.1")
		ctrl := &stubOverlayController{
			running: true,
			cfg: &overlay.Config{
				NodeID:            "test-node",
				VTEPIP:            vtepIP,
				UnderlayInterface: "eth0",
			},
			state: &overlay.State{
				VTEPs:      []overlay.VTEPInfo{{NodeID: "node-1"}},
				VNIs:       []overlay.VNIInfo{{VNI: 100}},
				Tunnels:    []overlay.TunnelInfo{{ID: "t1"}},
				RemoteMACs: []overlay.RemoteMACEntry{{VNI: 100}},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		status, err := a.GetOverlayStatus(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status.NodeID != "test-node" {
			t.Errorf("expected NodeID=test-node, got %q", status.NodeID)
		}
		if status.VTEPIP != "10.0.0.1" {
			t.Errorf("expected VTEPIP=10.0.0.1, got %q", status.VTEPIP)
		}
		if !status.Healthy {
			t.Error("expected Healthy=true")
		}
		if status.VTEPCount != 1 {
			t.Errorf("expected VTEPCount=1, got %d", status.VTEPCount)
		}
		if status.VNICount != 1 {
			t.Errorf("expected VNICount=1, got %d", status.VNICount)
		}
		if status.TunnelCount != 1 {
			t.Errorf("expected TunnelCount=1, got %d", status.TunnelCount)
		}
		if status.RemoteMACCount != 1 {
			t.Errorf("expected RemoteMACCount=1, got %d", status.RemoteMACCount)
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.GetOverlayStatus(context.Background())
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// VTEP operations
// =============================================================================

func TestOverlayRESTAdapter_ListVTEPs(t *testing.T) {
	t.Run("happy path returns vtep slice", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vteps: []overlay.VTEPInfo{
				{NodeID: "n1", IP: netip.MustParseAddr("10.1.0.1"), Healthy: true, TunnelCount: 3},
				{NodeID: "n2", IP: netip.MustParseAddr("10.1.0.2"), Healthy: false, TunnelCount: 0},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		vteps, err := a.ListVTEPs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vteps) != 2 {
			t.Fatalf("expected 2 vteps, got %d", len(vteps))
		}
		if vteps[0].NodeID != "n1" {
			t.Errorf("expected NodeID=n1, got %q", vteps[0].NodeID)
		}
		if !vteps[0].Healthy {
			t.Error("expected vtep[0].Healthy=true")
		}
		if vteps[1].Healthy {
			t.Error("expected vtep[1].Healthy=false")
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.ListVTEPs(context.Background())
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vtepsErr: errors.New("storage failure")}
		a := newOverlayControllerRESTAdapter(ctrl)
		_, err := a.ListVTEPs(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestOverlayRESTAdapter_GetVTEP(t *testing.T) {
	t.Run("happy path returns matching vtep by node id", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vteps: []overlay.VTEPInfo{
				{NodeID: "alpha", IP: netip.MustParseAddr("10.0.0.1"), Healthy: false},
				{NodeID: "beta", IP: netip.MustParseAddr("10.0.0.2"), Healthy: true},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		v, err := a.GetVTEP(context.Background(), "beta")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v.NodeID != "beta" {
			t.Errorf("expected NodeID=beta, got %q", v.NodeID)
		}
		if v.IP != "10.0.0.2" {
			t.Errorf("expected IP=10.0.0.2, got %q", v.IP)
		}
	})

	t.Run("unknown node id returns ErrVTEPNotFound", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vteps: []overlay.VTEPInfo{}}
		a := newOverlayControllerRESTAdapter(ctrl)
		_, err := a.GetVTEP(context.Background(), "ghost")
		var target restapi.ErrVTEPNotFound
		if !errors.As(err, &target) {
			t.Errorf("expected ErrVTEPNotFound, got %T: %v", err, err)
		}
	})

	t.Run("empty node id returns ErrInvalidNodeID", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		_, err := a.GetVTEP(context.Background(), "")
		var target restapi.ErrInvalidNodeID
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidNodeID, got %T: %v", err, err)
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.GetVTEP(context.Background(), "n1")
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// VNI operations
// =============================================================================

func TestOverlayRESTAdapter_ListVNIs(t *testing.T) {
	t.Run("happy path returns vni slice", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vnis: []overlay.VNIInfo{
				{VNI: 1001, VLAN: 10, TunnelCount: 2, MACCount: 4, CreatedAt: time.Now()},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		vnis, err := a.ListVNIs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vnis) != 1 {
			t.Fatalf("expected 1 vni, got %d", len(vnis))
		}
		if vnis[0].Config.VNI != 1001 {
			t.Errorf("expected VNI=1001, got %d", vnis[0].Config.VNI)
		}
		if vnis[0].Config.VLAN != 10 {
			t.Errorf("expected VLAN=10, got %d", vnis[0].Config.VLAN)
		}
		if vnis[0].MACCount != 4 {
			t.Errorf("expected MACCount=4, got %d", vnis[0].MACCount)
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.ListVNIs(context.Background())
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vnisErr: errors.New("datastore failure")}
		a := newOverlayControllerRESTAdapter(ctrl)
		_, err := a.ListVNIs(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestOverlayRESTAdapter_CreateVNI(t *testing.T) {
	t.Run("happy path creates and returns vni", func(t *testing.T) {
		created := &overlay.VNIInfo{VNI: 500, VLAN: 5, CreatedAt: time.Now()}
		ctrl := &stubOverlayController{
			running: true,
			vni:     created,
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		resp, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: 500, VLAN: 5})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Config.VNI != 500 {
			t.Errorf("expected VNI=500, got %d", resp.Config.VNI)
		}
	})

	t.Run("nil config returns ErrInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		_, err := a.CreateVNI(context.Background(), nil)
		var target restapi.ErrInvalidVNI
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidVNI, got %T: %v", err, err)
		}
	})

	t.Run("vni 0 in config returns ErrInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		_, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: 0})
		var target restapi.ErrInvalidVNI
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidVNI, got %T: %v", err, err)
		}
	})

	t.Run("vni exceeding max returns ErrInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		_, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: overlay.MaxVNI + 1})
		var target restapi.ErrInvalidVNI
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidVNI, got %T: %v", err, err)
		}
	})

	t.Run("controller addVNI error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, addVNIErr: errors.New("vni already exists")}
		a := newOverlayControllerRESTAdapter(ctrl)
		_, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: 200})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("fallback minimal response when GetVNI fails after add", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vniErr:  errors.New("not committed yet"),
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		resp, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: 300, VLAN: 3, Name: "test"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Config.VNI != 300 {
			t.Errorf("expected VNI=300, got %d", resp.Config.VNI)
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.CreateVNI(context.Background(), &restapi.VNIConfigRequest{VNI: 100})
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestOverlayRESTAdapter_DeleteVNI(t *testing.T) {
	t.Run("happy path deletes vni", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true}
		a := newOverlayControllerRESTAdapter(ctrl)
		if err := a.DeleteVNI(context.Background(), 100); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("vni 0 returns ErrInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		err := a.DeleteVNI(context.Background(), 0)
		var target restapi.ErrInvalidVNI
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidVNI, got %T: %v", err, err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, removeVNIErr: errors.New("vni not found")}
		a := newOverlayControllerRESTAdapter(ctrl)
		if err := a.DeleteVNI(context.Background(), 100); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		err := a.DeleteVNI(context.Background(), 100)
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// Tunnel operations
// =============================================================================

func TestOverlayRESTAdapter_ListTunnels(t *testing.T) {
	t.Run("happy path returns tunnels from state", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			state: &overlay.State{
				Tunnels: []overlay.TunnelInfo{
					{
						ID:         "tun-1",
						LocalVTEP:  netip.MustParseAddr("10.0.0.1"),
						RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
						VNI:        100,
						BytesTx:    8192,
						BytesRx:    4096,
					},
				},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		tunnels, err := a.ListTunnels(context.Background(), 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tunnels) != 1 {
			t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
		}
		if tunnels[0].VNI != 100 {
			t.Errorf("expected VNI=100, got %d", tunnels[0].VNI)
		}
		if tunnels[0].BytesTx != 8192 {
			t.Errorf("expected BytesTx=8192, got %d", tunnels[0].BytesTx)
		}
	})

	t.Run("vni filter excludes non-matching tunnels", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			state: &overlay.State{
				Tunnels: []overlay.TunnelInfo{
					{ID: "t1", VNI: 100},
					{ID: "t2", VNI: 200},
				},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		tunnels, err := a.ListTunnels(context.Background(), 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tunnels) != 1 {
			t.Fatalf("expected 1 tunnel after filter, got %d", len(tunnels))
		}
		if tunnels[0].VNI != 100 {
			t.Errorf("expected VNI=100, got %d", tunnels[0].VNI)
		}
	})

	t.Run("nil state returns empty slice", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true, state: nil})
		tunnels, err := a.ListTunnels(context.Background(), 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tunnels) != 0 {
			t.Errorf("expected empty slice, got %d tunnels", len(tunnels))
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.ListTunnels(context.Background(), 0)
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// MAC table operations
// =============================================================================

func TestOverlayRESTAdapter_ListRemoteMACs(t *testing.T) {
	t.Run("happy path returns mac entries for specific vni", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			macs: []overlay.RemoteMACEntry{
				{
					VNI:        100,
					RemoteVTEP: netip.MustParseAddr("10.0.0.5"),
					LearnedAt:  time.Now(),
				},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		macs, err := a.ListRemoteMACs(context.Background(), 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(macs) != 1 {
			t.Fatalf("expected 1 mac, got %d", len(macs))
		}
		if macs[0].VNI != 100 {
			t.Errorf("expected VNI=100, got %d", macs[0].VNI)
		}
	})

	t.Run("vni 0 lists all MACs via state (list-all semantics)", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			state: &overlay.State{
				RemoteMACs: []overlay.RemoteMACEntry{
					{VNI: 100},
					{VNI: 200},
				},
			},
		}
		a := newOverlayControllerRESTAdapter(ctrl)
		macs, err := a.ListRemoteMACs(context.Background(), 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(macs) != 2 {
			t.Errorf("expected 2 MACs, got %d", len(macs))
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, macsErr: errors.New("vni not found")}
		a := newOverlayControllerRESTAdapter(ctrl)
		_, err := a.ListRemoteMACs(context.Background(), 100)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		_, err := a.ListRemoteMACs(context.Background(), 0)
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestOverlayRESTAdapter_ForgetMAC(t *testing.T) {
	t.Run("happy path removes mac", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true}
		a := newOverlayControllerRESTAdapter(ctrl)
		if err := a.ForgetMAC(context.Background(), "aa:bb:cc:dd:ee:ff", 100); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty mac returns ErrInvalidMAC", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		err := a.ForgetMAC(context.Background(), "", 100)
		var target restapi.ErrInvalidMAC
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidMAC, got %T: %v", err, err)
		}
	})

	t.Run("invalid mac format returns ErrInvalidMAC", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: true})
		err := a.ForgetMAC(context.Background(), "not-a-mac", 100)
		var target restapi.ErrInvalidMAC
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidMAC, got %T: %v", err, err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, forgetMACErr: errors.New("mac not found")}
		a := newOverlayControllerRESTAdapter(ctrl)
		if err := a.ForgetMAC(context.Background(), "aa:bb:cc:dd:ee:ff", 100); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerRESTAdapter(&stubOverlayController{running: false})
		err := a.ForgetMAC(context.Background(), "aa:bb:cc:dd:ee:ff", 100)
		var target restapi.ErrOverlayServiceNotAvailable
		if !errors.As(err, &target) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// Error mapping
// =============================================================================

func TestMapOverlayToRESTError(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantNil bool
		checkFn func(err error) bool
	}{
		{
			name:    "nil passthrough",
			err:     nil,
			wantNil: true,
		},
		{
			name: "vtep not found",
			err:  errors.New("vtep not found for node x"),
			checkFn: func(err error) bool {
				var e restapi.ErrVTEPNotFound
				return errors.As(err, &e)
			},
		},
		{
			name: "vni not found",
			err:  errors.New("vni not found: 100"),
			checkFn: func(err error) bool {
				var e restapi.ErrVNINotFound
				return errors.As(err, &e)
			},
		},
		{
			name: "mac not found",
			err:  errors.New("mac address not found"),
			checkFn: func(err error) bool {
				var e restapi.ErrMACNotFound
				return errors.As(err, &e)
			},
		},
		{
			name: "vni already exists",
			err:  errors.New("vni already exists: 200"),
			checkFn: func(err error) bool {
				var e restapi.ErrVNIAlreadyExists
				return errors.As(err, &e)
			},
		},
		{
			name: "not running passes through as ErrOverlayServiceNotAvailable",
			err:  errors.New("overlay is not running"),
			checkFn: func(err error) bool {
				var e restapi.ErrOverlayServiceNotAvailable
				return errors.As(err, &e)
			},
		},
		{
			name: "unknown error passes through unchanged",
			err:  errors.New("connection timeout"),
			checkFn: func(err error) bool {
				return err != nil && err.Error() == "connection timeout"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapOverlayToRESTError(tc.err)
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil error, got nil")
			}
			if tc.checkFn != nil && !tc.checkFn(got) {
				t.Errorf("error check failed for %q: got %T %v", tc.name, got, got)
			}
		})
	}
}
