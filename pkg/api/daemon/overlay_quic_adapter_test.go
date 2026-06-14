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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// =============================================================================
// Stub controller for unit tests
// =============================================================================

// stubOverlayController implements OverlayControllerInterface for unit tests.
// All method behaviours can be configured per test case.
type stubOverlayController struct {
	running      bool
	state        *overlay.State
	cfg          *overlay.Config
	vteps        []overlay.VTEPInfo
	vtepsErr     error
	vtep         *overlay.VTEPInfo
	vtepErr      error
	vnis         []overlay.VNIInfo
	vnisErr      error
	vni          *overlay.VNIInfo
	vniErr       error
	addVNIErr    error
	removeVNIErr error
	macs         []overlay.RemoteMACEntry
	macsErr      error
	forgetMACErr error
}

func (s *stubOverlayController) IsRunning() bool            { return s.running }
func (s *stubOverlayController) GetState() *overlay.State   { return s.state }
func (s *stubOverlayController) GetConfig() *overlay.Config { return s.cfg }
func (s *stubOverlayController) Uptime() time.Duration      { return 0 }
func (s *stubOverlayController) ListVTEPs(_ context.Context) ([]overlay.VTEPInfo, error) {
	return s.vteps, s.vtepsErr
}
func (s *stubOverlayController) GetVTEP(_ context.Context, _ netip.Addr) (*overlay.VTEPInfo, error) {
	return s.vtep, s.vtepErr
}
func (s *stubOverlayController) AddVNI(_ context.Context, _ *overlay.VNIConfig) error {
	return s.addVNIErr
}
func (s *stubOverlayController) RemoveVNI(_ context.Context, _ uint32) error {
	return s.removeVNIErr
}
func (s *stubOverlayController) ListVNIs(_ context.Context) ([]overlay.VNIInfo, error) {
	return s.vnis, s.vnisErr
}
func (s *stubOverlayController) GetVNI(_ context.Context, _ uint32) (*overlay.VNIInfo, error) {
	return s.vni, s.vniErr
}
func (s *stubOverlayController) GetRemoteMACs(_ context.Context, _ uint32) ([]overlay.RemoteMACEntry, error) {
	return s.macs, s.macsErr
}
func (s *stubOverlayController) ForgetMAC(_ context.Context, _ net.HardwareAddr, _ uint32) error {
	return s.forgetMACErr
}

// =============================================================================
// Status
// =============================================================================

func TestOverlayQUICAdapter_Status(t *testing.T) {
	t.Run("happy path returns populated status", func(t *testing.T) {
		vtepIP := netip.MustParseAddr("10.0.0.1")
		ctrl := &stubOverlayController{
			running: true,
			cfg: &overlay.Config{
				VTEPIP:            vtepIP,
				UnderlayInterface: "eth0",
				UnderlayMTU:       1500,
			},
			state: &overlay.State{
				VTEPs:      []overlay.VTEPInfo{{NodeID: "node-1"}},
				VNIs:       []overlay.VNIInfo{{VNI: 100}},
				Tunnels:    []overlay.TunnelInfo{{ID: "t1"}},
				RemoteMACs: []overlay.RemoteMACEntry{{VNI: 100}},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		status, err := a.Status(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !status.Enabled {
			t.Error("expected Enabled = true")
		}
		if status.LocalVTEP != "10.0.0.1" {
			t.Errorf("expected LocalVTEP=10.0.0.1, got %q", status.LocalVTEP)
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
		if status.MACCount != 1 {
			t.Errorf("expected MACCount=1, got %d", status.MACCount)
		}
		if status.HealthStatus != "healthy" {
			t.Errorf("expected HealthStatus=healthy, got %q", status.HealthStatus)
		}
	})

	t.Run("not running returns ErrOverlayServiceNotAvailable", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: false})
		_, err := a.Status(context.Background())
		if !errors.Is(err, quic.ErrOverlayServiceNotAvailable) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %v", err)
		}
	})
}

// =============================================================================
// VTEP operations
// =============================================================================

func TestOverlayQUICAdapter_ListVTEPs(t *testing.T) {
	t.Run("happy path returns vtep list", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vteps: []overlay.VTEPInfo{
				{NodeID: "node-a", IP: netip.MustParseAddr("10.1.0.1"), Healthy: true, TunnelCount: 2},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		vteps, err := a.ListVTEPs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vteps) != 1 {
			t.Fatalf("expected 1 vtep, got %d", len(vteps))
		}
		if vteps[0].ID != "node-a" {
			t.Errorf("expected ID=node-a, got %q", vteps[0].ID)
		}
		if vteps[0].Status != "healthy" {
			t.Errorf("expected Status=healthy, got %q", vteps[0].Status)
		}
		if vteps[0].TunnelCount != 2 {
			t.Errorf("expected TunnelCount=2, got %d", vteps[0].TunnelCount)
		}
	})

	t.Run("not running returns error", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: false})
		_, err := a.ListVTEPs(context.Background())
		if !errors.Is(err, quic.ErrOverlayServiceNotAvailable) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %v", err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vtepsErr: errors.New("rpc failure")}
		a := newOverlayControllerQUICAdapter(ctrl)
		_, err := a.ListVTEPs(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestOverlayQUICAdapter_GetVTEP(t *testing.T) {
	t.Run("happy path returns matching vtep by node id", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vteps: []overlay.VTEPInfo{
				{NodeID: "node-1", IP: netip.MustParseAddr("10.0.0.2"), Healthy: false},
				{NodeID: "node-2", IP: netip.MustParseAddr("10.0.0.3"), Healthy: true},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		v, err := a.GetVTEP(context.Background(), "node-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v.ID != "node-2" {
			t.Errorf("expected ID=node-2, got %q", v.ID)
		}
	})

	t.Run("unknown node id returns ErrOverlayVTEPNotFound", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vteps: []overlay.VTEPInfo{}}
		a := newOverlayControllerQUICAdapter(ctrl)
		_, err := a.GetVTEP(context.Background(), "ghost-node")
		if !errors.Is(err, quic.ErrOverlayVTEPNotFound) {
			t.Errorf("expected ErrOverlayVTEPNotFound, got %v", err)
		}
	})

	t.Run("empty id returns ErrOverlayMissingVTEPID", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		_, err := a.GetVTEP(context.Background(), "")
		if !errors.Is(err, quic.ErrOverlayMissingVTEPID) {
			t.Errorf("expected ErrOverlayMissingVTEPID, got %v", err)
		}
	})
}

// =============================================================================
// VNI operations
// =============================================================================

func TestOverlayQUICAdapter_ListVNIs(t *testing.T) {
	t.Run("happy path returns vni list", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running: true,
			vnis: []overlay.VNIInfo{
				{VNI: 1001, VLAN: 10, TunnelCount: 3, MACCount: 5, CreatedAt: time.Now()},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		vnis, err := a.ListVNIs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vnis) != 1 {
			t.Fatalf("expected 1 vni, got %d", len(vnis))
		}
		if vnis[0].VNI != 1001 {
			t.Errorf("expected VNI=1001, got %d", vnis[0].VNI)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, vnisErr: errors.New("datastore unavailable")}
		a := newOverlayControllerQUICAdapter(ctrl)
		_, err := a.ListVNIs(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestOverlayQUICAdapter_CreateVNI(t *testing.T) {
	t.Run("happy path creates and returns vni", func(t *testing.T) {
		created := &overlay.VNIInfo{VNI: 500, VLAN: 5, CreatedAt: time.Now()}
		ctrl := &stubOverlayController{
			running:   true,
			addVNIErr: nil,
			vni:       created,
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		info, err := a.CreateVNI(context.Background(), 500, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.VNI != 500 {
			t.Errorf("expected VNI=500, got %d", info.VNI)
		}
	})

	t.Run("invalid vni 0 returns ErrOverlayInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		_, err := a.CreateVNI(context.Background(), 0, nil)
		if !errors.Is(err, quic.ErrOverlayInvalidVNI) {
			t.Errorf("expected ErrOverlayInvalidVNI, got %v", err)
		}
	})

	t.Run("vni exceeding max returns ErrOverlayInvalidVNI", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		_, err := a.CreateVNI(context.Background(), overlay.MaxVNI+1, nil)
		if !errors.Is(err, quic.ErrOverlayInvalidVNI) {
			t.Errorf("expected ErrOverlayInvalidVNI, got %v", err)
		}
	})

	t.Run("addVNI error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, addVNIErr: errors.New("vni already exists")}
		a := newOverlayControllerQUICAdapter(ctrl)
		_, err := a.CreateVNI(context.Background(), 200, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("fallback minimal response when GetVNI fails after add", func(t *testing.T) {
		ctrl := &stubOverlayController{
			running:   true,
			addVNIErr: nil,
			vniErr:    errors.New("not found yet"),
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		info, err := a.CreateVNI(context.Background(), 300, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.VNI != 300 {
			t.Errorf("expected VNI=300, got %d", info.VNI)
		}
		if info.Status != "active" {
			t.Errorf("expected Status=active, got %q", info.Status)
		}
	})
}

func TestOverlayQUICAdapter_DeleteVNI(t *testing.T) {
	t.Run("happy path deletes vni", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, removeVNIErr: nil}
		a := newOverlayControllerQUICAdapter(ctrl)
		if err := a.DeleteVNI(context.Background(), 100); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("vni 0 returns ErrOverlayMissingVNI", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		if err := a.DeleteVNI(context.Background(), 0); !errors.Is(err, quic.ErrOverlayMissingVNI) {
			t.Errorf("expected ErrOverlayMissingVNI, got %v", err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, removeVNIErr: errors.New("vni not found")}
		a := newOverlayControllerQUICAdapter(ctrl)
		if err := a.DeleteVNI(context.Background(), 100); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

// =============================================================================
// Tunnel operations
// =============================================================================

func TestOverlayQUICAdapter_ListTunnels(t *testing.T) {
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
						BytesTx:    4096,
						BytesRx:    2048,
						CreatedAt:  time.Now(),
					},
				},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		tunnels, err := a.ListTunnels(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tunnels) != 1 {
			t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
		}
		if tunnels[0].ID != "tun-1" {
			t.Errorf("expected ID=tun-1, got %q", tunnels[0].ID)
		}
		if tunnels[0].TxBytes != 4096 {
			t.Errorf("expected TxBytes=4096, got %d", tunnels[0].TxBytes)
		}
	})

	t.Run("nil state returns empty slice", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, state: nil}
		a := newOverlayControllerQUICAdapter(ctrl)
		tunnels, err := a.ListTunnels(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tunnels) != 0 {
			t.Errorf("expected empty slice, got %d tunnels", len(tunnels))
		}
	})

	t.Run("not running returns error", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: false})
		_, err := a.ListTunnels(context.Background())
		if !errors.Is(err, quic.ErrOverlayServiceNotAvailable) {
			t.Errorf("expected ErrOverlayServiceNotAvailable, got %v", err)
		}
	})
}

// =============================================================================
// MAC table operations
// =============================================================================

func TestOverlayQUICAdapter_ListMACs(t *testing.T) {
	t.Run("happy path returns mac entries", func(t *testing.T) {
		hwAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		ctrl := &stubOverlayController{
			running: true,
			macs: []overlay.RemoteMACEntry{
				{
					MAC:        hwAddr,
					VNI:        100,
					RemoteVTEP: netip.MustParseAddr("10.0.0.5"),
					Source:     "evpn",
					LearnedAt:  time.Now(),
				},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		macs, err := a.ListMACs(context.Background(), 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(macs) != 1 {
			t.Fatalf("expected 1 mac, got %d", len(macs))
		}
		if macs[0].MAC != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("expected aa:bb:cc:dd:ee:ff, got %q", macs[0].MAC)
		}
	})

	t.Run("vni 0 lists all MACs via state (list-all semantics)", func(t *testing.T) {
		// VNI == 0 means list all MACs; the adapter reads state.RemoteMACs directly.
		ctrl := &stubOverlayController{
			running: true,
			state: &overlay.State{
				RemoteMACs: []overlay.RemoteMACEntry{{VNI: 100}},
			},
		}
		a := newOverlayControllerQUICAdapter(ctrl)
		macs, err := a.ListMACs(context.Background(), 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(macs) != 1 {
			t.Errorf("expected 1 MAC, got %d", len(macs))
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, macsErr: errors.New("vni not found")}
		a := newOverlayControllerQUICAdapter(ctrl)
		_, err := a.ListMACs(context.Background(), 100)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestOverlayQUICAdapter_ForgetMAC(t *testing.T) {
	t.Run("happy path removes mac", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, forgetMACErr: nil}
		a := newOverlayControllerQUICAdapter(ctrl)
		if err := a.ForgetMAC(context.Background(), 100, "aa:bb:cc:dd:ee:ff"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty mac returns ErrOverlayMissingMAC", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		if err := a.ForgetMAC(context.Background(), 100, ""); !errors.Is(err, quic.ErrOverlayMissingMAC) {
			t.Errorf("expected ErrOverlayMissingMAC, got %v", err)
		}
	})

	t.Run("invalid mac format returns ErrOverlayInvalidMAC", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		if err := a.ForgetMAC(context.Background(), 100, "not-a-mac"); !errors.Is(err, quic.ErrOverlayInvalidMAC) {
			t.Errorf("expected ErrOverlayInvalidMAC, got %v", err)
		}
	})

	t.Run("vni 0 returns ErrOverlayMissingVNI", func(t *testing.T) {
		a := newOverlayControllerQUICAdapter(&stubOverlayController{running: true})
		if err := a.ForgetMAC(context.Background(), 0, "aa:bb:cc:dd:ee:ff"); !errors.Is(err, quic.ErrOverlayMissingVNI) {
			t.Errorf("expected ErrOverlayMissingVNI, got %v", err)
		}
	})

	t.Run("controller error is propagated", func(t *testing.T) {
		ctrl := &stubOverlayController{running: true, forgetMACErr: errors.New("mac not found")}
		a := newOverlayControllerQUICAdapter(ctrl)
		if err := a.ForgetMAC(context.Background(), 100, "aa:bb:cc:dd:ee:ff"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

// =============================================================================
// Error mapping
// =============================================================================

func TestMapOverlayToQUICError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"nil passthrough", nil, nil},
		{"vtep not found", errors.New("vtep not found"), quic.ErrOverlayVTEPNotFound},
		{"vni not found", errors.New("vni not found"), quic.ErrOverlayVNINotFound},
		{"mac not found", errors.New("mac address not found"), quic.ErrOverlayMACNotFound},
		{"vni already exists", errors.New("vni already exists"), quic.ErrOverlayVNIAlreadyExists},
		{"not running", errors.New("overlay is not running"), quic.ErrOverlayServiceNotAvailable},
		{"unknown error passthrough", errors.New("timeout"), errors.New("timeout")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapOverlayToQUICError(tc.err)
			if tc.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %v, got nil", tc.want)
			}
			// For typed sentinel errors use errors.Is.
			if errors.Is(tc.want, quic.ErrOverlayVTEPNotFound) ||
				errors.Is(tc.want, quic.ErrOverlayVNINotFound) ||
				errors.Is(tc.want, quic.ErrOverlayMACNotFound) ||
				errors.Is(tc.want, quic.ErrOverlayVNIAlreadyExists) ||
				errors.Is(tc.want, quic.ErrOverlayServiceNotAvailable) {
				if !errors.Is(got, tc.want) {
					t.Errorf("expected %v, got %v", tc.want, got)
				}
			} else {
				// Unknown errors pass through as-is; just check non-nil.
				if got.Error() != tc.want.Error() {
					t.Errorf("expected %q, got %q", tc.want.Error(), got.Error())
				}
			}
		})
	}
}
