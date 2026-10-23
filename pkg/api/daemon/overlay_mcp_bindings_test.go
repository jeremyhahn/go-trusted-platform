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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errOverlayTestBackend is an error the overlay package does not type.
var errOverlayTestBackend = errors.New("overlay test backend failure")

// recordingOverlayController records the arguments the overlay tools pass
// to the controller.
type recordingOverlayController struct {
	*stubOverlayController
	added     *overlay.VNIConfig
	removed   uint32
	forgotMAC net.HardwareAddr
	forgotVNI uint32
}

func (r *recordingOverlayController) AddVNI(ctx context.Context, cfg *overlay.VNIConfig) error {
	r.added = cfg
	return r.stubOverlayController.AddVNI(ctx, cfg)
}

func (r *recordingOverlayController) RemoveVNI(ctx context.Context, vni uint32) error {
	r.removed = vni
	return r.stubOverlayController.RemoveVNI(ctx, vni)
}

func (r *recordingOverlayController) ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error {
	r.forgotMAC = mac
	r.forgotVNI = vni
	return r.stubOverlayController.ForgetMAC(ctx, mac, vni)
}

var (
	overlayTestLocal  = netip.MustParseAddr("10.0.0.1")
	overlayTestRemote = netip.MustParseAddr("10.0.0.2")
	overlayTestTime   = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
)

// newOverlayTestController returns a running controller with one remote VTEP
// carrying VNI 100.
func newOverlayTestController() *recordingOverlayController {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	return &recordingOverlayController{stubOverlayController: &stubOverlayController{
		running: true,
		cfg: &overlay.Config{
			NodeID:      "node-a",
			VTEPIP:      overlayTestLocal,
			UnderlayMTU: 9000,
			VXLANPort:   4789,
		},
		state: &overlay.State{
			ControllerState: overlay.ControllerStateRunning,
			VTEPs: []overlay.VTEPInfo{
				{NodeID: "node-a", IP: overlayTestLocal, Healthy: true},
				{NodeID: "node-b", IP: overlayTestRemote, Healthy: true, LastSeen: overlayTestTime, TunnelCount: 1},
			},
			VNIs: []overlay.VNIInfo{{VNI: 100, VLAN: 10}},
			Tunnels: []overlay.TunnelInfo{{
				ID: "t1", LocalVTEP: overlayTestLocal, RemoteVTEP: overlayTestRemote, VNI: 100,
				State: vxlan.TunnelStatusUp, OVSPort: "vxlan-t1", BytesTx: 10, BytesRx: 20,
			}},
			RemoteMACs: []overlay.RemoteMACEntry{{
				MAC: mac, VNI: 100, RemoteVTEP: overlayTestRemote, Source: "evpn", LearnedAt: overlayTestTime,
			}},
		},
		vteps: []overlay.VTEPInfo{
			{NodeID: "node-a", IP: overlayTestLocal, Healthy: true},
			{NodeID: "node-b", IP: overlayTestRemote, Healthy: true, LastSeen: overlayTestTime, TunnelCount: 1},
		},
		vnis: []overlay.VNIInfo{{VNI: 100, VLAN: 10, CreatedAt: overlayTestTime}},
		vni:  &overlay.VNIInfo{VNI: 200, VLAN: 20, CreatedAt: overlayTestTime},
		macs: []overlay.RemoteMACEntry{{MAC: mac, VNI: 100, RemoteVTEP: overlayTestRemote, Source: "evpn"}},
	}}
}

// overlayToolRegistry serves the overlay tools of an MCP service provider
// built on ctrl, the way the daemon's MCP server does.
func overlayToolRegistry(ctrl OverlayControllerInterface) *mcp.ToolRegistry {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Overlay: ctrl})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

func TestOverlayTools_Status(t *testing.T) {
	ctrl := newOverlayTestController()

	got, err := overlayTools{ctrl: ctrl}.OverlayStatus(context.Background())
	if err != nil {
		t.Fatalf("OverlayStatus: %v", err)
	}
	want := overlayStatusView{
		NodeID: "node-a", VTEPIP: "10.0.0.1", ControllerState: "running", Healthy: true,
		UnderlayMTU: 9000, VXLANPort: 4789, VNICount: 1, VTEPCount: 2, RemoteMACCount: 1, TunnelCount: 1,
	}
	if got != want {
		t.Fatalf("OverlayStatus = %+v, want %+v", got, want)
	}
}

func TestOverlayTools_StatusStoppedController(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.running = false

	got, err := overlayTools{ctrl: ctrl}.OverlayStatus(context.Background())
	if err != nil {
		t.Fatalf("OverlayStatus: %v", err)
	}
	if got.(overlayStatusView).Healthy {
		t.Fatal("a stopped controller must report unhealthy")
	}
}

func TestOverlayTools_VTEPList(t *testing.T) {
	got, err := overlayTools{ctrl: newOverlayTestController()}.OverlayVTEPList(context.Background())
	if err != nil {
		t.Fatalf("OverlayVTEPList: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	local := got[0].(overlayVTEPView)
	remote := got[1].(overlayVTEPView)
	if !local.IsLocal || remote.IsLocal {
		t.Fatalf("is_local = %v/%v, want true/false", local.IsLocal, remote.IsLocal)
	}
	if remote.TunnelPort != 4789 || remote.LastSeen != "2026-10-13T12:00:00Z" {
		t.Fatalf("remote = %+v", remote)
	}
}

func TestOverlayTools_VTEPListError(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.vtepsErr = overlay.ErrControllerNotRunning

	_, err := overlayTools{ctrl: ctrl}.OverlayVTEPList(context.Background())
	if !errors.Is(err, mcp.ErrOverlayControllerNotRunning) {
		t.Fatalf("err = %v, want %v", err, mcp.ErrOverlayControllerNotRunning)
	}
}

func TestOverlayTools_VTEPGet(t *testing.T) {
	got, err := overlayTools{ctrl: newOverlayTestController()}.OverlayVTEPGet(context.Background(), "node-b")
	if err != nil {
		t.Fatalf("OverlayVTEPGet: %v", err)
	}
	view := got.(overlayVTEPDetailView)
	if view.NodeID != "node-b" || view.MACCount != 1 || view.BytesSent != 10 || view.BytesRecv != 20 {
		t.Fatalf("view = %+v", view)
	}
	if len(view.VNIs) != 1 || view.VNIs[0] != 100 {
		t.Fatalf("vnis = %v, want [100]", view.VNIs)
	}
}

func TestOverlayTools_VTEPGetErrors(t *testing.T) {
	tools := overlayTools{ctrl: newOverlayTestController()}
	ctx := context.Background()

	if _, err := tools.OverlayVTEPGet(ctx, ""); !errors.Is(err, mcp.ErrOverlayNodeIDRequired) {
		t.Fatalf("empty node id: err = %v", err)
	}
	if _, err := tools.OverlayVTEPGet(ctx, "node-z"); !errors.Is(err, mcp.ErrOverlayVTEPNotFound) {
		t.Fatalf("unknown node id: err = %v", err)
	}
}

func TestOverlayTools_VTEPGetWithoutState(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.state = nil

	got, err := overlayTools{ctrl: ctrl}.OverlayVTEPGet(context.Background(), "node-b")
	if err != nil {
		t.Fatalf("OverlayVTEPGet: %v", err)
	}
	if vnis := got.(overlayVTEPDetailView).VNIs; vnis == nil || len(vnis) != 0 {
		t.Fatalf("vnis = %#v, want an empty non-nil slice", vnis)
	}
}

func TestOverlayTools_VNIList(t *testing.T) {
	got, err := overlayTools{ctrl: newOverlayTestController()}.OverlayVNIList(context.Background())
	if err != nil {
		t.Fatalf("OverlayVNIList: %v", err)
	}
	want := overlayVNIView{VNI: 100, VLAN: 10, CreatedAt: "2026-10-13T12:00:00Z"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("OverlayVNIList = %+v, want [%+v]", got, want)
	}
}

func TestOverlayTools_VNIListError(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.vnisErr = errOverlayTestBackend

	_, err := overlayTools{ctrl: ctrl}.OverlayVNIList(context.Background())
	if !errors.Is(err, errOverlayTestBackend) {
		t.Fatalf("err = %v, want %v", err, errOverlayTestBackend)
	}
}

func TestOverlayTools_VNICreate(t *testing.T) {
	ctrl := newOverlayTestController()

	got, err := overlayTools{ctrl: ctrl}.OverlayVNICreate(context.Background(), 200, 20, "tenant-a")
	if err != nil {
		t.Fatalf("OverlayVNICreate: %v", err)
	}
	if ctrl.added == nil || ctrl.added.VNI != 200 || ctrl.added.VLAN != 20 {
		t.Fatalf("controller got %+v, want VNI 200 VLAN 20", ctrl.added)
	}
	if view := got.(overlayVNIView); view.VNI != 200 || view.VLAN != 20 {
		t.Fatalf("view = %+v", view)
	}
}

func TestOverlayTools_VNICreateLookupFailure(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.vniErr = overlay.ErrVNINotFound

	got, err := overlayTools{ctrl: ctrl}.OverlayVNICreate(context.Background(), 300, 30, "")
	if err != nil {
		t.Fatalf("OverlayVNICreate: %v", err)
	}
	if view := got.(overlayVNIView); view.VNI != 300 || view.VLAN != 30 || view.CreatedAt == "" {
		t.Fatalf("view = %+v, want the configured VNI and VLAN", view)
	}
}

func TestOverlayTools_VNICreateErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		vni    uint32
		vlan   uint16
		addErr error
		want   error
	}{
		{"vni zero", 0, 0, nil, mcp.ErrOverlayInvalidVNI},
		{"vni above 24 bits", overlay.MaxVNI + 1, 0, nil, mcp.ErrOverlayInvalidVNI},
		{"vlan above 4094", 100, 4095, nil, mcp.ErrOverlayInvalidVLAN},
		{"vni exists", 100, 10, overlay.ErrVNIAlreadyExists, mcp.ErrOverlayVNIAlreadyExists},
		{"wrapped exists", 100, 10, &overlay.ErrVNIOperationFailed{VNI: 100, Operation: "add", Cause: overlay.ErrVNIAlreadyExists}, mcp.ErrOverlayVNIAlreadyExists},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := newOverlayTestController()
			ctrl.addVNIErr = tt.addErr

			_, err := overlayTools{ctrl: ctrl}.OverlayVNICreate(ctx, tt.vni, tt.vlan, "")
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOverlayTools_VNIDelete(t *testing.T) {
	ctrl := newOverlayTestController()

	if err := (overlayTools{ctrl: ctrl}).OverlayVNIDelete(context.Background(), 100); err != nil {
		t.Fatalf("OverlayVNIDelete: %v", err)
	}
	if ctrl.removed != 100 {
		t.Fatalf("controller removed %d, want 100", ctrl.removed)
	}
}

func TestOverlayTools_VNIDeleteErrors(t *testing.T) {
	ctx := context.Background()
	ctrl := newOverlayTestController()
	ctrl.removeVNIErr = overlay.ErrVNINotFound
	tools := overlayTools{ctrl: ctrl}

	if err := tools.OverlayVNIDelete(ctx, overlay.MaxVNI+1); !errors.Is(err, mcp.ErrOverlayInvalidVNI) {
		t.Fatalf("out of range: err = %v", err)
	}
	if err := tools.OverlayVNIDelete(ctx, 100); !errors.Is(err, mcp.ErrOverlayVNINotFound) {
		t.Fatalf("unknown vni: err = %v", err)
	}
}

func TestOverlayTools_TunnelList(t *testing.T) {
	tools := overlayTools{ctrl: newOverlayTestController()}
	ctx := context.Background()

	all, err := tools.OverlayTunnelList(ctx, 0)
	if err != nil {
		t.Fatalf("OverlayTunnelList: %v", err)
	}
	want := overlayTunnelView{
		ID: "t1", LocalVTEP: "10.0.0.1", RemoteVTEP: "10.0.0.2", VNI: 100,
		Port: "vxlan-t1", State: "up", BytesSent: 10, BytesRecv: 20,
	}
	if len(all) != 1 || all[0] != want {
		t.Fatalf("OverlayTunnelList = %+v, want [%+v]", all, want)
	}

	filtered, err := tools.OverlayTunnelList(ctx, 999)
	if err != nil || len(filtered) != 0 {
		t.Fatalf("filter by vni 999 = %v, %v; want empty", filtered, err)
	}
}

func TestOverlayTools_TunnelListWithoutState(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.state = nil

	got, err := overlayTools{ctrl: ctrl}.OverlayTunnelList(context.Background(), 0)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("OverlayTunnelList = %#v, %v; want an empty non-nil list", got, err)
	}
}

func TestOverlayTools_TunnelStats(t *testing.T) {
	tools := overlayTools{ctrl: newOverlayTestController()}
	want := overlayTunnelView{
		ID: "t1", LocalVTEP: "10.0.0.1", RemoteVTEP: "10.0.0.2", VNI: 100,
		Port: "vxlan-t1", State: "up", BytesSent: 10, BytesRecv: 20,
	}

	for _, vni := range []uint32{100, 0} {
		got, err := tools.OverlayTunnelStats(context.Background(), "10.0.0.2", vni)
		if err != nil {
			t.Fatalf("OverlayTunnelStats(vni %d): %v", vni, err)
		}
		if got != want {
			t.Fatalf("OverlayTunnelStats(vni %d) = %+v, want %+v", vni, got, want)
		}
	}
}

func TestOverlayTools_TunnelStatsErrors(t *testing.T) {
	ctx := context.Background()
	withoutState := newOverlayTestController()
	withoutState.state = nil

	tests := []struct {
		name   string
		tools  overlayTools
		remote string
		vni    uint32
		want   error
	}{
		{"remote missing", overlayTools{ctrl: newOverlayTestController()}, "", 100, mcp.ErrOverlayRemoteVTEPRequired},
		{"remote not an address", overlayTools{ctrl: newOverlayTestController()}, "vtep-b", 100, mcp.ErrOverlayInvalidRemoteVTEP},
		{"unknown remote", overlayTools{ctrl: newOverlayTestController()}, "10.0.0.9", 0, mcp.ErrOverlayTunnelNotFound},
		{"vni mismatch", overlayTools{ctrl: newOverlayTestController()}, "10.0.0.2", 999, mcp.ErrOverlayTunnelNotFound},
		{"no state", overlayTools{ctrl: withoutState}, "10.0.0.2", 100, mcp.ErrOverlayTunnelNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.tools.OverlayTunnelStats(ctx, tt.remote, tt.vni); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestOverlayTunnelStats_SameOnEveryTransport pins the tunnel statistics
// gRPC GetTunnelStats returns as the ones QUIC and MCP return from the same
// controller.
func TestOverlayTunnelStats_SameOnEveryTransport(t *testing.T) {
	ctx := context.Background()
	ctrl := newOverlayTestController()

	grpcResp, err := NewOverlayService(WithOverlayController(ctrl)).GetTunnelStats(ctx,
		&platformv1.GetTunnelStatsRequest{RemoteVtep: "10.0.0.2", Vni: 100})
	if err != nil {
		t.Fatalf("gRPC GetTunnelStats: %v", err)
	}
	quicTunnel, err := newOverlayControllerQUICAdapter(ctrl).TunnelStats(ctx, "10.0.0.2", 100)
	if err != nil {
		t.Fatalf("QUIC TunnelStats: %v", err)
	}
	mcpOut, err := overlayTools{ctrl: ctrl}.OverlayTunnelStats(ctx, "10.0.0.2", 100)
	if err != nil {
		t.Fatalf("MCP OverlayTunnelStats: %v", err)
	}
	mcpTunnel, ok := mcpOut.(overlayTunnelView)
	if !ok {
		t.Fatalf("MCP result = %T, want overlayTunnelView", mcpOut)
	}

	g := grpcResp.GetTunnel()
	if quicTunnel.RemoteVTEP != g.GetRemoteVtep() || quicTunnel.VNI != g.GetVni() ||
		uint64(quicTunnel.TxBytes) != g.GetBytesTx() || uint64(quicTunnel.RxBytes) != g.GetBytesRx() {
		t.Errorf("QUIC tunnel %+v differs from gRPC %+v", quicTunnel, g)
	}
	if mcpTunnel.RemoteVTEP != g.GetRemoteVtep() || mcpTunnel.VNI != g.GetVni() ||
		mcpTunnel.BytesSent != g.GetBytesTx() || mcpTunnel.BytesRecv != g.GetBytesRx() {
		t.Errorf("MCP tunnel %+v differs from gRPC %+v", mcpTunnel, g)
	}
}

func TestOverlayTools_MACList(t *testing.T) {
	tools := overlayTools{ctrl: newOverlayTestController()}
	ctx := context.Background()

	all, err := tools.OverlayMACList(ctx, 0)
	if err != nil {
		t.Fatalf("OverlayMACList(0): %v", err)
	}
	want := overlayMACView{
		MAC: "00:11:22:33:44:55", VNI: 100, RemoteVTEP: "10.0.0.2", Source: "evpn", LearnedAt: "2026-10-13T12:00:00Z",
	}
	if len(all) != 1 || all[0] != want {
		t.Fatalf("OverlayMACList(0) = %+v, want [%+v]", all, want)
	}

	byVNI, err := tools.OverlayMACList(ctx, 100)
	if err != nil || len(byVNI) != 1 {
		t.Fatalf("OverlayMACList(100) = %v, %v", byVNI, err)
	}
}

func TestOverlayTools_MACListError(t *testing.T) {
	ctrl := newOverlayTestController()
	ctrl.macsErr = overlay.ErrVNINotFound

	_, err := overlayTools{ctrl: ctrl}.OverlayMACList(context.Background(), 7)
	if !errors.Is(err, mcp.ErrOverlayVNINotFound) {
		t.Fatalf("err = %v, want %v", err, mcp.ErrOverlayVNINotFound)
	}
}

func TestOverlayTools_MACForget(t *testing.T) {
	ctrl := newOverlayTestController()

	if err := (overlayTools{ctrl: ctrl}).OverlayMACForget(context.Background(), "00:11:22:33:44:55", 100); err != nil {
		t.Fatalf("OverlayMACForget: %v", err)
	}
	if ctrl.forgotMAC.String() != "00:11:22:33:44:55" || ctrl.forgotVNI != 100 {
		t.Fatalf("controller forgot %s in %d", ctrl.forgotMAC, ctrl.forgotVNI)
	}
}

func TestOverlayTools_MACForgetErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		mac       string
		vni       uint32
		forgetErr error
		want      error
	}{
		{"mac missing", "", 100, nil, mcp.ErrOverlayMACRequired},
		{"vni missing", "00:11:22:33:44:55", 0, nil, mcp.ErrOverlayVNIRequired},
		{"mac malformed", "not-a-mac", 100, nil, mcp.ErrOverlayInvalidMAC},
		{"mac unknown", "00:11:22:33:44:55", 100, overlay.ErrMACNotFound, mcp.ErrOverlayMACNotFound},
		{"mac rejected", "00:11:22:33:44:55", 100, &overlay.ErrInvalidMAC{Reason: "multicast"}, mcp.ErrOverlayInvalidMAC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := newOverlayTestController()
			ctrl.forgetMACErr = tt.forgetErr

			err := overlayTools{ctrl: ctrl}.OverlayMACForget(ctx, tt.mac, tt.vni)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOverlayTools_ControllerUnavailable(t *testing.T) {
	ctx := context.Background()
	stopped := newOverlayTestController()
	stopped.running = false

	tests := []struct {
		name  string
		tools overlayTools
		want  error
	}{
		{"not configured", overlayTools{}, mcp.ErrOverlayServiceUnavailable},
		{"not running", overlayTools{ctrl: stopped}, mcp.ErrOverlayControllerNotRunning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := map[string]func() error{
				"vtep list":   func() error { _, err := tt.tools.OverlayVTEPList(ctx); return err },
				"vtep get":    func() error { _, err := tt.tools.OverlayVTEPGet(ctx, "node-b"); return err },
				"vni list":    func() error { _, err := tt.tools.OverlayVNIList(ctx); return err },
				"vni create":  func() error { _, err := tt.tools.OverlayVNICreate(ctx, 100, 10, ""); return err },
				"vni delete":  func() error { return tt.tools.OverlayVNIDelete(ctx, 100) },
				"tunnel list": func() error { _, err := tt.tools.OverlayTunnelList(ctx, 0); return err },
				"tunnel stats": func() error {
					_, err := tt.tools.OverlayTunnelStats(ctx, "10.0.0.2", 100)
					return err
				},
				"mac list":   func() error { _, err := tt.tools.OverlayMACList(ctx, 0); return err },
				"mac forget": func() error { return tt.tools.OverlayMACForget(ctx, "00:11:22:33:44:55", 100) },
			}
			for verb, call := range calls {
				if err := call(); !errors.Is(err, tt.want) {
					t.Errorf("%s: err = %v, want %v", verb, err, tt.want)
				}
			}
		})
	}

	if _, err := (overlayTools{}).OverlayStatus(ctx); !errors.Is(err, mcp.ErrOverlayServiceUnavailable) {
		t.Fatalf("status without controller: err = %v", err)
	}
}

func TestMapOverlayToMCPError_PassesUntypedErrors(t *testing.T) {
	if err := mapOverlayToMCPError(errOverlayTestBackend); !errors.Is(err, errOverlayTestBackend) {
		t.Fatalf("err = %v, want %v", err, errOverlayTestBackend)
	}
	if err := mapOverlayToMCPError(&overlay.ErrInvalidVNI{VNI: 0, Reason: "zero"}); !errors.Is(err, mcp.ErrOverlayInvalidVNI) {
		t.Fatalf("err = %v, want %v", err, mcp.ErrOverlayInvalidVNI)
	}
}

// TestOverlayMCPTools_ReachController drives every overlay tool through the
// MCP tool registry of the daemon's MCP service provider and checks it
// reaches the overlay controller.
func TestOverlayMCPTools_ReachController(t *testing.T) {
	ctx := context.Background()
	ctrl := newOverlayTestController()
	registry := overlayToolRegistry(ctrl)

	calls := []struct {
		tool string
		args map[string]interface{}
		key  string
	}{
		{"overlay_status", nil, "node_id"},
		{"overlay_vtep_list", nil, "vteps"},
		{"overlay_vtep_get", map[string]interface{}{"node_id": "node-b"}, "vnis"},
		{"overlay_vni_list", nil, "vnis"},
		{"overlay_vni_create", map[string]interface{}{"vni": float64(200), "vlan": float64(20)}, "vlan"},
		{"overlay_vni_delete", map[string]interface{}{"vni": float64(100)}, "success"},
		{"overlay_tunnel_list", nil, "tunnels"},
		{"overlay_tunnel_stats", map[string]interface{}{"remote_vtep": "10.0.0.2"}, "tunnel"},
		{"overlay_mac_list", nil, "macs"},
		{"overlay_mac_forget", map[string]interface{}{"mac": "00:11:22:33:44:55", "vni": float64(100)}, "success"},
	}
	for _, c := range calls {
		t.Run(c.tool, func(t *testing.T) {
			out, err := registry.ExecuteTool(ctx, c.tool, c.args)
			if err != nil {
				t.Fatalf("%s: %v", c.tool, err)
			}
			result, ok := out.(map[string]interface{})
			if !ok {
				t.Fatalf("%s result = %T, want an object", c.tool, out)
			}
			if _, ok := result[c.key]; !ok {
				t.Fatalf("%s result %v lacks %q", c.tool, result, c.key)
			}
		})
	}

	if ctrl.added == nil || ctrl.added.VLAN != 20 || ctrl.removed != 100 || ctrl.forgotVNI != 100 {
		t.Fatalf("controller saw add=%+v remove=%d forget=%d", ctrl.added, ctrl.removed, ctrl.forgotVNI)
	}
}

// TestOverlayMCPTools_TypedErrors checks the overlay controller's typed
// errors reach the MCP caller with their gRPC class.
func TestOverlayMCPTools_TypedErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		setup func(*recordingOverlayController)
		tool  string
		args  map[string]interface{}
		want  error
		code  codes.Code
	}{
		{
			name:  "vni exists",
			setup: func(c *recordingOverlayController) { c.addVNIErr = overlay.ErrVNIAlreadyExists },
			tool:  "overlay_vni_create", args: map[string]interface{}{"vni": float64(100)},
			want: mcp.ErrOverlayVNIAlreadyExists, code: codes.AlreadyExists,
		},
		{
			name:  "vni out of range",
			setup: func(*recordingOverlayController) {},
			tool:  "overlay_vni_create", args: map[string]interface{}{"vni": float64(1 << 24)},
			want: mcp.ErrOverlayInvalidVNI, code: codes.InvalidArgument,
		},
		{
			name:  "vni unknown",
			setup: func(c *recordingOverlayController) { c.removeVNIErr = overlay.ErrVNINotFound },
			tool:  "overlay_vni_delete", args: map[string]interface{}{"vni": float64(100)},
			want: mcp.ErrOverlayVNINotFound, code: codes.NotFound,
		},
		{
			name:  "vtep unknown",
			setup: func(*recordingOverlayController) {},
			tool:  "overlay_vtep_get", args: map[string]interface{}{"node_id": "node-z"},
			want: mcp.ErrOverlayVTEPNotFound, code: codes.NotFound,
		},
		{
			name:  "mac unknown",
			setup: func(c *recordingOverlayController) { c.forgetMACErr = overlay.ErrMACNotFound },
			tool:  "overlay_mac_forget", args: map[string]interface{}{"mac": "00:11:22:33:44:55", "vni": float64(100)},
			want: mcp.ErrOverlayMACNotFound, code: codes.NotFound,
		},
		{
			name:  "tunnel unknown",
			setup: func(*recordingOverlayController) {},
			tool:  "overlay_tunnel_stats", args: map[string]interface{}{"remote_vtep": "10.0.0.9"},
			want: mcp.ErrOverlayTunnelNotFound, code: codes.NotFound,
		},
		{
			name:  "tunnel remote malformed",
			setup: func(*recordingOverlayController) {},
			tool:  "overlay_tunnel_stats", args: map[string]interface{}{"remote_vtep": "vtep-b"},
			want: mcp.ErrOverlayInvalidRemoteVTEP, code: codes.InvalidArgument,
		},
		{
			name:  "controller stopped",
			setup: func(c *recordingOverlayController) { c.running = false },
			tool:  "overlay_vni_list",
			want:  mcp.ErrOverlayControllerNotRunning, code: codes.FailedPrecondition,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := newOverlayTestController()
			tt.setup(ctrl)

			_, err := overlayToolRegistry(ctrl).ExecuteTool(ctx, tt.tool, tt.args)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got := status.Code(err); got != tt.code {
				t.Fatalf("code = %v, want %v", got, tt.code)
			}
		})
	}

	_, err := overlayToolRegistry(nil).ExecuteTool(ctx, "overlay_status", nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("no controller: err = %v, want Unavailable", err)
	}
}
