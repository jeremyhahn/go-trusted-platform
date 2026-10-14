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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayTools serves the MCP overlay_* tools from the overlay controller
// the gRPC, REST and QUIC overlay services use. It is embedded by both MCP
// service providers.
type overlayTools struct {
	ctrl OverlayControllerInterface
}

// overlayStatusView is the overlay_status result.
type overlayStatusView struct {
	NodeID          string `json:"node_id"`
	VTEPIP          string `json:"vtep_ip"`
	ControllerState string `json:"controller_state"`
	Healthy         bool   `json:"healthy"`
	UnderlayMTU     int    `json:"underlay_mtu"`
	VXLANPort       uint16 `json:"vxlan_port"`
	VNICount        int    `json:"vni_count"`
	VTEPCount       int    `json:"vtep_count"`
	RemoteMACCount  int    `json:"remote_mac_count"`
	TunnelCount     int    `json:"tunnel_count"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
}

// overlayVTEPView is one overlay_vtep_list entry.
type overlayVTEPView struct {
	NodeID      string `json:"node_id"`
	IP          string `json:"ip"`
	Healthy     bool   `json:"healthy"`
	LastSeen    string `json:"last_seen"`
	IsLocal     bool   `json:"is_local"`
	TunnelPort  uint16 `json:"tunnel_port"`
	TunnelCount int    `json:"tunnel_count"`
	EVPNEnabled bool   `json:"evpn_enabled"`
}

// overlayVTEPDetailView is the overlay_vtep_get result.
type overlayVTEPDetailView struct {
	overlayVTEPView
	VNIs      []uint32 `json:"vnis"`
	MACCount  int      `json:"mac_count"`
	BytesSent uint64   `json:"bytes_sent"`
	BytesRecv uint64   `json:"bytes_recv"`
}

// overlayVNIView is one overlay_vni_list entry and the overlay_vni_create result.
type overlayVNIView struct {
	VNI            uint32 `json:"vni"`
	VLAN           uint16 `json:"vlan"`
	TunnelCount    int    `json:"tunnel_count"`
	MACCount       int    `json:"mac_count"`
	IMETAdvertised bool   `json:"imet_advertised"`
	CreatedAt      string `json:"created_at"`
}

// overlayTunnelView is one overlay_tunnel_list entry.
type overlayTunnelView struct {
	ID         string `json:"id"`
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	Port       string `json:"port"`
	State      string `json:"state"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
}

// overlayMACView is one overlay_mac_list entry.
type overlayMACView struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VNI        uint32 `json:"vni"`
	RemoteVTEP string `json:"remote_vtep"`
	Source     string `json:"source"`
	LearnedAt  string `json:"learned_at"`
	ExpiresAt  string `json:"expires_at"`
}

// overlayMCPErrorMap maps the overlay controller's sentinel errors onto the
// MCP overlay errors, so a tool caller sees the same class the gRPC, REST and
// QUIC callers see.
var overlayMCPErrorMap = []struct {
	target error
	mapped *mcp.OverlayError
}{
	{overlay.ErrControllerNotRunning, mcp.ErrOverlayControllerNotRunning},
	{overlay.ErrVTEPNotFound, mcp.ErrOverlayVTEPNotFound},
	{overlay.ErrVNINotFound, mcp.ErrOverlayVNINotFound},
	{overlay.ErrVNIAlreadyExists, mcp.ErrOverlayVNIAlreadyExists},
	{overlay.ErrVNIOutOfRange, mcp.ErrOverlayInvalidVNI},
	{overlay.ErrVLANOutOfRange, mcp.ErrOverlayInvalidVLAN},
	{overlay.ErrMACNotFound, mcp.ErrOverlayMACNotFound},
	{overlay.ErrTunnelNotFound, mcp.ErrOverlayTunnelNotFound},
}

// mapOverlayToMCPError converts an overlay controller error into its MCP
// overlay error. Errors the overlay package does not type pass through.
func mapOverlayToMCPError(err error) error {
	for _, m := range overlayMCPErrorMap {
		if errors.Is(err, m.target) {
			return m.mapped
		}
	}

	var invalidVNI *overlay.ErrInvalidVNI
	if errors.As(err, &invalidVNI) {
		return mcp.ErrOverlayInvalidVNI
	}

	var invalidMAC *overlay.ErrInvalidMAC
	if errors.As(err, &invalidMAC) {
		return mcp.ErrOverlayInvalidMAC
	}

	return err
}

// runningController returns the overlay controller when it is configured and
// running.
func (t overlayTools) runningController() (OverlayControllerInterface, error) {
	if t.ctrl == nil {
		return nil, mcp.ErrOverlayServiceUnavailable
	}
	if !t.ctrl.IsRunning() {
		return nil, mcp.ErrOverlayControllerNotRunning
	}
	return t.ctrl, nil
}

// OverlayStatus returns the overlay status. Like gRPC GetOverlayStatus it
// answers while the controller is stopped, reporting it unhealthy.
func (t overlayTools) OverlayStatus(ctx context.Context) (interface{}, error) {
	if t.ctrl == nil {
		return nil, mcp.ErrOverlayServiceUnavailable
	}

	view := overlayStatusView{
		Healthy:       t.ctrl.IsRunning(),
		UptimeSeconds: int64(t.ctrl.Uptime().Seconds()),
	}

	if cfg := t.ctrl.GetConfig(); cfg != nil {
		view.NodeID = cfg.NodeID
		if cfg.VTEPIP.IsValid() {
			view.VTEPIP = cfg.VTEPIP.String()
		}
		view.UnderlayMTU = cfg.UnderlayMTU
		view.VXLANPort = cfg.VXLANPort
	}

	if state := t.ctrl.GetState(); state != nil {
		view.ControllerState = state.ControllerState.String()
		view.VNICount = len(state.VNIs)
		view.VTEPCount = len(state.VTEPs)
		view.RemoteMACCount = len(state.RemoteMACs)
		view.TunnelCount = len(state.Tunnels)
	}

	return view, nil
}

// OverlayVTEPList lists the known VTEPs.
func (t overlayTools) OverlayVTEPList(ctx context.Context) ([]interface{}, error) {
	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	vteps, err := ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToMCPError(err)
	}

	cfg := ctrl.GetConfig()
	out := make([]interface{}, 0, len(vteps))
	for i := range vteps {
		out = append(out, newOverlayVTEPView(&vteps[i], cfg))
	}
	return out, nil
}

// OverlayVTEPGet returns one VTEP by node ID, with the configured VNIs and
// the MAC and byte counts of its tunnels.
func (t overlayTools) OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error) {
	if nodeID == "" {
		return nil, mcp.ErrOverlayNodeIDRequired
	}

	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	vteps, err := ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToMCPError(err)
	}

	for i := range vteps {
		if vteps[i].NodeID == nodeID {
			return newOverlayVTEPDetailView(&vteps[i], ctrl.GetConfig(), ctrl.GetState()), nil
		}
	}
	return nil, mcp.ErrOverlayVTEPNotFound
}

// OverlayVNIList lists the configured VNIs.
func (t overlayTools) OverlayVNIList(ctx context.Context) ([]interface{}, error) {
	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	vnis, err := ctrl.ListVNIs(ctx)
	if err != nil {
		return nil, mapOverlayToMCPError(err)
	}

	out := make([]interface{}, 0, len(vnis))
	for i := range vnis {
		out = append(out, newOverlayVNIView(&vnis[i]))
	}
	return out, nil
}

// OverlayVNICreate configures a VNI mapped to a VLAN. The overlay stores no
// VNI name, so the name argument is not kept, as on gRPC.
func (t overlayTools) OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, _ string) (interface{}, error) {
	cfg := &overlay.VNIConfig{VNI: vni, VLAN: vlan}
	if err := cfg.Validate(); err != nil {
		return nil, mapOverlayToMCPError(err)
	}

	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	if err := ctrl.AddVNI(ctx, cfg); err != nil {
		return nil, mapOverlayToMCPError(err)
	}

	info, err := ctrl.GetVNI(ctx, vni)
	if err != nil {
		// The VNI was created; answer with what was configured.
		return overlayVNIView{VNI: vni, VLAN: vlan, CreatedAt: formatOverlayTime(time.Now())}, nil
	}
	return newOverlayVNIView(info), nil
}

// OverlayVNIDelete removes a VNI.
func (t overlayTools) OverlayVNIDelete(ctx context.Context, vni uint32) error {
	if vni == 0 || vni > overlay.MaxVNI {
		return mcp.ErrOverlayInvalidVNI
	}

	ctrl, err := t.runningController()
	if err != nil {
		return err
	}

	if err := ctrl.RemoveVNI(ctx, vni); err != nil {
		return mapOverlayToMCPError(err)
	}
	return nil
}

// OverlayTunnelList lists the VXLAN tunnels; a non-zero vni keeps only that
// VNI's tunnels.
func (t overlayTools) OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error) {
	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	state := ctrl.GetState()
	if state == nil {
		return []interface{}{}, nil
	}

	out := make([]interface{}, 0, len(state.Tunnels))
	for i := range state.Tunnels {
		if vni != 0 && state.Tunnels[i].VNI != vni {
			continue
		}
		out = append(out, newOverlayTunnelView(&state.Tunnels[i]))
	}
	return out, nil
}

// OverlayTunnelStats returns the counters of the tunnel to remoteVTEP, the
// tunnel gRPC GetTunnelStats returns; vni 0 selects the first tunnel to it.
func (t overlayTools) OverlayTunnelStats(ctx context.Context, remoteVTEP string, vni uint32) (interface{}, error) {
	if remoteVTEP == "" {
		return nil, mcp.ErrOverlayRemoteVTEPRequired
	}

	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	remote, err := netip.ParseAddr(remoteVTEP)
	if err != nil {
		return nil, mcp.ErrOverlayInvalidRemoteVTEP
	}

	tunnel := findOverlayTunnel(ctrl.GetState(), remote, vni)
	if tunnel == nil {
		return nil, mcp.ErrOverlayTunnelNotFound
	}
	return newOverlayTunnelView(tunnel), nil
}

// OverlayMACList lists the learned remote MACs; vni 0 lists every VNI's.
func (t overlayTools) OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error) {
	ctrl, err := t.runningController()
	if err != nil {
		return nil, err
	}

	var macs []overlay.RemoteMACEntry
	if vni == 0 {
		if state := ctrl.GetState(); state != nil {
			macs = state.RemoteMACs
		}
	} else {
		macs, err = ctrl.GetRemoteMACs(ctx, vni)
		if err != nil {
			return nil, mapOverlayToMCPError(err)
		}
	}

	out := make([]interface{}, 0, len(macs))
	for i := range macs {
		out = append(out, newOverlayMACView(&macs[i]))
	}
	return out, nil
}

// OverlayMACForget removes a learned MAC from a VNI's forwarding table.
func (t overlayTools) OverlayMACForget(ctx context.Context, mac string, vni uint32) error {
	if mac == "" {
		return mcp.ErrOverlayMACRequired
	}
	if vni == 0 {
		return mcp.ErrOverlayVNIRequired
	}

	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return mcp.ErrOverlayInvalidMAC
	}

	ctrl, err := t.runningController()
	if err != nil {
		return err
	}

	if err := ctrl.ForgetMAC(ctx, hwAddr, vni); err != nil {
		return mapOverlayToMCPError(err)
	}
	return nil
}

// newOverlayVTEPView renders a VTEP; cfg marks the local VTEP and supplies
// the VXLAN port.
func newOverlayVTEPView(v *overlay.VTEPInfo, cfg *overlay.Config) overlayVTEPView {
	view := overlayVTEPView{
		NodeID:      v.NodeID,
		IP:          v.IP.String(),
		Healthy:     v.Healthy,
		LastSeen:    formatOverlayTime(v.LastSeen),
		TunnelCount: v.TunnelCount,
		EVPNEnabled: v.EVPNEnabled,
	}
	if cfg != nil {
		view.IsLocal = cfg.VTEPIP.IsValid() && cfg.VTEPIP == v.IP
		view.TunnelPort = cfg.VXLANPort
	}
	return view
}

// newOverlayVTEPDetailView renders a VTEP with the configured VNIs, the MACs
// learned behind it and the bytes its tunnels carried.
func newOverlayVTEPDetailView(v *overlay.VTEPInfo, cfg *overlay.Config, state *overlay.State) overlayVTEPDetailView {
	view := overlayVTEPDetailView{
		overlayVTEPView: newOverlayVTEPView(v, cfg),
		VNIs:            []uint32{},
	}
	if state == nil {
		return view
	}

	for i := range state.VNIs {
		view.VNIs = append(view.VNIs, state.VNIs[i].VNI)
	}
	for i := range state.RemoteMACs {
		if state.RemoteMACs[i].RemoteVTEP == v.IP {
			view.MACCount++
		}
	}
	for i := range state.Tunnels {
		if state.Tunnels[i].RemoteVTEP == v.IP {
			view.BytesSent += state.Tunnels[i].BytesTx
			view.BytesRecv += state.Tunnels[i].BytesRx
		}
	}
	return view
}

// newOverlayVNIView renders a VNI.
func newOverlayVNIView(v *overlay.VNIInfo) overlayVNIView {
	return overlayVNIView{
		VNI:            v.VNI,
		VLAN:           v.VLAN,
		TunnelCount:    v.TunnelCount,
		MACCount:       v.MACCount,
		IMETAdvertised: v.IMETAdvertised,
		CreatedAt:      formatOverlayTime(v.CreatedAt),
	}
}

// newOverlayTunnelView renders a tunnel.
func newOverlayTunnelView(t *overlay.TunnelInfo) overlayTunnelView {
	return overlayTunnelView{
		ID:         t.ID,
		LocalVTEP:  t.LocalVTEP.String(),
		RemoteVTEP: t.RemoteVTEP.String(),
		VNI:        t.VNI,
		Port:       t.OVSPort,
		State:      t.State.String(),
		BytesSent:  t.BytesTx,
		BytesRecv:  t.BytesRx,
	}
}

// newOverlayMACView renders a learned MAC; an unset IP renders empty.
func newOverlayMACView(m *overlay.RemoteMACEntry) overlayMACView {
	view := overlayMACView{
		MAC:        m.MAC.String(),
		VNI:        m.VNI,
		RemoteVTEP: m.RemoteVTEP.String(),
		Source:     m.Source,
		LearnedAt:  formatOverlayTime(m.LearnedAt),
		ExpiresAt:  formatOverlayTime(m.ExpiresAt),
	}
	if m.IP.IsValid() {
		view.IP = m.IP.String()
	}
	return view
}

// formatOverlayTime renders t as RFC 3339; the zero time renders empty.
func formatOverlayTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
