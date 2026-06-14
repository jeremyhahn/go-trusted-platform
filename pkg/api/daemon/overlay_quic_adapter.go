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
	"net"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayControllerQUICAdapter bridges an OverlayControllerInterface into the
// quic.OverlayServiceInterface consumed by quic.NewOverlayHandler.
//
// All nine interface methods are backed by real in-process data from the
// controller.  Controller errors are mapped to the quic sentinel errors so
// that the QUIC handler's overlayErrorResponse emits the correct status byte.
type overlayControllerQUICAdapter struct {
	ctrl OverlayControllerInterface
}

// Compile-time check.
var _ quic.OverlayServiceInterface = (*overlayControllerQUICAdapter)(nil)

// newOverlayControllerQUICAdapter wraps a non-nil overlay controller as a
// quic.OverlayServiceInterface.  Callers must pass nil to quic.NewOverlayHandler
// directly when no controller is available; they should not wrap nil here.
func newOverlayControllerQUICAdapter(ctrl OverlayControllerInterface) *overlayControllerQUICAdapter {
	return &overlayControllerQUICAdapter{ctrl: ctrl}
}

// =============================================================================
// Status
// =============================================================================

// Status returns the current overlay network status.
func (a *overlayControllerQUICAdapter) Status(ctx context.Context) (*quic.OverlayStatusInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	state := a.ctrl.GetState()
	cfg := a.ctrl.GetConfig()

	var nodeID, localVTEP, underlayIface, encapType string
	var mtu int
	var vxlanPort uint16

	if cfg != nil {
		nodeID = cfg.NodeID
		if cfg.VTEPIP.IsValid() {
			localVTEP = cfg.VTEPIP.String()
		}
		underlayIface = cfg.UnderlayInterface
		mtu = cfg.UnderlayMTU
		vxlanPort = cfg.VXLANPort
		encapType = "vxlan"
	}

	var vtepCount, vniCount, tunnelCount, macCount int
	if state != nil {
		vtepCount = len(state.VTEPs)
		vniCount = len(state.VNIs)
		tunnelCount = len(state.Tunnels)
		macCount = len(state.RemoteMACs)
	}

	healthStatus := "degraded"
	if a.ctrl.IsRunning() {
		healthStatus = "healthy"
	}

	return &quic.OverlayStatusInfo{
		Enabled:      true,
		NodeID:       nodeID,
		Mode:         "vxlan",
		LocalVTEP:    localVTEP,
		VXLANPort:    vxlanPort,
		VTEPCount:    vtepCount,
		VNICount:     vniCount,
		TunnelCount:  tunnelCount,
		MACCount:     macCount,
		UplinkIface:  underlayIface,
		MTU:          mtu,
		EncapType:    encapType,
		HealthStatus: healthStatus,
	}, nil
}

// =============================================================================
// VTEP operations
// =============================================================================

// ListVTEPs returns all known VTEP endpoints.
func (a *overlayControllerQUICAdapter) ListVTEPs(ctx context.Context) ([]*quic.VTEPInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	vteps, err := a.ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToQUICError(err)
	}

	out := make([]*quic.VTEPInfo, 0, len(vteps))
	for i := range vteps {
		out = append(out, overlayVTEPToQUIC(&vteps[i]))
	}

	return out, nil
}

// GetVTEP retrieves a VTEP by its node ID string.
func (a *overlayControllerQUICAdapter) GetVTEP(ctx context.Context, id string) (*quic.VTEPInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	if id == "" {
		return nil, quic.ErrOverlayMissingVTEPID
	}

	vteps, err := a.ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToQUICError(err)
	}

	for i := range vteps {
		if vteps[i].NodeID == id {
			return overlayVTEPToQUIC(&vteps[i]), nil
		}
	}

	return nil, quic.ErrOverlayVTEPNotFound
}

// =============================================================================
// VNI operations
// =============================================================================

// ListVNIs returns all configured VNIs.
func (a *overlayControllerQUICAdapter) ListVNIs(ctx context.Context) ([]*quic.VNIInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	vnis, err := a.ctrl.ListVNIs(ctx)
	if err != nil {
		return nil, mapOverlayToQUICError(err)
	}

	out := make([]*quic.VNIInfo, 0, len(vnis))
	for i := range vnis {
		out = append(out, overlayVNIToQUIC(&vnis[i]))
	}

	return out, nil
}

// CreateVNI creates a new VNI on the overlay network.
func (a *overlayControllerQUICAdapter) CreateVNI(ctx context.Context, vni uint32, opts *quic.VNICreateOptions) (*quic.VNIInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	if vni == 0 || vni > overlay.MaxVNI {
		return nil, quic.ErrOverlayInvalidVNI
	}

	cfg := &overlay.VNIConfig{VNI: vni}

	if err := a.ctrl.AddVNI(ctx, cfg); err != nil {
		return nil, mapOverlayToQUICError(err)
	}

	// Retrieve the created VNI info for a faithful response.
	vniInfo, err := a.ctrl.GetVNI(ctx, vni)
	if err != nil {
		// VNI was created; synthesise a minimal response.
		return &quic.VNIInfo{
			VNI:       vni,
			Status:    "active",
			CreatedAt: time.Now().Unix(),
			Learning:  true,
		}, nil
	}

	return overlayVNIToQUIC(vniInfo), nil
}

// DeleteVNI removes a VNI from the overlay network.
func (a *overlayControllerQUICAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	if !a.ctrl.IsRunning() {
		return quic.ErrOverlayServiceNotAvailable
	}

	if vni == 0 {
		return quic.ErrOverlayMissingVNI
	}

	if err := a.ctrl.RemoveVNI(ctx, vni); err != nil {
		return mapOverlayToQUICError(err)
	}

	return nil
}

// =============================================================================
// Tunnel operations
// =============================================================================

// ListTunnels returns all VXLAN tunnels from the controller state snapshot.
func (a *overlayControllerQUICAdapter) ListTunnels(ctx context.Context) ([]*quic.TunnelInfo, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	state := a.ctrl.GetState()
	if state == nil {
		return []*quic.TunnelInfo{}, nil
	}

	out := make([]*quic.TunnelInfo, 0, len(state.Tunnels))
	for i := range state.Tunnels {
		t := &state.Tunnels[i]
		out = append(out, &quic.TunnelInfo{
			ID:         t.ID,
			LocalVTEP:  t.LocalVTEP.String(),
			RemoteVTEP: t.RemoteVTEP.String(),
			VNI:        t.VNI,
			Status:     t.State.String(),
			EncapType:  "vxlan",
			TxBytes:    int64(t.BytesTx),
			RxBytes:    int64(t.BytesRx),
			CreatedAt:  t.CreatedAt.Unix(),
		})
	}

	return out, nil
}

// =============================================================================
// MAC table operations
// =============================================================================

// ListMACs returns all learned remote MAC entries for a VNI.
func (a *overlayControllerQUICAdapter) ListMACs(ctx context.Context, vni uint32) ([]*quic.MACEntry, error) {
	if !a.ctrl.IsRunning() {
		return nil, quic.ErrOverlayServiceNotAvailable
	}

	// VNI == 0 means list all MACs across all VNIs (list-all semantics).
	// Gather entries from the state snapshot directly to avoid requiring a VNI.
	var rawMacs []overlay.RemoteMACEntry
	if vni == 0 {
		state := a.ctrl.GetState()
		if state != nil {
			rawMacs = state.RemoteMACs
		}
	} else {
		macs, err := a.ctrl.GetRemoteMACs(ctx, vni)
		if err != nil {
			return nil, mapOverlayToQUICError(err)
		}
		rawMacs = macs
	}

	out := make([]*quic.MACEntry, 0, len(rawMacs))
	for i := range rawMacs {
		m := &rawMacs[i]
		entry := &quic.MACEntry{
			MAC:         m.MAC.String(),
			VNI:         m.VNI,
			VTEP:        m.RemoteVTEP.String(),
			Type:        m.Source,
			LastSeen:    m.LearnedAt.UnixNano(),
			IsPermanent: m.ExpiresAt.IsZero(),
		}
		if !m.ExpiresAt.IsZero() {
			entry.Age = int(time.Since(m.LearnedAt).Seconds())
		}
		out = append(out, entry)
	}

	return out, nil
}

// ForgetMAC removes a learned MAC address from the forwarding table.
func (a *overlayControllerQUICAdapter) ForgetMAC(ctx context.Context, vni uint32, mac string) error {
	if !a.ctrl.IsRunning() {
		return quic.ErrOverlayServiceNotAvailable
	}

	if vni == 0 {
		return quic.ErrOverlayMissingVNI
	}

	if mac == "" {
		return quic.ErrOverlayMissingMAC
	}

	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return quic.ErrOverlayInvalidMAC
	}

	if err := a.ctrl.ForgetMAC(ctx, hwAddr, vni); err != nil {
		return mapOverlayToQUICError(err)
	}

	return nil
}

// =============================================================================
// Error mapping
// =============================================================================

// mapOverlayToQUICError translates overlay controller errors to the quic
// sentinel errors recognised by quic.OverlayHandler.overlayErrorResponse.
func mapOverlayToQUICError(err error) error {
	if err == nil {
		return nil
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "vtep not found"):
		return quic.ErrOverlayVTEPNotFound
	case strings.Contains(msg, "vni not found"):
		return quic.ErrOverlayVNINotFound
	case strings.Contains(msg, "mac") && strings.Contains(msg, "not found"):
		return quic.ErrOverlayMACNotFound
	case strings.Contains(msg, "already exists") && strings.Contains(msg, "vni"):
		return quic.ErrOverlayVNIAlreadyExists
	case strings.Contains(msg, "not running"):
		return quic.ErrOverlayServiceNotAvailable
	}

	return err
}

// =============================================================================
// Conversion helpers
// =============================================================================

// overlayVTEPToQUIC converts an overlay.VTEPInfo value to a *quic.VTEPInfo.
func overlayVTEPToQUIC(v *overlay.VTEPInfo) *quic.VTEPInfo {
	info := &quic.VTEPInfo{
		ID:          v.NodeID,
		IPAddress:   v.IP.String(),
		Hostname:    v.NodeID,
		TunnelCount: v.TunnelCount,
		LastSeen:    v.LastSeen.UnixNano(),
	}

	if v.Healthy {
		info.Status = "healthy"
	} else {
		info.Status = "degraded"
	}

	if v.EVPNEnabled {
		info.Capabilities = []string{"evpn"}
	}

	return info
}

// overlayVNIToQUIC converts an overlay.VNIInfo value to a *quic.VNIInfo.
func overlayVNIToQUIC(v *overlay.VNIInfo) *quic.VNIInfo {
	return &quic.VNIInfo{
		VNI:       v.VNI,
		Status:    "active",
		Learning:  true,
		CreatedAt: v.CreatedAt.Unix(),
		MACCount:  v.MACCount,
		VTEPCount: v.TunnelCount,
	}
}
