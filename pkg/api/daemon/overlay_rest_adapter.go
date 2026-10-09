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
	"fmt"
	"net"
	"strings"
	"time"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayControllerRESTAdapter bridges an OverlayControllerInterface into the
// restapi.OverlayServiceInterface consumed by restapi.NewOverlayHandlers.
//
// All nine interface methods are backed by real in-process data from the
// controller. Controller errors are mapped to the typed REST sentinel errors
// so that the REST handler's writeOverlayError emits the correct HTTP status.
type overlayControllerRESTAdapter struct {
	ctrl  OverlayControllerInterface
	ipsec overlayIPsec
}

// Compile-time check.
var _ restapi.OverlayServiceInterface = (*overlayControllerRESTAdapter)(nil)

// newOverlayControllerRESTAdapter wraps a non-nil overlay controller as a
// restapi.OverlayServiceInterface. Callers must pass nil to
// restapi.NewOverlayHandlers directly when no controller is available; they
// should not wrap nil here.
func newOverlayControllerRESTAdapter(ctrl OverlayControllerInterface, sec ...overlayIPsec) *overlayControllerRESTAdapter {
	adapter := &overlayControllerRESTAdapter{ctrl: ctrl}
	if len(sec) > 0 {
		adapter.ipsec = sec[0]
	}
	return adapter
}

// =============================================================================
// Status
// =============================================================================

// GetOverlayStatus returns the current overlay network status.
func (a *overlayControllerRESTAdapter) GetOverlayStatus(ctx context.Context) (*restapi.OverlayStatusResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	state := a.ctrl.GetState()
	cfg := a.ctrl.GetConfig()

	resp := &restapi.OverlayStatusResponse{
		Healthy:   true,
		Timestamp: time.Now().UTC(),
	}

	if cfg != nil {
		resp.NodeID = cfg.NodeID
		resp.VXLANPort = cfg.VXLANPort
		if cfg.VTEPIP.IsValid() {
			resp.VTEPIP = cfg.VTEPIP.String()
		}
	}

	if state != nil {
		resp.VTEPCount = uint32(len(state.VTEPs))
		resp.VNICount = uint32(len(state.VNIs))
		resp.TunnelCount = uint32(len(state.Tunnels))
		resp.RemoteMACCount = uint32(len(state.RemoteMACs))
	}
	if a.ipsec != nil {
		resp.UnpeeredVTEPs = uint32(len(a.ipsec.Status().UnpeeredVTEPs))
	}

	return resp, nil
}

// =============================================================================
// VTEP operations
// =============================================================================

// ListVTEPs returns all known VTEP endpoints.
func (a *overlayControllerRESTAdapter) ListVTEPs(ctx context.Context) ([]restapi.VTEPInfoResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	vteps, err := a.ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToRESTError(err)
	}

	out := make([]restapi.VTEPInfoResponse, 0, len(vteps))
	for i := range vteps {
		out = append(out, overlayVTEPToREST(&vteps[i]))
	}

	return out, nil
}

// GetVTEP retrieves a VTEP by its node ID string. The controller stores VTEPs
// keyed by IP; this method scans the list and matches by NodeID, mirroring the
// QUIC adapter's identical lookup strategy.
func (a *overlayControllerRESTAdapter) GetVTEP(ctx context.Context, nodeID string) (*restapi.VTEPInfoResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	if nodeID == "" {
		return nil, restapi.ErrInvalidNodeID{}
	}

	vteps, err := a.ctrl.ListVTEPs(ctx)
	if err != nil {
		return nil, mapOverlayToRESTError(err)
	}

	for i := range vteps {
		if vteps[i].NodeID == nodeID {
			resp := overlayVTEPToREST(&vteps[i])
			return &resp, nil
		}
	}

	return nil, restapi.ErrVTEPNotFound{NodeID: nodeID}
}

// =============================================================================
// VNI operations
// =============================================================================

// ListVNIs returns all configured VNIs.
func (a *overlayControllerRESTAdapter) ListVNIs(ctx context.Context) ([]restapi.VNIResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	vnis, err := a.ctrl.ListVNIs(ctx)
	if err != nil {
		return nil, mapOverlayToRESTError(err)
	}

	out := make([]restapi.VNIResponse, 0, len(vnis))
	for i := range vnis {
		out = append(out, overlayVNIToREST(&vnis[i]))
	}

	return out, nil
}

// CreateVNI creates a new VNI on the overlay network.
func (a *overlayControllerRESTAdapter) CreateVNI(ctx context.Context, config *restapi.VNIConfigRequest) (*restapi.VNIResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	if config == nil || config.VNI == 0 {
		return nil, restapi.ErrInvalidVNI{VNI: 0}
	}

	if config.VNI > overlay.MaxVNI {
		return nil, restapi.ErrInvalidVNI{VNI: config.VNI}
	}

	cfg := &overlay.VNIConfig{VNI: config.VNI, VLAN: uint16(config.VLAN)}

	if err := a.ctrl.AddVNI(ctx, cfg); err != nil {
		return nil, mapOverlayToRESTError(err)
	}

	// Retrieve the created VNI info for a faithful response.
	vniInfo, err := a.ctrl.GetVNI(ctx, config.VNI)
	if err != nil {
		// VNI was created; synthesise a minimal response.
		resp := restapi.VNIResponse{
			ID: fmt.Sprintf("%d", config.VNI),
			Config: restapi.VNIConfigRequest{
				VNI:  config.VNI,
				VLAN: config.VLAN,
				Name: config.Name,
			},
			CreatedAt: time.Now().UTC(),
		}
		return &resp, nil
	}

	out := overlayVNIToREST(vniInfo)
	return &out, nil
}

// DeleteVNI removes a VNI from the overlay network.
func (a *overlayControllerRESTAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	if !a.ctrl.IsRunning() {
		return restapi.ErrOverlayServiceNotAvailable{}
	}

	if vni == 0 {
		return restapi.ErrInvalidVNI{VNI: 0}
	}

	if err := a.ctrl.RemoveVNI(ctx, vni); err != nil {
		return mapOverlayToRESTError(err)
	}

	return nil
}

// =============================================================================
// Tunnel operations
// =============================================================================

// ListTunnels returns all VXLAN tunnels from the controller state snapshot.
// A vni of 0 means list all tunnels (no filter).
func (a *overlayControllerRESTAdapter) ListTunnels(ctx context.Context, vni uint32) ([]restapi.TunnelInfoResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	state := a.ctrl.GetState()
	if state == nil {
		return []restapi.TunnelInfoResponse{}, nil
	}

	out := make([]restapi.TunnelInfoResponse, 0, len(state.Tunnels))
	for i := range state.Tunnels {
		t := &state.Tunnels[i]
		if vni != 0 && t.VNI != vni {
			continue
		}
		out = append(out, restapi.TunnelInfoResponse{
			LocalVTEP:  t.LocalVTEP.String(),
			RemoteVTEP: t.RemoteVTEP.String(),
			VNI:        t.VNI,
			State:      t.State.String(),
			BytesTx:    uint64(t.BytesTx),
			BytesRx:    uint64(t.BytesRx),
		})
	}

	return out, nil
}

// =============================================================================
// MAC table operations
// =============================================================================

// ListRemoteMACs returns all learned remote MAC entries for a VNI.
// A vni of 0 means list all MACs across all VNIs (list-all semantics), reading
// state.RemoteMACs directly to avoid requiring a specific VNI — mirroring the
// QUIC adapter's identical list-all path.
func (a *overlayControllerRESTAdapter) ListRemoteMACs(ctx context.Context, vni uint32) ([]restapi.RemoteMACResponse, error) {
	if !a.ctrl.IsRunning() {
		return nil, restapi.ErrOverlayServiceNotAvailable{}
	}

	var rawMacs []overlay.RemoteMACEntry
	if vni == 0 {
		state := a.ctrl.GetState()
		if state != nil {
			rawMacs = state.RemoteMACs
		}
	} else {
		macs, err := a.ctrl.GetRemoteMACs(ctx, vni)
		if err != nil {
			return nil, mapOverlayToRESTError(err)
		}
		rawMacs = macs
	}

	out := make([]restapi.RemoteMACResponse, 0, len(rawMacs))
	for i := range rawMacs {
		m := &rawMacs[i]
		out = append(out, restapi.RemoteMACResponse{
			MAC:        m.MAC.String(),
			VNI:        m.VNI,
			RemoteVTEP: m.RemoteVTEP.String(),
			LearnedAt:  m.LearnedAt,
		})
	}

	return out, nil
}

// ForgetMAC removes a learned MAC address from the forwarding table.
func (a *overlayControllerRESTAdapter) ForgetMAC(ctx context.Context, mac string, vni uint32) error {
	if !a.ctrl.IsRunning() {
		return restapi.ErrOverlayServiceNotAvailable{}
	}

	if mac == "" {
		return restapi.ErrInvalidMAC{}
	}

	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return restapi.ErrInvalidMAC{MAC: mac}
	}

	if err := a.ctrl.ForgetMAC(ctx, hwAddr, vni); err != nil {
		return mapOverlayToRESTError(err)
	}

	return nil
}

// =============================================================================
// Error mapping
// =============================================================================

// mapOverlayToRESTError translates overlay controller errors to the typed REST
// sentinel errors recognised by restapi.OverlayHandlers.writeOverlayError, which
// maps them to the appropriate HTTP status codes.
func mapOverlayToRESTError(err error) error {
	if err == nil {
		return nil
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "vtep not found"):
		return restapi.ErrVTEPNotFound{}
	case strings.Contains(msg, "vni not found"):
		return restapi.ErrVNINotFound{}
	case strings.Contains(msg, "mac") && strings.Contains(msg, "not found"):
		return restapi.ErrMACNotFound{}
	case strings.Contains(msg, "already exists") && strings.Contains(msg, "vni"):
		return restapi.ErrVNIAlreadyExists{}
	case strings.Contains(msg, "not running"):
		return restapi.ErrOverlayServiceNotAvailable{}
	}

	return err
}

// =============================================================================
// Conversion helpers
// =============================================================================

// overlayVTEPToREST converts an overlay.VTEPInfo value to a restapi.VTEPInfoResponse.
func overlayVTEPToREST(v *overlay.VTEPInfo) restapi.VTEPInfoResponse {
	return restapi.VTEPInfoResponse{
		NodeID: v.NodeID,
		IP:     v.IP.String(),
		// The controller does not track per-VTEP VNI membership; the wire
		// contract requires a non-nil slice (empty = none known).
		VNIs:     []uint32{},
		Healthy:  v.Healthy,
		LastSeen: v.LastSeen,
	}
}

// overlayVNIToREST converts an overlay.VNIInfo value to a restapi.VNIResponse.
func overlayVNIToREST(v *overlay.VNIInfo) restapi.VNIResponse {
	return restapi.VNIResponse{
		ID: fmt.Sprintf("%d", v.VNI),
		Config: restapi.VNIConfigRequest{
			VNI:  v.VNI,
			VLAN: uint32(v.VLAN),
		},
		CreatedAt: v.CreatedAt,
		MACCount:  uint32(v.MACCount),
	}
}
