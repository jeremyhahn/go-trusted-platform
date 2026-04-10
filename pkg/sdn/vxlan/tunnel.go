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

package vxlan

import (
	"context"
	"log/slog"
	"net/netip"
	"time"
)

// TunnelOperations provides high-level tunnel operations.
// It wraps the VTEPManager to provide a simplified interface for
// common tunnel management tasks.
type TunnelOperations struct {
	manager *VTEPManager
	logger  *slog.Logger
}

// NewTunnelOperations creates a new TunnelOperations instance.
func NewTunnelOperations(manager *VTEPManager, logger *slog.Logger) (*TunnelOperations, error) {
	if manager == nil {
		return nil, ErrVTEPNotConfigured
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}

	return &TunnelOperations{
		manager: manager,
		logger:  logger,
	}, nil
}

// CreateTunnel creates a new VXLAN tunnel to a remote VTEP.
func (t *TunnelOperations) CreateTunnel(ctx context.Context, remote netip.Addr, vni VNI) (*TunnelState, error) {
	if !remote.IsValid() || remote.IsUnspecified() {
		return nil, ErrInvalidVTEPIP
	}

	if !vni.Valid() {
		return nil, ErrVNIOutOfRange
	}

	return t.manager.AddTunnel(ctx, remote, vni)
}

// DestroyTunnel removes a VXLAN tunnel by its ID.
func (t *TunnelOperations) DestroyTunnel(ctx context.Context, tunnelID string) error {
	if tunnelID == "" {
		return ErrInvalidTunnelID
	}

	// Find the tunnel by ID
	tunnel, err := t.manager.GetTunnelByID(tunnelID)
	if err != nil {
		return err
	}

	return t.manager.RemoveTunnel(ctx, tunnel.RemoteVTEP, tunnel.VNI)
}

// DestroyTunnelByVTEP removes a VXLAN tunnel by remote VTEP and VNI.
func (t *TunnelOperations) DestroyTunnelByVTEP(ctx context.Context, remote netip.Addr, vni VNI) error {
	return t.manager.RemoveTunnel(ctx, remote, vni)
}

// GetTunnelStats retrieves statistics for a tunnel by its ID.
func (t *TunnelOperations) GetTunnelStats(ctx context.Context, tunnelID string) (*TunnelStats, error) {
	if tunnelID == "" {
		return nil, ErrInvalidTunnelID
	}

	tunnel, err := t.manager.GetTunnelByID(tunnelID)
	if err != nil {
		return nil, err
	}

	return &TunnelStats{
		BytesSent:   tunnel.BytesSent,
		BytesRecv:   tunnel.BytesRecv,
		PacketsSent: 0, // Would need OVS interface stats
		PacketsRecv: 0, // Would need OVS interface stats
		ErrorsSent:  0, // Would need OVS interface stats
		ErrorsRecv:  0, // Would need OVS interface stats
	}, nil
}

// HealthCheck performs a health check on a tunnel.
// Returns true if the tunnel is healthy, false otherwise.
func (t *TunnelOperations) HealthCheck(ctx context.Context, tunnelID string) (bool, error) {
	if tunnelID == "" {
		return false, ErrInvalidTunnelID
	}

	tunnel, err := t.manager.GetTunnelByID(tunnelID)
	if err != nil {
		return false, err
	}

	// Check basic tunnel state
	if tunnel.State != TunnelStatusUp {
		return false, nil
	}

	// Check if OFPort is valid
	if tunnel.OFPort <= 0 {
		return false, nil
	}

	return true, nil
}

// ListAllTunnels returns all active tunnels.
func (t *TunnelOperations) ListAllTunnels() []*TunnelState {
	return t.manager.ListTunnels()
}

// ListTunnelsByVNI returns all tunnels for a specific VNI.
func (t *TunnelOperations) ListTunnelsByVNI(vni VNI) []*TunnelState {
	all := t.manager.ListTunnels()
	result := make([]*TunnelState, 0)

	for _, tunnel := range all {
		if tunnel.VNI == vni {
			result = append(result, tunnel)
		}
	}

	return result
}

// ListTunnelsByRemoteVTEP returns all tunnels to a specific remote VTEP.
func (t *TunnelOperations) ListTunnelsByRemoteVTEP(remote netip.Addr) []*TunnelState {
	all := t.manager.ListTunnels()
	result := make([]*TunnelState, 0)

	for _, tunnel := range all {
		if tunnel.RemoteVTEP == remote {
			result = append(result, tunnel)
		}
	}

	return result
}

// GetTunnel retrieves a tunnel by remote VTEP and VNI.
func (t *TunnelOperations) GetTunnel(remote netip.Addr, vni VNI) (*TunnelState, error) {
	return t.manager.GetTunnel(remote, vni)
}

// GetTunnelByID retrieves a tunnel by its ID.
func (t *TunnelOperations) GetTunnelByID(tunnelID string) (*TunnelState, error) {
	if tunnelID == "" {
		return nil, ErrInvalidTunnelID
	}
	return t.manager.GetTunnelByID(tunnelID)
}

// SetTunnelState updates the state of a tunnel.
func (t *TunnelOperations) SetTunnelState(remote netip.Addr, vni VNI, state TunnelStatus) error {
	return t.manager.UpdateTunnelState(remote, vni, state)
}

// GetLocalVTEP returns the local VTEP IP address.
func (t *TunnelOperations) GetLocalVTEP() netip.Addr {
	return t.manager.GetLocalVTEP()
}

// TunnelCount returns the total number of active tunnels.
func (t *TunnelOperations) TunnelCount() int {
	return t.manager.TunnelCount()
}

// TunnelCountByStatus returns the count of tunnels in each status.
func (t *TunnelOperations) TunnelCountByStatus() map[TunnelStatus]int {
	result := make(map[TunnelStatus]int)
	result[TunnelStatusUnknown] = 0
	result[TunnelStatusUp] = 0
	result[TunnelStatusDown] = 0
	result[TunnelStatusError] = 0

	for _, tunnel := range t.manager.ListTunnels() {
		result[tunnel.State]++
	}

	return result
}

// GetHealthyTunnels returns all tunnels with TunnelStatusUp.
func (t *TunnelOperations) GetHealthyTunnels() []*TunnelState {
	all := t.manager.ListTunnels()
	result := make([]*TunnelState, 0)

	for _, tunnel := range all {
		if tunnel.State == TunnelStatusUp {
			result = append(result, tunnel)
		}
	}

	return result
}

// GetUnhealthyTunnels returns all tunnels not in TunnelStatusUp.
func (t *TunnelOperations) GetUnhealthyTunnels() []*TunnelState {
	all := t.manager.ListTunnels()
	result := make([]*TunnelState, 0)

	for _, tunnel := range all {
		if tunnel.State != TunnelStatusUp {
			result = append(result, tunnel)
		}
	}

	return result
}

// GetStaleTunnels returns tunnels that haven't been updated recently.
func (t *TunnelOperations) GetStaleTunnels(staleThreshold time.Duration) []*TunnelState {
	all := t.manager.ListTunnels()
	result := make([]*TunnelState, 0)
	cutoff := time.Now().Add(-staleThreshold)

	for _, tunnel := range all {
		if tunnel.UpdatedAt.Before(cutoff) {
			result = append(result, tunnel)
		}
	}

	return result
}

// EnsureTunnel creates a tunnel if it doesn't exist, otherwise returns existing.
func (t *TunnelOperations) EnsureTunnel(ctx context.Context, remote netip.Addr, vni VNI) (*TunnelState, error) {
	// Try to get existing tunnel first
	tunnel, err := t.manager.GetTunnel(remote, vni)
	if err == nil {
		return tunnel, nil
	}

	// If not found, create it
	if err == ErrTunnelNotFound {
		return t.manager.AddTunnel(ctx, remote, vni)
	}

	return nil, err
}

// RemoveAllTunnels removes all active tunnels.
func (t *TunnelOperations) RemoveAllTunnels(ctx context.Context) error {
	tunnels := t.manager.ListTunnels()
	var lastErr error

	for _, tunnel := range tunnels {
		if err := t.manager.RemoveTunnel(ctx, tunnel.RemoteVTEP, tunnel.VNI); err != nil {
			t.logger.Error("failed to remove tunnel",
				slog.String("tunnel_id", tunnel.ID),
				slog.Any("error", err),
			)
			lastErr = err
		}
	}

	return lastErr
}

// RemoveTunnelsByVNI removes all tunnels for a specific VNI.
func (t *TunnelOperations) RemoveTunnelsByVNI(ctx context.Context, vni VNI) error {
	tunnels := t.ListTunnelsByVNI(vni)
	var lastErr error

	for _, tunnel := range tunnels {
		if err := t.manager.RemoveTunnel(ctx, tunnel.RemoteVTEP, tunnel.VNI); err != nil {
			t.logger.Error("failed to remove tunnel for VNI",
				slog.String("tunnel_id", tunnel.ID),
				slog.Int("vni", int(vni)),
				slog.Any("error", err),
			)
			lastErr = err
		}
	}

	return lastErr
}

// RemoveTunnelsByRemoteVTEP removes all tunnels to a specific remote VTEP.
func (t *TunnelOperations) RemoveTunnelsByRemoteVTEP(ctx context.Context, remote netip.Addr) error {
	tunnels := t.ListTunnelsByRemoteVTEP(remote)
	var lastErr error

	for _, tunnel := range tunnels {
		if err := t.manager.RemoveTunnel(ctx, tunnel.RemoteVTEP, tunnel.VNI); err != nil {
			t.logger.Error("failed to remove tunnel to remote VTEP",
				slog.String("tunnel_id", tunnel.ID),
				slog.String("remote_vtep", remote.String()),
				slog.Any("error", err),
			)
			lastErr = err
		}
	}

	return lastErr
}
