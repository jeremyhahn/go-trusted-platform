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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// OVSClient defines the interface for OVS operations required by VTEP management.
// This interface is implemented by the ovs.Client type.
type OVSClient interface {
	// AddVXLANPort creates a VXLAN port on the specified bridge.
	AddVXLANPort(ctx context.Context, bridge, port string, remoteIP string, vni uint32, dstPort uint16) error

	// DeletePort removes a port from the specified bridge.
	DeletePort(ctx context.Context, bridge, port string) error

	// GetOFPort retrieves the OpenFlow port number for an interface.
	GetOFPort(ctx context.Context, portName string) (int32, error)

	// IsConnected returns true if connected to OVSDB.
	IsConnected() bool
}

// VTEPManager manages the local VTEP and tunnels to remote VTEPs.
// It provides thread-safe operations for creating, managing, and
// monitoring VXLAN tunnels.
type VTEPManager struct {
	config     VTEPConfig
	ovsClient  OVSClient
	bridgeName string
	logger     *slog.Logger

	// tunnels maps tunnel keys to tunnel state
	// Key format: "{remote_vtep}:{vni}"
	tunnels map[string]*TunnelState

	// started indicates if the manager has been started
	started atomic.Bool

	// mu protects tunnels map
	mu sync.RWMutex
}

// VTEPManagerOption is a functional option for configuring the VTEPManager.
type VTEPManagerOption func(*VTEPManager)

// WithVTEPLogger sets the logger for the VTEP manager.
func WithVTEPLogger(logger *slog.Logger) VTEPManagerOption {
	return func(m *VTEPManager) {
		m.logger = logger
	}
}

// NewVTEPManager creates a new VTEP manager with the given configuration.
func NewVTEPManager(
	config VTEPConfig,
	ovsClient OVSClient,
	bridgeName string,
	logger *slog.Logger,
	opts ...VTEPManagerOption,
) (*VTEPManager, error) {
	if err := config.Validate(); err != nil {
		return nil, &ErrVTEPValidationFailed{
			Field: "config",
			Cause: err,
		}
	}

	if ovsClient == nil {
		return nil, ErrOVSClientNil
	}

	if bridgeName == "" {
		return nil, ErrBridgeNameEmpty
	}

	if logger == nil {
		return nil, ErrLoggerNil
	}

	manager := &VTEPManager{
		config:     config,
		ovsClient:  ovsClient,
		bridgeName: bridgeName,
		logger:     logger,
		tunnels:    make(map[string]*TunnelState),
	}

	for _, opt := range opts {
		opt(manager)
	}

	return manager, nil
}

// Start initializes the VTEP manager.
// It validates the configuration and prepares for tunnel management.
func (m *VTEPManager) Start(ctx context.Context) error {
	if m.started.Load() {
		return ErrManagerAlreadyStarted
	}

	// Verify OVS connectivity
	if !m.ovsClient.IsConnected() {
		m.logger.Error("OVS client not connected during VTEP manager start")
		return &ErrOVSOperationFailed{
			Operation: "connect",
			Target:    "OVSDB",
			Cause:     ErrVTEPNotConfigured,
		}
	}

	m.started.Store(true)

	m.logger.Info("VTEP manager started",
		slog.String("local_vtep", m.config.LocalIP.String()),
		slog.String("underlay_iface", m.config.UnderlayIface),
		slog.Int("underlay_mtu", m.config.UnderlayMTU),
		slog.Int("vxlan_port", int(m.config.VXLANPort)),
	)

	return nil
}

// Stop shuts down the VTEP manager and removes all tunnels.
func (m *VTEPManager) Stop() error {
	if !m.started.Load() {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Mark as stopped first
	m.started.Store(false)

	// Clean up tunnels
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var lastErr error
	for key, tunnel := range m.tunnels {
		if err := m.removeTunnelLocked(ctx, tunnel); err != nil {
			m.logger.Error("failed to remove tunnel during shutdown",
				slog.String("tunnel_id", tunnel.ID),
				slog.Any("error", err),
			)
			lastErr = err
		}
		delete(m.tunnels, key)
	}

	m.logger.Info("VTEP manager stopped")

	return lastErr
}

// AddTunnel creates a new VXLAN tunnel to a remote VTEP.
func (m *VTEPManager) AddTunnel(ctx context.Context, remoteVTEP netip.Addr, vni VNI) (*TunnelState, error) {
	if !m.started.Load() {
		return nil, ErrManagerNotStarted
	}

	if !remoteVTEP.IsValid() || remoteVTEP.IsUnspecified() {
		return nil, ErrInvalidVTEPIP
	}

	if !vni.Valid() {
		return nil, ErrVNIOutOfRange
	}

	// Check if tunnel to same VTEP already exists
	key := m.tunnelKey(remoteVTEP, vni)

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.tunnels[key]; ok {
		return existing, ErrTunnelExists
	}

	// Generate port name
	portName := m.generatePortName(remoteVTEP, vni)

	// Create VXLAN port in OVS
	err := m.ovsClient.AddVXLANPort(
		ctx,
		m.bridgeName,
		portName,
		remoteVTEP.String(),
		vni.Uint32(),
		m.config.VXLANPort,
	)
	if err != nil {
		return nil, &ErrTunnelCreationFailed{
			RemoteVTEP: remoteVTEP,
			VNI:        vni,
			Cause:      err,
		}
	}

	// Get OpenFlow port number
	ofPort, err := m.ovsClient.GetOFPort(ctx, portName)
	if err != nil {
		// Cleanup on failure
		cleanupErr := m.ovsClient.DeletePort(ctx, m.bridgeName, portName)
		if cleanupErr != nil {
			m.logger.Error("failed to cleanup port after OFPort retrieval failure",
				slog.String("port", portName),
				slog.Any("error", cleanupErr),
			)
		}
		return nil, &ErrTunnelCreationFailed{
			RemoteVTEP: remoteVTEP,
			VNI:        vni,
			Cause:      err,
		}
	}

	now := time.Now()
	tunnel := &TunnelState{
		ID:         m.generateTunnelID(remoteVTEP, vni),
		LocalVTEP:  m.config.LocalIP,
		RemoteVTEP: remoteVTEP,
		VNI:        vni,
		OVSPort:    portName,
		OFPort:     ofPort,
		State:      TunnelStatusUp,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	m.tunnels[key] = tunnel

	m.logger.Info("tunnel created",
		slog.String("tunnel_id", tunnel.ID),
		slog.String("remote_vtep", remoteVTEP.String()),
		slog.Int("vni", int(vni)),
		slog.String("ovs_port", portName),
		slog.Int("of_port", int(ofPort)),
	)

	return tunnel, nil
}

// RemoveTunnel removes a VXLAN tunnel to a remote VTEP.
func (m *VTEPManager) RemoveTunnel(ctx context.Context, remoteVTEP netip.Addr, vni VNI) error {
	if !m.started.Load() {
		return ErrManagerNotStarted
	}

	key := m.tunnelKey(remoteVTEP, vni)

	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, ok := m.tunnels[key]
	if !ok {
		return ErrTunnelNotFound
	}

	if err := m.removeTunnelLocked(ctx, tunnel); err != nil {
		return err
	}

	delete(m.tunnels, key)

	m.logger.Info("tunnel removed",
		slog.String("tunnel_id", tunnel.ID),
		slog.String("remote_vtep", remoteVTEP.String()),
		slog.Int("vni", int(vni)),
	)

	return nil
}

// removeTunnelLocked removes a tunnel from OVS.
// Caller must hold the write lock.
func (m *VTEPManager) removeTunnelLocked(ctx context.Context, tunnel *TunnelState) error {
	err := m.ovsClient.DeletePort(ctx, m.bridgeName, tunnel.OVSPort)
	if err != nil {
		return &ErrTunnelDeletionFailed{
			TunnelID: tunnel.ID,
			Cause:    err,
		}
	}
	return nil
}

// GetTunnel retrieves a tunnel by remote VTEP and VNI.
func (m *VTEPManager) GetTunnel(remoteVTEP netip.Addr, vni VNI) (*TunnelState, error) {
	if !m.started.Load() {
		return nil, ErrManagerNotStarted
	}

	key := m.tunnelKey(remoteVTEP, vni)

	m.mu.RLock()
	defer m.mu.RUnlock()

	tunnel, ok := m.tunnels[key]
	if !ok {
		return nil, ErrTunnelNotFound
	}

	// Return a copy to prevent external modification
	tunnelCopy := *tunnel
	return &tunnelCopy, nil
}

// GetTunnelByID retrieves a tunnel by its ID.
func (m *VTEPManager) GetTunnelByID(tunnelID string) (*TunnelState, error) {
	if !m.started.Load() {
		return nil, ErrManagerNotStarted
	}

	if tunnelID == "" {
		return nil, ErrInvalidTunnelID
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, tunnel := range m.tunnels {
		if tunnel.ID == tunnelID {
			tunnelCopy := *tunnel
			return &tunnelCopy, nil
		}
	}

	return nil, ErrTunnelNotFound
}

// ListTunnels returns a list of all tunnels.
func (m *VTEPManager) ListTunnels() []*TunnelState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*TunnelState, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnelCopy := *tunnel
		result = append(result, &tunnelCopy)
	}

	return result
}

// GetLocalVTEP returns the local VTEP IP address.
func (m *VTEPManager) GetLocalVTEP() netip.Addr {
	return m.config.LocalIP
}

// GetConfig returns a copy of the VTEP configuration.
func (m *VTEPManager) GetConfig() VTEPConfig {
	return m.config
}

// GetBridgeName returns the bridge name.
func (m *VTEPManager) GetBridgeName() string {
	return m.bridgeName
}

// IsStarted returns true if the manager has been started.
func (m *VTEPManager) IsStarted() bool {
	return m.started.Load()
}

// TunnelCount returns the number of active tunnels.
func (m *VTEPManager) TunnelCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.tunnels)
}

// UpdateTunnelState updates the state of a tunnel.
func (m *VTEPManager) UpdateTunnelState(remoteVTEP netip.Addr, vni VNI, state TunnelStatus) error {
	if !m.started.Load() {
		return ErrManagerNotStarted
	}

	key := m.tunnelKey(remoteVTEP, vni)

	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, ok := m.tunnels[key]
	if !ok {
		return ErrTunnelNotFound
	}

	tunnel.State = state
	tunnel.UpdatedAt = time.Now()

	m.logger.Debug("tunnel state updated",
		slog.String("tunnel_id", tunnel.ID),
		slog.String("state", state.String()),
	)

	return nil
}

// UpdateTunnelStats updates the statistics for a tunnel.
func (m *VTEPManager) UpdateTunnelStats(remoteVTEP netip.Addr, vni VNI, bytesSent, bytesRecv uint64) error {
	if !m.started.Load() {
		return ErrManagerNotStarted
	}

	key := m.tunnelKey(remoteVTEP, vni)

	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, ok := m.tunnels[key]
	if !ok {
		return ErrTunnelNotFound
	}

	tunnel.BytesSent = bytesSent
	tunnel.BytesRecv = bytesRecv
	tunnel.UpdatedAt = time.Now()

	return nil
}

// tunnelKey generates a map key for a tunnel.
func (m *VTEPManager) tunnelKey(remoteVTEP netip.Addr, vni VNI) string {
	return fmt.Sprintf("%s:%d", remoteVTEP.String(), vni)
}

// generateTunnelID generates a unique tunnel ID.
func (m *VTEPManager) generateTunnelID(remoteVTEP netip.Addr, vni VNI) string {
	return fmt.Sprintf("%s-%s-%d", m.config.LocalIP.String(), remoteVTEP.String(), vni)
}

// generatePortName generates an OVS port name for a VXLAN tunnel.
// Uses a hash-based approach for deterministic, collision-free names.
func (m *VTEPManager) generatePortName(remoteVTEP netip.Addr, vni VNI) string {
	// Create a deterministic hash of the tunnel parameters
	input := fmt.Sprintf("%s:%s:%d", m.config.LocalIP.String(), remoteVTEP.String(), vni)
	hash := sha256.Sum256([]byte(input))
	hashStr := hex.EncodeToString(hash[:8]) // First 8 bytes = 16 hex chars

	// OVS port names have a 15 character limit
	// "vxlan-" (6) + hash (9) = 15
	return fmt.Sprintf("vxlan-%s", hashStr[:9])
}
