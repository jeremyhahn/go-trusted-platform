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

package bridge

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBridgePrefix is the default prefix for tenant bridges
	DefaultBridgePrefix = "br-tenant-"

	// DefaultDatapath is the default OVS datapath type
	DefaultDatapath = "system"

	// DefaultFailMode is the default bridge fail mode
	DefaultFailMode = "secure"

	// MaxBridgeNameLength is the maximum length for a bridge name
	MaxBridgeNameLength = 15

	// MinTenantNameLength is the minimum length for a tenant name
	MinTenantNameLength = 1

	// MaxTenantNameLength is the maximum length for a tenant name
	MaxTenantNameLength = 64
)

var (
	// validTenantNameRegex matches valid tenant names (alphanumeric, hyphens, underscores)
	validTenantNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
)

// Config holds configuration for the bridge manager
type Config struct {
	// BridgePrefix is the prefix for tenant bridge names
	BridgePrefix string

	// Datapath is the OVS datapath type (system, netdev)
	Datapath string

	// FailMode is the default fail mode for bridges
	FailMode string

	// Protocols are the OpenFlow protocols to enable
	Protocols []string

	// OVSSocket is the path to the OVSDB socket
	OVSSocket string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		BridgePrefix: DefaultBridgePrefix,
		Datapath:     DefaultDatapath,
		FailMode:     DefaultFailMode,
		Protocols:    []string{"OpenFlow13", "OpenFlow15"},
		OVSSocket:    "/var/run/openvswitch/db.sock",
	}
}

// Manager handles per-tenant OVS bridge lifecycle
type Manager struct {
	ovsClient OVSClient
	ofClient  OpenFlowClient
	logger    *slog.Logger
	config    *Config

	// Runtime tracking
	mu      sync.RWMutex
	bridges map[string]*TenantBridge // tenantID -> bridge
}

// NewManager creates a new bridge manager
func NewManager(ovsClient OVSClient, ofClient OpenFlowClient, cfg *Config, logger *slog.Logger) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.BridgePrefix == "" {
		cfg.BridgePrefix = DefaultBridgePrefix
	}

	if cfg.Datapath == "" {
		cfg.Datapath = DefaultDatapath
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		ovsClient: ovsClient,
		ofClient:  ofClient,
		logger:    logger,
		config:    cfg,
		bridges:   make(map[string]*TenantBridge),
	}
}

// CreateBridge creates a new OVS bridge for a tenant
func (m *Manager) CreateBridge(ctx context.Context, tenantID, tenantName string, vlanRange VLANRange) (*TenantBridge, error) {
	// Validate inputs
	if err := m.validateTenantName(tenantName); err != nil {
		return nil, err
	}

	if !vlanRange.IsValid() {
		return nil, ErrInvalidVLANRange{
			Start:  vlanRange.Start,
			End:    vlanRange.End,
			Reason: "VLAN range must be 1-4094 and start <= end",
		}
	}

	bridgeName := m.bridgeName(tenantName)

	m.logger.Info("creating tenant bridge",
		"tenant_id", tenantID,
		"tenant_name", tenantName,
		"bridge_name", bridgeName,
		"vlan_range", vlanRange,
	)

	// Check for existing bridge
	m.mu.Lock()
	if existing, ok := m.bridges[tenantID]; ok {
		m.mu.Unlock()
		if existing.Status == StatusPending || existing.Status == StatusDeleting {
			return nil, ErrOperationInProgress{
				TenantID:  tenantID,
				Operation: string(existing.Status),
			}
		}
		return nil, ErrBridgeExists{Name: bridgeName}
	}

	// Create placeholder with pending status
	bridge := &TenantBridge{
		Name:       bridgeName,
		TenantID:   tenantID,
		TenantName: tenantName,
		Datapath:   m.config.Datapath,
		VLANRange:  vlanRange,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Status:     StatusPending,
	}
	m.bridges[tenantID] = bridge
	m.mu.Unlock()

	// Create the OVS bridge
	if err := m.ovsClient.CreateBridge(ctx, bridgeName); err != nil {
		m.mu.Lock()
		bridge.Status = StatusError
		bridge.ErrorMessage = err.Error()
		bridge.UpdatedAt = time.Now()
		m.mu.Unlock()

		m.logger.Error("failed to create OVS bridge",
			"bridge_name", bridgeName,
			"error", err,
		)

		return nil, ErrBridgeCreateFailed{Name: bridgeName, Err: err}
	}

	// Configure bridge properties
	if err := m.configureBridge(ctx, bridgeName); err != nil {
		// Rollback: delete the bridge
		m.logger.Warn("rolling back bridge creation due to configuration failure",
			"bridge_name", bridgeName,
			"error", err,
		)

		if delErr := m.ovsClient.DeleteBridge(ctx, bridgeName); delErr != nil {
			m.logger.Error("failed to rollback bridge creation",
				"bridge_name", bridgeName,
				"error", delErr,
			)
		}

		m.mu.Lock()
		bridge.Status = StatusError
		bridge.ErrorMessage = err.Error()
		bridge.UpdatedAt = time.Now()
		m.mu.Unlock()

		return nil, ErrBridgeCreateFailed{Name: bridgeName, Err: err}
	}

	// Get bridge info from OVS
	info, err := m.ovsClient.GetBridge(ctx, bridgeName)
	if err != nil {
		m.logger.Warn("failed to get bridge info after creation",
			"bridge_name", bridgeName,
			"error", err,
		)
	} else if info != nil {
		bridge.UUID = info.UUID
		bridge.PortCount = len(info.Ports)
	}

	// Update status to active
	m.mu.Lock()
	bridge.Status = StatusActive
	bridge.UpdatedAt = time.Now()
	m.mu.Unlock()

	m.logger.Info("tenant bridge created successfully",
		"tenant_id", tenantID,
		"bridge_name", bridgeName,
		"uuid", bridge.UUID,
	)

	return bridge, nil
}

// DeleteBridge removes a tenant's OVS bridge
func (m *Manager) DeleteBridge(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	bridge, ok := m.bridges[tenantID]
	if !ok {
		m.mu.Unlock()
		return ErrTenantNotFound{TenantID: tenantID}
	}

	if bridge.Status == StatusDeleting {
		m.mu.Unlock()
		return ErrOperationInProgress{
			TenantID:  tenantID,
			Operation: "delete",
		}
	}

	// Mark as deleting
	bridge.Status = StatusDeleting
	bridge.UpdatedAt = time.Now()
	m.mu.Unlock()

	bridgeName := bridge.Name

	m.logger.Info("deleting tenant bridge",
		"tenant_id", tenantID,
		"bridge_name", bridgeName,
	)

	// Delete all flows first
	if m.ofClient != nil {
		if err := m.ofClient.DeleteAllFlows(ctx, bridgeName); err != nil {
			m.logger.Warn("failed to delete flows before bridge deletion",
				"bridge_name", bridgeName,
				"error", err,
			)
		}
	}

	// Delete the OVS bridge
	if err := m.ovsClient.DeleteBridge(ctx, bridgeName); err != nil {
		m.mu.Lock()
		bridge.Status = StatusError
		bridge.ErrorMessage = err.Error()
		bridge.UpdatedAt = time.Now()
		m.mu.Unlock()

		m.logger.Error("failed to delete OVS bridge",
			"bridge_name", bridgeName,
			"error", err,
		)

		return ErrBridgeDeleteFailed{Name: bridgeName, Err: err}
	}

	// Remove from tracking
	m.mu.Lock()
	delete(m.bridges, tenantID)
	m.mu.Unlock()

	m.logger.Info("tenant bridge deleted successfully",
		"tenant_id", tenantID,
		"bridge_name", bridgeName,
	)

	return nil
}

// GetBridge returns a tenant's bridge info
func (m *Manager) GetBridge(ctx context.Context, tenantID string) (*TenantBridge, error) {
	m.mu.RLock()
	bridge, ok := m.bridges[tenantID]
	m.mu.RUnlock()

	if !ok {
		return nil, ErrTenantNotFound{TenantID: tenantID}
	}

	// Return a copy to prevent external modification
	return m.copyBridge(bridge), nil
}

// GetBridgeByName returns bridge info by bridge name
func (m *Manager) GetBridgeByName(ctx context.Context, name string) (*TenantBridge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, bridge := range m.bridges {
		if bridge.Name == name {
			return m.copyBridge(bridge), nil
		}
	}

	return nil, ErrBridgeNotFound{Name: name}
}

// ListBridges returns all tenant bridges
func (m *Manager) ListBridges(ctx context.Context) ([]*TenantBridge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	bridges := make([]*TenantBridge, 0, len(m.bridges))
	for _, bridge := range m.bridges {
		bridges = append(bridges, m.copyBridge(bridge))
	}

	return bridges, nil
}

// GetStatus returns bridge operational status
func (m *Manager) GetStatus(ctx context.Context, tenantID string) (BridgeStatus, error) {
	m.mu.RLock()
	bridge, ok := m.bridges[tenantID]
	m.mu.RUnlock()

	if !ok {
		return "", ErrTenantNotFound{TenantID: tenantID}
	}

	return bridge.Status, nil
}

// Refresh updates bridge info from OVS
func (m *Manager) Refresh(ctx context.Context, tenantID string) error {
	m.mu.RLock()
	bridge, ok := m.bridges[tenantID]
	m.mu.RUnlock()

	if !ok {
		return ErrTenantNotFound{TenantID: tenantID}
	}

	m.logger.Debug("refreshing bridge info",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
	)

	// Get bridge info from OVS
	info, err := m.ovsClient.GetBridge(ctx, bridge.Name)
	if err != nil {
		m.mu.Lock()
		bridge.Status = StatusError
		bridge.ErrorMessage = err.Error()
		bridge.UpdatedAt = time.Now()
		m.mu.Unlock()
		return err
	}

	// Get flow count
	var flowCount int
	if m.ofClient != nil {
		flows, err := m.ofClient.GetFlows(ctx, bridge.Name)
		if err == nil {
			flowCount = len(flows)
		}
	}

	// Update bridge info
	m.mu.Lock()
	bridge.UUID = info.UUID
	bridge.PortCount = len(info.Ports)
	bridge.FlowCount = flowCount
	bridge.UpdatedAt = time.Now()

	// Update status based on OVS state
	if bridge.Status == StatusError {
		bridge.Status = StatusActive
		bridge.ErrorMessage = ""
	}
	m.mu.Unlock()

	return nil
}

// SetStatus sets the bridge status
func (m *Manager) SetStatus(ctx context.Context, tenantID string, status BridgeStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	bridge, ok := m.bridges[tenantID]
	if !ok {
		return ErrTenantNotFound{TenantID: tenantID}
	}

	bridge.Status = status
	bridge.UpdatedAt = time.Now()

	m.logger.Info("bridge status updated",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
		"status", status,
	)

	return nil
}

// bridgeName generates the bridge name for a tenant
func (m *Manager) bridgeName(tenantName string) string {
	// Normalize tenant name: lowercase, replace spaces with hyphens
	name := strings.ToLower(tenantName)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "_", "-")

	// Construct bridge name
	bridgeName := m.config.BridgePrefix + name

	// Truncate if too long (OVS has a 15 char limit on interface names)
	if len(bridgeName) > MaxBridgeNameLength {
		bridgeName = bridgeName[:MaxBridgeNameLength]
	}

	return bridgeName
}

// validateTenantName validates a tenant name
func (m *Manager) validateTenantName(name string) error {
	if len(name) < MinTenantNameLength {
		return ErrInvalidBridgeName{
			Name:   name,
			Reason: "tenant name is too short",
		}
	}

	if len(name) > MaxTenantNameLength {
		return ErrInvalidBridgeName{
			Name:   name,
			Reason: "tenant name is too long",
		}
	}

	if !validTenantNameRegex.MatchString(name) {
		return ErrInvalidBridgeName{
			Name:   name,
			Reason: "tenant name must start with a letter and contain only alphanumeric characters, hyphens, and underscores",
		}
	}

	return nil
}

// configureBridge configures bridge properties after creation
func (m *Manager) configureBridge(ctx context.Context, bridgeName string) error {
	// Set datapath type if not default
	if m.config.Datapath != "" && m.config.Datapath != "system" {
		if err := m.ovsClient.SetBridgeDatapath(ctx, bridgeName, m.config.Datapath); err != nil {
			return err
		}
	}

	// Set fail mode
	if m.config.FailMode != "" {
		if err := m.ovsClient.SetBridgeFailMode(ctx, bridgeName, m.config.FailMode); err != nil {
			return err
		}
	}

	// Set protocols
	if len(m.config.Protocols) > 0 {
		if err := m.ovsClient.SetBridgeProtocols(ctx, bridgeName, m.config.Protocols); err != nil {
			return err
		}
	}

	return nil
}

// copyBridge creates a copy of a TenantBridge
func (m *Manager) copyBridge(bridge *TenantBridge) *TenantBridge {
	return &TenantBridge{
		Name:         bridge.Name,
		TenantID:     bridge.TenantID,
		TenantName:   bridge.TenantName,
		Datapath:     bridge.Datapath,
		VLANRange:    bridge.VLANRange,
		CreatedAt:    bridge.CreatedAt,
		UpdatedAt:    bridge.UpdatedAt,
		Status:       bridge.Status,
		PortCount:    bridge.PortCount,
		FlowCount:    bridge.FlowCount,
		UUID:         bridge.UUID,
		ErrorMessage: bridge.ErrorMessage,
	}
}

// Sync synchronizes the manager's state with OVS
func (m *Manager) Sync(ctx context.Context) error {
	m.logger.Info("synchronizing bridge state with OVS")

	// Get all bridges from OVS
	bridgeNames, err := m.ovsClient.ListBridges(ctx)
	if err != nil {
		return ErrOVSConnectionFailed{Err: err}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Create a set of bridge names we manage
	managedBridges := make(map[string]bool)
	for _, bridge := range m.bridges {
		managedBridges[bridge.Name] = true
	}

	// Check for bridges that exist in OVS but not in our state
	for _, name := range bridgeNames {
		if strings.HasPrefix(name, m.config.BridgePrefix) {
			if !managedBridges[name] {
				m.logger.Warn("found orphaned tenant bridge in OVS",
					"bridge_name", name,
				)
			}
		}
	}

	// Check for bridges in our state that don't exist in OVS
	ovsBridgeSet := make(map[string]bool)
	for _, name := range bridgeNames {
		ovsBridgeSet[name] = true
	}

	for tenantID, bridge := range m.bridges {
		if !ovsBridgeSet[bridge.Name] {
			m.logger.Warn("managed bridge not found in OVS, marking as error",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
			)
			bridge.Status = StatusError
			bridge.ErrorMessage = "bridge not found in OVS"
			bridge.UpdatedAt = time.Now()
		}
	}

	return nil
}
