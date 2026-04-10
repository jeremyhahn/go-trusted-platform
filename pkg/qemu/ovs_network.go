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

package qemu

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netlink"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// OVSNetwork manages OVS networking for a QEMU VM
type OVSNetwork struct {
	config    *Config
	logger    *logging.Logger
	ovsClient *ovs.Client
	nlManager *netlink.Manager
	tapName   string
}

// NewOVSNetwork creates a new OVS network manager for a VM
func NewOVSNetwork(config *Config, logger *logging.Logger) (*OVSNetwork, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is required", ErrInvalidConfiguration)
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	if !config.OVSEnabled() {
		return nil, fmt.Errorf("%w: OVS is not enabled", ErrInvalidOVSConfig)
	}

	socketPath := config.GetOVSSocketPath()
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("%w: socket not found at %s", ErrOVSNotAvailable, socketPath)
	}

	ovsClient, err := ovs.NewClient(socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOVSConnectionFailed, err)
	}

	return &OVSNetwork{
		config:    config,
		logger:    logger,
		ovsClient: ovsClient,
		nlManager: netlink.NewManager(),
	}, nil
}

// Setup creates a TAP device and attaches it to the OVS bridge
func (n *OVSNetwork) Setup(ctx context.Context) error {
	// Connect to OVSDB
	if err := n.ovsClient.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrOVSConnectionFailed, err)
	}

	bridgeName := n.config.GetOVSBridgeName()

	// Verify bridge exists
	bridge, err := n.ovsClient.GetBridge(ctx, bridgeName)
	if err != nil || bridge == nil {
		return fmt.Errorf("%w: %s", ErrOVSBridgeNotFound, bridgeName)
	}

	// Generate TAP device name
	n.tapName = n.generateTAPName()

	// Get current user UID/GID for TAP ownership
	owner, group := n.getOwnership()

	// Create TAP device
	tapConfig := &netlink.TAPConfig{
		Name:       n.tapName,
		Owner:      owner,
		Group:      group,
		MultiQueue: false,
		Persist:    true,
		MTU:        1500,
	}

	if err := n.nlManager.CreateTAP(tapConfig); err != nil {
		return fmt.Errorf("%w: %v", ErrTAPCreationFailed, err)
	}

	// Bring up the TAP device
	if err := n.nlManager.SetTAPUp(n.tapName); err != nil {
		// Cleanup TAP on failure
		_ = n.nlManager.DeleteTAP(n.tapName)
		return fmt.Errorf("%w: failed to bring up TAP: %v", ErrTAPCreationFailed, err)
	}

	// Add TAP device as OVS port
	port, err := n.ovsClient.AddPort(ctx, bridgeName, n.tapName)
	if err != nil {
		// Cleanup TAP on failure
		_ = n.nlManager.DeleteTAP(n.tapName)
		return fmt.Errorf("%w: %v", ErrOVSPortCreationFailed, err)
	}

	// Configure VLAN if specified
	if n.config.OVS.VLAN > 0 {
		if err := n.ovsClient.SetPortVLAN(ctx, n.tapName, int64(n.config.OVS.VLAN)); err != nil {
			_ = n.Cleanup(ctx)
			return fmt.Errorf("failed to set VLAN tag: %w", err)
		}
	}

	// Configure trunk VLANs if specified
	if len(n.config.OVS.Trunks) > 0 {
		trunks := make([]int64, len(n.config.OVS.Trunks))
		for i, v := range n.config.OVS.Trunks {
			trunks[i] = int64(v)
		}
		if err := n.ovsClient.SetPortTrunks(ctx, n.tapName, trunks); err != nil {
			_ = n.Cleanup(ctx)
			return fmt.Errorf("failed to set trunk VLANs: %w", err)
		}
	}

	// Set external IDs for identification
	if n.config.OVS.ExternalIDs != nil {
		if err := n.ovsClient.UpdatePort(ctx, n.tapName, map[string]interface{}{
			"external_ids": ovs.MarshalMap(n.config.OVS.ExternalIDs),
		}); err != nil {
			// Non-fatal - log warning and continue
			n.logger.Warnf("failed to set OVS port external IDs for %s: %v", n.tapName, err)
		}
	}

	// Set port to UP state
	if err := n.ovsClient.SetPortState(ctx, port.Name, ovs.PortStateUp); err != nil {
		// Non-fatal - port might come up automatically, log warning
		n.logger.Warnf("failed to set OVS port state to UP for %s: %v", port.Name, err)
	}

	return nil
}

// Cleanup removes the TAP device and OVS port
func (n *OVSNetwork) Cleanup(ctx context.Context) error {
	if n.tapName == "" {
		return nil
	}

	var lastErr error

	// Remove port from OVS bridge
	bridgeName := n.config.GetOVSBridgeName()
	if err := n.ovsClient.DeletePort(ctx, bridgeName, n.tapName); err != nil {
		lastErr = fmt.Errorf("failed to delete OVS port: %w", err)
	}

	// Delete TAP device
	if err := n.nlManager.DeleteTAP(n.tapName); err != nil {
		lastErr = fmt.Errorf("failed to delete TAP device: %w", err)
	}

	n.tapName = ""

	return lastErr
}

// Close disconnects from OVSDB
func (n *OVSNetwork) Close() error {
	if n.ovsClient != nil {
		return n.ovsClient.Disconnect()
	}
	return nil
}

// GetTAPName returns the name of the created TAP device
func (n *OVSNetwork) GetTAPName() string {
	return n.tapName
}

// generateTAPName generates a unique TAP device name
func (n *OVSNetwork) generateTAPName() string {
	// Use configured port name if provided
	if n.config.OVS != nil && n.config.OVS.PortName != "" {
		return n.config.OVS.PortName
	}

	// Generate unique name based on timestamp
	// Format: qemu-XXXX where XXXX is last 4 chars of timestamp
	timestamp := time.Now().UnixNano()
	suffix := fmt.Sprintf("%04d", timestamp%10000)
	return fmt.Sprintf("qemu-%s", suffix)
}

// getOwnership returns the UID and GID for TAP device ownership
func (n *OVSNetwork) getOwnership() (uint32, uint32) {
	// Default to current user
	currentUser, err := user.Current()
	if err != nil {
		return 0, 0 // Fall back to root
	}

	uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		return 0, 0
	}

	gid, err := strconv.ParseUint(currentUser.Gid, 10, 32)
	if err != nil {
		return uint32(uid), 0
	}

	return uint32(uid), uint32(gid)
}

// ValidateOVSConfig validates the OVS configuration
func ValidateOVSConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("%w: config is nil", ErrInvalidOVSConfig)
	}

	if !config.OVSEnabled() {
		return nil // OVS not enabled, nothing to validate
	}

	ovs := config.OVS

	// Validate VLAN tag
	if ovs.VLAN > 4094 {
		return fmt.Errorf("%w: VLAN tag must be 0-4094", ErrInvalidOVSConfig)
	}

	// Validate trunk VLANs
	for _, vlan := range ovs.Trunks {
		if vlan > 4094 {
			return fmt.Errorf("%w: trunk VLAN must be 0-4094", ErrInvalidOVSConfig)
		}
	}

	// Validate VLAN mode
	if ovs.VLANMode != "" {
		validModes := map[string]bool{
			"access":        true,
			"trunk":         true,
			"native-tagged": true,
		}
		if !validModes[ovs.VLANMode] {
			return fmt.Errorf("%w: invalid VLAN mode: %s", ErrInvalidOVSConfig, ovs.VLANMode)
		}
	}

	// Validate QoS configuration
	if ovs.QoS != nil {
		if ovs.QoS.MaxRate < 0 {
			return fmt.Errorf("%w: QoS max rate must be non-negative", ErrInvalidOVSConfig)
		}
		if ovs.QoS.MinRate < 0 {
			return fmt.Errorf("%w: QoS min rate must be non-negative", ErrInvalidOVSConfig)
		}
		if ovs.QoS.Burst < 0 {
			return fmt.Errorf("%w: QoS burst must be non-negative", ErrInvalidOVSConfig)
		}
		if ovs.QoS.Priority < 0 || ovs.QoS.Priority > 7 {
			return fmt.Errorf("%w: QoS priority must be 0-7", ErrInvalidOVSConfig)
		}
	}

	return nil
}
