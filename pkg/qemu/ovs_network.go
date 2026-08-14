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
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "config is required"}}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	if !config.OVSEnabled() {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "OVS is not enabled"}}
	}

	socketPath := config.GetOVSSocketPath()
	if _, err := os.Stat(socketPath); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOVSNotAvailable, Cause: &MessageError{Msg: fmt.Sprintf("socket not found at %s", socketPath)}}
	}

	ovsClient, err := ovs.NewClient(socketPath)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOVSConnectionFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
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
		return &SentinelCauseError{Sentinel: ErrOVSConnectionFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}

	bridgeName := n.config.GetOVSBridgeName()

	// Verify bridge exists
	bridge, err := n.ovsClient.GetBridge(ctx, bridgeName)
	if err != nil || bridge == nil {
		return &SentinelCauseError{Sentinel: ErrOVSBridgeNotFound, Cause: &MessageError{Msg: bridgeName}}
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
		return &SentinelCauseError{Sentinel: ErrTAPCreationFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}

	// Bring up the TAP device
	if err := n.nlManager.SetTAPUp(n.tapName); err != nil {
		// Cleanup TAP on failure
		_ = n.nlManager.DeleteTAP(n.tapName)
		return &SentinelCauseError{Sentinel: ErrTAPCreationFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to bring up TAP: %v", err)}}
	}

	// Add TAP device as OVS port
	port, err := n.ovsClient.AddPort(ctx, bridgeName, n.tapName)
	if err != nil {
		// Cleanup TAP on failure
		_ = n.nlManager.DeleteTAP(n.tapName)
		return &SentinelCauseError{Sentinel: ErrOVSPortCreationFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}

	// Configure VLAN if specified
	if n.config.OVS.VLAN > 0 {
		if err := n.ovsClient.SetPortVLAN(ctx, n.tapName, int64(n.config.OVS.VLAN)); err != nil {
			_ = n.Cleanup(ctx)
			return &WrappedError{Msg: "failed to set VLAN tag", Err: err}
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
			return &WrappedError{Msg: "failed to set trunk VLANs", Err: err}
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
		lastErr = &WrappedError{Msg: "failed to delete OVS port", Err: err}
	}

	// Delete TAP device
	if err := n.nlManager.DeleteTAP(n.tapName); err != nil {
		lastErr = &WrappedError{Msg: "failed to delete TAP device", Err: err}
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
		return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "config is nil"}}
	}

	if !config.OVSEnabled() {
		return nil // OVS not enabled, nothing to validate
	}

	ovs := config.OVS

	// Validate VLAN tag
	if ovs.VLAN > 4094 {
		return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "VLAN tag must be 0-4094"}}
	}

	// Validate trunk VLANs
	for _, vlan := range ovs.Trunks {
		if vlan > 4094 {
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "trunk VLAN must be 0-4094"}}
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
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: fmt.Sprintf("invalid VLAN mode: %s", ovs.VLANMode)}}
		}
	}

	// Validate QoS configuration
	if ovs.QoS != nil {
		if ovs.QoS.MaxRate < 0 {
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "QoS max rate must be non-negative"}}
		}
		if ovs.QoS.MinRate < 0 {
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "QoS min rate must be non-negative"}}
		}
		if ovs.QoS.Burst < 0 {
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "QoS burst must be non-negative"}}
		}
		if ovs.QoS.Priority < 0 || ovs.QoS.Priority > 7 {
			return &SentinelCauseError{Sentinel: ErrInvalidOVSConfig, Cause: &MessageError{Msg: "QoS priority must be 0-7"}}
		}
	}

	return nil
}
