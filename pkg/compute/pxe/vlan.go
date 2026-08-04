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

package pxe

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// DefaultBridgeName is the default OVS bridge name.
const DefaultBridgeName = "br-int"

// VLANIntegration defines the interface for network zone management operations.
// The PXE service uses this interface to transition device ports between network
// zones during the provisioning lifecycle.
type VLANIntegration interface {
	// ApplyQuarantineVLAN places the device in the quarantine VLAN.
	ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error

	// ApplyProvisioningVLAN moves the device to the provisioning VLAN.
	ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error

	// ApplyZoneVLAN moves the device to the VLAN for the given zone.
	// The VLAN is resolved by the underlying ZoneFlowManager via its ZoneIndex
	// or built-in zone defaults.
	ApplyZoneVLAN(ctx context.Context, portID string, z zone.Zone) error

	// GetCurrentVLAN returns the current VLAN assignment for a port.
	GetCurrentVLAN(ctx context.Context, portID string) (uint16, error)

	// ApplyQuarantineFlows moves device to quarantine zone.
	// Only allows access to auth service and remediation portal.
	ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error

	// ApplyProvisioningFlows moves device to provisioning zone.
	// Allows DHCP, TFTP, HTTP, DNS, ACME access.
	ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error

	// ApplyProductionFlows moves device to trusted production zone.
	// The zone is zone.ZoneTrusted; the VLAN is resolved by ZoneFlowManager.
	ApplyProductionFlows(ctx context.Context, portID string, mac net.HardwareAddr) error
}

// VLANIntegrationWrapper provides an extended interface with additional
// PXE-specific operations beyond the base VLANIntegration interface.
type VLANIntegrationWrapper interface {
	VLANIntegration

	// BlockPort sets OVS port admin state to down (for severe violations).
	BlockPort(ctx context.Context, portID string) error

	// UnblockPort sets OVS port admin state to up.
	UnblockPort(ctx context.Context, portID string) error

	// GetPortVLAN returns current VLAN for a port.
	GetPortVLAN(ctx context.Context, portID string) (uint16, error)

	// Close releases resources.
	Close() error
}

// vlanIntegrationWrapper implements VLANIntegrationWrapper by delegating zone
// transitions to the SDN ZoneFlowManager.
type vlanIntegrationWrapper struct {
	flowManager      *policy.ZoneFlowManager
	bridgeName       string
	quarantineVLAN   uint16
	provisioningVLAN uint16
	logger           *slog.Logger
	closed           atomic.Bool
}

// VLANIntegrationOption is a functional option for configuring VLANIntegrationWrapper.
type VLANIntegrationOption func(*vlanIntegrationWrapper)

// WithFlowManager sets the SDN ZoneFlowManager to use.
func WithFlowManager(fm *policy.ZoneFlowManager) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.flowManager = fm
	}
}

// WithBridgeName sets the OVS bridge name.
func WithBridgeName(name string) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.bridgeName = name
	}
}

// WithQuarantineVLAN sets the fallback quarantine VLAN ID.
func WithQuarantineVLAN(vlan uint16) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.quarantineVLAN = vlan
	}
}

// WithProvisioningVLAN sets the fallback provisioning VLAN ID.
func WithProvisioningVLAN(vlan uint16) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.provisioningVLAN = vlan
	}
}

// WithVLANLogger sets the logger for VLAN operations.
func WithVLANLogger(logger *slog.Logger) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.logger = logger
	}
}

// NewVLANIntegrationWrapper creates a new VLANIntegrationWrapper with the provided options.
func NewVLANIntegrationWrapper(opts ...VLANIntegrationOption) VLANIntegrationWrapper {
	v := &vlanIntegrationWrapper{
		bridgeName:       DefaultBridgeName,
		quarantineVLAN:   DefaultQuarantineVLAN,
		provisioningVLAN: DefaultProvisioningVLAN,
		logger:           slog.Default(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ApplyQuarantineVLAN implements VLANIntegration.ApplyQuarantineVLAN.
func (v *vlanIntegrationWrapper) ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	return v.applyZone(ctx, portID, zone.ZoneQuarantine)
}

// ApplyProvisioningVLAN implements VLANIntegration.ApplyProvisioningVLAN.
func (v *vlanIntegrationWrapper) ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	return v.applyZone(ctx, portID, zone.ZoneProvisioning)
}

// ApplyZoneVLAN implements VLANIntegration.ApplyZoneVLAN.
// The VLAN is resolved by the ZoneFlowManager from the zone name.
func (v *vlanIntegrationWrapper) ApplyZoneVLAN(ctx context.Context, portID string, z zone.Zone) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if z == "" {
		return ErrInvalidConfiguration{Field: "zone", Reason: "zone is required"}
	}
	return v.applyZone(ctx, portID, z)
}

// GetCurrentVLAN implements VLANIntegration.GetCurrentVLAN.
func (v *vlanIntegrationWrapper) GetCurrentVLAN(ctx context.Context, portID string) (uint16, error) {
	if v.closed.Load() {
		return 0, ErrServiceNotRunning{}
	}
	if portID == "" {
		return 0, ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if v.flowManager == nil {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}
	vlanID, err := v.flowManager.GetPortVLAN(portID)
	if err != nil {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}
	return vlanID, nil
}

// ApplyQuarantineFlows implements VLANIntegration.ApplyQuarantineFlows.
func (v *vlanIntegrationWrapper) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}
	return v.applyZoneWithLog(ctx, portID, zone.ZoneQuarantine, mac, v.quarantineVLAN)
}

// ApplyProvisioningFlows implements VLANIntegration.ApplyProvisioningFlows.
func (v *vlanIntegrationWrapper) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}
	return v.applyZoneWithLog(ctx, portID, zone.ZoneProvisioning, mac, v.provisioningVLAN)
}

// ApplyProductionFlows implements VLANIntegration.ApplyProductionFlows.
// The device is placed in zone.ZoneTrusted; the VLAN is resolved by the ZoneFlowManager.
func (v *vlanIntegrationWrapper) ApplyProductionFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}
	return v.applyZoneWithLog(ctx, portID, zone.ZoneTrusted, mac, 0)
}

// BlockPort removes all OVS flows for the port (no new traffic accepted).
func (v *vlanIntegrationWrapper) BlockPort(ctx context.Context, portID string) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if v.flowManager == nil {
		return nil
	}
	if err := v.flowManager.RemoveFlows(portID); err != nil {
		return ErrVLANTransitionFailed{DeviceID: portID, Reason: "failed to block port", Cause: err}
	}
	return nil
}

// UnblockPort prepares a port for the next zone assignment (no flows restored here).
func (v *vlanIntegrationWrapper) UnblockPort(ctx context.Context, portID string) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	return nil
}

// GetPortVLAN returns current VLAN for a port.
func (v *vlanIntegrationWrapper) GetPortVLAN(ctx context.Context, portID string) (uint16, error) {
	return v.GetCurrentVLAN(ctx, portID)
}

// Close releases resources.
func (v *vlanIntegrationWrapper) Close() error {
	v.closed.Swap(true)
	return nil
}

// applyZone delegates zone flow installation to the ZoneFlowManager. When no
// flow manager is configured the call is a no-op (policy does not require OVS).
func (v *vlanIntegrationWrapper) applyZone(ctx context.Context, portID string, z zone.Zone) error {
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping zone flow application",
			slog.String("port_id", portID),
			slog.String("zone", string(z)))
		return nil
	}
	if err := v.flowManager.ApplyZoneFlows(ctx, portID, z); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			Reason:   fmt.Sprintf("failed to apply %s zone flows", z),
			Cause:    err,
		}
	}
	return nil
}

// applyZoneWithLog is applyZone with structured logging. The logVLAN parameter
// is informational only (used when the VLAN is already known to the caller).
func (v *vlanIntegrationWrapper) applyZoneWithLog(
	ctx context.Context,
	portID string,
	z zone.Zone,
	mac net.HardwareAddr,
	logVLAN uint16,
) error {
	v.logger.Info("applying zone flows",
		slog.String("port_id", portID),
		slog.String("zone", string(z)),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan_hint", uint64(logVLAN)))

	if err := v.applyZone(ctx, portID, z); err != nil {
		return err
	}

	v.logger.Info("zone flows applied successfully",
		slog.String("port_id", portID),
		slog.String("zone", string(z)),
		slog.String("mac", mac.String()))

	return nil
}

// validateInputs validates the common inputs for network operations.
func (v *vlanIntegrationWrapper) validateInputs(portID string, mac net.HardwareAddr) error {
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if len(mac) == 0 {
		return ErrInvalidMACAddress{Reason: "MAC address is required"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// noopVLANIntegration — in-memory implementation for tests
// ---------------------------------------------------------------------------

// noopVLANIntegration implements VLANIntegrationWrapper without requiring OVS.
// Port→VLAN mappings are stored in memory. Intended for unit tests only.
type noopVLANIntegration struct {
	portVLANs    sync.Map // map[string]uint16
	blockedPorts sync.Map // map[string]bool
	closed       atomic.Bool
	logger       *slog.Logger
}

// NewNoopVLANIntegration creates a no-op VLANIntegrationWrapper for testing.
func NewNoopVLANIntegration() VLANIntegrationWrapper {
	return &noopVLANIntegration{
		logger: slog.Default(),
	}
}

func (n *noopVLANIntegration) ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) ApplyZoneVLAN(ctx context.Context, portID string, z zone.Zone) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if z == "" {
		return ErrInvalidConfiguration{Field: "zone", Reason: "zone is required"}
	}
	// Map zone to a VLAN for in-memory tracking.
	vlanID := zoneToDefaultVLAN(z)
	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) GetCurrentVLAN(ctx context.Context, portID string) (uint16, error) {
	if n.closed.Load() {
		return 0, ErrServiceNotRunning{}
	}
	if portID == "" {
		return 0, ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	value, ok := n.portVLANs.Load(portID)
	if !ok {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}
	vlan, ok := value.(uint16)
	if !ok {
		return 0, &MessageError{Msg: fmt.Sprintf("pxe: invalid VLAN type stored for port %s", portID)}
	}
	return vlan, nil
}

func (n *noopVLANIntegration) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}
	n.portVLANs.Store(portID, DefaultQuarantineVLAN)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}
	n.portVLANs.Store(portID, DefaultProvisioningVLAN)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) ApplyProductionFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}
	n.portVLANs.Store(portID, DefaultTrustedVLAN)
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) BlockPort(ctx context.Context, portID string) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	n.blockedPorts.Store(portID, true)
	return nil
}

func (n *noopVLANIntegration) UnblockPort(ctx context.Context, portID string) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	n.blockedPorts.Delete(portID)
	return nil
}

func (n *noopVLANIntegration) GetPortVLAN(ctx context.Context, portID string) (uint16, error) {
	return n.GetCurrentVLAN(ctx, portID)
}

func (n *noopVLANIntegration) Close() error {
	n.closed.Swap(true)
	return nil
}

func (n *noopVLANIntegration) validateInputs(portID string, mac net.HardwareAddr) error {
	if portID == "" {
		return ErrInvalidConfiguration{Field: "portID", Reason: "port ID is required"}
	}
	if len(mac) == 0 {
		return ErrInvalidMACAddress{Reason: "MAC address is required"}
	}
	return nil
}

// IsPortBlocked returns true if the port is blocked (test helper).
func (n *noopVLANIntegration) IsPortBlocked(portID string) bool {
	value, ok := n.blockedPorts.Load(portID)
	if !ok {
		return false
	}
	blocked, _ := value.(bool)
	return blocked
}

// zoneToDefaultVLAN maps a zone name to its default VLAN using the built-in
// policy package defaults.
func zoneToDefaultVLAN(z zone.Zone) uint16 {
	defaults := map[zone.Zone]uint16{
		zone.ZoneTrusted:      DefaultTrustedVLAN,
		zone.ZoneProvisioning: DefaultProvisioningVLAN,
		zone.ZoneQuarantine:   DefaultQuarantineVLAN,
		zone.ZoneStorage:      DefaultStorageVLAN,
		zone.ZoneManagement:   DefaultManagementVLAN,
	}
	if v, ok := defaults[z]; ok {
		return v
	}
	return 0
}
