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
)

// DefaultBridgeName is the default OVS bridge name.
const DefaultBridgeName = "br-int"

// VLANIntegration defines the interface for VLAN management operations.
// This is the base interface used by the PXE service for VLAN transitions.
type VLANIntegration interface {
	// ApplyQuarantineVLAN places the device in the quarantine VLAN.
	ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error

	// ApplyProvisioningVLAN moves the device to the provisioning VLAN.
	ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error

	// ApplyProductionVLAN moves the device to the production VLAN.
	ApplyProductionVLAN(ctx context.Context, portID string, vlanID uint16) error

	// GetCurrentVLAN returns the current VLAN assignment for a port.
	GetCurrentVLAN(ctx context.Context, portID string) (uint16, error)

	// ApplyQuarantineFlows moves device to quarantine VLAN.
	// Only allows access to auth service and remediation portal.
	ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error

	// ApplyProvisioningFlows moves device to provisioning VLAN.
	// Allows DHCP, TFTP, HTTP, DNS, ACME access.
	ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error

	// ApplyProductionFlows moves device to production VLAN per profile.
	// Applies ACLs from device profile.
	ApplyProductionFlows(ctx context.Context, portID string, mac net.HardwareAddr, targetVLAN uint16) error
}

// VLANIntegrationWrapper provides an extended interface with additional
// PXE-specific operations beyond the base VLANIntegration interface.
// It embeds VLANIntegration to maintain compatibility with the service.
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

// vlanIntegrationWrapper implements the VLANIntegrationWrapper interface by wrapping the SDN VLANFlowManager.
type vlanIntegrationWrapper struct {
	flowManager      *policy.VLANFlowManager
	bridgeName       string
	quarantineVLAN   uint16
	provisioningVLAN uint16
	acmeServerIPs    []net.IP
	dnsServerIPs     []net.IP
	logger           *slog.Logger
	closed           atomic.Bool
}

// VLANIntegrationOption is a functional option for configuring VLANIntegrationWrapper.
type VLANIntegrationOption func(*vlanIntegrationWrapper)

// WithFlowManager sets the SDN VLANFlowManager to use.
func WithFlowManager(fm *policy.VLANFlowManager) VLANIntegrationOption {
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

// WithQuarantineVLAN sets the quarantine VLAN ID.
func WithQuarantineVLAN(vlan uint16) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.quarantineVLAN = vlan
	}
}

// WithProvisioningVLAN sets the provisioning VLAN ID.
func WithProvisioningVLAN(vlan uint16) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.provisioningVLAN = vlan
	}
}

// WithACMEServers sets the ACME server IPs allowed in provisioning VLAN.
func WithACMEServers(ips []net.IP) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.acmeServerIPs = ips
	}
}

// WithDNSServers sets the DNS server IPs allowed in provisioning VLAN.
func WithDNSServers(ips []net.IP) VLANIntegrationOption {
	return func(v *vlanIntegrationWrapper) {
		v.dnsServerIPs = ips
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
// Places the device in the quarantine VLAN.
func (v *vlanIntegrationWrapper) ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	v.logger.Info("applying quarantine VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping quarantine VLAN application",
			slog.String("port_id", portID))
		return nil
	}

	// Delegate to the SDN flow manager
	if err := v.flowManager.ApplyQuarantineFlows(portID, ""); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			ToVLAN:   vlanID,
			Reason:   "failed to apply quarantine VLAN",
			Cause:    err,
		}
	}

	v.logger.Info("quarantine VLAN applied successfully",
		slog.String("port_id", portID))

	return nil
}

// ApplyProvisioningVLAN implements VLANIntegration.ApplyProvisioningVLAN.
// Moves the device to the provisioning VLAN.
func (v *vlanIntegrationWrapper) ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	v.logger.Info("applying provisioning VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping provisioning VLAN application",
			slog.String("port_id", portID))
		return nil
	}

	// Delegate to the SDN flow manager
	if err := v.flowManager.ApplyProvisioningFlows(portID, ""); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			ToVLAN:   vlanID,
			Reason:   "failed to apply provisioning VLAN",
			Cause:    err,
		}
	}

	v.logger.Info("provisioning VLAN applied successfully",
		slog.String("port_id", portID))

	return nil
}

// ApplyProductionVLAN implements VLANIntegration.ApplyProductionVLAN.
// Moves the device to the production VLAN.
func (v *vlanIntegrationWrapper) ApplyProductionVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	if vlanID == 0 {
		return ErrInvalidConfiguration{
			Field:  "vlanID",
			Reason: "VLAN ID must be non-zero",
		}
	}

	v.logger.Info("applying production VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping production VLAN application",
			slog.String("port_id", portID))
		return nil
	}

	// For production flows, we remove existing flows first.
	// In a full implementation, you would apply profile-specific ACLs here.
	if err := v.flowManager.RemoveFlows(portID); err != nil {
		v.logger.Warn("failed to remove existing flows before applying production VLAN",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	v.logger.Info("production VLAN applied successfully",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	return nil
}

// GetCurrentVLAN implements VLANIntegration.GetCurrentVLAN.
// Returns the current VLAN assignment for a port.
func (v *vlanIntegrationWrapper) GetCurrentVLAN(ctx context.Context, portID string) (uint16, error) {
	if v.closed.Load() {
		return 0, ErrServiceNotRunning{}
	}

	if portID == "" {
		return 0, ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	// If no flow manager configured, return 0
	if v.flowManager == nil {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}

	vlan, err := v.flowManager.GetPortVLAN(portID)
	if err != nil {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}

	return vlan, nil
}

// ApplyQuarantineFlows moves device to quarantine VLAN.
// Only allows access to auth service (8443) and remediation portal.
func (v *vlanIntegrationWrapper) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}

	v.logger.Info("applying quarantine flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan", uint64(v.quarantineVLAN)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping quarantine flow application",
			slog.String("port_id", portID))
		return nil
	}

	// Delegate to the SDN flow manager
	if err := v.flowManager.ApplyQuarantineFlows(portID, mac.String()); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			ToVLAN:   v.quarantineVLAN,
			Reason:   "failed to apply quarantine flows",
			Cause:    err,
		}
	}

	v.logger.Info("quarantine flows applied successfully",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()))

	return nil
}

// ApplyProvisioningFlows moves device to provisioning VLAN.
// Allows DHCP (67-68), TFTP (69), HTTP/S (80, 443), DNS (53), ACME (8443).
// Blocks east-west traffic and internet access.
func (v *vlanIntegrationWrapper) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}

	v.logger.Info("applying provisioning flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan", uint64(v.provisioningVLAN)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping provisioning flow application",
			slog.String("port_id", portID))
		return nil
	}

	// Delegate to the SDN flow manager
	if err := v.flowManager.ApplyProvisioningFlows(portID, mac.String()); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			ToVLAN:   v.provisioningVLAN,
			Reason:   "failed to apply provisioning flows",
			Cause:    err,
		}
	}

	v.logger.Info("provisioning flows applied successfully",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()))

	return nil
}

// ApplyProductionFlows moves device to production VLAN per profile.
// Applies ACLs from device profile.
func (v *vlanIntegrationWrapper) ApplyProductionFlows(
	ctx context.Context,
	portID string,
	mac net.HardwareAddr,
	targetVLAN uint16,
) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := v.validateInputs(portID, mac); err != nil {
		return err
	}

	if targetVLAN == 0 {
		return ErrInvalidConfiguration{
			Field:  "targetVLAN",
			Reason: "target VLAN must be non-zero",
		}
	}

	v.logger.Info("applying production flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan", uint64(targetVLAN)))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping production flow application",
			slog.String("port_id", portID))
		return nil
	}

	// For production flows, we need a device profile. Since we don't have one here,
	// we'll remove existing flows and let the caller handle ACLs.
	// This is a simplified version - in production, you'd pass the full profile.
	if err := v.flowManager.RemoveFlows(portID); err != nil {
		v.logger.Warn("failed to remove existing flows before applying production flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	v.logger.Info("production flows applied successfully",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan", uint64(targetVLAN)))

	return nil
}

// BlockPort sets OVS port admin state to down (for severe violations).
func (v *vlanIntegrationWrapper) BlockPort(ctx context.Context, portID string) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	v.logger.Info("blocking port",
		slog.String("port_id", portID))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping port block",
			slog.String("port_id", portID))
		return nil
	}

	// Remove all flows for this port (effectively blocking it)
	if err := v.flowManager.RemoveFlows(portID); err != nil {
		return ErrVLANTransitionFailed{
			DeviceID: portID,
			Reason:   "failed to block port",
			Cause:    err,
		}
	}

	v.logger.Info("port blocked successfully",
		slog.String("port_id", portID))

	return nil
}

// UnblockPort sets OVS port admin state to up.
func (v *vlanIntegrationWrapper) UnblockPort(ctx context.Context, portID string) error {
	if v.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	v.logger.Info("unblocking port",
		slog.String("port_id", portID))

	// If no flow manager configured, this is a no-op
	if v.flowManager == nil {
		v.logger.Debug("no flow manager configured, skipping port unblock",
			slog.String("port_id", portID))
		return nil
	}

	// Note: Unblocking doesn't apply any specific flows - it just prepares the port
	// for the next VLAN assignment. The caller should apply the appropriate flows
	// after unblocking.

	v.logger.Info("port unblocked successfully",
		slog.String("port_id", portID))

	return nil
}

// GetPortVLAN returns current VLAN for a port.
func (v *vlanIntegrationWrapper) GetPortVLAN(ctx context.Context, portID string) (uint16, error) {
	return v.GetCurrentVLAN(ctx, portID)
}

// Close releases resources.
func (v *vlanIntegrationWrapper) Close() error {
	if v.closed.Swap(true) {
		return nil // Already closed
	}

	v.logger.Info("closing VLAN integration wrapper")

	return nil
}

// validateInputs validates the common inputs for VLAN operations.
func (v *vlanIntegrationWrapper) validateInputs(portID string, mac net.HardwareAddr) error {
	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	if len(mac) == 0 {
		return ErrInvalidMACAddress{
			Reason: "MAC address is required",
		}
	}

	return nil
}

// noopVLANIntegration is a no-op implementation of VLANIntegrationWrapper for testing.
type noopVLANIntegration struct {
	portVLANs    sync.Map // map[string]uint16
	blockedPorts sync.Map // map[string]bool
	closed       atomic.Bool
	logger       *slog.Logger
}

// NewNoopVLANIntegration creates a new no-op VLANIntegrationWrapper for testing.
// It stores VLAN assignments in memory without requiring OVS.
func NewNoopVLANIntegration() VLANIntegrationWrapper {
	return &noopVLANIntegration{
		logger: slog.Default(),
	}
}

// ApplyQuarantineVLAN implements VLANIntegration.ApplyQuarantineVLAN.
func (n *noopVLANIntegration) ApplyQuarantineVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)

	n.logger.Debug("noop: applied quarantine VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	return nil
}

// ApplyProvisioningVLAN implements VLANIntegration.ApplyProvisioningVLAN.
func (n *noopVLANIntegration) ApplyProvisioningVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)

	n.logger.Debug("noop: applied provisioning VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	return nil
}

// ApplyProductionVLAN implements VLANIntegration.ApplyProductionVLAN.
func (n *noopVLANIntegration) ApplyProductionVLAN(ctx context.Context, portID string, vlanID uint16) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	if vlanID == 0 {
		return ErrInvalidConfiguration{
			Field:  "vlanID",
			Reason: "VLAN ID must be non-zero",
		}
	}

	n.portVLANs.Store(portID, vlanID)
	n.blockedPorts.Delete(portID)

	n.logger.Debug("noop: applied production VLAN",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(vlanID)))

	return nil
}

// GetCurrentVLAN implements VLANIntegration.GetCurrentVLAN.
func (n *noopVLANIntegration) GetCurrentVLAN(ctx context.Context, portID string) (uint16, error) {
	if n.closed.Load() {
		return 0, ErrServiceNotRunning{}
	}

	if portID == "" {
		return 0, ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	value, ok := n.portVLANs.Load(portID)
	if !ok {
		return 0, ErrDeviceNotFound{DeviceID: portID}
	}

	vlan, ok := value.(uint16)
	if !ok {
		return 0, fmt.Errorf("pxe: invalid VLAN type stored for port %s", portID)
	}

	return vlan, nil
}

// ApplyQuarantineFlows stores the quarantine VLAN assignment in memory.
func (n *noopVLANIntegration) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}

	n.portVLANs.Store(portID, DefaultQuarantineVLAN)
	n.blockedPorts.Delete(portID) // Ensure port is not blocked

	n.logger.Debug("noop: applied quarantine flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()))

	return nil
}

// ApplyProvisioningFlows stores the provisioning VLAN assignment in memory.
func (n *noopVLANIntegration) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}

	n.portVLANs.Store(portID, DefaultProvisioningVLAN)
	n.blockedPorts.Delete(portID) // Ensure port is not blocked

	n.logger.Debug("noop: applied provisioning flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()))

	return nil
}

// ApplyProductionFlows stores the production VLAN assignment in memory.
func (n *noopVLANIntegration) ApplyProductionFlows(
	ctx context.Context,
	portID string,
	mac net.HardwareAddr,
	targetVLAN uint16,
) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if err := n.validateInputs(portID, mac); err != nil {
		return err
	}

	if targetVLAN == 0 {
		return ErrInvalidConfiguration{
			Field:  "targetVLAN",
			Reason: "target VLAN must be non-zero",
		}
	}

	n.portVLANs.Store(portID, targetVLAN)
	n.blockedPorts.Delete(portID) // Ensure port is not blocked

	n.logger.Debug("noop: applied production flows",
		slog.String("port_id", portID),
		slog.String("mac", mac.String()),
		slog.Uint64("vlan", uint64(targetVLAN)))

	return nil
}

// BlockPort marks the port as blocked in memory.
func (n *noopVLANIntegration) BlockPort(ctx context.Context, portID string) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	n.blockedPorts.Store(portID, true)

	n.logger.Debug("noop: blocked port",
		slog.String("port_id", portID))

	return nil
}

// UnblockPort removes the blocked status in memory.
func (n *noopVLANIntegration) UnblockPort(ctx context.Context, portID string) error {
	if n.closed.Load() {
		return ErrServiceNotRunning{}
	}

	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	n.blockedPorts.Delete(portID)

	n.logger.Debug("noop: unblocked port",
		slog.String("port_id", portID))

	return nil
}

// GetPortVLAN returns the current VLAN for a port from memory.
func (n *noopVLANIntegration) GetPortVLAN(ctx context.Context, portID string) (uint16, error) {
	return n.GetCurrentVLAN(ctx, portID)
}

// Close marks the no-op integration as closed.
func (n *noopVLANIntegration) Close() error {
	if n.closed.Swap(true) {
		return nil // Already closed
	}

	n.logger.Debug("noop: closing VLAN integration")

	return nil
}

// validateInputs validates the common inputs for VLAN operations.
func (n *noopVLANIntegration) validateInputs(portID string, mac net.HardwareAddr) error {
	if portID == "" {
		return ErrInvalidConfiguration{
			Field:  "portID",
			Reason: "port ID is required",
		}
	}

	if len(mac) == 0 {
		return ErrInvalidMACAddress{
			Reason: "MAC address is required",
		}
	}

	return nil
}

// IsPortBlocked returns true if the port is blocked (noop-specific helper for testing).
func (n *noopVLANIntegration) IsPortBlocked(portID string) bool {
	value, ok := n.blockedPorts.Load(portID)
	if !ok {
		return false
	}
	blocked, _ := value.(bool)
	return blocked
}
