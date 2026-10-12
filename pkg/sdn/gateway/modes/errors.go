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

package modes

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// Sentinel errors for mode operations.
var (
	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrSpeakerNil is returned when a nil speaker is provided.
	ErrSpeakerNil = &errSpeakerNil{}

	// ErrAlreadyRunning is returned when attempting to start an already running handler.
	ErrAlreadyRunning = &errAlreadyRunning{}

	// ErrNotRunning is returned when operations are attempted on a stopped handler.
	ErrNotRunning = &errNotRunning{}

	// ErrInvalidTier is returned when an invalid speaker tier is configured.
	ErrInvalidTier = &errInvalidTier{}

	// ErrNoPrefixesConfigured is returned when no prefixes are configured for announcement.
	ErrNoPrefixesConfigured = &errNoPrefixesConfigured{}

	// ErrInvalidIPv6Prefix is returned when an IPv6 prefix is invalid.
	ErrInvalidIPv6Prefix = &errInvalidIPv6Prefix{}

	// ErrInvalidIPv4Prefix is returned when an IPv4 prefix is invalid.
	ErrInvalidIPv4Prefix = &errInvalidIPv4Prefix{}

	// ErrInvalidASN is returned when an invalid ASN is configured.
	ErrInvalidASN = &errInvalidASN{}

	// ErrNoRPKIValidators is returned when RPKI is enabled but no validators configured.
	ErrNoRPKIValidators = &errNoRPKIValidators{}

	// ErrSigningKeyRequired is returned when coordinator tier lacks signing key.
	ErrSigningKeyRequired = &errSigningKeyRequired{}

	// ErrInvalidMinGateways is returned when MinGatewaysForRoute is negative.
	ErrInvalidMinGateways = &errInvalidMinGateways{}

	// ErrNotCoordinatorTier is returned when route signing is attempted on non-coordinator.
	ErrNotCoordinatorTier = &errNotCoordinatorTier{}

	// ErrSigningKeyNotConfigured is returned when signing key is not configured.
	ErrSigningKeyNotConfigured = &errSigningKeyNotConfigured{}

	// ErrEmptySignature is returned when an empty signature is provided.
	ErrEmptySignature = &errEmptySignature{}

	// ErrEmptySignerID is returned when an empty signer ID is provided.
	ErrEmptySignerID = &errEmptySignerID{}

	// ErrRPKINotInitialized is returned when RPKI validator is not initialized.
	ErrRPKINotInitialized = &errRPKINotInitialized{}

	// ErrInvalidIPAddress is returned when IP address conversion fails.
	ErrInvalidIPAddress = &errInvalidIPAddress{}

	// Edge mode specific errors

	// ErrInvalidIPv6Pool is returned when the IPv6 pool is invalid.
	ErrInvalidIPv6Pool = &errInvalidIPv6Pool{}

	// ErrInvalidIPv6Address is returned when an IPv6 address is invalid.
	ErrInvalidIPv6Address = &errInvalidIPv6Address{}

	// ErrIPv6PoolExhausted is returned when the IPv6 pool has no available addresses.
	ErrIPv6PoolExhausted = &errIPv6PoolExhausted{}

	// ErrIPv6AllocationFailed is returned when IPv6 allocation fails.
	ErrIPv6AllocationFailed = &errIPv6AllocationFailed{}

	// ErrIPv6AlreadyAllocated is returned when an IPv6 address is already allocated.
	ErrIPv6AlreadyAllocated = &errIPv6AlreadyAllocated{}

	// ErrIPv6OutOfPool is returned when an IPv6 address is outside the pool.
	ErrIPv6OutOfPool = &errIPv6OutOfPool{}

	// ErrIPv6NotAllocated is returned when an IPv6 address is not allocated.
	ErrIPv6NotAllocated = &errIPv6NotAllocated{}

	// ErrDeviceIDRequired is returned when a device ID is required but not provided.
	ErrDeviceIDRequired = &errDeviceIDRequired{}

	// ErrNodeIDRequired is returned when a node ID is required but not provided.
	ErrNodeIDRequired = &errNodeIDRequired{}

	// ErrPeerIDRequired is returned when a peer ID is required but not provided.
	ErrPeerIDRequired = &errPeerIDRequired{}

	// ErrRequestNil is returned when a nil request is provided.
	ErrRequestNil = &errRequestNil{}

	// ErrTPMEKRequired is returned when a TPM EK is required but not provided.
	ErrTPMEKRequired = &errTPMEKRequired{}

	// ErrTPMQuoteRequired is returned when a TPM quote is required but not provided.
	ErrTPMQuoteRequired = &errTPMQuoteRequired{}

	// ErrFROSTPoolRequired is returned when a FROST pool ID is required but not provided.
	ErrFROSTPoolRequired = &errFROSTPoolRequired{}

	// ErrRateLimitExceeded is returned when a peer exceeds its rate limit.
	ErrRateLimitExceeded = &errRateLimitExceeded{}

	// ErrP2PNotEnabled is returned when P2P operations are attempted without P2P support.
	ErrP2PNotEnabled = &errP2PNotEnabled{}

	// ErrPXEControllerConfigNil is returned when a nil PXE controller config is provided.
	ErrPXEControllerConfigNil = &errPXEControllerConfigNil{}

	// Overlay mode specific errors

	// ErrVTEPConfigNil is returned when VTEP configuration is nil.
	ErrVTEPConfigNil = &errVTEPConfigNil{}

	// ErrBridgeNameEmpty is returned when bridge name is empty.
	ErrBridgeNameEmpty = &errBridgeNameEmpty{}

	// ErrLoggerNil is returned when logger is nil.
	ErrLoggerNil = &errLoggerNil{}

	// ErrOVSClientNil is returned when OVS client is nil.
	ErrOVSClientNil = &errOVSClientNil{}

	// ErrOpenFlowClientNil is returned when OpenFlow client is nil.
	ErrOpenFlowClientNil = &errOpenFlowClientNil{}

	// ErrVNIOutOfRange is returned when VNI is outside valid range.
	ErrVNIOutOfRange = &errVNIOutOfRange{}

	// ErrVLANOutOfRange is returned when VLAN ID is outside valid range.
	ErrVLANOutOfRange = &errVLANOutOfRange{}

	// ErrVNIAlreadyExists is returned when VNI is already configured.
	ErrVNIAlreadyExists = &errVNIAlreadyExists{}

	// ErrVNINotFound is returned when VNI is not found.
	ErrVNINotFound = &errVNINotFound{}

	// ErrMACNil is returned when MAC address is nil.
	ErrMACNil = &errMACNil{}

	// ErrMACInvalid is returned when MAC address is invalid.
	ErrMACInvalid = &errMACInvalid{}

	// ErrMACNotFound is returned when MAC address is not found.
	ErrMACNotFound = &errMACNotFound{}

	// ErrInvalidVTEPIP is returned when VTEP IP is invalid.
	ErrInvalidVTEPIP = &errInvalidVTEPIP{}

	// ErrAccessPortEmpty is returned when the overlay has no access port.
	ErrAccessPortEmpty = &errAccessPortEmpty{}

	// ErrAccessPortUnresolved is returned when the access port has no
	// OpenFlow port number on the bridge.
	ErrAccessPortUnresolved = &errAccessPortUnresolved{}

	// ErrVLANInUse is returned when a VLAN already carries another VNI.
	ErrVLANInUse = &errVLANInUse{}

	// ErrAnycastGatewayIncomplete is returned when the anycast gateway
	// has only one of its IPv4 address and MAC.
	ErrAnycastGatewayIncomplete = &errAnycastGatewayIncomplete{}

	// ErrAnycastGatewayRequired is returned when an L3VNI is configured
	// without the anycast gateway that routes into it.
	ErrAnycastGatewayRequired = &errAnycastGatewayRequired{}

	// ErrRouterMACRequired is returned when an L3VNI is configured
	// without the EVPN router MAC symmetric IRB addresses.
	ErrRouterMACRequired = &errRouterMACRequired{}

	// ErrAdmitterNil is returned when the overlay runs EVPN without a
	// VTEP admitter.
	ErrAdmitterNil = &errAdmitterNil{}

	// ErrFlowNotTracked is returned when the overlay releases a flow it
	// never installed.
	ErrFlowNotTracked = &errFlowNotTracked{}

	// ErrSwitchNotRestored is returned for an overlay change while the
	// switch has reconnected but the OpenFlow numbers of the overlay's
	// ports, which a restart can change, have not been read again.
	ErrSwitchNotRestored = &errSwitchNotRestored{}
)

// Transit mode sentinel error types.

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errSpeakerNil struct{}

func (e *errSpeakerNil) Error() string { return "BGP speaker is nil" }

type errAlreadyRunning struct{}

func (e *errAlreadyRunning) Error() string { return "handler already running" }

type errNotRunning struct{}

func (e *errNotRunning) Error() string { return "handler not running" }

type errInvalidTier struct{}

func (e *errInvalidTier) Error() string { return "invalid speaker tier" }

type errNoPrefixesConfigured struct{}

func (e *errNoPrefixesConfigured) Error() string { return "no prefixes configured for announcement" }

type errInvalidIPv6Prefix struct{}

func (e *errInvalidIPv6Prefix) Error() string { return "invalid IPv6 prefix" }

type errInvalidIPv4Prefix struct{}

func (e *errInvalidIPv4Prefix) Error() string { return "invalid IPv4 prefix" }

type errInvalidASN struct{}

func (e *errInvalidASN) Error() string { return "invalid ASN: must be non-zero" }

type errNoRPKIValidators struct{}

func (e *errNoRPKIValidators) Error() string {
	return "RPKI enabled but no validators configured"
}

type errSigningKeyRequired struct{}

func (e *errSigningKeyRequired) Error() string {
	return "route signing key required for coordinator tier"
}

type errInvalidMinGateways struct{}

func (e *errInvalidMinGateways) Error() string {
	return "MinGatewaysForRoute cannot be negative"
}

type errNotCoordinatorTier struct{}

func (e *errNotCoordinatorTier) Error() string {
	return "route signing only available on coordinator tier"
}

type errSigningKeyNotConfigured struct{}

func (e *errSigningKeyNotConfigured) Error() string {
	return "route signing key not configured"
}

type errEmptySignature struct{}

func (e *errEmptySignature) Error() string { return "signature is empty" }

type errEmptySignerID struct{}

func (e *errEmptySignerID) Error() string { return "signer ID is empty" }

type errRPKINotInitialized struct{}

func (e *errRPKINotInitialized) Error() string { return "RPKI validator not initialized" }

type errInvalidIPAddress struct{}

func (e *errInvalidIPAddress) Error() string { return "invalid IP address" }

// Edge mode sentinel error types.

type errInvalidIPv6Pool struct{}

func (e *errInvalidIPv6Pool) Error() string { return "invalid IPv6 pool" }

type errInvalidIPv6Address struct{}

func (e *errInvalidIPv6Address) Error() string { return "invalid IPv6 address" }

type errIPv6PoolExhausted struct{}

func (e *errIPv6PoolExhausted) Error() string { return "IPv6 pool exhausted" }

type errIPv6AllocationFailed struct{}

func (e *errIPv6AllocationFailed) Error() string { return "IPv6 allocation failed" }

type errIPv6AlreadyAllocated struct{}

func (e *errIPv6AlreadyAllocated) Error() string { return "IPv6 address already allocated" }

type errIPv6OutOfPool struct{}

func (e *errIPv6OutOfPool) Error() string { return "IPv6 address outside pool" }

type errIPv6NotAllocated struct{}

func (e *errIPv6NotAllocated) Error() string { return "IPv6 address not allocated" }

type errDeviceIDRequired struct{}

func (e *errDeviceIDRequired) Error() string { return "device ID required" }

type errNodeIDRequired struct{}

func (e *errNodeIDRequired) Error() string { return "node ID required" }

type errPeerIDRequired struct{}

func (e *errPeerIDRequired) Error() string { return "peer ID required" }

type errRequestNil struct{}

func (e *errRequestNil) Error() string { return "request is nil" }

type errTPMEKRequired struct{}

func (e *errTPMEKRequired) Error() string { return "TPM endorsement key required" }

type errTPMQuoteRequired struct{}

func (e *errTPMQuoteRequired) Error() string { return "TPM quote required" }

type errFROSTPoolRequired struct{}

func (e *errFROSTPoolRequired) Error() string { return "FROST pool ID required for ACME enrollment" }

type errRateLimitExceeded struct{}

func (e *errRateLimitExceeded) Error() string { return "rate limit exceeded" }

type errP2PNotEnabled struct{}

func (e *errP2PNotEnabled) Error() string {
	return "gateway: P2P support not enabled (build with -tags platform_p2p)"
}

// PXE controller sentinel error types.

type errPXEControllerConfigNil struct{}

func (e *errPXEControllerConfigNil) Error() string { return "PXE controller configuration is nil" }

// Overlay mode sentinel error types.

type errVTEPConfigNil struct{}

func (e *errVTEPConfigNil) Error() string { return "VTEP configuration is nil" }

type errBridgeNameEmpty struct{}

func (e *errBridgeNameEmpty) Error() string { return "bridge name is empty" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errOVSClientNil struct{}

func (e *errOVSClientNil) Error() string { return "OVS client is nil" }

type errOpenFlowClientNil struct{}

func (e *errOpenFlowClientNil) Error() string { return "OpenFlow client is nil" }

type errVNIOutOfRange struct{}

func (e *errVNIOutOfRange) Error() string { return "VNI must be between 1 and 16777215" }

type errVLANOutOfRange struct{}

func (e *errVLANOutOfRange) Error() string { return "VLAN ID must be between 1 and 4094" }

type errVNIAlreadyExists struct{}

func (e *errVNIAlreadyExists) Error() string { return "VNI already exists" }

type errVNINotFound struct{}

func (e *errVNINotFound) Error() string { return "VNI not found" }

type errMACNil struct{}

func (e *errMACNil) Error() string { return "MAC address is nil" }

type errMACInvalid struct{}

func (e *errMACInvalid) Error() string { return "MAC address must be 6 bytes" }

type errMACNotFound struct{}

func (e *errMACNotFound) Error() string { return "MAC address not found" }

type errInvalidVTEPIP struct{}

func (e *errInvalidVTEPIP) Error() string { return "invalid VTEP IP address" }

type errAccessPortEmpty struct{}

func (e *errAccessPortEmpty) Error() string { return "access port is empty" }

type errAccessPortUnresolved struct{}

func (e *errAccessPortUnresolved) Error() string { return "access port has no OpenFlow port number" }

type errVLANInUse struct{}

func (e *errVLANInUse) Error() string { return "VLAN already carries another VNI" }

type errAnycastGatewayIncomplete struct{}

func (e *errAnycastGatewayIncomplete) Error() string {
	return "anycast gateway needs both an IPv4 address and a MAC"
}

type errAnycastGatewayRequired struct{}

func (e *errAnycastGatewayRequired) Error() string {
	return "an L3VNI needs the anycast gateway to route into it"
}

type errRouterMACRequired struct{}

func (e *errRouterMACRequired) Error() string {
	return "an L3VNI needs the EVPN router MAC for symmetric IRB"
}

type errAdmitterNil struct{}

func (e *errAdmitterNil) Error() string {
	return "EVPN needs a VTEP admitter to vet the VTEPs its routes name"
}

type errFlowNotTracked struct{}

func (e *errFlowNotTracked) Error() string { return "overlay flow is not installed" }

type errSwitchNotRestored struct{}

func (e *errSwitchNotRestored) Error() string {
	return "overlay ports not resolved since the switch reconnected"
}

// Transit mode contextual error types.

// ErrComponentInitFailed is returned when a component fails to initialize.
type ErrComponentInitFailed struct {
	Component string
	Cause     error
}

func (e *ErrComponentInitFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to initialize %s: %v", e.Component, e.Cause)
	}
	return fmt.Sprintf("failed to initialize %s", e.Component)
}

func (e *ErrComponentInitFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPrefixFormat is returned when a prefix has an invalid format.
type ErrInvalidPrefixFormat struct {
	Prefix string
	Cause  error
}

func (e *ErrInvalidPrefixFormat) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invalid prefix format %q: %v", e.Prefix, e.Cause)
	}
	return fmt.Sprintf("invalid prefix format %q", e.Prefix)
}

func (e *ErrInvalidPrefixFormat) Unwrap() error {
	return e.Cause
}

// ErrPrefixAlreadyAnnounced is returned when a prefix is already announced.
type ErrPrefixAlreadyAnnounced struct {
	Prefix netip.Prefix
}

func (e *ErrPrefixAlreadyAnnounced) Error() string {
	return fmt.Sprintf("prefix %s already announced", e.Prefix)
}

// ErrPrefixNotAnnounced is returned when a prefix is not announced.
type ErrPrefixNotAnnounced struct {
	Prefix netip.Prefix
}

func (e *ErrPrefixNotAnnounced) Error() string {
	return fmt.Sprintf("prefix %s not announced", e.Prefix)
}

// ErrAnnounceFailed is returned when prefix announcement fails.
type ErrAnnounceFailed struct {
	Prefix netip.Prefix
	Cause  error
}

func (e *ErrAnnounceFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to announce prefix %s: %v", e.Prefix, e.Cause)
	}
	return fmt.Sprintf("failed to announce prefix %s", e.Prefix)
}

func (e *ErrAnnounceFailed) Unwrap() error {
	return e.Cause
}

// ErrWithdrawFailed is returned when prefix withdrawal fails.
type ErrWithdrawFailed struct {
	Prefix netip.Prefix
	Cause  error
}

func (e *ErrWithdrawFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to withdraw prefix %s: %v", e.Prefix, e.Cause)
	}
	return fmt.Sprintf("failed to withdraw prefix %s", e.Prefix)
}

func (e *ErrWithdrawFailed) Unwrap() error {
	return e.Cause
}

// ErrPrefixTooLarge is returned when a prefix is too large for the speaker tier.
type ErrPrefixTooLarge struct {
	Prefix  netip.Prefix
	MaxBits int
	Tier    bgp.SpeakerTier
}

func (e *ErrPrefixTooLarge) Error() string {
	return fmt.Sprintf("prefix %s too large for tier %s (max /%d)", e.Prefix, e.Tier, e.MaxBits)
}

// ErrRPKIValidationFailed is returned when RPKI validation fails.
type ErrRPKIValidationFailed struct {
	Prefix netip.Prefix
	Cause  error
}

func (e *ErrRPKIValidationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("RPKI validation failed for prefix %s: %v", e.Prefix, e.Cause)
	}
	return fmt.Sprintf("RPKI validation failed for prefix %s", e.Prefix)
}

func (e *ErrRPKIValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrSignerNotFound is returned when a signer's public key is not found.
type ErrSignerNotFound struct {
	SignerID string
}

func (e ErrSignerNotFound) Error() string {
	return fmt.Sprintf("signer not found: %s", e.SignerID)
}

// ErrSignatureInvalid is returned when a route signature is invalid.
type ErrSignatureInvalid struct {
	Prefix   netip.Prefix
	SignerID string
}

func (e *ErrSignatureInvalid) Error() string {
	return fmt.Sprintf("invalid signature for prefix %s from signer %s", e.Prefix, e.SignerID)
}

// Edge mode contextual error types.

// ErrStartFailed is returned when a component fails to start.
type ErrStartFailed struct {
	Component string
	Cause     error
}

func (e *ErrStartFailed) Error() string {
	return fmt.Sprintf("failed to start %s: %v", e.Component, e.Cause)
}

func (e *ErrStartFailed) Unwrap() error {
	return e.Cause
}

// ErrStopFailed is returned when a component fails to stop.
type ErrStopFailed struct {
	Component string
	Cause     error
}

func (e *ErrStopFailed) Error() string {
	return fmt.Sprintf("failed to stop %s: %v", e.Component, e.Cause)
}

func (e *ErrStopFailed) Unwrap() error {
	return e.Cause
}

// ErrMultipleFailures is returned when multiple operations fail.
type ErrMultipleFailures struct {
	Errors []error
}

func (e *ErrMultipleFailures) Error() string {
	if len(e.Errors) == 0 {
		return "multiple failures occurred"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString("multiple failures: ")
	for i, err := range e.Errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// ErrOnboardingFailed is returned when device onboarding fails.
type ErrOnboardingFailed struct {
	Step  string
	Cause error
}

func (e *ErrOnboardingFailed) Error() string {
	return fmt.Sprintf("onboarding failed at step %q: %v", e.Step, e.Cause)
}

func (e *ErrOnboardingFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMValidationFailed is returned when TPM validation fails.
type ErrTPMValidationFailed struct {
	Reason string
}

func (e *ErrTPMValidationFailed) Error() string {
	return fmt.Sprintf("TPM validation failed: %s", e.Reason)
}

// ErrIDevIDIssuanceFailed is returned when IDevID issuance fails.
type ErrIDevIDIssuanceFailed struct {
	DeviceID string
	Cause    error
}

func (e *ErrIDevIDIssuanceFailed) Error() string {
	return fmt.Sprintf("failed to issue IDevID for device %s: %v", e.DeviceID, e.Cause)
}

func (e *ErrIDevIDIssuanceFailed) Unwrap() error {
	return e.Cause
}

// ErrDHTRegistrationFailed is returned when DHT registration fails.
type ErrDHTRegistrationFailed struct {
	DeviceID string
	Cause    error
}

func (e *ErrDHTRegistrationFailed) Error() string {
	return fmt.Sprintf("failed to register device %s in DHT: %v", e.DeviceID, e.Cause)
}

func (e *ErrDHTRegistrationFailed) Unwrap() error {
	return e.Cause
}

// ErrIPv6AllocationError is returned when a specific IPv6 allocation error occurs.
type ErrIPv6AllocationError struct {
	DeviceID string
	IP       string
	Reason   string
}

func (e *ErrIPv6AllocationError) Error() string {
	if e.IP != "" {
		return fmt.Sprintf("IPv6 allocation error for device %s (IP %s): %s", e.DeviceID, e.IP, e.Reason)
	}
	return fmt.Sprintf("IPv6 allocation error for device %s: %s", e.DeviceID, e.Reason)
}

// ErrRateLimitError is returned when a rate limit error occurs with context.
type ErrRateLimitError struct {
	PeerID     string
	Reputation float64
	Limit      int
}

func (e *ErrRateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded for peer %s (reputation: %.2f, limit: %d req/s)",
		e.PeerID, e.Reputation, e.Limit)
}

// ErrACMEChallengeFailed is returned when an ACME challenge fails.
type ErrACMEChallengeFailed struct {
	ChallengeType string
	DeviceID      string
	Reason        string
}

func (e *ErrACMEChallengeFailed) Error() string {
	return fmt.Sprintf("ACME %s challenge failed for device %s: %s",
		e.ChallengeType, e.DeviceID, e.Reason)
}

// ErrNATTraversalFailed is returned when NAT traversal fails.
type ErrNATTraversalFailed struct {
	Method string
	Cause  error
}

func (e *ErrNATTraversalFailed) Error() string {
	return fmt.Sprintf("NAT traversal via %s failed: %v", e.Method, e.Cause)
}

func (e *ErrNATTraversalFailed) Unwrap() error {
	return e.Cause
}

// Overlay mode contextual error types.

// ErrOverlayInitFailed represents an overlay initialization failure.
type ErrOverlayInitFailed struct {
	Component string
	Cause     error
}

func (e *ErrOverlayInitFailed) Error() string {
	return fmt.Sprintf("overlay initialization failed for %s: %v", e.Component, e.Cause)
}

func (e *ErrOverlayInitFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayStartFailed represents an overlay start failure.
type ErrOverlayStartFailed struct {
	Component string
	Cause     error
}

func (e *ErrOverlayStartFailed) Error() string {
	return fmt.Sprintf("overlay start failed for %s: %v", e.Component, e.Cause)
}

func (e *ErrOverlayStartFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayPortUnresolved reports that the OpenFlow number of one of the
// overlay's ports, VXLANPort or AccessPort, could not be read.
type ErrOverlayPortUnresolved struct {
	Port  string
	Cause error
}

func (e *ErrOverlayPortUnresolved) Error() string {
	return fmt.Sprintf("resolving the overlay %s: %v", e.Port, e.Cause)
}

func (e *ErrOverlayPortUnresolved) Unwrap() error {
	return e.Cause
}

// ErrVNIOperationFailed represents a VNI operation failure.
type ErrVNIOperationFailed struct {
	VNI       uint32
	Operation string
	Cause     error
}

func (e *ErrVNIOperationFailed) Error() string {
	return fmt.Sprintf("VNI %d %s failed: %v", e.VNI, e.Operation, e.Cause)
}

func (e *ErrVNIOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrMACOperationFailed represents a MAC operation failure.
type ErrMACOperationFailed struct {
	MAC       net.HardwareAddr
	Operation string
	Cause     error
}

func (e *ErrMACOperationFailed) Error() string {
	return fmt.Sprintf("MAC %s %s failed: %v", e.MAC.String(), e.Operation, e.Cause)
}

func (e *ErrMACOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrVTEPOperationFailed represents a VTEP operation failure.
type ErrVTEPOperationFailed struct {
	VTEPIP    netip.Addr
	Operation string
	Cause     error
}

func (e *ErrVTEPOperationFailed) Error() string {
	return fmt.Sprintf("VTEP %s %s failed: %v", e.VTEPIP.String(), e.Operation, e.Cause)
}

func (e *ErrVTEPOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrFlowOperationFailed represents an OpenFlow operation failure.
type ErrFlowOperationFailed struct {
	Table     uint8
	Operation string
	Cause     error
}

func (e *ErrFlowOperationFailed) Error() string {
	return fmt.Sprintf("flow %s on table %d failed: %v", e.Operation, e.Table, e.Cause)
}

func (e *ErrFlowOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrFlowResyncFailed reports that the switch refused the flow mods that
// undo a failed change, so it may hold flows the overlay does not track,
// or refused the flush-and-rebuild that replaces them on the next change.
type ErrFlowResyncFailed struct {
	Cause error
}

func (e *ErrFlowResyncFailed) Error() string {
	return fmt.Sprintf("restoring the overlay flows after a failed change failed: %v", e.Cause)
}

func (e *ErrFlowResyncFailed) Unwrap() error {
	return e.Cause
}

// ErrBindingConflict reports a remote MAC/IP binding refused because it
// claims an address this VTEP answers for: the anycast gateway's or a
// local host's. Owner names which.
type ErrBindingConflict struct {
	VNI   uint32
	MAC   net.HardwareAddr
	IP    netip.Addr
	Owner string
}

func (e *ErrBindingConflict) Error() string {
	return fmt.Sprintf("remote binding %s %s on VNI %d conflicts with the %s", e.MAC, e.IP, e.VNI, e.Owner)
}

// ErrInvalidNDMessage reports a neighbor discovery message the overlay
// will not act on: one RFC 4861 §7.1.1 has a node discard, or one it
// cannot build an answer for. Reason names the check that failed.
type ErrInvalidNDMessage struct {
	Reason string
}

func (e *ErrInvalidNDMessage) Error() string {
	return "overlay: invalid neighbor discovery message: " + e.Reason
}

// ErrUnsupportedNDMessage reports a neighbor discovery message the overlay
// cannot read although RFC 4861 does not have a node discard it: one behind
// an IPv6 extension header. The overlay passes it on unread. Reason names
// what it could not read.
type ErrUnsupportedNDMessage struct {
	Reason string
}

func (e *ErrUnsupportedNDMessage) Error() string {
	return "overlay: unsupported neighbor discovery message: " + e.Reason
}
