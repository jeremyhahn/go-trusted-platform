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

// Package bgp provides BGP and EVPN route handling for VXLAN overlay networking.
package bgp

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Sentinel errors for BGP speaker operations.
var (
	// ErrSpeakerNotStarted is returned when operations are attempted on an unstarted speaker.
	ErrSpeakerNotStarted = &errSpeakerNotStarted{}

	// ErrSpeakerAlreadyRunning is returned when Start is called on an already running speaker.
	ErrSpeakerAlreadyRunning = &errSpeakerAlreadyRunning{}

	// ErrInvalidRouterID is returned when an invalid router ID is provided.
	ErrInvalidRouterID = &errInvalidRouterID{}

	// ErrInvalidASN is returned when an invalid AS number is provided.
	ErrInvalidASN = &errInvalidASN{}

	// ErrInvalidPeerAddress is returned when an invalid peer address is provided.
	ErrInvalidPeerAddress = &errInvalidPeerAddress{}

	// ErrInvalidPeerASN is returned when an invalid peer AS number is provided.
	ErrInvalidPeerASN = &errInvalidPeerASN{}

	// ErrInvalidHoldTime is returned when an invalid hold time is provided.
	ErrInvalidHoldTime = &errInvalidHoldTime{}

	// ErrPeerNotFound is returned when a requested peer does not exist.
	ErrPeerNotFound = &errPeerNotFound{}

	// ErrPeerAlreadyExists is returned when attempting to add a peer that already exists.
	ErrPeerAlreadyExists = &errPeerAlreadyExists{}

	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrServerNil is returned when the underlying server is nil.
	ErrServerNil = &errServerNil{}

	// ErrShutdownTimeout is returned when graceful shutdown times out.
	ErrShutdownTimeout = &errShutdownTimeout{}

	// ErrSessionNotEstablished is returned when session operations require an established session.
	ErrSessionNotEstablished = &errSessionNotEstablished{}

	// ErrSessionFailed is returned when a BGP session fails to establish.
	ErrSessionFailed = &errSessionFailed{}

	// ErrRPKIValidationFailed is returned when RPKI validation fails for a route.
	ErrRPKIValidationFailed = &errRPKIValidationFailed{}

	// ErrRouteRejected is returned when a route is rejected by policy.
	ErrRouteRejected = &errRouteRejected{}

	// ErrDampeningActive is returned when a route is suppressed due to dampening.
	ErrDampeningActive = &errDampeningActive{}

	// ErrInvalidPrefix is returned when an IP prefix is invalid.
	ErrInvalidPrefix = &errInvalidPrefix{}

	// ErrInvalidRouteTarget is returned when a route target is invalid.
	ErrInvalidRouteTarget = &errInvalidRouteTarget{}

	// ErrConfigurationInvalid is returned when configuration is invalid.
	ErrConfigurationInvalid = &errConfigurationInvalid{}

	// ErrIPv6Required is returned when IPv6 is required but IPv4 was provided.
	ErrIPv6Required = &errIPv6Required{}

	// ErrIPv4Required is returned when IPv4 is required but IPv6 was provided.
	ErrIPv4Required = &errIPv4Required{}

	// ErrPrefixNotAnnounced is returned when a prefix is not announced.
	ErrPrefixNotAnnounced = &errPrefixNotAnnounced{}

	// ErrInvalidASPathPrepend is returned when AS path prepend count is invalid.
	ErrInvalidASPathPrepend = &errInvalidASPathPrepend{}

	// ErrInvalidSpeakerTier is returned when speaker tier is invalid.
	ErrInvalidSpeakerTier = &errInvalidSpeakerTier{}

	// ErrInvalidRemoteAS is returned when remote AS is invalid.
	ErrInvalidRemoteAS = &errInvalidRemoteAS{}

	// ErrInvalidPeerType is returned when peer type is invalid.
	ErrInvalidPeerType = &errInvalidPeerType{}

	// ErrInvalidPeerConfig is returned when peer configuration is invalid.
	ErrInvalidPeerConfig = &errInvalidPeerConfig{}

	// ErrHealthMonitorAlreadyRunning is returned when health monitor is already running.
	ErrHealthMonitorAlreadyRunning = &errHealthMonitorAlreadyRunning{}

	// ErrNoValidatorsAvailable is returned when no RPKI validators are available.
	ErrNoValidatorsAvailable = &errNoValidatorsAvailable{}

	// ErrInvalidOriginAS is returned when origin AS is invalid.
	ErrInvalidOriginAS = &errInvalidOriginAS{}

	// ErrInvalidValidatorAddress is returned when validator address is invalid.
	ErrInvalidValidatorAddress = &errInvalidValidatorAddress{}

	// ErrValidatorExists is returned when validator already exists.
	ErrValidatorExists = &errValidatorExists{}

	// ErrValidatorNotFound is returned when validator is not found.
	ErrValidatorNotFound = &errValidatorNotFound{}

	// ErrInvalidROA is returned when ROA is invalid.
	ErrInvalidROA = &errInvalidROA{}

	// ErrROANotFound is returned when ROA is not found.
	ErrROANotFound = &errROANotFound{}

	// ErrInvalidHalfLife is returned when half-life is invalid.
	ErrInvalidHalfLife = &errInvalidHalfLife{}

	// ErrInvalidReuseThreshold is returned when reuse threshold is invalid.
	ErrInvalidReuseThreshold = &errInvalidReuseThreshold{}

	// ErrInvalidSuppressThreshold is returned when suppress threshold is invalid.
	ErrInvalidSuppressThreshold = &errInvalidSuppressThreshold{}

	// ErrReuseExceedsSuppressThreshold is returned when reuse threshold >= suppress threshold.
	ErrReuseExceedsSuppressThreshold = &errReuseExceedsSuppressThreshold{}

	// ErrInvalidMaxSuppressTime is returned when max suppress time is invalid.
	ErrInvalidMaxSuppressTime = &errInvalidMaxSuppressTime{}

	// ErrInvalidFlapPenalty is returned when flap penalty is invalid.
	ErrInvalidFlapPenalty = &errInvalidFlapPenalty{}

	// ErrDampeningStateNotFound is returned when dampening state is not found.
	ErrDampeningStateNotFound = &errDampeningStateNotFound{}

	// ErrDecayTimerAlreadyRunning is returned when decay timer is already running.
	ErrDecayTimerAlreadyRunning = &errDecayTimerAlreadyRunning{}

	// ErrSpeakerNil is returned when a nil speaker is provided.
	ErrSpeakerNil = &errSpeakerNil{}

	// ErrLoggerNil is returned when a nil logger is provided.
	ErrLoggerNil = &errLoggerNil{}

	// ErrManagerNotStarted is returned when the EVPN manager is not started.
	ErrManagerNotStarted = &errManagerNotStarted{}

	// ErrManagerAlreadyStarted is returned when the EVPN manager is already started.
	ErrManagerAlreadyStarted = &errManagerAlreadyStarted{}
)

type errSpeakerNotStarted struct{}

func (e *errSpeakerNotStarted) Error() string { return "BGP speaker not started" }

type errSpeakerAlreadyRunning struct{}

func (e *errSpeakerAlreadyRunning) Error() string { return "BGP speaker already running" }

type errInvalidRouterID struct{}

func (e *errInvalidRouterID) Error() string { return "invalid router ID" }

type errInvalidASN struct{}

func (e *errInvalidASN) Error() string { return "invalid AS number" }

type errInvalidPeerAddress struct{}

func (e *errInvalidPeerAddress) Error() string { return "invalid peer address" }

type errInvalidPeerASN struct{}

func (e *errInvalidPeerASN) Error() string { return "invalid peer AS number" }

type errInvalidHoldTime struct{}

func (e *errInvalidHoldTime) Error() string { return "invalid hold time (minimum 3 seconds)" }

type errPeerNotFound struct{}

func (e *errPeerNotFound) Error() string { return "peer not found" }

type errPeerAlreadyExists struct{}

func (e *errPeerAlreadyExists) Error() string { return "peer already exists" }

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errServerNil struct{}

func (e *errServerNil) Error() string { return "BGP server is nil" }

type errShutdownTimeout struct{}

func (e *errShutdownTimeout) Error() string { return "shutdown timeout exceeded" }

type errSessionNotEstablished struct{}

func (e *errSessionNotEstablished) Error() string { return "BGP session not established" }

type errSessionFailed struct{}

func (e *errSessionFailed) Error() string { return "BGP session failed" }

type errRPKIValidationFailed struct{}

func (e *errRPKIValidationFailed) Error() string { return "RPKI validation failed" }

type errRouteRejected struct{}

func (e *errRouteRejected) Error() string { return "route rejected by policy" }

type errDampeningActive struct{}

func (e *errDampeningActive) Error() string { return "route dampening active" }

type errInvalidPrefix struct{}

func (e *errInvalidPrefix) Error() string { return "invalid IP prefix" }

type errInvalidRouteTarget struct{}

func (e *errInvalidRouteTarget) Error() string { return "invalid route target" }

type errConfigurationInvalid struct{}

func (e *errConfigurationInvalid) Error() string { return "invalid configuration" }

type errIPv6Required struct{}

func (e *errIPv6Required) Error() string { return "IPv6 prefix required" }

type errIPv4Required struct{}

func (e *errIPv4Required) Error() string { return "IPv4 prefix required" }

type errPrefixNotAnnounced struct{}

func (e *errPrefixNotAnnounced) Error() string { return "prefix not announced" }

type errInvalidASPathPrepend struct{}

func (e *errInvalidASPathPrepend) Error() string { return "invalid AS path prepend count" }

type errInvalidSpeakerTier struct{}

func (e *errInvalidSpeakerTier) Error() string { return "invalid speaker tier" }

type errInvalidRemoteAS struct{}

func (e *errInvalidRemoteAS) Error() string { return "invalid remote AS number" }

type errInvalidPeerType struct{}

func (e *errInvalidPeerType) Error() string { return "invalid peer type" }

type errInvalidPeerConfig struct{}

func (e *errInvalidPeerConfig) Error() string { return "invalid peer configuration" }

type errHealthMonitorAlreadyRunning struct{}

func (e *errHealthMonitorAlreadyRunning) Error() string { return "health monitor already running" }

type errNoValidatorsAvailable struct{}

func (e *errNoValidatorsAvailable) Error() string { return "no RPKI validators available" }

type errInvalidOriginAS struct{}

func (e *errInvalidOriginAS) Error() string { return "invalid origin AS number" }

type errInvalidValidatorAddress struct{}

func (e *errInvalidValidatorAddress) Error() string { return "invalid validator address" }

type errValidatorExists struct{}

func (e *errValidatorExists) Error() string { return "validator already exists" }

type errValidatorNotFound struct{}

func (e *errValidatorNotFound) Error() string { return "validator not found" }

type errInvalidROA struct{}

func (e *errInvalidROA) Error() string { return "invalid ROA" }

type errROANotFound struct{}

func (e *errROANotFound) Error() string { return "ROA not found" }

type errInvalidHalfLife struct{}

func (e *errInvalidHalfLife) Error() string { return "invalid half-life value" }

type errInvalidReuseThreshold struct{}

func (e *errInvalidReuseThreshold) Error() string { return "invalid reuse threshold" }

type errInvalidSuppressThreshold struct{}

func (e *errInvalidSuppressThreshold) Error() string { return "invalid suppress threshold" }

type errReuseExceedsSuppressThreshold struct{}

func (e *errReuseExceedsSuppressThreshold) Error() string {
	return "reuse threshold must be less than suppress threshold"
}

type errInvalidMaxSuppressTime struct{}

func (e *errInvalidMaxSuppressTime) Error() string { return "invalid max suppress time" }

type errInvalidFlapPenalty struct{}

func (e *errInvalidFlapPenalty) Error() string { return "invalid flap penalty" }

type errDampeningStateNotFound struct{}

func (e *errDampeningStateNotFound) Error() string { return "dampening state not found" }

type errDecayTimerAlreadyRunning struct{}

func (e *errDecayTimerAlreadyRunning) Error() string { return "decay timer already running" }

type errSpeakerNil struct{}

func (e *errSpeakerNil) Error() string { return "BGP speaker is nil" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errManagerNotStarted struct{}

func (e *errManagerNotStarted) Error() string { return "EVPN manager not started" }

type errManagerAlreadyStarted struct{}

func (e *errManagerAlreadyStarted) Error() string { return "EVPN manager already started" }

// ErrInvalidRouteDistinguisher is returned when the route distinguisher is invalid.
type ErrInvalidRouteDistinguisher struct {
	RD     string
	Reason string
}

func (e ErrInvalidRouteDistinguisher) Error() string {
	if e.RD == "" {
		return fmt.Sprintf("invalid route distinguisher: %s", e.Reason)
	}
	return fmt.Sprintf("invalid route distinguisher %q: %s", e.RD, e.Reason)
}

// ErrRouteTargetInvalid is returned when a route target is invalid with context.
type ErrRouteTargetInvalid struct {
	RT     string
	Reason string
}

func (e ErrRouteTargetInvalid) Error() string {
	if e.RT == "" {
		return fmt.Sprintf("invalid route target: %s", e.Reason)
	}
	return fmt.Sprintf("invalid route target %q: %s", e.RT, e.Reason)
}

// ErrInvalidVNI is returned when a VNI is out of range.
type ErrInvalidVNI struct {
	VNI    uint32
	Reason string
}

func (e ErrInvalidVNI) Error() string {
	return fmt.Sprintf("invalid VNI %d: %s", e.VNI, e.Reason)
}

// ErrInvalidMAC is returned when a MAC address is invalid.
type ErrInvalidMAC struct {
	MAC    net.HardwareAddr
	Reason string
}

func (e ErrInvalidMAC) Error() string {
	if e.MAC == nil {
		return fmt.Sprintf("invalid MAC address: %s", e.Reason)
	}
	return fmt.Sprintf("invalid MAC address %s: %s", e.MAC.String(), e.Reason)
}

// ErrInvalidIP is returned when an IP address is invalid.
type ErrInvalidIP struct {
	IP     netip.Addr
	Reason string
}

func (e ErrInvalidIP) Error() string {
	if !e.IP.IsValid() {
		return fmt.Sprintf("invalid IP address: %s", e.Reason)
	}
	return fmt.Sprintf("invalid IP address %s: %s", e.IP.String(), e.Reason)
}

// ErrPrefixInvalid is returned when an IP prefix is invalid with context.
type ErrPrefixInvalid struct {
	Prefix netip.Prefix
	Reason string
}

func (e ErrPrefixInvalid) Error() string {
	if !e.Prefix.IsValid() {
		return fmt.Sprintf("invalid IP prefix: %s", e.Reason)
	}
	return fmt.Sprintf("invalid IP prefix %s: %s", e.Prefix.String(), e.Reason)
}

// ErrMACNotFound is returned when a MAC address is not found.
type ErrMACNotFound struct {
	VNI uint32
	MAC net.HardwareAddr
}

func (e ErrMACNotFound) Error() string {
	return fmt.Sprintf("MAC not found: vni=%d mac=%s", e.VNI, e.MAC.String())
}

// ErrMACIPNotFound is returned when a MAC/IP binding is not found.
type ErrMACIPNotFound struct {
	VNI uint32
	MAC net.HardwareAddr
	IP  netip.Addr
}

func (e ErrMACIPNotFound) Error() string {
	return fmt.Sprintf("MAC/IP not found: vni=%d mac=%s ip=%s", e.VNI, e.MAC.String(), e.IP.String())
}

// ErrIMETNotFound is returned when an IMET entry is not found.
type ErrIMETNotFound struct {
	VNI uint32
}

func (e ErrIMETNotFound) Error() string {
	return fmt.Sprintf("IMET not found for VNI %d", e.VNI)
}

// ErrPrefixNotFound is returned when a prefix route is not found.
type ErrPrefixNotFound struct {
	VNI    uint32
	Prefix netip.Prefix
}

func (e ErrPrefixNotFound) Error() string {
	return fmt.Sprintf("prefix not found: vni=%d prefix=%s", e.VNI, e.Prefix.String())
}

// ErrRouteEncodingFailed is returned when EVPN route encoding fails.
type ErrRouteEncodingFailed struct {
	RouteType EVPNRouteType
	Cause     error
}

func (e ErrRouteEncodingFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to encode EVPN %s route: %v", e.RouteType, e.Cause)
	}
	return fmt.Sprintf("failed to encode EVPN %s route", e.RouteType)
}

func (e ErrRouteEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrRouteDecodingFailed is returned when EVPN route decoding fails.
type ErrRouteDecodingFailed struct {
	RouteType EVPNRouteType
	Cause     error
}

func (e ErrRouteDecodingFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to decode EVPN %s route: %v", e.RouteType, e.Cause)
	}
	return fmt.Sprintf("failed to decode EVPN %s route", e.RouteType)
}

func (e ErrRouteDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrRouteAdvertisementFailed is returned when route advertisement fails.
type ErrRouteAdvertisementFailed struct {
	RouteType EVPNRouteType
	Cause     error
}

func (e ErrRouteAdvertisementFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to advertise EVPN %s route: %v", e.RouteType, e.Cause)
	}
	return fmt.Sprintf("failed to advertise EVPN %s route", e.RouteType)
}

func (e ErrRouteAdvertisementFailed) Unwrap() error {
	return e.Cause
}

// ErrRouteWithdrawalFailed is returned when route withdrawal fails.
type ErrRouteWithdrawalFailed struct {
	RouteType EVPNRouteType
	Cause     error
}

func (e ErrRouteWithdrawalFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to withdraw EVPN %s route: %v", e.RouteType, e.Cause)
	}
	return fmt.Sprintf("failed to withdraw EVPN %s route", e.RouteType)
}

func (e ErrRouteWithdrawalFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidEVPNRoute is returned when an EVPN route is invalid.
type ErrInvalidEVPNRoute struct {
	RouteType EVPNRouteType
	Reason    string
}

func (e ErrInvalidEVPNRoute) Error() string {
	return fmt.Sprintf("invalid EVPN %s route: %s", e.RouteType, e.Reason)
}

// ErrMACMobilityConflict is returned when a MAC mobility conflict is detected.
type ErrMACMobilityConflict struct {
	VNI         uint32
	MAC         net.HardwareAddr
	OldVTEP     netip.Addr
	NewVTEP     netip.Addr
	OldSequence uint32
	NewSequence uint32
}

func (e ErrMACMobilityConflict) Error() string {
	return fmt.Sprintf("MAC mobility conflict: vni=%d mac=%s old_vtep=%s new_vtep=%s old_seq=%d new_seq=%d",
		e.VNI, e.MAC.String(), e.OldVTEP.String(), e.NewVTEP.String(), e.OldSequence, e.NewSequence)
}

// ErrUnsupportedRouteType is returned when an unsupported EVPN route type is encountered.
type ErrUnsupportedRouteType struct {
	RouteType EVPNRouteType
}

func (e ErrUnsupportedRouteType) Error() string {
	return fmt.Sprintf("unsupported EVPN route type: %s", e.RouteType)
}

// ErrNLRITooShort is returned when NLRI data is too short.
type ErrNLRITooShort struct {
	Expected int
	Actual   int
}

func (e ErrNLRITooShort) Error() string {
	return fmt.Sprintf("NLRI data too short: expected at least %d bytes, got %d", e.Expected, e.Actual)
}

// ErrInvalidNLRI is returned when NLRI data is malformed.
type ErrInvalidNLRI struct {
	Reason string
}

func (e ErrInvalidNLRI) Error() string {
	return fmt.Sprintf("invalid NLRI: %s", e.Reason)
}

// ErrEntryNil is returned when a nil entry is provided.
type ErrEntryNil struct {
	EntryType string
}

func (e ErrEntryNil) Error() string {
	return fmt.Sprintf("%s entry is nil", e.EntryType)
}

// ErrPeerOperationFailed represents a peer operation failure with context.
type ErrPeerOperationFailed struct {
	Operation   string
	PeerAddress netip.Addr
	Cause       error
}

// Error implements the error interface.
func (e *ErrPeerOperationFailed) Error() string {
	return fmt.Sprintf("peer %s operation %q failed: %v",
		e.PeerAddress, e.Operation, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrPeerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrPathOperationFailed represents a path operation failure with context.
type ErrPathOperationFailed struct {
	Operation string
	Prefix    netip.Prefix
	Cause     error
}

// Error implements the error interface.
func (e *ErrPathOperationFailed) Error() string {
	return fmt.Sprintf("path operation %q for %s failed: %v",
		e.Operation, e.Prefix, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrPathOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrServerOperationFailed represents a server operation failure with context.
type ErrServerOperationFailed struct {
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e *ErrServerOperationFailed) Error() string {
	return fmt.Sprintf("server operation %q failed: %v", e.Operation, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrServerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrRIBQueryFailed represents a RIB query failure with context.
type ErrRIBQueryFailed struct {
	Family  AddressFamily
	RIBType RIBType
	Cause   error
}

// Error implements the error interface.
func (e *ErrRIBQueryFailed) Error() string {
	return fmt.Sprintf("RIB query failed for %s/%s: %v",
		e.Family, e.RIBType, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrRIBQueryFailed) Unwrap() error {
	return e.Cause
}

// ErrRPKIValidation is returned when RPKI validation fails with details.
type ErrRPKIValidation struct {
	Prefix netip.Prefix
	ASN    uint32
	State  RPKIValidationState
}

func (e ErrRPKIValidation) Error() string {
	return fmt.Sprintf("RPKI validation failed for prefix %s (origin ASN %d): state=%s",
		e.Prefix.String(), e.ASN, e.State.String())
}

// ErrRouteDampened is returned when a route is dampened.
type ErrRouteDampened struct {
	Prefix    netip.Prefix
	Penalty   int
	ReuseTime string
}

func (e ErrRouteDampened) Error() string {
	return fmt.Sprintf("route %s is dampened (penalty=%d, reuse in %s)",
		e.Prefix.String(), e.Penalty, e.ReuseTime)
}

// ErrSpeakerOperationFailed is returned when a speaker operation fails.
type ErrSpeakerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSpeakerOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("speaker %s operation failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("speaker %s operation failed", e.Operation)
}

func (e ErrSpeakerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigValidationFailed is returned when configuration validation fails.
type ErrConfigValidationFailed struct {
	Field  string
	Value  string
	Reason string
}

func (e ErrConfigValidationFailed) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("configuration validation failed for %s=%s: %s", e.Field, e.Value, e.Reason)
	}
	return fmt.Sprintf("configuration validation failed for %s: %s", e.Field, e.Reason)
}

// ErrSessionEstablishmentFailed is returned when session establishment fails.
type ErrSessionEstablishmentFailed struct {
	PeerAddress netip.Addr
	State       PeerState
	Cause       error
}

func (e ErrSessionEstablishmentFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("session establishment failed with peer %s (state: %s): %v",
			e.PeerAddress.String(), e.State.String(), e.Cause)
	}
	return fmt.Sprintf("session establishment failed with peer %s (state: %s)",
		e.PeerAddress.String(), e.State.String())
}

func (e ErrSessionEstablishmentFailed) Unwrap() error {
	return e.Cause
}

// ErrPrefixAlreadyAnnounced represents a duplicate prefix announcement error.
type ErrPrefixAlreadyAnnounced struct {
	Prefix netip.Prefix
}

// Error implements the error interface.
func (e *ErrPrefixAlreadyAnnounced) Error() string {
	return fmt.Sprintf("prefix %s already announced", e.Prefix)
}

// ErrAnnouncementFailed represents an announcement failure.
type ErrAnnouncementFailed struct {
	Prefix netip.Prefix
	Cause  error
}

// Error implements the error interface.
func (e *ErrAnnouncementFailed) Error() string {
	return fmt.Sprintf("failed to announce prefix %s: %v", e.Prefix, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrAnnouncementFailed) Unwrap() error {
	return e.Cause
}

// ErrWithdrawalFailed represents a withdrawal failure.
type ErrWithdrawalFailed struct {
	Prefix netip.Prefix
	Cause  error
}

// Error implements the error interface.
func (e *ErrWithdrawalFailed) Error() string {
	return fmt.Sprintf("failed to withdraw prefix %s: %v", e.Prefix, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrWithdrawalFailed) Unwrap() error {
	return e.Cause
}

// ErrPeerExists represents a duplicate peer error.
type ErrPeerExists struct {
	Address netip.Addr
}

// Error implements the error interface.
func (e *ErrPeerExists) Error() string {
	return fmt.Sprintf("peer %s already exists", e.Address)
}

// ErrDampeningOperationFailed represents a dampening operation failure.
type ErrDampeningOperationFailed struct {
	Prefix    netip.Prefix
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e *ErrDampeningOperationFailed) Error() string {
	return fmt.Sprintf("dampening %s failed for prefix %s: %v", e.Operation, e.Prefix, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrDampeningOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrWatchFilterUnknown reports a watch request naming a table filter the
// speaker cannot subscribe to, or none at all.
type ErrWatchFilterUnknown struct {
	Type string
}

// Error implements the error interface.
func (e ErrWatchFilterUnknown) Error() string {
	return "bgp: unknown watch filter type: " + e.Type
}

// ErrUnknownAuthType reports an auth-type spelling the configuration does
// not recognise.
type ErrUnknownAuthType struct {
	Value string
}

// Error implements the error interface.
func (e ErrUnknownAuthType) Error() string {
	return "bgp: unknown auth-type " + e.Value + " (none, md5, tcp-ao)"
}

// ErrUnknownAddressFamily reports an address-family spelling the
// configuration does not recognise.
type ErrUnknownAddressFamily struct {
	Value string
}

// Error implements the error interface.
func (e ErrUnknownAddressFamily) Error() string {
	return "bgp: unknown address family " + e.Value + " (ipv4-unicast, ipv6-unicast, evpn)"
}

// ErrUnknownSpeakerTier reports a tier spelling the configuration does not
// recognise.
type ErrUnknownSpeakerTier struct {
	Value string
}

// Error implements the error interface.
func (e ErrUnknownSpeakerTier) Error() string {
	return "bgp: unknown speaker tier " + e.Value + " (backbone, datacenter, coordinator)"
}

// ErrUnknownTCPAOAlgorithm reports a TCP-AO algorithm spelling the
// configuration does not recognise.
type ErrUnknownTCPAOAlgorithm struct {
	Value string
}

// Error implements the error interface.
func (e ErrUnknownTCPAOAlgorithm) Error() string {
	return "bgp: unknown tcp-ao algorithm " + e.Value + " (hmac-sha256-128, hmac-sha256-96, aes-128-cmac-96, hmac-sha1-96)"
}

// ErrAuthTypeUnavailableInFIPS is returned when a peer asks for a session
// authentication algorithm the FIPS build compiles out.
type ErrAuthTypeUnavailableInFIPS struct {
	Peer     string
	AuthType AuthType
}

// Error implements the error interface.
func (e ErrAuthTypeUnavailableInFIPS) Error() string {
	return "bgp: peer " + e.Peer + ": auth-type " + e.AuthType.String() + " is not available in a FIPS build; use tcp-ao"
}

// ErrAuthSecretRequired is returned when a peer selects an authentication
// type but names no secret reference or keychain for it.
type ErrAuthSecretRequired struct {
	Peer     string
	AuthType AuthType
}

// Error implements the error interface.
func (e ErrAuthSecretRequired) Error() string {
	switch e.AuthType {
	case AuthTypeTCPAO:
		return "bgp: peer " + e.Peer + ": auth-type tcp-ao requires a keychain name"
	default:
		return "bgp: peer " + e.Peer + ": auth-type " + e.AuthType.String() + " requires auth-key-ref"
	}
}

// ErrKeychainInvalid is returned when a TCP-AO keychain is malformed.
type ErrKeychainInvalid struct {
	Name   string
	Reason string
}

// Error implements the error interface.
func (e ErrKeychainInvalid) Error() string {
	return "bgp: tcp-ao keychain " + e.Name + ": " + e.Reason
}

// ErrDuplicateKeychain is returned when two keychains share a name.
type ErrDuplicateKeychain struct {
	Name string
}

// Error implements the error interface.
func (e ErrDuplicateKeychain) Error() string {
	return "bgp: duplicate tcp-ao keychain " + e.Name
}

// ErrKeychainNotFound is returned when a peer references a keychain the
// configuration does not define.
type ErrKeychainNotFound struct {
	Peer string
	Name string
}

// Error implements the error interface.
func (e ErrKeychainNotFound) Error() string {
	return "bgp: peer " + e.Peer + " references unknown tcp-ao keychain " + e.Name
}

// ErrSecretResolverRequired is returned when a configuration carries a
// secret reference and no resolver was supplied to resolve it.
type ErrSecretResolverRequired struct {
	Ref string
}

// Error implements the error interface.
func (e ErrSecretResolverRequired) Error() string {
	return "bgp: no secret resolver to resolve " + e.Ref
}

// ErrSecretResolutionFailed is returned when a secret reference could not
// be resolved. The reference is named, the value never is.
type ErrSecretResolutionFailed struct {
	Ref   string
	Cause error
}

// ErrSecretEmpty is the cause recorded when a secret reference resolves to
// zero bytes: a session keyed with it would be unauthenticated.
type ErrSecretEmpty struct{}

// Error implements the error interface.
func (ErrSecretEmpty) Error() string {
	return "resolved secret is empty"
}

// Error implements the error interface.
func (e ErrSecretResolutionFailed) Error() string {
	return "bgp: resolving " + e.Ref + ": " + e.Cause.Error()
}

// Unwrap returns the cause.
func (e ErrSecretResolutionFailed) Unwrap() error {
	return e.Cause
}

// ErrBFDIntervalTooShort is returned when a BFD interval is below the
// speaker's floor.
type ErrBFDIntervalTooShort struct {
	Minimum time.Duration
}

// Error implements the error interface.
func (e ErrBFDIntervalTooShort) Error() string {
	return "bgp: bfd interval below the minimum of " + e.Minimum.String()
}

// ErrTCPAOSessionBindingUnsupported is returned when a peer asks for TCP-AO
// and the linked GoBGP release can store keychains but not bind one to a
// neighbor session. The speaker refuses rather than run the session with
// no authentication while the configuration says tcp-ao.
type ErrTCPAOSessionBindingUnsupported struct {
	Peer  string
	GoBGP string
}

// Error implements the error interface.
func (e ErrTCPAOSessionBindingUnsupported) Error() string {
	return "bgp: peer " + e.Peer + ": tcp-ao session binding is not available in GoBGP " + e.GoBGP +
		" (keychain store only); the session is refused rather than run unauthenticated"
}
