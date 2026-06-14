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

package policy

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

var (
	// ErrPortNotFound is returned when a port does not exist.
	ErrPortNotFound = errors.New("port not found")

	// ErrPortExists is returned when attempting to create a port that already exists.
	ErrPortExists = errors.New("port already exists")

	// ErrInvalidPortID is returned when a port ID is invalid.
	ErrInvalidPortID = errors.New("invalid port ID")

	// ErrInvalidState is returned when a state transition is invalid.
	ErrInvalidState = errors.New("invalid state transition")

	// ErrPolicyNotFound is returned when a policy does not exist.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrPolicyExists is returned when attempting to apply a policy that already exists.
	ErrPolicyExists = errors.New("policy already exists")

	// ErrInvalidPolicy is returned when a policy specification is invalid.
	ErrInvalidPolicy = errors.New("invalid policy specification")

	// ErrInvalidConfiguration is returned when a configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrInvalidCertificate is returned when a certificate is invalid or cannot be parsed.
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrCertificateExpired is returned when a certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateRevoked is returned when a certificate has been revoked.
	ErrCertificateRevoked = errors.New("certificate revoked")

	// ErrMissingTenantID is returned when a tenant ID is required but not provided.
	ErrMissingTenantID = errors.New("missing tenant ID in certificate")

	// ErrMissingVLAN is returned when a VLAN is required but not provided.
	// Retained for backward compatibility; zone-based enforcement replaces direct
	// VLAN extraction from certificates.
	ErrMissingVLAN = errors.New("missing VLAN in certificate")

	// ErrInvalidVLAN is returned when a VLAN ID is invalid.
	ErrInvalidVLAN = errors.New("invalid VLAN ID")

	// ErrInvalidACL is returned when an ACL rule is invalid.
	ErrInvalidACL = errors.New("invalid ACL rule")

	// ErrFlowInstallFailed is returned when installing an OpenFlow rule fails.
	ErrFlowInstallFailed = errors.New("failed to install flow rule")

	// ErrFlowDeleteFailed is returned when deleting an OpenFlow rule fails.
	ErrFlowDeleteFailed = errors.New("failed to delete flow rule")

	// ErrEngineNotRunning is returned when attempting operations on a stopped engine.
	ErrEngineNotRunning = errors.New("policy engine not running")

	// ErrEngineAlreadyRunning is returned when attempting to start an already running engine.
	ErrEngineAlreadyRunning = errors.New("policy engine already running")

	// ErrInvalidClient is returned when a client is nil or invalid.
	ErrInvalidClient = errors.New("invalid client")

	// ErrInvalidBridgeName is returned when a bridge name is empty or invalid.
	ErrInvalidBridgeName = errors.New("invalid bridge name")

	// ErrMissingZoneExtension is returned by ExtractZone when a certificate
	// does not carry the OIDTPNetworkZone extension.
	ErrMissingZoneExtension = errors.New("sdn/policy: certificate has no network zone extension")
)

// ErrZoneNotDeclared is returned when a certificate carries a zone value that
// is not present in the configured resolved zone set. The policy engine
// applies fail-closed behaviour: the port is placed in the quarantine zone
// and this error is returned so callers can emit audit events.
type ErrZoneNotDeclared struct {
	// Zone is the undeclared zone value found in the certificate.
	Zone zone.Zone
	// Subject is the certificate subject for log correlation.
	Subject string
}

// Error implements the error interface.
func (e ErrZoneNotDeclared) Error() string {
	return fmt.Sprintf("sdn/policy: certificate zone %q is not declared in the resolved zone set (subject %q)", e.Zone, e.Subject)
}

// ErrEmptyZoneForEncoding is returned when encode_zone_in_cert is enabled
// but no zone can be resolved from the device profile.
type ErrEmptyZoneForEncoding struct {
	// Serial is the device serial number, when known.
	Serial string
}

// Error implements the error interface.
func (e ErrEmptyZoneForEncoding) Error() string {
	return fmt.Sprintf("sdn/policy: encode_zone_in_cert is enabled but no zone is configured for device serial %q", e.Serial)
}

// ErrZoneMismatch is returned by buildPortPolicy when the zone embedded in
// the issued certificate does not match the device profile's expected zone.
// Callers apply quarantine flows and emit an audit event.
type ErrZoneMismatch struct {
	// CertZone is the zone read from the certificate extension.
	CertZone zone.Zone
	// ProfileZone is the zone expected from the device profile.
	ProfileZone zone.Zone
	// Serial is the device serial number for audit correlation.
	Serial string
}

// Error implements the error interface.
func (e ErrZoneMismatch) Error() string {
	return fmt.Sprintf("sdn/policy: zone mismatch for serial %q: cert=%q profile=%q", e.Serial, e.CertZone, e.ProfileZone)
}
