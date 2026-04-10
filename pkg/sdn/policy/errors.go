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

import "errors"

var (
	// ErrPortNotFound is returned when a port does not exist
	ErrPortNotFound = errors.New("port not found")

	// ErrPortExists is returned when attempting to create a port that already exists
	ErrPortExists = errors.New("port already exists")

	// ErrInvalidPortID is returned when a port ID is invalid
	ErrInvalidPortID = errors.New("invalid port ID")

	// ErrInvalidState is returned when a state transition is invalid
	ErrInvalidState = errors.New("invalid state transition")

	// ErrPolicyNotFound is returned when a policy does not exist
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrPolicyExists is returned when attempting to apply a policy that already exists
	ErrPolicyExists = errors.New("policy already exists")

	// ErrInvalidPolicy is returned when a policy specification is invalid
	ErrInvalidPolicy = errors.New("invalid policy specification")

	// ErrInvalidConfiguration is returned when a configuration is invalid
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrInvalidCertificate is returned when a certificate is invalid or cannot be parsed
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrCertificateExpired is returned when a certificate has expired
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateRevoked is returned when a certificate has been revoked
	ErrCertificateRevoked = errors.New("certificate revoked")

	// ErrMissingTenantID is returned when a tenant ID is required but not provided
	ErrMissingTenantID = errors.New("missing tenant ID in certificate")

	// ErrMissingVLAN is returned when a VLAN is required but not provided
	ErrMissingVLAN = errors.New("missing VLAN in certificate")

	// ErrInvalidVLAN is returned when a VLAN ID is invalid
	ErrInvalidVLAN = errors.New("invalid VLAN ID")

	// ErrInvalidACL is returned when an ACL rule is invalid
	ErrInvalidACL = errors.New("invalid ACL rule")

	// ErrFlowInstallFailed is returned when installing an OpenFlow rule fails
	ErrFlowInstallFailed = errors.New("failed to install flow rule")

	// ErrFlowDeleteFailed is returned when deleting an OpenFlow rule fails
	ErrFlowDeleteFailed = errors.New("failed to delete flow rule")

	// ErrEngineNotRunning is returned when attempting operations on a stopped engine
	ErrEngineNotRunning = errors.New("policy engine not running")

	// ErrEngineAlreadyRunning is returned when attempting to start an already running engine
	ErrEngineAlreadyRunning = errors.New("policy engine already running")

	// ErrInvalidClient is returned when a client is nil or invalid
	ErrInvalidClient = errors.New("invalid client")

	// ErrInvalidBridgeName is returned when a bridge name is empty or invalid
	ErrInvalidBridgeName = errors.New("invalid bridge name")
)
