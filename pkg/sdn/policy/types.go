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
	"context"
	"crypto/x509"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// PortState represents the authentication state of a network port
type PortState int

const (
	// PortStateUnconnected indicates the port is not yet detected
	PortStateUnconnected PortState = iota

	// PortStateProvisioning indicates the port has limited access for enrollment
	PortStateProvisioning

	// PortStateEnrolled indicates the device is enrolled but awaiting activation
	PortStateEnrolled

	// PortStateUnauthorized indicates the port is not authenticated
	PortStateUnauthorized

	// PortStateAuthenticating indicates authentication is in progress
	PortStateAuthenticating

	// PortStateAuthorized indicates the port is authenticated and authorized
	PortStateAuthorized

	// PortStateQuarantined indicates the port is in isolated VLAN for scanning/remediation
	PortStateQuarantined

	// PortStateBlocked indicates the port is blocked due to policy violation
	PortStateBlocked
)

// String returns the string representation of PortState
func (s PortState) String() string {
	switch s {
	case PortStateUnconnected:
		return "unconnected"
	case PortStateProvisioning:
		return "provisioning"
	case PortStateEnrolled:
		return "enrolled"
	case PortStateUnauthorized:
		return "unauthorized"
	case PortStateAuthenticating:
		return "authenticating"
	case PortStateAuthorized:
		return "authorized"
	case PortStateQuarantined:
		return "quarantined"
	case PortStateBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// PortPolicy represents the security policy for a network port
type PortPolicy struct {
	// TenantID is the tenant identifier extracted from the certificate
	TenantID string

	// VLAN is the VLAN ID assigned to this port
	VLAN uint16

	// ACLs are the access control list rules for this port
	ACLs []ACLRule

	// Certificate is the X.509 certificate used for authentication
	Certificate *x509.Certificate

	// ExpiresAt is the expiration time of the certificate
	ExpiresAt time.Time

	// IssuedAt is when the policy was issued
	IssuedAt time.Time

	// Metadata contains additional policy metadata
	Metadata map[string]string
}

// ACLRule represents an access control list rule
type ACLRule struct {
	// Priority determines the order in which rules are evaluated (higher = first)
	Priority int

	// Match contains the flow matching criteria
	Match FlowMatch

	// Action defines what to do when the match criteria are met
	Action FlowAction

	// Description provides human-readable rule description
	Description string
}

// FlowMatch represents OpenFlow matching criteria
type FlowMatch struct {
	// InPort is the input port number
	InPort string

	// EthSrc is the source Ethernet address
	EthSrc string

	// EthDst is the destination Ethernet address
	EthDst string

	// EthType is the Ethernet protocol type
	EthType uint16

	// VLANVid is the VLAN ID
	VLANVid uint16

	// IPProto is the IP protocol number
	IPProto uint8

	// IPv4Src is the source IPv4 address (CIDR notation)
	IPv4Src string

	// IPv4Dst is the destination IPv4 address (CIDR notation)
	IPv4Dst string

	// TCPSrc is the source TCP port
	TCPSrc uint16

	// TCPDst is the destination TCP port
	TCPDst uint16

	// UDPSrc is the source UDP port
	UDPSrc uint16

	// UDPDst is the destination UDP port
	UDPDst uint16
}

// FlowAction represents OpenFlow actions
type FlowAction struct {
	// Type is the action type (allow, deny, forward, etc.)
	Type FlowActionType

	// Output specifies the output port for forward actions
	Output string

	// SetVLAN specifies the VLAN to set
	SetVLAN uint16

	// Params contains additional action parameters
	Params map[string]string
}

// FlowActionType represents the type of flow action
type FlowActionType string

const (
	// FlowActionAllow allows the traffic
	FlowActionAllow FlowActionType = "allow"

	// FlowActionDeny drops the traffic
	FlowActionDeny FlowActionType = "deny"

	// FlowActionForward forwards to specified port
	FlowActionForward FlowActionType = "forward"

	// FlowActionNormal uses normal L2/L3 switching
	FlowActionNormal FlowActionType = "normal"
)

// PortInfo contains runtime information about a port
type PortInfo struct {
	// PortID is the unique identifier for the port
	PortID string

	// State is the current authentication state
	State PortState

	// Policy is the active policy (nil if none)
	Policy *PortPolicy

	// LastStateChange is when the state last changed
	LastStateChange time.Time

	// AuthAttempts is the number of authentication attempts
	AuthAttempts int

	// LastAuthAttempt is when the last authentication was attempted
	LastAuthAttempt time.Time

	// ErrorCount is the number of errors encountered
	ErrorCount int

	// LastError is the last error message
	LastError string
}

// FlowController defines the interface for OpenFlow rule management
type FlowController interface {
	// InstallFlow installs an OpenFlow rule
	InstallFlow(bridgeName string, priority int, match string, actions string) error

	// DeleteFlow deletes OpenFlow rules matching the criteria
	DeleteFlow(bridgeName string, match string) error

	// DeleteFlowsByPort deletes all flows for a specific port
	DeleteFlowsByPort(bridgeName string, portID string) error

	// ListFlows returns all flows for a bridge
	ListFlows(bridgeName string) ([]string, error)
}

// OVSPortController extends FlowController with OVS-specific port operations
type OVSPortController interface {
	FlowController

	// SetPortVLAN sets the VLAN tag for a port using OVSDB
	SetPortVLAN(ctx context.Context, portName string, vlan int64) error

	// SetPortState sets the admin state of a port (up/down)
	SetPortState(ctx context.Context, portName string, state ovs.PortState) error

	// GetOFPort retrieves the OpenFlow port number for a port name
	GetOFPort(ctx context.Context, portName string) (int32, error)
}

// CertificateValidator defines the interface for certificate validation
type CertificateValidator interface {
	// ValidateCertificate validates a certificate and returns any errors
	ValidateCertificate(cert *x509.Certificate) error

	// IsRevoked checks if a certificate has been revoked
	IsRevoked(cert *x509.Certificate) (bool, error)

	// CheckExpiry checks if a certificate has expired or will expire soon
	CheckExpiry(cert *x509.Certificate, threshold time.Duration) error
}

// PolicyExtractor defines the interface for extracting policy from certificates
type PolicyExtractor interface {
	// ExtractPolicy extracts policy information from a certificate
	ExtractPolicy(cert *x509.Certificate) (*PortPolicy, error)

	// ExtractTenantID extracts the tenant ID from a certificate
	ExtractTenantID(cert *x509.Certificate) (string, error)

	// ExtractVLAN extracts the VLAN ID from a certificate
	ExtractVLAN(cert *x509.Certificate) (uint16, error)

	// ExtractACLs extracts ACL rules from a certificate
	ExtractACLs(cert *x509.Certificate) ([]ACLRule, error)
}
