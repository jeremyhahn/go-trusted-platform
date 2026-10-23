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

package sdn

import "time"

// CreateBridgeRequest is the request body for creating a bridge
type CreateBridgeRequest struct {
	Name       string            `json:"name"`
	Type       string            `json:"type,omitempty"`
	DatapathID string            `json:"datapath_id,omitempty"`
	StpEnabled bool              `json:"stp_enabled,omitempty"`
	MTU        uint32            `json:"mtu,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// BridgeResponse is the response for bridge operations
type BridgeResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Status    string            `json:"status"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ListBridgesResponse is the response for listing bridges
type ListBridgesResponse struct {
	Bridges []BridgeResponse `json:"bridges"`
}

// AddPortRequest is the request body for adding a port
type AddPortRequest struct {
	Name        string            `json:"name"`
	Type        string            `json:"type,omitempty"`
	VLAN        uint32            `json:"vlan,omitempty"`
	TrunkVLANs  []uint32          `json:"trunk_vlans,omitempty"`
	MACAddress  string            `json:"mac_address,omitempty"`
	MTU         uint32            `json:"mtu,omitempty"`
	Promiscuous bool              `json:"promiscuous,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// PortResponse is the response for port operations
type PortResponse struct {
	ID        string            `json:"id"`
	BridgeID  string            `json:"bridge_id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	VLAN      uint32            `json:"vlan,omitempty"`
	Status    string            `json:"status"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// AuthenticatePortRequest is the request body for authenticating a port with
// a client certificate. The certificate travels base64-encoded; format is
// "PEM" (the default) or "DER".
type AuthenticatePortRequest struct {
	Certificate []byte `json:"certificate"`
	Format      string `json:"format,omitempty"`
}

// PortAuthResponse is the authentication state of a port.
type PortAuthResponse struct {
	BridgeID        string     `json:"bridge_id"`
	PortID          string     `json:"port_id"`
	Authenticated   bool       `json:"authenticated"`
	CertificateCN   string     `json:"certificate_cn,omitempty"`
	AuthenticatedAt *time.Time `json:"authenticated_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	AuthorizedVLANs []uint32   `json:"authorized_vlans,omitempty"`
}

// ListPortsResponse is the response for listing ports
type ListPortsResponse struct {
	Ports []PortResponse `json:"ports"`
}

// SetPortStateRequest is the request body for setting port state
type SetPortStateRequest struct {
	AdminState   string `json:"admin_state"`   // "up" or "down", case-insensitive
	IngressRate  uint64 `json:"ingress_rate"`  // bits/s; 0 leaves policing as it is
	IngressBurst uint64 `json:"ingress_burst"` // bits; 0 lets Open vSwitch pick
	EgressRate   uint64 `json:"egress_rate"`   // bits/s; 0 leaves shaping as it is
	EgressBurst  uint64 `json:"egress_burst"`  // bits; 0 lets Open vSwitch pick
}

// PortStateResponse is the response for port state operations. The field
// names match the daemon REST answer (docs/sdn/api-reference-rest.md).
type PortStateResponse struct {
	BridgeID   string `json:"bridge_id"`
	PortID     string `json:"port_id"`
	AdminState string `json:"admin_state"`
}

// AddFlowRequest is the request body for adding a flow
type AddFlowRequest struct {
	BridgeID    string            `json:"bridge_id"`
	Table       uint32            `json:"table,omitempty"`
	Priority    uint32            `json:"priority,omitempty"`
	Match       *FlowMatch        `json:"match,omitempty"`
	Actions     []*FlowAction     `json:"actions,omitempty"`
	IdleTimeout uint32            `json:"idle_timeout,omitempty"`
	HardTimeout uint32            `json:"hard_timeout,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// FlowMatch represents flow match criteria
type FlowMatch struct {
	InPort  string `json:"in_port,omitempty"`
	VlanID  uint32 `json:"vlan_id,omitempty"`
	EthSrc  string `json:"eth_src,omitempty"`
	EthDst  string `json:"eth_dst,omitempty"`
	EthType uint32 `json:"eth_type,omitempty"`
	IPSrc   string `json:"ip_src,omitempty"`
	IPDst   string `json:"ip_dst,omitempty"`
	IPProto uint32 `json:"ip_proto,omitempty"`
	TCPSrc  uint32 `json:"tcp_src,omitempty"`
	TCPDst  uint32 `json:"tcp_dst,omitempty"`
	UDPSrc  uint32 `json:"udp_src,omitempty"`
	UDPDst  uint32 `json:"udp_dst,omitempty"`
}

// FlowAction represents a flow action
type FlowAction struct {
	Type    string `json:"type"`
	Port    string `json:"port,omitempty"`
	VlanID  uint32 `json:"vlan_id,omitempty"`
	Field   string `json:"field,omitempty"`
	Value   string `json:"value,omitempty"`
	TableID uint32 `json:"table_id,omitempty"`
}

// FlowResponse is the response for flow operations
type FlowResponse struct {
	ID        string            `json:"id"`
	BridgeID  string            `json:"bridge_id"`
	Table     uint32            `json:"table"`
	Priority  uint32            `json:"priority"`
	Match     *FlowMatch        `json:"match,omitempty"`
	Actions   []*FlowAction     `json:"actions,omitempty"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	Stats     *FlowStats        `json:"stats,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// FlowStats represents flow statistics
type FlowStats struct {
	PacketCount     uint64 `json:"packet_count"`
	ByteCount       uint64 `json:"byte_count"`
	DurationSeconds uint32 `json:"duration_seconds"`
}

// ListFlowsResponse is the response for listing flows
type ListFlowsResponse struct {
	Flows []FlowResponse `json:"flows"`
}

// DeleteFlowRequest is the request body for deleting a flow
type DeleteFlowRequest struct {
	BridgeID string `json:"bridge_id"`
	FlowID   string `json:"flow_id"`
}

// Rule represents a policy rule
type Rule struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Match       *FlowMatch        `json:"match,omitempty"`
	Actions     []*FlowAction     `json:"actions,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyResponse is the response for policy operations
type PolicyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Rules       []Rule     `json:"rules"`
	BridgeIDs   []string   `json:"bridge_ids,omitempty"`
	Priority    int32      `json:"priority"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// ListPoliciesResponse is the response for listing policies
type ListPoliciesResponse struct {
	Policies []PolicyResponse `json:"policies"`
}

// CreateVLANRequest is the request body for creating a VLAN
type CreateVLANRequest struct {
	VlanID   uint32            `json:"vlan_id"`
	Name     string            `json:"name,omitempty"`
	BridgeID string            `json:"bridge_id"`
	Ports    []string          `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// VLANResponse is the response for VLAN operations
type VLANResponse struct {
	ID        string            `json:"id"`
	VlanID    uint32            `json:"vlan_id"`
	Name      string            `json:"name,omitempty"`
	BridgeID  string            `json:"bridge_id"`
	Ports     []string          `json:"ports,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
}

// ListVLANsResponse is the response for listing VLANs
type ListVLANsResponse struct {
	VLANs []VLANResponse `json:"vlans"`
}

// PortStatsResponse is the response for port statistics
type PortStatsResponse struct {
	PortID          string `json:"port_id"`
	PacketsReceived uint64 `json:"packets_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	BytesSent       uint64 `json:"bytes_sent"`
	Errors          uint64 `json:"errors"`
	Dropped         uint64 `json:"dropped"`
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}
