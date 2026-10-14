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

package quicwire

// Overlay wire shapes. They live here so the SDK QUIC adapter decodes the
// same structs the daemon overlay handler (pkg/api/quic/overlay_handlers.go)
// encodes.

// OverlayStatusInfo contains overlay network status information
type OverlayStatusInfo struct {
	Enabled      bool   `codec:"enabled"`
	NodeID       string `codec:"node_id,omitempty"`
	Mode         string `codec:"mode"`
	LocalVTEP    string `codec:"local_vtep"`
	VXLANPort    uint16 `codec:"vxlan_port,omitempty"`
	VTEPCount    int    `codec:"vtep_count"`
	VNICount     int    `codec:"vni_count"`
	TunnelCount  int    `codec:"tunnel_count"`
	MACCount     int    `codec:"mac_count"`
	UplinkIface  string `codec:"uplink_iface,omitempty"`
	MTU          int    `codec:"mtu"`
	EncapType    string `codec:"encap_type"`
	HealthStatus string `codec:"health_status"`
}

// VTEPInfo contains VTEP information
type VTEPInfo struct {
	ID           string   `codec:"id"`
	IPAddress    string   `codec:"ip_address"`
	Hostname     string   `codec:"hostname,omitempty"`
	Status       string   `codec:"status"`
	VNIs         []uint32 `codec:"vnis,omitempty"`
	TunnelCount  int      `codec:"tunnel_count"`
	LastSeen     int64    `codec:"last_seen"`
	Version      string   `codec:"version,omitempty"`
	Capabilities []string `codec:"capabilities,omitempty"`
}

// VNIInfo contains VNI information
type VNIInfo struct {
	VNI         uint32            `codec:"vni"`
	VLAN        uint16            `codec:"vlan,omitempty"`
	Name        string            `codec:"name,omitempty"`
	BridgeName  string            `codec:"bridge_name,omitempty"`
	Status      string            `codec:"status"`
	MTU         int               `codec:"mtu"`
	MACCount    int               `codec:"mac_count"`
	VTEPCount   int               `codec:"vtep_count"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	CreatedAt   int64             `codec:"created_at"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// VNICreateOptions contains options for creating a VNI
type VNICreateOptions struct {
	// VLAN is the 802.1Q VLAN ID the VNI maps to; 0 is none.
	VLAN        uint32            `codec:"vlan,omitempty"`
	Name        string            `codec:"name,omitempty"`
	MTU         int               `codec:"mtu,omitempty"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// TunnelInfo contains tunnel information
type TunnelInfo struct {
	ID         string `codec:"id"`
	LocalVTEP  string `codec:"local_vtep"`
	RemoteVTEP string `codec:"remote_vtep"`
	VNI        uint32 `codec:"vni"`
	Status     string `codec:"status"`
	EncapType  string `codec:"encap_type"`
	TxBytes    int64  `codec:"tx_bytes"`
	RxBytes    int64  `codec:"rx_bytes"`
	TxPackets  int64  `codec:"tx_packets"`
	RxPackets  int64  `codec:"rx_packets"`
	CreatedAt  int64  `codec:"created_at"`
	LastActive int64  `codec:"last_active"`
}

// MACEntry contains MAC table entry information
type MACEntry struct {
	MAC         string `codec:"mac"`
	VNI         uint32 `codec:"vni"`
	VTEP        string `codec:"vtep"`
	Port        string `codec:"port,omitempty"`
	Type        string `codec:"type"` // static, dynamic, learned
	VLAN        int    `codec:"vlan,omitempty"`
	Age         int    `codec:"age"`
	LastSeen    int64  `codec:"last_seen"`
	IsPermanent bool   `codec:"is_permanent"`
}

// OverlayStatusRequest represents a status request
type OverlayStatusRequest struct{}

// OverlayStatusResponse represents a status response
type OverlayStatusResponse struct {
	Status    *OverlayStatusInfo `codec:"status"`
	Timestamp int64              `codec:"timestamp"`
}

// OverlayListVTEPsRequest asks for the page of VTEPs starting at Offset.
type OverlayListVTEPsRequest struct {
	Limit  int32 `codec:"limit,omitempty"`
	Offset int32 `codec:"offset,omitempty"`
}

// OverlayListVTEPsResponse carries one page of VTEPs; Count is the page
// length and Total the number of VTEPs in all.
type OverlayListVTEPsResponse struct {
	VTEPs     []*VTEPInfo `codec:"vteps"`
	Count     int32       `codec:"count"`
	Total     int32       `codec:"total"`
	Timestamp int64       `codec:"timestamp"`
}

// OverlayGetVTEPRequest represents a VTEP get request
type OverlayGetVTEPRequest struct {
	ID string `codec:"id"`
}

// OverlayGetVTEPResponse represents a VTEP get response
type OverlayGetVTEPResponse struct {
	VTEP      *VTEPInfo `codec:"vtep"`
	Timestamp int64     `codec:"timestamp"`
}

// OverlayListVNIsRequest asks for the page of VNIs starting at Offset.
type OverlayListVNIsRequest struct {
	Limit  int32 `codec:"limit,omitempty"`
	Offset int32 `codec:"offset,omitempty"`
}

// OverlayListVNIsResponse carries one page of VNIs; Count is the page
// length and Total the number of VNIs in all.
type OverlayListVNIsResponse struct {
	VNIs      []*VNIInfo `codec:"vnis"`
	Count     int32      `codec:"count"`
	Total     int32      `codec:"total"`
	Timestamp int64      `codec:"timestamp"`
}

// OverlayCreateVNIRequest represents a VNI creation request
type OverlayCreateVNIRequest struct {
	VNI uint32 `codec:"vni"`
	// VLAN is the 802.1Q VLAN ID the VNI maps to; 0 is none. It is wider
	// than a VLAN ID so an out-of-range value reaches validation instead of
	// wrapping.
	VLAN        uint32            `codec:"vlan,omitempty"`
	Name        string            `codec:"name,omitempty"`
	MTU         int               `codec:"mtu,omitempty"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// OverlayCreateVNIResponse represents a VNI creation response
type OverlayCreateVNIResponse struct {
	VNI       *VNIInfo `codec:"vni"`
	Timestamp int64    `codec:"timestamp"`
}

// OverlayDeleteVNIRequest represents a VNI deletion request
type OverlayDeleteVNIRequest struct {
	VNI uint32 `codec:"vni"`
}

// OverlayDeleteVNIResponse represents a VNI deletion response
type OverlayDeleteVNIResponse struct {
	VNI       uint32 `codec:"vni"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// OverlayListTunnelsRequest asks for the page of tunnels starting at
// Offset, only those carrying VNI when it is non-zero.
type OverlayListTunnelsRequest struct {
	VNI    uint32 `codec:"vni,omitempty"`
	Limit  int32  `codec:"limit,omitempty"`
	Offset int32  `codec:"offset,omitempty"`
}

// OverlayListTunnelsResponse carries one page of tunnels; Count is the page
// length and Total the number of matching tunnels in all.
type OverlayListTunnelsResponse struct {
	Tunnels   []*TunnelInfo `codec:"tunnels"`
	Count     int32         `codec:"count"`
	Total     int32         `codec:"total"`
	Timestamp int64         `codec:"timestamp"`
}

// OverlayTunnelStatsRequest selects one tunnel by remote VTEP and, when VNI
// is non-zero, by VNI.
type OverlayTunnelStatsRequest struct {
	RemoteVTEP string `codec:"remote_vtep"`
	VNI        uint32 `codec:"vni,omitempty"`
}

// OverlayTunnelStatsResponse carries the selected tunnel and its counters.
type OverlayTunnelStatsResponse struct {
	Tunnel    *TunnelInfo `codec:"tunnel"`
	Timestamp int64       `codec:"timestamp"`
}

// OverlayListMACsRequest asks for the page of learned MACs starting at
// Offset, only those in VNI when it is non-zero.
type OverlayListMACsRequest struct {
	VNI    uint32 `codec:"vni"`
	Limit  int32  `codec:"limit,omitempty"`
	Offset int32  `codec:"offset,omitempty"`
}

// OverlayListMACsResponse carries one page of MACs; Count is the page
// length and Total the number of matching MACs in all.
type OverlayListMACsResponse struct {
	MACs      []*MACEntry `codec:"macs"`
	Count     int32       `codec:"count"`
	Total     int32       `codec:"total"`
	Timestamp int64       `codec:"timestamp"`
}

// OverlayForgetMACRequest represents a MAC forget request
type OverlayForgetMACRequest struct {
	VNI uint32 `codec:"vni"`
	MAC string `codec:"mac"`
}

// OverlayForgetMACResponse represents a MAC forget response
type OverlayForgetMACResponse struct {
	VNI       uint32 `codec:"vni"`
	MAC       string `codec:"mac"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}
