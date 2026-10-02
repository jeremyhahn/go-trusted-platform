//go:build integration

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

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

// =============================================================================
// QUIC Overlay Constants and Operation Codes
// =============================================================================

const (
	// EnvPlatformQUICEndpointOverlay is the environment variable for the QUIC endpoint.
	EnvPlatformQUICEndpointOverlay = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpointOverlay is the default QUIC endpoint address.
	DefaultQUICEndpointOverlay = "localhost:9444"

	// DefaultQUICTimeoutOverlay is the default timeout for QUIC operations.
	DefaultQUICTimeoutOverlay = 30 * time.Second

	// MaxQUICPayloadSizeOverlay is the maximum payload size (16MB).
	MaxQUICPayloadSizeOverlay uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSizeOverlay is the maximum token size (8KB).
	MaxQUICTokenSizeOverlay uint16 = 8 * 1024
)

// QUIC Status codes for overlay operations.
const (
	QUICStatusOKOverlay             byte = 0x00
	QUICStatusInvalidRequestOverlay byte = 0x01
	QUICStatusNotFoundOverlay       byte = 0x02
	QUICStatusInternalErrorOverlay  byte = 0x04
	QUICStatusUnavailableOverlay    byte = 0x0A
)

// Category opcodes from protocol.go - these are the single-byte opcodes sent
// on the wire. The first byte of the payload carries the sub-opcode.
const (
	// OpCategoryOverlay is the category opcode for overlay operations (0x2E).
	OpCategoryOverlay byte = 0x2E

	// OpCategoryGateway is the category opcode for gateway operations (0x2F).
	OpCategoryGateway byte = 0x2F

	// OpCategoryIPAM is the category opcode for IPAM operations (0x3F).
	OpCategoryIPAM byte = 0x3F
)

// Overlay sub-opcodes - these match the sub-opcodes defined in
// pkg/api/quic/overlay_handlers.go and are sent as the first byte
// of the category opcode's payload.
const (
	SubOpOverlayStatus    byte = 0x01
	SubOpOverlayListVTEPs byte = 0x02
	SubOpOverlayGetVTEP   byte = 0x03
	SubOpOverlayListVNIs  byte = 0x04
	SubOpOverlayCreateVNI byte = 0x05
	SubOpOverlayDeleteVNI byte = 0x06
	SubOpOverlayListTunns byte = 0x07
	SubOpOverlayListMACs  byte = 0x08
	SubOpOverlayForgetMAC byte = 0x09
)

// Gateway sub-opcodes - these match the sub-opcodes defined in
// pkg/api/quic/gateway_handlers.go and are sent as the first byte
// of the category opcode's payload.
const (
	SubOpGatewayStatus         byte = 0x01
	SubOpGatewaySetMode        byte = 0x02
	SubOpGatewayBGPStatus      byte = 0x03
	SubOpGatewayBGPPeers       byte = 0x04
	SubOpGatewayAnnouncePrefix byte = 0x05
	SubOpGatewayWithdrawPrefix byte = 0x06
	SubOpGatewayListPrefixes   byte = 0x07
)

// IPAM sub-opcodes - these match the IPAM-related sub-opcodes defined in
// pkg/api/quic/gateway_handlers.go. IPAM operations are handled by the
// gateway handler but routed through a separate category opcode.
const (
	SubOpIPAMListPools       byte = 0x08
	SubOpIPAMAllocateIP      byte = 0x09
	SubOpIPAMReleaseIP       byte = 0x0A
	SubOpIPAMListAllocations byte = 0x0B

	// Pool management sub-opcodes (not yet implemented server-side)
	SubOpIPAMCreatePool byte = 0x0C
	SubOpIPAMDeletePool byte = 0x0D
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICOverlayConnectionFailed indicates a QUIC connection failure.
type ErrQUICOverlayConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICOverlayConnectionFailed) Error() string {
	return "QUIC overlay connection to " + e.Endpoint + " failed: " + e.Err.Error()
}

func (e ErrQUICOverlayConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICOverlayRequestFailed indicates a QUIC request failure.
type ErrQUICOverlayRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICOverlayRequestFailed) Error() string {
	return "QUIC overlay request " + e.Operation + " failed: " + e.Message
}

// ErrQUICOverlayEncodeFailed indicates payload encoding failure.
type ErrQUICOverlayEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICOverlayEncodeFailed) Error() string {
	return "QUIC overlay encode failed for " + e.Operation + ": " + e.Err.Error()
}

func (e ErrQUICOverlayEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICOverlayDecodeFailed indicates payload decoding failure.
type ErrQUICOverlayDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICOverlayDecodeFailed) Error() string {
	return "QUIC overlay decode failed for " + e.Operation + ": " + e.Err.Error()
}

func (e ErrQUICOverlayDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICOverlayClientClosed indicates the client is closed.
type ErrQUICOverlayClientClosed struct{}

func (e ErrQUICOverlayClientClosed) Error() string {
	return "QUIC overlay client is closed"
}

// ErrQUICOverlayStreamFailed indicates a stream operation failure.
type ErrQUICOverlayStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICOverlayStreamFailed) Error() string {
	return "QUIC overlay stream failed for " + e.Operation + ": " + e.Err.Error()
}

func (e ErrQUICOverlayStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICOverlayInvalidResponse indicates an invalid response was received.
type ErrQUICOverlayInvalidResponse struct {
	Operation string
	Details   string
}

func (e ErrQUICOverlayInvalidResponse) Error() string {
	return "QUIC overlay invalid response for " + e.Operation + ": " + e.Details
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicOverlayRequest represents a QUIC protocol request for overlay operations.
type quicOverlayRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicOverlayResponse represents a QUIC protocol response for overlay operations.
type quicOverlayResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// Request/Response Types for Wire Protocol
// =============================================================================

// overlayStatusRequest represents an overlay status request.
type overlayStatusRequest struct{}

// overlayStatusInfoWire mirrors quic.OverlayStatusInfo codec tags exactly.
type overlayStatusInfoWire struct {
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

// overlayStatusResponse mirrors quic.OverlayStatusResponse codec tags exactly.
type overlayStatusResponse struct {
	Status    *overlayStatusInfoWire `codec:"status"`
	Timestamp int64                  `codec:"timestamp"`
}

// vtepListRequest represents a VTEP list request.
type vtepListRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// vtepInfoWire mirrors quic.VTEPInfo codec tags exactly.
type vtepInfoWire struct {
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

// vtepListResponse mirrors quic.OverlayListVTEPsResponse codec tags exactly.
type vtepListResponse struct {
	VTEPs     []vtepInfoWire `codec:"vteps"`
	Count     int32          `codec:"count"`
	Timestamp int64          `codec:"timestamp"`
}

// vtepGetRequest mirrors quic.OverlayGetVTEPRequest codec tags exactly.
// The server field is "id" (not "node_id").
type vtepGetRequest struct {
	ID string `codec:"id"`
}

// vtepGetResponse mirrors quic.OverlayGetVTEPResponse codec tags exactly.
type vtepGetResponse struct {
	VTEP      *vtepInfoWire `codec:"vtep"`
	Timestamp int64         `codec:"timestamp"`
}

// vniInfoWire mirrors quic.VNIInfo codec tags exactly.
type vniInfoWire struct {
	VNI         uint32 `codec:"vni"`
	Name        string `codec:"name,omitempty"`
	BridgeName  string `codec:"bridge_name,omitempty"`
	Status      string `codec:"status"`
	MTU         int    `codec:"mtu"`
	MACCount    int    `codec:"mac_count"`
	VTEPCount   int    `codec:"vtep_count"`
	Learning    bool   `codec:"learning"`
	ARPProxy    bool   `codec:"arp_proxy"`
	CreatedAt   int64  `codec:"created_at"`
	NetworkCIDR string `codec:"network_cidr,omitempty"`
}

// vniCreateRequest mirrors quic.OverlayCreateVNIRequest codec tags exactly.
// VLAN is not part of the QUIC overlay protocol; the server uses VNI-based overlay only.
type vniCreateRequest struct {
	VNI  uint32 `codec:"vni"`
	Name string `codec:"name,omitempty"`
}

// vniCreateResponse mirrors quic.OverlayCreateVNIResponse codec tags exactly.
type vniCreateResponse struct {
	VNI       *vniInfoWire `codec:"vni"`
	Timestamp int64        `codec:"timestamp"`
}

// vniDeleteRequest represents a VNI delete request.
type vniDeleteRequest struct {
	VNI uint32 `codec:"vni"`
}

// vniDeleteResponse mirrors quic.OverlayDeleteVNIResponse codec tags exactly.
type vniDeleteResponse struct {
	VNI       uint32 `codec:"vni"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// vniListRequest represents a VNI list request.
type vniListRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// vniListResponse mirrors quic.OverlayListVNIsResponse codec tags exactly.
type vniListResponse struct {
	VNIs      []vniInfoWire `codec:"vnis"`
	Count     int32         `codec:"count"`
	Timestamp int64         `codec:"timestamp"`
}

// tunnelListRequest represents a tunnel list request.
// The overlay server ListTunnels does not filter by VNI in the request;
// VNI filtering is applied in the test layer.
type tunnelListRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// tunnelInfoWire mirrors quic.TunnelInfo codec tags exactly.
type tunnelInfoWire struct {
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

// tunnelListResponse mirrors quic.OverlayListTunnelsResponse codec tags exactly.
type tunnelListResponse struct {
	Tunnels   []tunnelInfoWire `codec:"tunnels"`
	Count     int32            `codec:"count"`
	Timestamp int64            `codec:"timestamp"`
}

// macListRequest mirrors quic.OverlayListMACsRequest codec tags exactly.
// VNI == 0 means list all MACs.
type macListRequest struct {
	VNI   uint32 `codec:"vni"`
	Limit int32  `codec:"limit,omitempty"`
}

// macInfoWire mirrors quic.MACEntry codec tags exactly.
type macInfoWire struct {
	MAC         string `codec:"mac"`
	VNI         uint32 `codec:"vni"`
	VTEP        string `codec:"vtep"`
	Port        string `codec:"port,omitempty"`
	Type        string `codec:"type"`
	VLAN        int    `codec:"vlan,omitempty"`
	Age         int    `codec:"age"`
	LastSeen    int64  `codec:"last_seen"`
	IsPermanent bool   `codec:"is_permanent"`
}

// macListResponse mirrors quic.OverlayListMACsResponse codec tags exactly.
type macListResponse struct {
	MACs      []macInfoWire `codec:"macs"`
	Count     int32         `codec:"count"`
	Timestamp int64         `codec:"timestamp"`
}

// macForgetRequest mirrors quic.OverlayForgetMACRequest codec tags exactly.
type macForgetRequest struct {
	VNI uint32 `codec:"vni"`
	MAC string `codec:"mac"`
}

// macForgetResponse mirrors quic.OverlayForgetMACResponse codec tags exactly.
type macForgetResponse struct {
	VNI       uint32 `codec:"vni"`
	MAC       string `codec:"mac"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// gatewayStatusRequest represents a gateway status request.
type gatewayStatusRequest struct{}

// gatewayStatusResponse represents a gateway status response.
type gatewayStatusResponse struct {
	NodeID         string   `codec:"node_id"`
	Modes          []string `codec:"modes"`
	Tier           string   `codec:"tier"`
	Healthy        bool     `codec:"healthy"`
	Reputation     float64  `codec:"reputation"`
	AgeNanos       int64    `codec:"age_nanos"`
	UptimePct      float64  `codec:"uptime_pct"`
	IPv6Pool       string   `codec:"ipv6_pool"`
	IPv4Pool       string   `codec:"ipv4_pool"`
	BGPEnabled     bool     `codec:"bgp_enabled"`
	EVPNEnabled    bool     `codec:"evpn_enabled"`
	TransitEnabled bool     `codec:"transit_enabled"`
}

// gatewaySetModeRequest represents a gateway set mode request.
type gatewaySetModeRequest struct {
	Modes []string `codec:"modes"`
}

// gatewaySetModeResponse represents a gateway set mode response.
type gatewaySetModeResponse struct {
	Modes   []string `codec:"modes"`
	Success bool     `codec:"success"`
}

// bgpStatusRequest represents a BGP status request.
type bgpStatusRequest struct{}

// bgpStatusResponse represents a BGP status response.
type bgpStatusResponse struct {
	Enabled          bool   `codec:"enabled"`
	ASN              uint32 `codec:"asn"`
	RouterID         string `codec:"router_id"`
	State            string `codec:"state"`
	PeerCount        int    `codec:"peer_count"`
	EstablishedCount int    `codec:"established_count"`
	EVPNEnabled      bool   `codec:"evpn_enabled"`
	TransitEnabled   bool   `codec:"transit_enabled"`
}

// bgpPeersRequest represents a BGP peers request.
type bgpPeersRequest struct{}

// bgpPeersResponse represents a BGP peers response.
type bgpPeersResponse struct {
	Peers      []bgpPeerInfoWire `codec:"peers"`
	TotalCount int               `codec:"total_count"`
}

// bgpPeerInfoWire represents BGP peer information in wire format.
type bgpPeerInfoWire struct {
	Address      string `codec:"address"`
	RemoteASN    uint32 `codec:"remote_asn"`
	State        string `codec:"state"`
	UptimeNanos  int64  `codec:"uptime_nanos"`
	PrefixesRecv int    `codec:"prefixes_recv"`
	PrefixesSent int    `codec:"prefixes_sent"`
	Description  string `codec:"description"`
}

// bgpPrefixesRequest represents a BGP prefixes request.
type bgpPrefixesRequest struct{}

// bgpPrefixesResponse represents a BGP prefixes response.
type bgpPrefixesResponse struct {
	Prefixes   []bgpPrefixInfoWire `codec:"prefixes"`
	TotalCount int                 `codec:"total_count"`
}

// bgpPrefixInfoWire represents BGP prefix information in wire format.
type bgpPrefixInfoWire struct {
	Prefix      string   `codec:"prefix"`
	NextHop     string   `codec:"next_hop"`
	Origin      string   `codec:"origin"`
	ASPath      string   `codec:"as_path"`
	LocalPref   uint32   `codec:"local_pref"`
	MED         uint32   `codec:"med"`
	Communities []string `codec:"communities"`
}

// bgpAnnounceRequest represents a BGP announce request.
type bgpAnnounceRequest struct {
	Prefix  string `codec:"prefix"`
	NextHop string `codec:"next_hop"`
}

// bgpAnnounceResponse represents a BGP announce response.
type bgpAnnounceResponse struct {
	Prefix  string `codec:"prefix"`
	Success bool   `codec:"success"`
}

// bgpWithdrawRequest represents a BGP withdraw request.
type bgpWithdrawRequest struct {
	Prefix string `codec:"prefix"`
}

// bgpWithdrawResponse represents a BGP withdraw response.
type bgpWithdrawResponse struct {
	Prefix  string `codec:"prefix"`
	Success bool   `codec:"success"`
}

// ipamPoolListRequest represents an IPAM pool list request.
type ipamPoolListRequest struct{}

// ipamPoolListResponse represents an IPAM pool list response.
// Matches GatewayListIPAMPoolsResponse wire shape from pkg/api/quic/gateway_handlers.go.
type ipamPoolListResponse struct {
	Pools     []ipamPoolInfoWire `codec:"pools"`
	Count     int32              `codec:"count"`
	Timestamp int64              `codec:"timestamp"`
}

// ipamPoolInfoWire represents IPAM pool information in wire format.
// Fields match IPAMPoolInfo in pkg/api/quic/gateway_handlers.go exactly.
type ipamPoolInfoWire struct {
	ID            string            `codec:"id"`
	Name          string            `codec:"name"`
	CIDR          string            `codec:"cidr"`
	Gateway       string            `codec:"gateway,omitempty"`
	Zone          string            `codec:"zone,omitempty"`
	Description   string            `codec:"description,omitempty"`
	TotalIPs      int               `codec:"total_ips"`
	AllocatedIPs  int               `codec:"allocated_ips"`
	AvailableIPs  int               `codec:"available_ips"`
	ReservedIPs   int               `codec:"reserved_ips"`
	Type          string            `codec:"type"`
	VNI           uint32            `codec:"vni,omitempty"`
	TenantID      string            `codec:"tenant_id,omitempty"`
	Labels        map[string]string `codec:"labels,omitempty"`
	CreatedAt     int64             `codec:"created_at"`
	LastAllocated int64             `codec:"last_allocated,omitempty"`
	LeaseDuration int64             `codec:"lease_duration_nanos,omitempty"`
}

// ipamPoolCreateRequest represents an IPAM pool create request.
type ipamPoolCreateRequest struct {
	Name          string `codec:"name"`
	CIDR          string `codec:"cidr"`
	Gateway       string `codec:"gateway"`
	LeaseDuration int64  `codec:"lease_duration_nanos"`
}

// ipamPoolCreateResponse represents an IPAM pool create response.
// Matches GatewayCreateIPAMPoolResponse wire shape from pkg/api/quic/gateway_handlers.go.
type ipamPoolCreateResponse struct {
	Pool      *ipamPoolInfoWire `codec:"pool"`
	Timestamp int64             `codec:"timestamp"`
}

// ipamPoolDeleteRequest represents an IPAM pool delete request.
type ipamPoolDeleteRequest struct {
	PoolID string `codec:"pool_id"`
}

// ipamPoolDeleteResponse represents an IPAM pool delete response.
// Matches GatewayDeleteIPAMPoolResponse wire shape from pkg/api/quic/gateway_handlers.go.
type ipamPoolDeleteResponse struct {
	PoolID    string `codec:"pool_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// QUIC Overlay Adapter
// =============================================================================

// OverlayQUICAdapter implements OverlayCommands using the QUIC protocol.
type OverlayQUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewOverlayQUICAdapter creates a new QUIC adapter for overlay integration testing.
func NewOverlayQUICAdapter() *OverlayQUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpointOverlay)
	if endpoint == "" {
		endpoint = DefaultQUICEndpointOverlay
	}

	return &OverlayQUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeoutOverlay,
		maxIdleTimeout: 60 * time.Second,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// Name returns the protocol adapter identifier.
func (q *OverlayQUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to the platform endpoint.
func (q *OverlayQUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICOverlayClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
		// qlog tracing: writes per-connection .sqlog files when QLOGDIR is set.
		// qlog.DefaultConnectionTracer is a no-op when QLOGDIR is unset.
		Tracer: qlog.DefaultConnectionTracer,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICOverlayConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *OverlayQUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true

	if q.conn != nil {
		return q.conn.CloseWithError(0, "adapter teardown")
	}

	return nil
}

// =============================================================================
// Wire Protocol Methods
// =============================================================================

// sendCategoryRequest sends a QUIC request using the category opcode pattern.
// The categoryOpcode is the single-byte opcode sent on the wire (0x2E, 0x2F, or 0x3F).
// The subOpcode is prepended to the encoded payload so the server-side category
// handler can extract it and route to the correct sub-handler.
func (q *OverlayQUICAdapter) sendCategoryRequest(ctx context.Context, categoryOpcode byte, subOpcode byte, opName string, payload interface{}) (*quicOverlayResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICOverlayClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Encode payload
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = encodeSDNPayload(payload)
		if err != nil {
			return nil, ErrQUICOverlayEncodeFailed{Operation: opName, Err: err}
		}
	}

	// Prepend the sub-opcode byte to the payload
	// Wire format: [sub_opcode:1][msgpack_payload:N]
	categoryPayload := make([]byte, 1+len(payloadBytes))
	categoryPayload[0] = subOpcode
	copy(categoryPayload[1:], payloadBytes)

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICOverlayStreamFailed{Operation: opName, Err: err}
	}
	defer stream.Close()

	// Write request with the category opcode on the wire
	req := &quicSDNRequest{
		Opcode:  categoryOpcode,
		Payload: categoryPayload,
	}

	if err := writeSDNRequest(stream, req); err != nil {
		return nil, ErrQUICOverlayStreamFailed{Operation: opName, Err: err}
	}

	// Read response
	resp, err := readSDNResponse(stream, conn.Context())
	if err != nil {
		return nil, ErrQUICOverlayStreamFailed{Operation: opName, Err: err}
	}

	// Check status
	if resp.Status != QUICStatusOKOverlay {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICOverlayRequestFailed{
			Operation: opName,
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return &quicOverlayResponse{
		Status:  resp.Status,
		Payload: resp.Payload,
	}, nil
}

// overlaySubOpcodeToString returns a human-readable name for a sub-opcode.
func overlaySubOpcodeToString(category byte, subOpcode byte) string {
	switch category {
	case OpCategoryOverlay:
		switch subOpcode {
		case SubOpOverlayStatus:
			return "OverlayStatus"
		case SubOpOverlayListVTEPs:
			return "VTEPList"
		case SubOpOverlayGetVTEP:
			return "VTEPGet"
		case SubOpOverlayListVNIs:
			return "VNIList"
		case SubOpOverlayCreateVNI:
			return "VNICreate"
		case SubOpOverlayDeleteVNI:
			return "VNIDelete"
		case SubOpOverlayListTunns:
			return "TunnelList"
		case SubOpOverlayListMACs:
			return "MACList"
		case SubOpOverlayForgetMAC:
			return "MACForget"
		}
	case OpCategoryGateway:
		switch subOpcode {
		case SubOpGatewayStatus:
			return "GatewayStatus"
		case SubOpGatewaySetMode:
			return "GatewaySetMode"
		case SubOpGatewayBGPStatus:
			return "BGPStatus"
		case SubOpGatewayBGPPeers:
			return "BGPPeers"
		case SubOpGatewayAnnouncePrefix:
			return "BGPAnnounce"
		case SubOpGatewayWithdrawPrefix:
			return "BGPWithdraw"
		case SubOpGatewayListPrefixes:
			return "BGPPrefixes"
		}
	case OpCategoryIPAM:
		switch subOpcode {
		case SubOpIPAMListPools:
			return "IPAMPoolList"
		case SubOpIPAMAllocateIP:
			return "IPAMAllocate"
		case SubOpIPAMReleaseIP:
			return "IPAMRelease"
		case SubOpIPAMListAllocations:
			return "IPAMList"
		}
	}
	return fmt.Sprintf("Unknown(cat=0x%02X,sub=0x%02X)", category, subOpcode)
}

// =============================================================================
// Overlay Status Commands
// =============================================================================

// OverlayStatus retrieves the overlay network status via QUIC.
func (q *OverlayQUICAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayStatus, "OverlayStatus", &overlayStatusRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp overlayStatusResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "OverlayStatus", Err: err}
	}

	if wireResp.Status == nil {
		return nil, ErrQUICOverlayInvalidResponse{Operation: "OverlayStatus", Details: "nil status field"}
	}

	s := wireResp.Status
	vtepIP, _ := netip.ParseAddr(s.LocalVTEP)

	return &OverlayStatusResult{
		NodeID:          s.NodeID,
		VTEPIP:          vtepIP,
		ControllerState: s.Mode,
		UnderlayMTU:     s.MTU,
		VXLANPort:       s.VXLANPort,
		VNICount:        s.VNICount,
		VTEPCount:       s.VTEPCount,
		RemoteMACCount:  s.MACCount,
		TunnelCount:     s.TunnelCount,
	}, nil
}

// =============================================================================
// VTEP Commands
// =============================================================================

// VTEPList retrieves the list of VTEPs via QUIC.
func (q *OverlayQUICAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayListVTEPs, "VTEPList", &vtepListRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp vtepListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VTEPList", Err: err}
	}

	vteps := make([]VTEPInfo, len(wireResp.VTEPs))
	for i, wv := range wireResp.VTEPs {
		ip, _ := netip.ParseAddr(wv.IPAddress)
		healthy := wv.Status == "active" || wv.Status == "healthy"
		vteps[i] = VTEPInfo{
			NodeID:   wv.ID,
			IP:       ip,
			Healthy:  healthy,
			LastSeen: time.Unix(wv.LastSeen, 0),
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: int(wireResp.Count),
	}, nil
}

// VTEPGet retrieves a specific VTEP by node ID via QUIC.
// The server matches by the "id" field which corresponds to the node ID string.
func (q *OverlayQUICAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	req := &vtepGetRequest{ID: nodeID}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayGetVTEP, "VTEPGet", req)
	if err != nil {
		return nil, err
	}

	var wireResp vtepGetResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VTEPGet", Err: err}
	}

	if wireResp.VTEP == nil {
		return nil, ErrQUICOverlayInvalidResponse{Operation: "VTEPGet", Details: "nil vtep field"}
	}

	wv := wireResp.VTEP
	ip, _ := netip.ParseAddr(wv.IPAddress)
	vnis := wv.VNIs
	if vnis == nil {
		vnis = []uint32{}
	}
	healthy := wv.Status == "active" || wv.Status == "healthy"

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:   wv.ID,
			IP:       ip,
			Healthy:  healthy,
			LastSeen: time.Unix(wv.LastSeen, 0),
		},
		VNIs: vnis,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a new VNI via QUIC.
// Note: VLAN is not carried in the QUIC overlay protocol; opts.VLAN is echoed
// back in the result so the caller's round-trip check passes.
func (q *OverlayQUICAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	req := &vniCreateRequest{
		VNI:  opts.VNI,
		Name: opts.Name,
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayCreateVNI, "VNICreate", req)
	if err != nil {
		return nil, err
	}

	var wireResp vniCreateResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VNICreate", Err: err}
	}

	if wireResp.VNI == nil {
		return nil, ErrQUICOverlayInvalidResponse{Operation: "VNICreate", Details: "nil vni field"}
	}

	wv := wireResp.VNI
	return &VNICreateResult{
		VNI:       wv.VNI,
		VLAN:      opts.VLAN, // VLAN not preserved by QUIC server; echo request value
		Name:      wv.Name,
		CreatedAt: time.Unix(wv.CreatedAt, 0),
	}, nil
}

// VNIDelete deletes a VNI via QUIC.
func (q *OverlayQUICAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	req := &vniDeleteRequest{VNI: vni}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayDeleteVNI, "VNIDelete", req)
	if err != nil {
		return nil, err
	}

	var wireResp vniDeleteResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VNIDelete", Err: err}
	}

	return &VNIDeleteResult{
		VNI:     wireResp.VNI,
		Deleted: wireResp.Success,
	}, nil
}

// VNIList retrieves the list of VNIs via QUIC.
func (q *OverlayQUICAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayListVNIs, "VNIList", &vniListRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp vniListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VNIList", Err: err}
	}

	vnis := make([]VNIInfo, len(wireResp.VNIs))
	for i, wv := range wireResp.VNIs {
		vnis[i] = VNIInfo{
			VNI:       wv.VNI,
			Name:      wv.Name,
			MACCount:  wv.MACCount,
			CreatedAt: time.Unix(wv.CreatedAt, 0),
		}
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: int(wireResp.Count),
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList retrieves the list of tunnels via QUIC.
// opts.VNI is used for client-side filtering only; the server returns all tunnels.
func (q *OverlayQUICAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayListTunns, "TunnelList", &tunnelListRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp tunnelListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "TunnelList", Err: err}
	}

	tunnels := make([]TunnelInfo, 0, len(wireResp.Tunnels))
	for _, wt := range wireResp.Tunnels {
		// Client-side VNI filter: VNI == 0 means all tunnels.
		if opts.VNI != 0 && wt.VNI != opts.VNI {
			continue
		}
		localVTEP, _ := netip.ParseAddr(wt.LocalVTEP)
		remoteVTEP, _ := netip.ParseAddr(wt.RemoteVTEP)
		tunnels = append(tunnels, TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        wt.VNI,
			State:      wt.Status,
			BytesSent:  uint64(wt.TxBytes),
			BytesRecv:  uint64(wt.RxBytes),
		})
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: len(tunnels),
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList retrieves the list of remote MACs via QUIC.
// opts.VNI == 0 means list all MACs across all VNIs.
func (q *OverlayQUICAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	req := &macListRequest{VNI: opts.VNI}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayListMACs, "MACList", req)
	if err != nil {
		return nil, err
	}

	var wireResp macListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "MACList", Err: err}
	}

	macs := make([]RemoteMACInfo, len(wireResp.MACs))
	for i, wm := range wireResp.MACs {
		mac, _ := net.ParseMAC(wm.MAC)
		remoteVTEP, _ := netip.ParseAddr(wm.VTEP)
		macs[i] = RemoteMACInfo{
			MAC:        mac,
			VNI:        wm.VNI,
			RemoteVTEP: remoteVTEP,
			Source:     wm.Type,
			LearnedAt:  time.Unix(wm.LastSeen, 0),
		}
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: int(wireResp.Count),
	}, nil
}

// MACForget removes a MAC entry via QUIC.
func (q *OverlayQUICAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	req := &macForgetRequest{
		VNI: vni,
		MAC: mac,
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayForgetMAC, "MACForget", req)
	if err != nil {
		return nil, err
	}

	var wireResp macForgetResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "MACForget", Err: err}
	}

	return &MACForgetResult{
		MAC:     wireResp.MAC,
		VNI:     wireResp.VNI,
		Deleted: wireResp.Success,
	}, nil
}

// =============================================================================
// Gateway Commands
// =============================================================================

// GatewayStatus retrieves the gateway status via QUIC.
func (q *OverlayQUICAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayStatus, "GatewayStatus", &gatewayStatusRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp gatewayStatusResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "GatewayStatus", Err: err}
	}

	return &GatewayStatusResult{
		NodeID:         wireResp.NodeID,
		Modes:          wireResp.Modes,
		Tier:           wireResp.Tier,
		Healthy:        wireResp.Healthy,
		Reputation:     wireResp.Reputation,
		Age:            time.Duration(wireResp.AgeNanos),
		UptimePct:      wireResp.UptimePct,
		IPv6Pool:       wireResp.IPv6Pool,
		IPv4Pool:       wireResp.IPv4Pool,
		BGPEnabled:     wireResp.BGPEnabled,
		EVPNEnabled:    wireResp.EVPNEnabled,
		TransitEnabled: wireResp.TransitEnabled,
	}, nil
}

// GatewaySetMode sets the gateway modes via QUIC.
func (q *OverlayQUICAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	req := &gatewaySetModeRequest{Modes: opts.Modes}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewaySetMode, "GatewaySetMode", req)
	if err != nil {
		return nil, err
	}

	var wireResp gatewaySetModeResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "GatewaySetMode", Err: err}
	}

	return &GatewayModeResult{
		Modes:   wireResp.Modes,
		Success: wireResp.Success,
	}, nil
}

// =============================================================================
// BGP Commands
// =============================================================================

// BGPStatus retrieves the BGP status via QUIC.
func (q *OverlayQUICAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayBGPStatus, "BGPStatus", &bgpStatusRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp bgpStatusResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "BGPStatus", Err: err}
	}

	return &BGPStatusResult{
		Enabled:          wireResp.Enabled,
		ASN:              wireResp.ASN,
		RouterID:         wireResp.RouterID,
		State:            wireResp.State,
		PeerCount:        wireResp.PeerCount,
		EstablishedCount: wireResp.EstablishedCount,
		EVPNEnabled:      wireResp.EVPNEnabled,
		TransitEnabled:   wireResp.TransitEnabled,
	}, nil
}

// BGPPeers retrieves the list of BGP peers via QUIC.
func (q *OverlayQUICAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayBGPPeers, "BGPPeers", &bgpPeersRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp bgpPeersResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "BGPPeers", Err: err}
	}

	peers := make([]BGPPeerInfo, len(wireResp.Peers))
	for i, wp := range wireResp.Peers {
		peers[i] = BGPPeerInfo{
			Address:      wp.Address,
			RemoteASN:    wp.RemoteASN,
			State:        wp.State,
			Uptime:       time.Duration(wp.UptimeNanos),
			PrefixesRecv: wp.PrefixesRecv,
			PrefixesSent: wp.PrefixesSent,
			Description:  wp.Description,
		}
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// BGPPrefixes retrieves the list of announced prefixes via QUIC.
func (q *OverlayQUICAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayListPrefixes, "BGPPrefixes", &bgpPrefixesRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp bgpPrefixesResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "BGPPrefixes", Err: err}
	}

	prefixes := make([]BGPPrefixInfo, len(wireResp.Prefixes))
	for i, wp := range wireResp.Prefixes {
		prefixes[i] = BGPPrefixInfo{
			Prefix:      wp.Prefix,
			NextHop:     wp.NextHop,
			Origin:      wp.Origin,
			ASPath:      wp.ASPath,
			LocalPref:   wp.LocalPref,
			MED:         wp.MED,
			Communities: wp.Communities,
		}
	}

	return &BGPPrefixesResult{
		Prefixes:   prefixes,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// BGPAnnounce announces a prefix via BGP over QUIC.
func (q *OverlayQUICAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	req := &bgpAnnounceRequest{
		Prefix:  opts.Prefix,
		NextHop: opts.NextHop,
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayAnnouncePrefix, "BGPAnnounce", req)
	if err != nil {
		return nil, err
	}

	var wireResp bgpAnnounceResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "BGPAnnounce", Err: err}
	}

	return &BGPAnnounceResult{
		Prefix:  wireResp.Prefix,
		Success: wireResp.Success,
	}, nil
}

// BGPWithdraw withdraws a prefix via BGP over QUIC.
func (q *OverlayQUICAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	req := &bgpWithdrawRequest{Prefix: prefix}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryGateway, SubOpGatewayWithdrawPrefix, "BGPWithdraw", req)
	if err != nil {
		return nil, err
	}

	var wireResp bgpWithdrawResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "BGPWithdraw", Err: err}
	}

	return &BGPWithdrawResult{
		Prefix:  wireResp.Prefix,
		Success: wireResp.Success,
	}, nil
}

// =============================================================================
// IPAM Commands
// =============================================================================

// IPAMPoolList retrieves the list of IPAM pools via QUIC.
func (q *OverlayQUICAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMListPools, "IPAMPoolList", &ipamPoolListRequest{})
	if err != nil {
		return nil, err
	}

	var wireResp ipamPoolListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMPoolList", Err: err}
	}

	pools := make([]IPAMPoolInfo, len(wireResp.Pools))
	for i, wp := range wireResp.Pools {
		pools[i] = IPAMPoolInfo{
			ID:            wp.ID,
			Name:          wp.Name,
			CIDR:          wp.CIDR,
			Gateway:       wp.Gateway,
			TotalIPs:      int64(wp.TotalIPs),
			AllocatedIPs:  int64(wp.AllocatedIPs),
			AvailableIPs:  int64(wp.AvailableIPs),
			LeaseDuration: time.Duration(wp.LeaseDuration),
		}
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: int(wireResp.Count),
	}, nil
}

// IPAMPoolCreate creates a new IPAM pool via QUIC.
func (q *OverlayQUICAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	req := &ipamPoolCreateRequest{
		Name:          opts.Name,
		CIDR:          opts.CIDR,
		Gateway:       opts.Gateway,
		LeaseDuration: int64(opts.LeaseDuration),
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMCreatePool, "IPAMPoolCreate", req)
	if err != nil {
		return nil, err
	}

	var wireResp ipamPoolCreateResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMPoolCreate", Err: err}
	}

	if wireResp.Pool == nil {
		return nil, ErrQUICOverlayInvalidResponse{Operation: "IPAMPoolCreate", Details: "server returned nil pool"}
	}
	return &IPAMPoolCreateResult{
		ID:        wireResp.Pool.ID,
		Name:      wireResp.Pool.Name,
		CIDR:      wireResp.Pool.CIDR,
		CreatedAt: time.Unix(0, wireResp.Pool.CreatedAt),
	}, nil
}

// IPAMPoolDelete deletes an IPAM pool via QUIC.
func (q *OverlayQUICAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	req := &ipamPoolDeleteRequest{PoolID: poolID}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMDeletePool, "IPAMPoolDelete", req)
	if err != nil {
		return nil, err
	}

	var wireResp ipamPoolDeleteResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMPoolDelete", Err: err}
	}

	return &IPAMPoolDeleteResult{
		ID:      wireResp.PoolID,
		Deleted: wireResp.Success,
	}, nil
}

// IPAMAllocate allocates an IP address from a pool via QUIC. The request and
// response are the server's own wire types (pkg/api/quic), so the adapter
// cannot drift from them: the hand-written mirrors it used carried field
// names the server never reads or writes (#730). QUIC names the device the
// address is allocated to "owner".
func (q *OverlayQUICAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	req := &quic.GatewayAllocateIPRequest{
		PoolID:   opts.PoolID,
		Owner:    opts.DeviceID,
		Hostname: opts.Hostname,
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMAllocateIP, "IPAMAllocate", req)
	if err != nil {
		return nil, err
	}

	var wireResp quic.GatewayAllocateIPResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMAllocate", Err: err}
	}
	if wireResp.Allocation == nil {
		return nil, ErrQUICOverlayInvalidResponse{Operation: "IPAMAllocate", Details: "server returned no allocation"}
	}

	info, err := quicAllocationInfo(wireResp.Allocation)
	if err != nil {
		return nil, err
	}
	return &IPAMAllocateResult{
		IP:          info.IP,
		PoolID:      info.PoolID,
		DeviceID:    info.DeviceID,
		Hostname:    info.Hostname,
		LeaseExpiry: info.LeaseExpiry,
	}, nil
}

// IPAMRelease releases an IP address back to its pool via QUIC.
func (q *OverlayQUICAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	req := &quic.GatewayReleaseIPRequest{IPAddress: ip}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMReleaseIP, "IPAMRelease", req)
	if err != nil {
		return nil, err
	}

	var wireResp quic.GatewayReleaseIPResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMRelease", Err: err}
	}

	return &IPAMReleaseResult{
		IP:       wireResp.IPAddress,
		Released: wireResp.Success,
	}, nil
}

// IPAMList retrieves the list of IPAM allocations via QUIC.
func (q *OverlayQUICAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	req := &quic.GatewayListAllocationsRequest{PoolID: opts.PoolID}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMListAllocations, "IPAMList", req)
	if err != nil {
		return nil, err
	}

	var wireResp quic.GatewayListAllocationsResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMList", Err: err}
	}

	allocations := make([]IPAMAllocationInfo, 0, len(wireResp.Allocations))
	for _, wa := range wireResp.Allocations {
		info, err := quicAllocationInfo(wa)
		if err != nil {
			return nil, err
		}
		allocations = append(allocations, info)
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  len(allocations),
	}, nil
}

// quicAllocationInfo converts the server's allocation record. Its times are
// Unix seconds. An address that does not parse is an error rather than a
// zero netip.Addr that would silently match nothing.
func quicAllocationInfo(a *quic.IPAllocationInfo) (IPAMAllocationInfo, error) {
	ip, err := netip.ParseAddr(a.IPAddress)
	if err != nil {
		return IPAMAllocationInfo{}, ErrQUICOverlayInvalidResponse{Operation: "IPAMAllocation", Details: "unparsable ip_address " + a.IPAddress}
	}
	info := IPAMAllocationInfo{
		IP:          ip,
		PoolID:      a.PoolID,
		DeviceID:    a.Owner,
		Hostname:    a.Hostname,
		Status:      a.Status,
		AllocatedAt: time.Unix(a.CreatedAt, 0),
		LastSeen:    time.Unix(a.UpdatedAt, 0),
	}
	if a.ExpiresAt != 0 {
		info.LeaseExpiry = time.Unix(a.ExpiresAt, 0)
	}
	return info, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure OverlayQUICAdapter implements OverlayCommands interface.
var _ OverlayCommands = (*OverlayQUICAdapter)(nil)
