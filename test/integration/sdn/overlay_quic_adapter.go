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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
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

// overlayStatusResponse represents an overlay status response.
type overlayStatusResponse struct {
	NodeID          string `codec:"node_id"`
	VTEPIP          string `codec:"vtep_ip"`
	ControllerState string `codec:"controller_state"`
	UnderlayMTU     int    `codec:"underlay_mtu"`
	VXLANPort       uint16 `codec:"vxlan_port"`
	VNICount        int    `codec:"vni_count"`
	VTEPCount       int    `codec:"vtep_count"`
	RemoteMACCount  int    `codec:"remote_mac_count"`
	TunnelCount     int    `codec:"tunnel_count"`
	UptimeNanos     int64  `codec:"uptime_nanos"`
}

// vtepListRequest represents a VTEP list request.
type vtepListRequest struct{}

// vtepListResponse represents a VTEP list response.
type vtepListResponse struct {
	VTEPs      []vtepInfoWire `codec:"vteps"`
	TotalCount int            `codec:"total_count"`
}

// vtepInfoWire represents VTEP information in wire format.
type vtepInfoWire struct {
	NodeID     string `codec:"node_id"`
	IP         string `codec:"ip"`
	Healthy    bool   `codec:"healthy"`
	LastSeen   int64  `codec:"last_seen"`
	IsLocal    bool   `codec:"is_local"`
	TunnelPort int    `codec:"tunnel_port"`
}

// vtepGetRequest represents a VTEP get request.
type vtepGetRequest struct {
	NodeID string `codec:"node_id"`
}

// vtepGetResponse represents a VTEP get response.
type vtepGetResponse struct {
	NodeID     string   `codec:"node_id"`
	IP         string   `codec:"ip"`
	Healthy    bool     `codec:"healthy"`
	LastSeen   int64    `codec:"last_seen"`
	IsLocal    bool     `codec:"is_local"`
	TunnelPort int      `codec:"tunnel_port"`
	VNIs       []uint32 `codec:"vnis"`
	MACCount   int      `codec:"mac_count"`
	BytesSent  uint64   `codec:"bytes_sent"`
	BytesRecv  uint64   `codec:"bytes_recv"`
}

// vniCreateRequest represents a VNI create request.
type vniCreateRequest struct {
	VNI  uint32 `codec:"vni"`
	VLAN uint16 `codec:"vlan"`
	Name string `codec:"name"`
}

// vniCreateResponse represents a VNI create response.
type vniCreateResponse struct {
	VNI       uint32 `codec:"vni"`
	VLAN      uint16 `codec:"vlan"`
	Name      string `codec:"name"`
	CreatedAt int64  `codec:"created_at"`
}

// vniDeleteRequest represents a VNI delete request.
type vniDeleteRequest struct {
	VNI uint32 `codec:"vni"`
}

// vniDeleteResponse represents a VNI delete response.
type vniDeleteResponse struct {
	VNI     uint32 `codec:"vni"`
	Deleted bool   `codec:"deleted"`
}

// vniListRequest represents a VNI list request.
type vniListRequest struct{}

// vniListResponse represents a VNI list response.
type vniListResponse struct {
	VNIs       []vniInfoWire `codec:"vnis"`
	TotalCount int           `codec:"total_count"`
}

// vniInfoWire represents VNI information in wire format.
type vniInfoWire struct {
	VNI        uint32 `codec:"vni"`
	VLAN       uint16 `codec:"vlan"`
	Name       string `codec:"name"`
	MACCount   int    `codec:"mac_count"`
	TunnelPort string `codec:"tunnel_port"`
	CreatedAt  int64  `codec:"created_at"`
}

// tunnelListRequest represents a tunnel list request.
type tunnelListRequest struct {
	VNI uint32 `codec:"vni"`
}

// tunnelListResponse represents a tunnel list response.
type tunnelListResponse struct {
	Tunnels    []tunnelInfoWire `codec:"tunnels"`
	TotalCount int              `codec:"total_count"`
}

// tunnelInfoWire represents tunnel information in wire format.
type tunnelInfoWire struct {
	LocalVTEP  string `codec:"local_vtep"`
	RemoteVTEP string `codec:"remote_vtep"`
	VNI        uint32 `codec:"vni"`
	Port       string `codec:"port"`
	State      string `codec:"state"`
	BytesSent  uint64 `codec:"bytes_sent"`
	BytesRecv  uint64 `codec:"bytes_recv"`
}

// macListRequest represents a MAC list request.
type macListRequest struct {
	VNI uint32 `codec:"vni"`
}

// macListResponse represents a MAC list response.
type macListResponse struct {
	MACs       []macInfoWire `codec:"macs"`
	TotalCount int           `codec:"total_count"`
}

// macInfoWire represents MAC information in wire format.
type macInfoWire struct {
	MAC        string `codec:"mac"`
	IP         string `codec:"ip"`
	VNI        uint32 `codec:"vni"`
	RemoteVTEP string `codec:"remote_vtep"`
	Source     string `codec:"source"`
	LearnedAt  int64  `codec:"learned_at"`
	ExpiresAt  int64  `codec:"expires_at"`
}

// macForgetRequest represents a MAC forget request.
type macForgetRequest struct {
	MAC string `codec:"mac"`
	VNI uint32 `codec:"vni"`
}

// macForgetResponse represents a MAC forget response.
type macForgetResponse struct {
	MAC     string `codec:"mac"`
	VNI     uint32 `codec:"vni"`
	Deleted bool   `codec:"deleted"`
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
type ipamPoolListResponse struct {
	Pools      []ipamPoolInfoWire `codec:"pools"`
	TotalCount int                `codec:"total_count"`
}

// ipamPoolInfoWire represents IPAM pool information in wire format.
type ipamPoolInfoWire struct {
	ID             string   `codec:"id"`
	Name           string   `codec:"name"`
	CIDR           string   `codec:"cidr"`
	Gateway        string   `codec:"gateway"`
	TotalIPs       int64    `codec:"total_ips"`
	AllocatedIPs   int64    `codec:"allocated_ips"`
	AvailableIPs   int64    `codec:"available_ips"`
	UtilizationPct float64  `codec:"utilization_pct"`
	DNS            []string `codec:"dns"`
	LeaseDuration  int64    `codec:"lease_duration_nanos"`
}

// ipamPoolCreateRequest represents an IPAM pool create request.
type ipamPoolCreateRequest struct {
	Name          string   `codec:"name"`
	CIDR          string   `codec:"cidr"`
	Gateway       string   `codec:"gateway"`
	DNS           []string `codec:"dns"`
	LeaseDuration int64    `codec:"lease_duration_nanos"`
}

// ipamPoolCreateResponse represents an IPAM pool create response.
type ipamPoolCreateResponse struct {
	ID        string `codec:"id"`
	Name      string `codec:"name"`
	CIDR      string `codec:"cidr"`
	CreatedAt int64  `codec:"created_at"`
}

// ipamPoolDeleteRequest represents an IPAM pool delete request.
type ipamPoolDeleteRequest struct {
	PoolID string `codec:"pool_id"`
}

// ipamPoolDeleteResponse represents an IPAM pool delete response.
type ipamPoolDeleteResponse struct {
	ID      string `codec:"id"`
	Deleted bool   `codec:"deleted"`
}

// ipamAllocateRequest represents an IPAM allocate request.
type ipamAllocateRequest struct {
	PoolID   string `codec:"pool_id"`
	DeviceID string `codec:"device_id"`
	Hostname string `codec:"hostname"`
}

// ipamAllocateResponse represents an IPAM allocate response.
type ipamAllocateResponse struct {
	IP          string `codec:"ip"`
	PoolID      string `codec:"pool_id"`
	DeviceID    string `codec:"device_id"`
	Hostname    string `codec:"hostname"`
	LeaseExpiry int64  `codec:"lease_expiry"`
}

// ipamReleaseRequest represents an IPAM release request.
type ipamReleaseRequest struct {
	IP string `codec:"ip"`
}

// ipamReleaseResponse represents an IPAM release response.
type ipamReleaseResponse struct {
	IP       string `codec:"ip"`
	Released bool   `codec:"released"`
}

// ipamListRequest represents an IPAM allocations list request.
type ipamListRequest struct {
	PoolID string `codec:"pool_id"`
}

// ipamListResponse represents an IPAM allocations list response.
type ipamListResponse struct {
	Allocations []ipamAllocationInfoWire `codec:"allocations"`
	TotalCount  int                      `codec:"total_count"`
}

// ipamAllocationInfoWire represents IPAM allocation information in wire format.
type ipamAllocationInfoWire struct {
	IP          string `codec:"ip"`
	PoolID      string `codec:"pool_id"`
	DeviceID    string `codec:"device_id"`
	Hostname    string `codec:"hostname"`
	Status      string `codec:"status"`
	AllocatedAt int64  `codec:"allocated_at"`
	LeaseExpiry int64  `codec:"lease_expiry"`
	LastSeen    int64  `codec:"last_seen"`
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
		tlsConfig:      helpers.QUICTLSConfig([]string{"platform-quic"}),
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
	resp, err := readSDNResponse(stream)
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

	vtepIP, _ := netip.ParseAddr(wireResp.VTEPIP)

	return &OverlayStatusResult{
		NodeID:          wireResp.NodeID,
		VTEPIP:          vtepIP,
		ControllerState: wireResp.ControllerState,
		UnderlayMTU:     wireResp.UnderlayMTU,
		VXLANPort:       wireResp.VXLANPort,
		VNICount:        wireResp.VNICount,
		VTEPCount:       wireResp.VTEPCount,
		RemoteMACCount:  wireResp.RemoteMACCount,
		TunnelCount:     wireResp.TunnelCount,
		Uptime:          time.Duration(wireResp.UptimeNanos),
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
		ip, _ := netip.ParseAddr(wv.IP)
		vteps[i] = VTEPInfo{
			NodeID:     wv.NodeID,
			IP:         ip,
			Healthy:    wv.Healthy,
			LastSeen:   time.Unix(0, wv.LastSeen),
			IsLocal:    wv.IsLocal,
			TunnelPort: wv.TunnelPort,
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// VTEPGet retrieves a specific VTEP by node ID via QUIC.
func (q *OverlayQUICAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	req := &vtepGetRequest{NodeID: nodeID}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayGetVTEP, "VTEPGet", req)
	if err != nil {
		return nil, err
	}

	var wireResp vtepGetResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "VTEPGet", Err: err}
	}

	ip, _ := netip.ParseAddr(wireResp.IP)

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:     wireResp.NodeID,
			IP:         ip,
			Healthy:    wireResp.Healthy,
			LastSeen:   time.Unix(0, wireResp.LastSeen),
			IsLocal:    wireResp.IsLocal,
			TunnelPort: wireResp.TunnelPort,
		},
		VNIs:      wireResp.VNIs,
		MACCount:  wireResp.MACCount,
		BytesSent: wireResp.BytesSent,
		BytesRecv: wireResp.BytesRecv,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a new VNI via QUIC.
func (q *OverlayQUICAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	req := &vniCreateRequest{
		VNI:  opts.VNI,
		VLAN: opts.VLAN,
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

	return &VNICreateResult{
		VNI:       wireResp.VNI,
		VLAN:      wireResp.VLAN,
		Name:      wireResp.Name,
		CreatedAt: time.Unix(0, wireResp.CreatedAt),
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
		Deleted: wireResp.Deleted,
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
			VNI:        wv.VNI,
			VLAN:       wv.VLAN,
			Name:       wv.Name,
			MACCount:   wv.MACCount,
			TunnelPort: wv.TunnelPort,
			CreatedAt:  time.Unix(0, wv.CreatedAt),
		}
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList retrieves the list of tunnels via QUIC.
func (q *OverlayQUICAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	req := &tunnelListRequest{VNI: opts.VNI}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryOverlay, SubOpOverlayListTunns, "TunnelList", req)
	if err != nil {
		return nil, err
	}

	var wireResp tunnelListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "TunnelList", Err: err}
	}

	tunnels := make([]TunnelInfo, len(wireResp.Tunnels))
	for i, wt := range wireResp.Tunnels {
		localVTEP, _ := netip.ParseAddr(wt.LocalVTEP)
		remoteVTEP, _ := netip.ParseAddr(wt.RemoteVTEP)
		tunnels[i] = TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        wt.VNI,
			Port:       wt.Port,
			State:      wt.State,
			BytesSent:  wt.BytesSent,
			BytesRecv:  wt.BytesRecv,
		}
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList retrieves the list of remote MACs via QUIC.
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
		ip, _ := netip.ParseAddr(wm.IP)
		remoteVTEP, _ := netip.ParseAddr(wm.RemoteVTEP)
		macs[i] = RemoteMACInfo{
			MAC:        mac,
			IP:         ip,
			VNI:        wm.VNI,
			RemoteVTEP: remoteVTEP,
			Source:     wm.Source,
			LearnedAt:  time.Unix(0, wm.LearnedAt),
			ExpiresAt:  time.Unix(0, wm.ExpiresAt),
		}
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// MACForget removes a MAC entry via QUIC.
func (q *OverlayQUICAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	req := &macForgetRequest{
		MAC: mac,
		VNI: vni,
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
		Deleted: wireResp.Deleted,
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
			ID:             wp.ID,
			Name:           wp.Name,
			CIDR:           wp.CIDR,
			Gateway:        wp.Gateway,
			TotalIPs:       wp.TotalIPs,
			AllocatedIPs:   wp.AllocatedIPs,
			AvailableIPs:   wp.AvailableIPs,
			UtilizationPct: wp.UtilizationPct,
			DNS:            wp.DNS,
			LeaseDuration:  time.Duration(wp.LeaseDuration),
		}
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: wireResp.TotalCount,
	}, nil
}

// IPAMPoolCreate creates a new IPAM pool via QUIC.
func (q *OverlayQUICAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	req := &ipamPoolCreateRequest{
		Name:          opts.Name,
		CIDR:          opts.CIDR,
		Gateway:       opts.Gateway,
		DNS:           opts.DNS,
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

	return &IPAMPoolCreateResult{
		ID:        wireResp.ID,
		Name:      wireResp.Name,
		CIDR:      wireResp.CIDR,
		CreatedAt: time.Unix(0, wireResp.CreatedAt),
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
		ID:      wireResp.ID,
		Deleted: wireResp.Deleted,
	}, nil
}

// IPAMAllocate allocates an IP address from a pool via QUIC.
func (q *OverlayQUICAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	req := &ipamAllocateRequest{
		PoolID:   opts.PoolID,
		DeviceID: opts.DeviceID,
		Hostname: opts.Hostname,
	}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMAllocateIP, "IPAMAllocate", req)
	if err != nil {
		return nil, err
	}

	var wireResp ipamAllocateResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMAllocate", Err: err}
	}

	ip, _ := netip.ParseAddr(wireResp.IP)

	return &IPAMAllocateResult{
		IP:          ip,
		PoolID:      wireResp.PoolID,
		DeviceID:    wireResp.DeviceID,
		Hostname:    wireResp.Hostname,
		LeaseExpiry: time.Unix(0, wireResp.LeaseExpiry),
	}, nil
}

// IPAMRelease releases an IP address back to the pool via QUIC.
func (q *OverlayQUICAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	req := &ipamReleaseRequest{IP: ip}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMReleaseIP, "IPAMRelease", req)
	if err != nil {
		return nil, err
	}

	var wireResp ipamReleaseResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMRelease", Err: err}
	}

	return &IPAMReleaseResult{
		IP:       wireResp.IP,
		Released: wireResp.Released,
	}, nil
}

// IPAMList retrieves the list of IPAM allocations via QUIC.
func (q *OverlayQUICAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	req := &ipamListRequest{PoolID: opts.PoolID}

	resp, err := q.sendCategoryRequest(ctx, OpCategoryIPAM, SubOpIPAMListAllocations, "IPAMList", req)
	if err != nil {
		return nil, err
	}

	var wireResp ipamListResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICOverlayDecodeFailed{Operation: "IPAMList", Err: err}
	}

	allocations := make([]IPAMAllocationInfo, len(wireResp.Allocations))
	for i, wa := range wireResp.Allocations {
		ip, _ := netip.ParseAddr(wa.IP)
		allocations[i] = IPAMAllocationInfo{
			IP:          ip,
			PoolID:      wa.PoolID,
			DeviceID:    wa.DeviceID,
			Hostname:    wa.Hostname,
			Status:      wa.Status,
			AllocatedAt: time.Unix(0, wa.AllocatedAt),
			LeaseExpiry: time.Unix(0, wa.LeaseExpiry),
			LastSeen:    time.Unix(0, wa.LastSeen),
		}
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  wireResp.TotalCount,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure OverlayQUICAdapter implements OverlayCommands interface.
var _ OverlayCommands = (*OverlayQUICAdapter)(nil)
