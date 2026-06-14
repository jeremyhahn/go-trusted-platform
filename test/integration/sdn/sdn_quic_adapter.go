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

// Package sdn provides multi-protocol integration test adapters for SDN services.
// This file implements the SDNTestAdapter interface using the platform binary
// QUIC protocol (NOT HTTP/3 — the QUIC server uses custom opcodes + MessagePack).

package sdn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

// =============================================================================
// QUIC Protocol Constants
// These MUST match the server-side definitions in pkg/api/quic/protocol.go and
// pkg/api/quic/gateway_handlers.go.
// =============================================================================

const (
	// OpGatewayCategory is the top-level category opcode that routes to the
	// GatewayHandler. The first byte of the payload is the sub-opcode.
	opGatewayCategory byte = 0x2F

	// OpIPAMCategory is the top-level category opcode for IPAM operations.
	// The first byte of the payload is the sub-opcode.
	opIPAMCategory byte = 0x3F

	// Gateway zone sub-opcodes (payload byte 0 when opcode == opGatewayCategory)
	opGatewayListNetworkZones  byte = 0x10
	opGatewayCreateNetworkZone byte = 0x11
	opGatewayUpdateNetworkZone byte = 0x12
	opGatewayDeleteNetworkZone byte = 0x13
	opGatewayAssignNetworkZone byte = 0x14

	// IPAM pool sub-opcodes (payload byte 0 when opcode == opIPAMCategory)
	opGatewayListIPAMPools  byte = 0x08
	opGatewayCreateIPAMPool byte = 0x0C
	opGatewayDeleteIPAMPool byte = 0x0D
	opGatewayGetIPAMPool    byte = 0x0E
	opGatewayUpdateIPAMPool byte = 0x0F

	// Status codes from pkg/api/quic/protocol.go
	quicStatusOK            byte = 0x00
	quicStatusNotFound      byte = 0x02
	quicStatusAlreadyExists byte = 0x06
	quicStatusInvalidArg    byte = 0x09
	quicStatusUnavailable   byte = 0x0A

	// Wire limits
	maxQUICPayload uint32 = 16 * 1024 * 1024
	maxQUICToken   uint16 = 8 * 1024

	// Timeouts
	quicDialTimeout    = 30 * time.Second
	quicIdleTimeout    = 60 * time.Second
	quicKeepAlive      = 15 * time.Second
	quicRequestTimeout = 30 * time.Second
)

// =============================================================================
// Wire types — MessagePack (`codec` tags must match server-side types exactly)
// =============================================================================

type quicGatewayListZonesReq struct {
	LifecycleRole string `codec:"lifecycle_role,omitempty"`
}

type quicGatewayListZonesResp struct {
	Zones     []*quicZoneInfo `codec:"zones"`
	Timestamp int64           `codec:"timestamp"`
}

type quicZoneInfo struct {
	Name             string   `codec:"name"`
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
	RestartRequired  bool     `codec:"restart_required,omitempty"`
	CreatedAt        int64    `codec:"created_at"`
	UpdatedAt        int64    `codec:"updated_at"`
}

type quicGatewayCreateZoneReq struct {
	Opts *quicCreateZoneOpts `codec:"opts"`
}

type quicCreateZoneOpts struct {
	Name             string   `codec:"name"`
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
}

type quicGatewayCreateZoneResp struct {
	Zone *quicZoneInfo `codec:"zone"`
}

type quicGatewayUpdateZoneReq struct {
	Name string              `codec:"name"`
	Opts *quicUpdateZoneOpts `codec:"opts"`
}

type quicUpdateZoneOpts struct {
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
}

type quicGatewayUpdateZoneResp struct {
	Zone *quicZoneInfo `codec:"zone"`
}

type quicGatewayDeleteZoneReq struct {
	Name string `codec:"name"`
}

type quicGatewayDeleteZoneResp struct {
	RestartRequired bool  `codec:"restart_required"`
	Timestamp       int64 `codec:"timestamp"`
}

type quicGatewayAssignZoneReq struct {
	Network string `codec:"network"`
	Zone    string `codec:"zone"`
}

type quicGatewayAssignZoneResp struct {
	RestartRequired bool  `codec:"restart_required"`
	Timestamp       int64 `codec:"timestamp"`
}

// IPAM pool types

type quicIPAMListPoolsReq struct {
	Zone string `codec:"zone,omitempty"`
}

type quicIPAMListPoolsResp struct {
	Pools     []*quicIPAMPool `codec:"pools"`
	Timestamp int64           `codec:"timestamp"`
}

type quicIPAMPool struct {
	ID            string   `codec:"id"`
	Name          string   `codec:"name"`
	CIDR          string   `codec:"cidr"`
	Gateway       string   `codec:"gateway,omitempty"`
	Zone          string   `codec:"zone,omitempty"`
	Description   string   `codec:"description,omitempty"`
	DNS           []string `codec:"dns,omitempty"`
	TotalIPs      int      `codec:"total_ips"`
	AllocatedIPs  int      `codec:"allocated_ips"`
	AvailableIPs  int      `codec:"available_ips"`
	LeaseDuration int64    `codec:"lease_duration_nanos,omitempty"`
}

// quicIPAMCreatePoolReq matches GatewayCreateIPAMPoolRequest (flat — no opts wrapper).
type quicIPAMCreatePoolReq struct {
	ID            string   `codec:"id,omitempty"`
	Name          string   `codec:"name"`
	CIDR          string   `codec:"cidr"`
	Gateway       string   `codec:"gateway,omitempty"`
	Zone          string   `codec:"zone,omitempty"`
	Description   string   `codec:"description,omitempty"`
	DNS           []string `codec:"dns,omitempty"`
	LeaseDuration int64    `codec:"lease_duration_nanos,omitempty"`
}

type quicIPAMCreatePoolResp struct {
	Pool *quicIPAMPool `codec:"pool"`
}

type quicIPAMDeletePoolReq struct {
	PoolID string `codec:"pool_id"`
}

type quicIPAMDeletePoolResp struct {
	Deleted bool `codec:"deleted"`
}

type quicIPAMGetPoolReq struct {
	PoolID string `codec:"pool_id"`
}

type quicIPAMGetPoolResp struct {
	Pool *quicIPAMPool `codec:"pool"`
}

// quicIPAMUpdatePoolReq matches GatewayUpdateIPAMPoolRequest (flat — no opts wrapper).
type quicIPAMUpdatePoolReq struct {
	PoolID        string `codec:"pool_id"`
	Name          string `codec:"name,omitempty"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
}

type quicIPAMUpdatePoolResp struct {
	Pool *quicIPAMPool `codec:"pool"`
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// SDNQUICAdapter implements SDNTestAdapter using the platform binary QUIC
// protocol. Requests are sent as [opcode 1B | token_len 2B | token | payload_len 4B | payload]
// and responses are [status 1B | payload_len 4B | payload], with all
// structured payloads encoded as MessagePack.
type SDNQUICAdapter struct {
	endpoint  string
	conn      *quicgo.Conn
	tlsConfig *tls.Config
	mu        sync.RWMutex
	closed    bool
}

// NewSDNQUICAdapter creates a new binary-protocol QUIC adapter for SDN tests.
func NewSDNQUICAdapter() *SDNQUICAdapter {
	return &SDNQUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *SDNQUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection using the binary platform-quic protocol.
//
// When QLOGDIR is set in the environment, qlog tracing is enabled for this
// connection. quic-go's qlog.DefaultConnectionTracer reads QLOGDIR directly
// and writes one <odcid>_client.sqlog file per connection.
func (q *SDNQUICAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()

	q.mu.Lock()
	q.endpoint = endpoints.PlatformQUIC
	q.tlsConfig = helpers.QUICTLSConfig([]string{"platform-quic"})
	q.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, quicDialTimeout)
	defer cancel()

	conn, err := quicgo.DialAddr(dialCtx, q.endpoint, q.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  quicIdleTimeout,
		KeepAlivePeriod: quicKeepAlive,
		// qlog tracing: writes per-connection .sqlog files when QLOGDIR is set.
		// qlog.DefaultConnectionTracer is a no-op when QLOGDIR is unset.
		Tracer: qlog.DefaultConnectionTracer,
	})
	if err != nil {
		return ErrQUICSDNConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.mu.Lock()
	q.conn = conn
	q.mu.Unlock()

	// Verify zone service availability. Use a short deadline distinct from the
	// dial context so a slow server doesn't block the full dial timeout.
	verifyCtx, verifyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer verifyCancel()

	// sendCategoryRequest acquires q.mu.RLock; must NOT hold q.mu here.
	_, err = q.listZonesRaw(verifyCtx, "")
	if err != nil {
		q.mu.Lock()
		if q.conn != nil {
			_ = q.conn.CloseWithError(0, "setup verify failed")
			q.conn = nil
		}
		q.mu.Unlock()
		return ErrQUICSDNNotImplemented{Method: "ListNetworkZones", Cause: err}
	}

	return nil
}

// Teardown closes the QUIC connection.
func (q *SDNQUICAdapter) Teardown() error {
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
// Binary protocol helpers
// =============================================================================

// sendCategoryRequest sends a category-opcode request where the first byte of
// the payload is the sub-opcode and the rest is the msgpack-encoded body.
func (q *SDNQUICAdapter) sendCategoryRequest(ctx context.Context, categoryOpcode, subOpcode byte, body interface{}) ([]byte, error) {
	q.mu.RLock()
	conn := q.conn
	closed := q.closed
	q.mu.RUnlock()

	if closed || conn == nil {
		return nil, ErrQUICSDNNotImplemented{Method: "sendCategoryRequest"}
	}

	// Encode structured body (may be nil for no-payload requests)
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = quicEncode(body)
		if err != nil {
			return nil, fmt.Errorf("QUIC encode: %w", err)
		}
	}

	// Build payload: [sub_opcode(1)] + [msgpack body]
	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = subOpcode
	copy(payload[1:], bodyBytes)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("QUIC open stream: %w", err)
	}
	defer stream.Close()

	if err := quicWriteRequest(stream, categoryOpcode, payload); err != nil {
		return nil, fmt.Errorf("QUIC write request: %w", err)
	}

	// Pass conn.Context() so quicReadResponse can include connection-level
	// cancellation state in any error message it produces.
	status, respPayload, err := quicReadResponse(stream, conn.Context())
	if err != nil {
		return nil, fmt.Errorf("QUIC read response: %w", err)
	}

	if status != quicStatusOK {
		msg := string(respPayload)
		if msg == "" {
			msg = fmt.Sprintf("status 0x%02x", status)
		}
		switch status {
		case quicStatusUnavailable:
			return nil, ErrQUICSDNNotImplemented{Method: fmt.Sprintf("sub-op 0x%02x: %s", subOpcode, msg)}
		case quicStatusNotFound:
			return nil, fmt.Errorf("not found: %s", msg)
		case quicStatusAlreadyExists:
			return nil, fmt.Errorf("already exists: %s", msg)
		case quicStatusInvalidArg:
			return nil, fmt.Errorf("invalid argument: %s", msg)
		default:
			return nil, fmt.Errorf("QUIC error (0x%02x): %s", status, msg)
		}
	}

	return respPayload, nil
}

// quicWriteRequest writes the binary request frame to a QUIC stream.
// Frame format: [opcode 1B | token_len 2B | token nB | payload_len 4B | payload nB]
func quicWriteRequest(w interface{ Write([]byte) (int, error) }, opcode byte, payload []byte) error {
	payloadLen := uint32(len(payload))
	if payloadLen > maxQUICPayload {
		return fmt.Errorf("payload %d exceeds max %d", payloadLen, maxQUICPayload)
	}

	buf := make([]byte, 0, 1+2+4+len(payload))
	buf = append(buf, opcode)
	buf = append(buf, 0, 0) // token_len = 0 (no auth token in integration tests)
	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, payloadLen)
	buf = append(buf, b4...)
	buf = append(buf, payload...)

	_, err := w.Write(buf)
	return err
}

// quicReadResponse reads the binary response frame from a QUIC stream.
// Frame format: [status 1B | payload_len 4B | payload nB]
//
// connCtx is the parent QUIC connection context. When an unexpected EOF occurs
// mid-payload, connCtx.Err() is included in the error to distinguish a
// server-initiated stream reset from an OS-level EOF — both surface as
// io.ErrUnexpectedEOF from readFull but the connection-level cause differs.
func quicReadResponse(r interface {
	Read([]byte) (int, error)
}, connCtx context.Context) (status byte, payload []byte, err error) {
	connCtxStr := ctxErrSDN(connCtx)

	// Read status byte
	statusBuf := make([]byte, 1)
	if _, err = readFull(r, statusBuf); err != nil {
		return 0, nil, fmt.Errorf("read status: %w (conn_ctx=%s)", err, connCtxStr)
	}
	status = statusBuf[0]

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err = readFull(r, lenBuf); err != nil {
		return status, nil, fmt.Errorf("read payload len: %w (conn_ctx=%s)", err, connCtxStr)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)
	if payloadLen > maxQUICPayload {
		return status, nil, fmt.Errorf("payload len %d exceeds max", payloadLen)
	}

	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		n, rerr := readFull(r, payload)
		if rerr != nil {
			return status, nil, fmt.Errorf(
				"read payload: %w (expected=%d read=%d conn_ctx=%s)",
				rerr, payloadLen, n, connCtxStr,
			)
		}
	}
	return status, payload, nil
}

// readFull reads exactly len(buf) bytes from r. A reader may legally return
// the final bytes together with io.EOF (e.g. a QUIC FIN coalesced with the
// last STREAM frame); like io.ReadFull, a completely filled buffer is success
// regardless of the accompanying error.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

// quicEncode MessagePack-encodes entity using the codec factory.
func quicEncode(entity interface{}) ([]byte, error) {
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return nil, err
	}
	return c.Marshal(entity)
}

// quicDecode MessagePack-decodes data into entity.
func quicDecode(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return err
	}
	return c.Unmarshal(data, &entity)
}

// =============================================================================
// Overlay Operations (not supported via QUIC zone adapter — return unavailable)
// =============================================================================

// ListVTEPs returns all discovered VTEPs. QUIC zone adapter does not support overlay.
func (q *SDNQUICAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "ListVTEPs"}
}

// CreateVNI creates a new VNI. Not supported via QUIC zone adapter.
func (q *SDNQUICAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	return ErrQUICSDNNotImplemented{Method: "CreateVNI"}
}

// DeleteVNI removes a VNI. Not supported via QUIC zone adapter.
func (q *SDNQUICAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	return ErrQUICSDNNotImplemented{Method: "DeleteVNI"}
}

// ListTunnels returns active tunnels. Not supported via QUIC zone adapter.
func (q *SDNQUICAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "ListTunnels"}
}

// ListRemoteMACs returns learned remote MACs. Not supported via QUIC zone adapter.
func (q *SDNQUICAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "ListRemoteMACs"}
}

// =============================================================================
// Gateway Status / Mode Operations (not supported via zone-only adapter)
// =============================================================================

// GetGatewayStatus returns gateway status. Not available without full gateway service.
func (q *SDNQUICAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "GetGatewayStatus"}
}

// SetGatewayMode sets the gateway mode. Not available without full gateway service.
func (q *SDNQUICAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	return ErrQUICSDNNotImplemented{Method: "SetGatewayMode"}
}

// =============================================================================
// BGP Operations (not supported via zone-only adapter)
// =============================================================================

func (q *SDNQUICAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "GetBGPStatus"}
}

func (q *SDNQUICAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "ListBGPPeers"}
}

func (q *SDNQUICAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	return ErrQUICSDNNotImplemented{Method: "AnnouncePrefix"}
}

func (q *SDNQUICAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	return ErrQUICSDNNotImplemented{Method: "WithdrawPrefix"}
}

// =============================================================================
// IPAM Pool Operations (via opIPAMCategory + IPAM sub-opcodes)
// =============================================================================

// CreatePool creates a new IPAM pool via the binary QUIC protocol.
func (q *SDNQUICAdapter) CreatePool(ctx context.Context, req IPAMPoolCreateRequest) (*IPAMPoolEntry, error) {
	body := &quicIPAMCreatePoolReq{
		ID:            req.ID,
		Name:          req.Name,
		CIDR:          req.CIDR,
		Gateway:       req.Gateway,
		Zone:          req.Zone,
		Description:   req.Description,
		LeaseDuration: req.LeaseDuration.Nanoseconds(),
	}
	raw, err := q.sendCategoryRequest(ctx, opIPAMCategory, opGatewayCreateIPAMPool, body)
	if err != nil {
		return nil, err
	}
	var resp quicIPAMCreatePoolResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode CreatePool: %w", err)
	}
	if resp.Pool == nil {
		return nil, fmt.Errorf("QUIC CreatePool: empty response")
	}
	return quicIPAMPoolToEntry(resp.Pool), nil
}

// GetPool retrieves an IPAM pool by ID.
func (q *SDNQUICAdapter) GetPool(ctx context.Context, poolID string) (*IPAMPoolEntry, error) {
	body := &quicIPAMGetPoolReq{PoolID: poolID}
	raw, err := q.sendCategoryRequest(ctx, opIPAMCategory, opGatewayGetIPAMPool, body)
	if err != nil {
		return nil, err
	}
	var resp quicIPAMGetPoolResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode GetPool: %w", err)
	}
	if resp.Pool == nil {
		return nil, fmt.Errorf("QUIC GetPool: empty response")
	}
	return quicIPAMPoolToEntry(resp.Pool), nil
}

// UpdatePool updates mutable fields of an IPAM pool.
func (q *SDNQUICAdapter) UpdatePool(ctx context.Context, poolID string, req IPAMPoolUpdateRequest) (*IPAMPoolEntry, error) {
	body := &quicIPAMUpdatePoolReq{
		PoolID:        poolID,
		Name:          req.Name,
		Gateway:       req.Gateway,
		Zone:          req.Zone,
		Description:   req.Description,
		LeaseDuration: req.LeaseDuration.Nanoseconds(),
	}
	raw, err := q.sendCategoryRequest(ctx, opIPAMCategory, opGatewayUpdateIPAMPool, body)
	if err != nil {
		return nil, err
	}
	var resp quicIPAMUpdatePoolResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode UpdatePool: %w", err)
	}
	if resp.Pool == nil {
		return nil, fmt.Errorf("QUIC UpdatePool: empty response")
	}
	return quicIPAMPoolToEntry(resp.Pool), nil
}

// DeletePool removes an IPAM pool by ID.
func (q *SDNQUICAdapter) DeletePool(ctx context.Context, poolID string) error {
	body := &quicIPAMDeletePoolReq{PoolID: poolID}
	_, err := q.sendCategoryRequest(ctx, opIPAMCategory, opGatewayDeleteIPAMPool, body)
	return err
}

// ListPools returns all IPAM pools, optionally filtered by zone.
func (q *SDNQUICAdapter) ListPools(ctx context.Context, zoneFilter string) (*IPAMPoolListResponse, error) {
	body := &quicIPAMListPoolsReq{Zone: zoneFilter}
	raw, err := q.sendCategoryRequest(ctx, opIPAMCategory, opGatewayListIPAMPools, body)
	if err != nil {
		return nil, err
	}
	var resp quicIPAMListPoolsResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode ListPools: %w", err)
	}
	pools := make([]IPAMPoolEntry, 0, len(resp.Pools))
	for _, p := range resp.Pools {
		if p != nil {
			pools = append(pools, *quicIPAMPoolToEntry(p))
		}
	}
	return &IPAMPoolListResponse{Pools: pools, TotalCount: len(pools)}, nil
}

// AllocateIP is not exercised by the IPAM suite — returns not-implemented.
func (q *SDNQUICAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "AllocateIP"}
}

// ReleaseIP is not exercised by the IPAM suite — returns not-implemented.
func (q *SDNQUICAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	return ErrQUICSDNNotImplemented{Method: "ReleaseIP"}
}

// =============================================================================
// DHCP Operations (not supported via zone-only QUIC adapter)
// =============================================================================

func (q *SDNQUICAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "GetDHCPStatus"}
}

func (q *SDNQUICAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	return nil, ErrQUICSDNNotImplemented{Method: "ListLeases"}
}

// =============================================================================
// Network Zone Operations (via opGatewayCategory + zone sub-opcodes)
// =============================================================================

// listZonesRaw is the internal helper used in Setup to verify connectivity.
func (q *SDNQUICAdapter) listZonesRaw(ctx context.Context, lifecycleRole string) ([]*quicZoneInfo, error) {
	body := &quicGatewayListZonesReq{LifecycleRole: lifecycleRole}
	raw, err := q.sendCategoryRequest(ctx, opGatewayCategory, opGatewayListNetworkZones, body)
	if err != nil {
		return nil, err
	}
	var resp quicGatewayListZonesResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode ListZones: %w", err)
	}
	return resp.Zones, nil
}

// ListZones returns all network trust zones via the binary QUIC protocol.
func (q *SDNQUICAdapter) ListZones(ctx context.Context, lifecycleRole string) (*ZoneListResponse, error) {
	zones, err := q.listZonesRaw(ctx, lifecycleRole)
	if err != nil {
		return nil, err
	}
	out := make([]ZoneEntry, 0, len(zones))
	for _, z := range zones {
		if z != nil {
			out = append(out, quicZoneInfoToEntry(z))
		}
	}
	return &ZoneListResponse{Zones: out, TotalCount: len(out)}, nil
}

// CreateZone creates a new network trust zone via the binary QUIC protocol.
func (q *SDNQUICAdapter) CreateZone(ctx context.Context, req ZoneCreateRequest) (*ZoneEntry, error) {
	body := &quicGatewayCreateZoneReq{
		Opts: &quicCreateZoneOpts{
			Name:             req.Name,
			InternetIngress:  req.InternetIngress,
			Isolate:          req.Isolate,
			IsolatePerTenant: req.IsolatePerTenant,
			OOB:              req.OOB,
			LifecycleRole:    req.LifecycleRole,
		},
	}
	raw, err := q.sendCategoryRequest(ctx, opGatewayCategory, opGatewayCreateNetworkZone, body)
	if err != nil {
		return nil, err
	}
	var resp quicGatewayCreateZoneResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode CreateZone: %w", err)
	}
	if resp.Zone == nil {
		return nil, fmt.Errorf("QUIC CreateZone: empty response")
	}
	entry := quicZoneInfoToEntry(resp.Zone)
	return &entry, nil
}

// UpdateZone updates an existing network trust zone.
func (q *SDNQUICAdapter) UpdateZone(ctx context.Context, name string, req ZoneUpdateRequest) (*ZoneEntry, error) {
	body := &quicGatewayUpdateZoneReq{
		Name: name,
		Opts: &quicUpdateZoneOpts{
			InternetIngress:  req.InternetIngress,
			Isolate:          req.Isolate,
			IsolatePerTenant: req.IsolatePerTenant,
			OOB:              req.OOB,
			LifecycleRole:    req.LifecycleRole,
		},
	}
	raw, err := q.sendCategoryRequest(ctx, opGatewayCategory, opGatewayUpdateNetworkZone, body)
	if err != nil {
		return nil, err
	}
	var resp quicGatewayUpdateZoneResp
	if err := quicDecode(raw, &resp); err != nil {
		return nil, fmt.Errorf("QUIC decode UpdateZone: %w", err)
	}
	if resp.Zone == nil {
		return nil, fmt.Errorf("QUIC UpdateZone: empty response")
	}
	entry := quicZoneInfoToEntry(resp.Zone)
	return &entry, nil
}

// DeleteZone deletes a network trust zone by name.
func (q *SDNQUICAdapter) DeleteZone(ctx context.Context, name string) (bool, error) {
	body := &quicGatewayDeleteZoneReq{Name: name}
	raw, err := q.sendCategoryRequest(ctx, opGatewayCategory, opGatewayDeleteNetworkZone, body)
	if err != nil {
		return false, err
	}
	var resp quicGatewayDeleteZoneResp
	if err := quicDecode(raw, &resp); err != nil {
		return false, fmt.Errorf("QUIC decode DeleteZone: %w", err)
	}
	return resp.RestartRequired, nil
}

// AssignZone assigns a network segment to a trust zone.
func (q *SDNQUICAdapter) AssignZone(ctx context.Context, network string, zoneName string) (bool, error) {
	body := &quicGatewayAssignZoneReq{Network: network, Zone: zoneName}
	raw, err := q.sendCategoryRequest(ctx, opGatewayCategory, opGatewayAssignNetworkZone, body)
	if err != nil {
		return false, err
	}
	var resp quicGatewayAssignZoneResp
	if err := quicDecode(raw, &resp); err != nil {
		return false, fmt.Errorf("QUIC decode AssignZone: %w", err)
	}
	return resp.RestartRequired, nil
}

// =============================================================================
// Conversion helpers
// =============================================================================

func quicZoneInfoToEntry(z *quicZoneInfo) ZoneEntry {
	return ZoneEntry{
		Name:             z.Name,
		InternetIngress:  z.InternetIngress,
		Isolate:          z.Isolate,
		IsolatePerTenant: z.IsolatePerTenant,
		OOB:              z.OOB,
		LifecycleRole:    z.LifecycleRole,
		RestartRequired:  z.RestartRequired,
		CreatedAt:        time.Unix(z.CreatedAt, 0),
		UpdatedAt:        time.Unix(z.UpdatedAt, 0),
	}
}

func quicIPAMPoolToEntry(p *quicIPAMPool) *IPAMPoolEntry {
	return &IPAMPoolEntry{
		ID:            p.ID,
		Name:          p.Name,
		CIDR:          p.CIDR,
		Gateway:       p.Gateway,
		Zone:          p.Zone,
		Description:   p.Description,
		TotalIPs:      int64(p.TotalIPs),
		AllocatedIPs:  int64(p.AllocatedIPs),
		AvailableIPs:  int64(p.AvailableIPs),
		DNS:           p.DNS,
		LeaseDuration: time.Duration(p.LeaseDuration),
	}
}

// =============================================================================
// Unused overlay conversion stubs (satisfy compiler for unused imports)
// =============================================================================

var _ = net.ParseMAC
var _ = netip.ParseAddr

// Ensure SDNQUICAdapter implements SDNTestAdapter.
var _ SDNTestAdapter = (*SDNQUICAdapter)(nil)
