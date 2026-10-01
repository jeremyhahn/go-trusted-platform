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

// Package tenant provides multi-protocol integration test adapters for Tenant
// services. This file implements the TenantCommands interface using the
// platform binary QUIC protocol (NOT HTTP/3 — the QUIC server uses custom
// opcodes + MessagePack). The wire contract is the platform.v1 protobuf
// request/response messages themselves, exactly like the SDK QUIC transport:
// the adapter encodes the generated pb request struct and decodes the pb
// response struct, so the daemon's converged pb-delegating handlers see the
// real SDK wire shape.
package tenant

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// QUIC Protocol Constants (must match pkg/api/quic/protocol.go +
// pkg/api/quic/phase35_opcodes.go)
// =============================================================================

const (
	tqOpTenantList         byte = 0xDB
	tqOpTenantGet          byte = 0xDC
	tqOpTenantGetByName    byte = 0xDD
	tqOpTenantCreate       byte = 0xDE
	tqOpTenantUpdate       byte = 0xDF
	tqOpTenantDelete       byte = 0xE0
	tqOpTenantSuspend      byte = 0xE1
	tqOpTenantResume       byte = 0xE2
	tqOpTenantGetQuotas    byte = 0xE3
	tqOpTenantUpdateQuotas byte = 0xE4
	tqOpTenantGetUsage     byte = 0xE5
	tqOpTenantCheckQuota   byte = 0xE6
	tqOpTenantSync         byte = 0xE9
	tqOpTenantRotateDEK    byte = 0xEA
	tqOpTenantGetDEKStatus byte = 0xEB

	tqOpTenantBarrierCategory byte = 0x9E
	tqBarrierSubInit          byte = 0x01
	tqBarrierSubUnseal        byte = 0x02
	tqBarrierSubSeal          byte = 0x03
	tqBarrierSubStatus        byte = 0x04

	tqDialTimeout = 30 * time.Second
	tqIdleTimeout = 60 * time.Second
	tqKeepAlive   = 15 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error { return e.Err }

// ErrQUICRequestFailed indicates a QUIC request failure.
// ErrQUICStatus reports a non-OK status byte from the daemon, carrying the
// byte itself so a test can assert WHICH refusal it got rather than only that
// something failed. A broken adapter also errors -- ErrQUICRequestFailed is
// what it produces -- so only this type proves the daemon answered.
type ErrQUICStatus struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICStatus) Error() string {
	return fmt.Sprintf("QUIC %s refused with status 0x%02X: %s", e.Operation, e.Status, e.Message)
}

type ErrQUICRequestFailed struct {
	Operation string
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request failed [%s]: %s", e.Operation, e.Message)
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements TenantCommands using the platform binary QUIC
// protocol. Requests are framed as [opcode 1B | token_len 2B | token | payload_len 4B | payload]
// and responses as [status 1B | payload_len 4B | payload], with structured
// payloads encoded as MessagePack over the platform.v1 protobuf messages.
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config
	conn      *quicgo.Conn
	mu        sync.RWMutex
}

// NewQUICAdapter creates a new binary-protocol QUIC adapter for tenant tests.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig(),
	}
}

// Name returns the adapter name.
func (a *QUICAdapter) Name() string { return "QUIC" }

// Setup establishes the QUIC connection.
func (a *QUICAdapter) Setup(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, tqDialTimeout)
	defer cancel()

	conn, err := quicgo.DialAddr(dialCtx, a.endpoint, a.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  tqIdleTimeout,
		KeepAlivePeriod: tqKeepAlive,
	})
	if err != nil {
		return ErrQUICConnectionFailed{Endpoint: a.endpoint, Err: err}
	}

	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	return nil
}

// Teardown closes the QUIC connection.
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		err := a.conn.CloseWithError(0, "teardown")
		a.conn = nil
		return err
	}
	return nil
}

// =============================================================================
// Binary protocol helpers
// =============================================================================

// send encodes body (a platform.v1 request, or nil) and performs one binary
// request/response round trip for the given opcode.
func (a *QUICAdapter) send(ctx context.Context, op string, opcode byte, body interface{}) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = tqEncode(body)
		if err != nil {
			return nil, ErrQUICRequestFailed{Operation: op, Message: "encode: " + err.Error()}
		}
	}
	return a.roundTrip(ctx, op, opcode, payload)
}

// sendCategory performs a category-opcode round trip where payload[0] is the
// sub-opcode and the remainder is the msgpack-encoded body.
func (a *QUICAdapter) sendCategory(ctx context.Context, op string, categoryOpcode, subOpcode byte, body interface{}) ([]byte, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = tqEncode(body)
		if err != nil {
			return nil, ErrQUICRequestFailed{Operation: op, Message: "encode: " + err.Error()}
		}
	}
	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = subOpcode
	copy(payload[1:], bodyBytes)
	return a.roundTrip(ctx, op, categoryOpcode, payload)
}

// roundTrip opens a stream, writes the request frame, reads the response frame
// and translates non-OK status bytes into typed errors.
func (a *QUICAdapter) roundTrip(ctx context.Context, op string, opcode byte, payload []byte) ([]byte, error) {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()
	if conn == nil {
		return nil, ErrQUICRequestFailed{Operation: op, Message: "not connected"}
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICRequestFailed{Operation: op, Message: "open stream: " + err.Error()}
	}
	defer stream.Close()

	// token_len is zero: the daemon authenticates these connections by the
	// mTLS client certificate, not a bearer token.
	if err := quicapi.WriteRequest(stream, &quicapi.Request{Opcode: opcode, Payload: payload}); err != nil {
		return nil, ErrQUICRequestFailed{Operation: op, Message: "write: " + err.Error()}
	}

	resp, err := quicapi.ReadResponse(stream)
	if err != nil {
		return nil, ErrQUICRequestFailed{Operation: op, Message: "read: " + err.Error()}
	}

	if resp.Status != quicapi.StatusOK {
		msg := string(resp.Payload)
		if msg == "" {
			msg = quicapi.StatusToString(resp.Status)
		}
		return nil, ErrQUICStatus{Operation: op, Status: resp.Status, Message: msg}
	}
	return resp.Payload, nil
}

func tqEncode(entity interface{}) ([]byte, error) {
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return nil, err
	}
	return c.Marshal(entity)
}

func tqDecode(data []byte, entity interface{}) error {
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
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant.
func (a *QUICAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	req := &platformv1.CreateTenantRequest{
		Name:        opts.Name,
		DisplayName: opts.DisplayName,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}

	raw, err := a.send(ctx, "CreateTenant", tqOpTenantCreate, req)
	if err != nil {
		return nil, err
	}
	var resp platformv1.CreateTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "CreateTenant", Message: "decode: " + err.Error()}
	}
	return &CreateTenantResult{Tenant: pbTenantToData(resp.GetTenant())}, nil
}

// GetTenant retrieves a tenant by ID.
func (a *QUICAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	raw, err := a.send(ctx, "GetTenant", tqOpTenantGet, &platformv1.GetTenantRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.GetTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "GetTenant", Message: "decode: " + err.Error()}
	}
	return &GetTenantResult{Tenant: pbTenantToData(resp.GetTenant())}, nil
}

// GetTenantByName retrieves a tenant by name.
func (a *QUICAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	raw, err := a.send(ctx, "GetTenantByName", tqOpTenantGetByName, &platformv1.GetTenantByNameRequest{Name: opts.Name})
	if err != nil {
		return nil, err
	}
	var resp platformv1.GetTenantByNameResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "GetTenantByName", Message: "decode: " + err.Error()}
	}
	return &GetTenantByNameResult{Tenant: pbTenantToData(resp.GetTenant())}, nil
}

// UpdateTenant updates an existing tenant.
func (a *QUICAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	req := &platformv1.UpdateTenantRequest{
		TenantId:    opts.TenantID,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}
	if opts.DisplayName != nil {
		req.DisplayName = *opts.DisplayName
	}

	raw, err := a.send(ctx, "UpdateTenant", tqOpTenantUpdate, req)
	if err != nil {
		return nil, err
	}
	var resp platformv1.UpdateTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "UpdateTenant", Message: "decode: " + err.Error()}
	}
	return &UpdateTenantResult{Tenant: pbTenantToData(resp.GetTenant())}, nil
}

// DeleteTenant removes a tenant.
func (a *QUICAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	raw, err := a.send(ctx, "DeleteTenant", tqOpTenantDelete, &platformv1.DeleteTenantRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.DeleteTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "DeleteTenant", Message: "decode: " + err.Error()}
	}
	return &DeleteTenantResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// ListTenants lists all tenants with optional pagination.
func (a *QUICAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	raw, err := a.send(ctx, "ListTenants", tqOpTenantList, &platformv1.ListTenantsRequest{
		Limit:  int32(opts.Limit),
		Offset: int32(opts.Offset),
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.ListTenantsResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "ListTenants", Message: "decode: " + err.Error()}
	}
	tenants := make([]*TenantData, 0, len(resp.GetTenants()))
	for _, t := range resp.GetTenants() {
		tenants = append(tenants, pbTenantToData(t))
	}
	return &ListTenantsResult{Tenants: tenants, Total: int(resp.GetTotal())}, nil
}

// =============================================================================
// Tenant Lifecycle Operations
// =============================================================================

// SuspendTenant suspends a tenant.
func (a *QUICAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	raw, err := a.send(ctx, "SuspendTenant", tqOpTenantSuspend, &platformv1.SuspendTenantRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.SuspendTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "SuspendTenant", Message: "decode: " + err.Error()}
	}
	return &SuspendTenantResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// ResumeTenant resumes a suspended tenant.
func (a *QUICAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	raw, err := a.send(ctx, "ResumeTenant", tqOpTenantResume, &platformv1.ResumeTenantRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.ResumeTenantResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "ResumeTenant", Message: "decode: " + err.Error()}
	}
	return &ResumeTenantResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas.
func (a *QUICAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	raw, err := a.send(ctx, "GetQuotas", tqOpTenantGetQuotas, &platformv1.GetQuotasRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.GetQuotasResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "GetQuotas", Message: "decode: " + err.Error()}
	}
	return &GetQuotasResult{
		TenantID: resp.GetTenantId(),
		Compute:  pbComputeToData(resp.GetCompute()),
		Network:  pbNetworkToData(resp.GetNetwork()),
		Storage:  pbStorageToData(resp.GetStorage()),
	}, nil
}

// UpdateQuotas updates tenant quotas.
func (a *QUICAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	req := &platformv1.UpdateQuotasRequest{TenantId: opts.TenantID}
	if opts.Compute != nil {
		req.Compute = &platformv1.ComputeQuota{
			MaxVms:        opts.Compute.MaxVMs,
			MaxContainers: opts.Compute.MaxContainers,
			MaxVcpus:      opts.Compute.MaxVCPUs,
			MaxMemoryMb:   opts.Compute.MaxMemoryMB,
		}
	}
	if opts.Network != nil {
		req.Network = &platformv1.NetworkQuota{
			MaxBridges:       opts.Network.MaxBridges,
			MaxPorts:         opts.Network.MaxPorts,
			MaxBandwidthMbps: opts.Network.MaxBandwidthMbps,
		}
	}
	if opts.Storage != nil {
		req.Storage = &platformv1.StorageQuota{
			MaxVolumesGb: opts.Storage.MaxVolumesGB,
			MaxSnapshots: opts.Storage.MaxSnapshots,
		}
	}

	if _, err := a.send(ctx, "UpdateQuotas", tqOpTenantUpdateQuotas, req); err != nil {
		return nil, err
	}

	// The pb UpdateQuotasResponse carries only a Status; re-read the persisted
	// quotas so the result reflects server state, matching the other adapters.
	return a.quotasAsUpdateResult(ctx, opts.TenantID)
}

func (a *QUICAdapter) quotasAsUpdateResult(ctx context.Context, tenantID string) (*UpdateQuotasResult, error) {
	got, err := a.GetQuotas(ctx, GetQuotasOptions{TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	return &UpdateQuotasResult{
		TenantID: got.TenantID,
		Compute:  got.Compute,
		Network:  got.Network,
		Storage:  got.Storage,
	}, nil
}

// GetUsage retrieves tenant resource usage.
func (a *QUICAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	raw, err := a.send(ctx, "GetUsage", tqOpTenantGetUsage, &platformv1.GetUsageRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.GetUsageResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "GetUsage", Message: "decode: " + err.Error()}
	}
	u := resp.GetUsage()
	return &GetUsageResult{
		TenantID:      u.GetTenantId(),
		VMs:           u.GetVms(),
		Containers:    u.GetContainers(),
		VCPUs:         u.GetVcpus(),
		MemoryMB:      u.GetMemoryMb(),
		DiskGB:        u.GetDiskGb(),
		Bridges:       u.GetBridges(),
		Ports:         u.GetPorts(),
		BandwidthMbps: u.GetBandwidthMbps(),
		Volumes:       u.GetVolumes(),
		Snapshots:     u.GetSnapshots(),
	}, nil
}

// CheckQuota checks if a resource request can be fulfilled. The delegate reports
// availability in-band (StatusOK with Available=false), so exhaustion is not an
// error.
func (a *QUICAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	raw, err := a.send(ctx, "CheckQuota", tqOpTenantCheckQuota, &platformv1.CheckQuotaRequest{
		TenantId: opts.TenantID,
		Resource: opts.Resource,
		Amount:   opts.Amount,
	})
	if err != nil {
		return &CheckQuotaResult{
			TenantID: opts.TenantID,
			Resource: opts.Resource,
			Amount:   opts.Amount,
			Allowed:  false,
			Message:  err.Error(),
		}, nil
	}
	var resp platformv1.CheckQuotaResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "CheckQuota", Message: "decode: " + err.Error()}
	}
	return &CheckQuotaResult{
		TenantID: resp.GetTenantId(),
		Resource: resp.GetResource(),
		Amount:   resp.GetAmount(),
		Allowed:  resp.GetAvailable(),
		Message:  resp.GetMessage(),
	}, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state.
func (a *QUICAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	raw, err := a.send(ctx, "SyncTenants", tqOpTenantSync, &platformv1.SyncTenantsRequest{})
	if err != nil {
		return nil, err
	}
	var resp platformv1.SyncTenantsResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "SyncTenants", Message: "decode: " + err.Error()}
	}
	return &SyncTenantsResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier.
func (a *QUICAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	raw, err := a.sendCategory(ctx, "InitTenantBarrier", tqOpTenantBarrierCategory, tqBarrierSubInit,
		&platformv1.InitTenantBarrierRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.InitTenantBarrierResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "InitTenantBarrier", Message: "decode: " + err.Error()}
	}
	return &InitTenantBarrierResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier.
func (a *QUICAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	raw, err := a.sendCategory(ctx, "UnsealTenantBarrier", tqOpTenantBarrierCategory, tqBarrierSubUnseal,
		&platformv1.UnsealTenantBarrierRequest{TenantId: opts.TenantID, Key: opts.Key})
	if err != nil {
		return nil, err
	}
	var resp platformv1.UnsealTenantBarrierResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "UnsealTenantBarrier", Message: "decode: " + err.Error()}
	}
	return &UnsealTenantBarrierResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// SealTenantBarrier seals a per-tenant barrier.
func (a *QUICAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	raw, err := a.sendCategory(ctx, "SealTenantBarrier", tqOpTenantBarrierCategory, tqBarrierSubSeal,
		&platformv1.SealTenantBarrierRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.SealTenantBarrierResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "SealTenantBarrier", Message: "decode: " + err.Error()}
	}
	return &SealTenantBarrierResult{Success: resp.GetStatus().GetSuccess(), Message: resp.GetStatus().GetMessage()}, nil
}

// TenantBarrierStatus reports the current barrier state for a tenant.
func (a *QUICAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	raw, err := a.sendCategory(ctx, "TenantBarrierStatus", tqOpTenantBarrierCategory, tqBarrierSubStatus,
		&platformv1.GetTenantBarrierStatusRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, err
	}
	var resp platformv1.GetTenantBarrierStatusResponse
	if err := tqDecode(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "TenantBarrierStatus", Message: "decode: " + err.Error()}
	}
	st := resp.GetBarrierStatus()
	return &TenantBarrierStatusResult{
		TenantID:       st.GetTenantId(),
		Sealed:         st.GetSealed(),
		Initialized:    st.GetInitialized(),
		Strategy:       st.GetStrategy(),
		HardwareBacked: st.GetHardwareBacked(),
	}, nil
}

// =============================================================================
// Conversion helpers
// =============================================================================

func pbTenantToData(t *platformv1.Tenant) *TenantData {
	if t == nil {
		return nil
	}
	data := &TenantData{
		ID:           t.GetId(),
		Name:         t.GetName(),
		DisplayName:  t.GetDisplayName(),
		State:        pbTenantStateToState(t.GetState()),
		ComputeQuota: pbComputeToData(t.GetComputeQuota()),
		NetworkQuota: pbNetworkToData(t.GetNetworkQuota()),
		StorageQuota: pbStorageToData(t.GetStorageQuota()),
		Labels:       t.GetLabels(),
		Annotations:  t.GetAnnotations(),
	}
	if ts := t.GetCreatedAt(); ts != nil {
		data.CreatedAt = ts.AsTime()
	}
	if ts := t.GetUpdatedAt(); ts != nil {
		data.UpdatedAt = ts.AsTime()
	}
	return data
}

func pbComputeToData(c *platformv1.ComputeQuota) *ComputeQuotaData {
	if c == nil {
		return nil
	}
	return &ComputeQuotaData{
		MaxVMs:        c.GetMaxVms(),
		MaxContainers: c.GetMaxContainers(),
		MaxVCPUs:      c.GetMaxVcpus(),
		MaxMemoryMB:   c.GetMaxMemoryMb(),
	}
}

func pbNetworkToData(n *platformv1.NetworkQuota) *NetworkQuotaData {
	if n == nil {
		return nil
	}
	return &NetworkQuotaData{
		MaxBridges:       n.GetMaxBridges(),
		MaxPorts:         n.GetMaxPorts(),
		MaxBandwidthMbps: n.GetMaxBandwidthMbps(),
	}
}

func pbStorageToData(s *platformv1.StorageQuota) *StorageQuotaData {
	if s == nil {
		return nil
	}
	return &StorageQuotaData{
		MaxVolumesGB: s.GetMaxVolumesGb(),
		MaxSnapshots: s.GetMaxSnapshots(),
	}
}

func pbTenantStateToState(s platformv1.TenantState) tenant.State {
	switch s {
	case platformv1.TenantState_TENANT_STATE_PENDING:
		return tenant.StateCreated
	case platformv1.TenantState_TENANT_STATE_ACTIVE:
		return tenant.StateActive
	case platformv1.TenantState_TENANT_STATE_SUSPENDED:
		return tenant.StateSuspended
	case platformv1.TenantState_TENANT_STATE_DELETING:
		return tenant.StateDeleting
	case platformv1.TenantState_TENANT_STATE_DELETED:
		return tenant.StateDeleted
	default:
		return tenant.State("")
	}
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ TenantCommands = (*QUICAdapter)(nil)
