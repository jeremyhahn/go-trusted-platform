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

// This file implements multi-tenant operations for the QUIC protocol transport
// layer. QUIC provides low-latency, multiplexed streams with built-in TLS 1.3,
// making it ideal for mobile and high-performance clients.
//
// # Wire contract
//
// The canonical QUIC wire contract for the Tenant surface is the platform.v1
// protobuf request/response messages themselves: the SDK QUIC transport adapter
// encodes the generated pb request struct directly and decodes daemon replies
// directly into the generated pb response struct. The payload codec keys on the
// exact Go field names of the message, so decoding the payload into the same
// platform.v1 message types on the daemon side — and delegating to the shared
// *TenantGRPCServer — guarantees SDK<->daemon shape parity by construction and
// gives the QUIC transport identical semantics to gRPC.
//
// Before this convergence the daemon decoded flat local structs whose Go field
// names diverged from the pb Go field names (TenantID vs TenantId, uint16
// VLANStart/VLANEnd vs uint32 VlanRangeStart/VlanRangeEnd, *ComputeQuotaDTO with
// MaxVMs/MaxVCPUs vs pb MaxVms/MaxVcpus), silently dropping every diverging
// field on the wire. Those flat structs are gone; every handler now delegates
// to the pb gRPC server.
//
// # Supported Operations
//
// Tenant Management:
//   - OpTenantList: List all tenants with pagination
//   - OpTenantGet: Get tenant by ID
//   - OpTenantGetByName: Get tenant by name
//   - OpTenantCreate: Create a new tenant
//   - OpTenantUpdate: Update tenant metadata
//   - OpTenantDelete: Delete a tenant
//   - OpTenantSuspend: Suspend tenant (blocks traffic)
//   - OpTenantResume: Resume suspended tenant
//
// Quota Management:
//   - OpTenantGetQuotas: Get tenant quotas
//   - OpTenantUpdateQuotas: Update tenant quotas
//   - OpTenantGetUsage: Get tenant resource usage
//   - OpTenantCheckQuota: Check quota availability
//
// Network/VLAN Operations:
//   - OpTenantValidateVLAN: Validate VLAN for tenant
//   - OpTenantGetBridge: Get OVS bridge name for tenant
//
// Synchronization:
//   - OpTenantSync: Synchronize tenant state with external systems
//
// DEK Operations:
//   - OpTenantRotateDEK: Rotate tenant DEK
//   - OpTenantGetDEKStatus: Get tenant DEK status
//
// Per-Tenant Barrier Operations (sub-opcodes under OpTenantBarrierCategory):
//   - Init/Unseal/Seal/Status

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Tenant QUIC opcodes - aliased from quic.protocol for convenience
const (
	OpTenantList         = quic.OpTenantList         // 0xDB
	OpTenantGet          = quic.OpTenantGet          // 0xDC
	OpTenantGetByName    = quic.OpTenantGetByName    // 0xDD
	OpTenantCreate       = quic.OpTenantCreate       // 0xDE
	OpTenantUpdate       = quic.OpTenantUpdate       // 0xDF
	OpTenantDelete       = quic.OpTenantDelete       // 0xE0
	OpTenantSuspend      = quic.OpTenantSuspend      // 0xE1
	OpTenantResume       = quic.OpTenantResume       // 0xE2
	OpTenantGetQuotas    = quic.OpTenantGetQuotas    // 0xE3
	OpTenantUpdateQuotas = quic.OpTenantUpdateQuotas // 0xE4
	OpTenantGetUsage     = quic.OpTenantGetUsage     // 0xE5
	OpTenantCheckQuota   = quic.OpTenantCheckQuota   // 0xE6
	OpTenantValidateVLAN = quic.OpTenantValidateVLAN // 0xE7
	OpTenantGetBridge    = quic.OpTenantGetBridge    // 0xE8
	OpTenantSync         = quic.OpTenantSync         // 0xE9
	OpTenantRotateDEK    = quic.OpTenantRotateDEK    // 0xEA
	OpTenantGetDEKStatus = quic.OpTenantGetDEKStatus // 0xEB
)

// =============================================================================
// Service Interface
// =============================================================================

// TenantManagerInterface defines the interface for tenant management operations.
// It abstracts the underlying tenant manager implementation. The QUIC handlers
// no longer dispatch through this interface — they delegate to the shared
// *TenantGRPCServer — but the interface is retained for the health/readiness
// surface and the WithQUICTenantManager wiring seam.
type TenantManagerInterface interface {
	// Tenant CRUD operations
	CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error)
	GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error)
	ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error)
	UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error)
	DeleteTenant(ctx context.Context, id string) error

	// Lifecycle operations
	SuspendTenant(ctx context.Context, id string) error
	ResumeTenant(ctx context.Context, id string) error

	// Quota operations
	GetQuotas(ctx context.Context, tenantID string) (*tenant.TenantQuotas, error)
	UpdateQuotas(ctx context.Context, tenantID string, quotas *tenant.TenantQuotas) error
	GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error)
	CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error

	// Network operations
	ValidateVLAN(ctx context.Context, tenantID string, vlanID uint16) error
	GetBridgeName(ctx context.Context, tenantID string) (string, error)

	// Synchronization
	Sync(ctx context.Context) error

	// DEK operations
	RotateDEK(ctx context.Context, tenantID string, background bool) (*tenant.DEKRotationResult, error)
	GetDEKStatus(ctx context.Context, tenantID string) (*tenant.DEKStatus, error)

	// Per-tenant barrier operations
	InitTenantBarrier(ctx context.Context, tenantID string) error
	UnsealTenantBarrier(ctx context.Context, tenantID string, key []byte) error
	SealTenantBarrier(ctx context.Context, tenantID string) error
	TenantBarrierStatus(ctx context.Context, tenantID string) (*tenant.TenantBarrierState, error)
}

// =============================================================================
// Service Handler Wiring
// =============================================================================

// WithQUICTenantManager sets the tenant manager for the QUIC handler. Retained
// for the health/readiness surface; request dispatch delegates to the shared
// *TenantGRPCServer wired via SetTenantGRPCServer.
func WithQUICTenantManager(mgr TenantManagerInterface) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.tenantManager = mgr
	}
}

// SetTenantManager sets the tenant manager after construction.
func (h *QUICServiceHandler) SetTenantManager(mgr TenantManagerInterface) {
	h.tenantManager = mgr
}

// =============================================================================
// Handler Implementation
// =============================================================================

// handleTenantOperation routes tenant opcodes to their pb-delegating handlers.
// Readiness is gated on the shared *TenantGRPCServer delegate rather than the
// retained tenant manager interface.
func (h *QUICServiceHandler) handleTenantOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.tenantGRPC == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "tenant"})
	}

	switch req.Opcode {
	case OpTenantList:
		return h.handleTenantList(ctx, req)
	case OpTenantGet:
		return h.handleTenantGet(ctx, req)
	case OpTenantGetByName:
		return h.handleTenantGetByName(ctx, req)
	case OpTenantCreate:
		return h.handleTenantCreate(ctx, req)
	case OpTenantUpdate:
		return h.handleTenantUpdate(ctx, req)
	case OpTenantDelete:
		return h.handleTenantDelete(ctx, req)
	case OpTenantSuspend:
		return h.handleTenantSuspend(ctx, req)
	case OpTenantResume:
		return h.handleTenantResume(ctx, req)
	case OpTenantGetQuotas:
		return h.handleTenantGetQuotas(ctx, req)
	case OpTenantUpdateQuotas:
		return h.handleTenantUpdateQuotas(ctx, req)
	case OpTenantGetUsage:
		return h.handleTenantGetUsage(ctx, req)
	case OpTenantCheckQuota:
		return h.handleTenantCheckQuota(ctx, req)
	case OpTenantValidateVLAN:
		return h.handleTenantValidateVLAN(ctx, req)
	case OpTenantGetBridge:
		return h.handleTenantGetBridge(ctx, req)
	case OpTenantSync:
		return h.handleTenantSync(ctx, req)
	case OpTenantRotateDEK:
		return h.handleTenantRotateDEK(ctx, req)
	case OpTenantGetDEKStatus:
		return h.handleTenantGetDEKStatus(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleTenantList lists tenants. The list request payload is optional.
func (h *QUICServiceHandler) handleTenantList(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.ListTenantsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.tenantGRPC.ListTenants(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantList", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGet gets a tenant by ID.
func (h *QUICServiceHandler) handleTenantGet(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGet", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGetByName gets a tenant by name.
func (h *QUICServiceHandler) handleTenantGetByName(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetTenantByNameRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetTenantByName(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGetByName", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantCreate creates a tenant. The pb request carries the uint32 VLAN
// range and the nested ComputeQuota/NetworkQuota/StorageQuota that the former
// flat decode silently dropped.
func (h *QUICServiceHandler) handleTenantCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.CreateTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.CreateTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantCreate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantUpdate updates tenant metadata.
func (h *QUICServiceHandler) handleTenantUpdate(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.UpdateTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.UpdateTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantUpdate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantDelete deletes a tenant and all its resources.
func (h *QUICServiceHandler) handleTenantDelete(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.DeleteTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.DeleteTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantDelete", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantSuspend suspends a tenant (blocks traffic).
func (h *QUICServiceHandler) handleTenantSuspend(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.SuspendTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.SuspendTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantSuspend", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantResume resumes a suspended tenant.
func (h *QUICServiceHandler) handleTenantResume(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.ResumeTenantRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.ResumeTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantResume", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGetQuotas returns tenant quotas.
func (h *QUICServiceHandler) handleTenantGetQuotas(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetQuotasRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetQuotas(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGetQuotas", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantUpdateQuotas updates tenant quotas.
func (h *QUICServiceHandler) handleTenantUpdateQuotas(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.UpdateQuotasRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.UpdateQuotas(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantUpdateQuotas", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGetUsage returns tenant resource usage.
func (h *QUICServiceHandler) handleTenantGetUsage(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetUsageRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetUsage(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGetUsage", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantCheckQuota checks whether a resource request can be fulfilled.
// The delegate returns Available=false in-band (not an error) when the quota
// is exhausted, matching the gRPC transport semantics.
func (h *QUICServiceHandler) handleTenantCheckQuota(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.CheckQuotaRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.CheckQuota(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantCheckQuota", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantValidateVLAN checks whether a tenant can use a specific VLAN.
func (h *QUICServiceHandler) handleTenantValidateVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.ValidateVLANRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.ValidateVLAN(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantValidateVLAN", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGetBridge returns the OVS bridge name for a tenant.
func (h *QUICServiceHandler) handleTenantGetBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetBridgeNameRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetBridgeName(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGetBridge", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantSync synchronizes tenant manager state with external systems.
// The sync request payload is optional.
func (h *QUICServiceHandler) handleTenantSync(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.SyncTenantsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.tenantGRPC.Sync(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantSync", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantRotateDEK rotates the DEK for a tenant.
func (h *QUICServiceHandler) handleTenantRotateDEK(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.RotateTenantDEKRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.RotateTenantDEK(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantRotateDEK", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantGetDEKStatus returns the DEK status for a tenant.
func (h *QUICServiceHandler) handleTenantGetDEKStatus(ctx context.Context, req *quic.Request) *quic.Response {
	var pbReq platformv1.GetTenantDEKStatusRequest
	if err := quic.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetTenantDEKStatus(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantGetDEKStatus", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// =============================================================================
// Per-Tenant Barrier Handlers
// =============================================================================

// handleTenantBarrierCategory handles the tenant barrier category opcode
// (OpTenantBarrierCategory, 0x9E). The first byte of the payload is the
// sub-opcode that selects the barrier operation; the remaining bytes carry the
// codec-encoded platform.v1 sub-request.
func (h *QUICServiceHandler) handleTenantBarrierCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.tenantGRPC == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "tenant"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	switch subOpcode {
	case quic.TenantBarrierSubInit:
		return h.handleTenantBarrierInit(ctx, subPayload)
	case quic.TenantBarrierSubUnseal:
		return h.handleTenantBarrierUnseal(ctx, subPayload)
	case quic.TenantBarrierSubSeal:
		return h.handleTenantBarrierSeal(ctx, subPayload)
	case quic.TenantBarrierSubStatus:
		return h.handleTenantBarrierStatus(ctx, subPayload)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: subOpcode})
	}
}

// handleTenantBarrierInit handles the explicit barrier init sub-operation.
func (h *QUICServiceHandler) handleTenantBarrierInit(ctx context.Context, payload []byte) *quic.Response {
	var pbReq platformv1.InitTenantBarrierRequest
	if err := quic.DecodePayload(payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.InitTenantBarrier(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantBarrierInit", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantBarrierUnseal handles the barrier unseal sub-operation.
func (h *QUICServiceHandler) handleTenantBarrierUnseal(ctx context.Context, payload []byte) *quic.Response {
	var pbReq platformv1.UnsealTenantBarrierRequest
	if err := quic.DecodePayload(payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.UnsealTenantBarrier(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantBarrierUnseal", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantBarrierSeal handles the barrier seal sub-operation.
func (h *QUICServiceHandler) handleTenantBarrierSeal(ctx context.Context, payload []byte) *quic.Response {
	var pbReq platformv1.SealTenantBarrierRequest
	if err := quic.DecodePayload(payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.SealTenantBarrier(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantBarrierSeal", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleTenantBarrierStatus handles the barrier status sub-operation.
func (h *QUICServiceHandler) handleTenantBarrierStatus(ctx context.Context, payload []byte) *quic.Response {
	var pbReq platformv1.GetTenantBarrierStatusRequest
	if err := quic.DecodePayload(payload, &pbReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.tenantGRPC.GetTenantBarrierStatus(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("TenantBarrierStatus", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}
