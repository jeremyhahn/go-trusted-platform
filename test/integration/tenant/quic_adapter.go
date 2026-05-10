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

// Package tenant provides integration test adapters for Tenant services.
// This file implements the TenantCommands interface using QUIC protocol.
package tenant

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICRequestFailed indicates a QUIC request failure
type ErrQUICRequestFailed struct {
	Operation string
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request failed [%s]: %s", e.Operation, e.Message)
}

// =============================================================================
// QUIC Protocol Types
// =============================================================================

// QUICRequest represents a QUIC protocol request
type QUICRequest struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Body   interface{} `json:"body,omitempty"`
}

// QUICResponse represents a QUIC protocol response
type QUICResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Error  string          `json:"error,omitempty"`
}

// =============================================================================
// QUIC Protocol Adapter
// =============================================================================

// QUICAdapter implements TenantCommands using QUIC protocol
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig([]string{"tenant-quic"}),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return ErrQUICConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// doRequest performs a QUIC request and returns the response
func (a *QUICAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to open stream: " + err.Error(),
		}
	}
	defer stream.Close()

	req := QUICRequest{
		Method: method,
		Path:   path,
		Body:   body,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	if _, err := stream.Write(reqData); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to write request: " + err.Error(),
		}
	}

	if err := stream.Close(); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to close write: " + err.Error(),
		}
	}

	respData, err := io.ReadAll(stream)
	if err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var resp QUICResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to unmarshal response: " + err.Error(),
		}
	}

	if resp.Error != "" {
		return nil, ErrQUICRequestFailed{
			Operation: method + " " + path,
			Message:   resp.Error,
		}
	}

	return resp.Body, nil
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant
func (a *QUICAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	body, err := a.doRequest(ctx, "POST", "/tenants", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "CreateTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &CreateTenantResult{Tenant: &tenant}, nil
}

// GetTenant retrieves a tenant by ID
func (a *QUICAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	path := fmt.Sprintf("/tenants/%s", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "GetTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetTenantResult{Tenant: &tenant}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *QUICAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	path := fmt.Sprintf("/tenants/name/%s", opts.Name)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "GetTenantByName",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetTenantByNameResult{Tenant: &tenant}, nil
}

// UpdateTenant updates an existing tenant
func (a *QUICAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	path := fmt.Sprintf("/tenants/%s", opts.TenantID)

	body, err := a.doRequest(ctx, "PUT", path, opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "UpdateTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateTenantResult{Tenant: &tenant}, nil
}

// DeleteTenant removes a tenant
func (a *QUICAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	path := fmt.Sprintf("/tenants/%s", opts.TenantID)

	_, err := a.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteTenantResult{Success: true, Message: "tenant deleted successfully"}, nil
}

// ListTenants lists all tenants with optional pagination
func (a *QUICAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	body, err := a.doRequest(ctx, "GET", "/tenants", opts)
	if err != nil {
		return nil, err
	}

	var result ListTenantsResult
	if err := json.Unmarshal(body, &result); err != nil {
		var tenants []*TenantData
		if err := json.Unmarshal(body, &tenants); err != nil {
			return nil, ErrQUICRequestFailed{
				Operation: "ListTenants",
				Message:   "failed to parse response: " + err.Error(),
			}
		}
		result.Tenants = tenants
		result.Total = len(tenants)
	}

	return &result, nil
}

// =============================================================================
// Tenant Lifecycle Operations
// =============================================================================

// SuspendTenant suspends a tenant
func (a *QUICAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	path := fmt.Sprintf("/tenants/%s/suspend", opts.TenantID)

	_, err := a.doRequest(ctx, "POST", path, nil)
	if err != nil {
		return nil, err
	}

	return &SuspendTenantResult{Success: true, Message: "tenant suspended successfully"}, nil
}

// ResumeTenant resumes a suspended tenant
func (a *QUICAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	path := fmt.Sprintf("/tenants/%s/resume", opts.TenantID)

	_, err := a.doRequest(ctx, "POST", path, nil)
	if err != nil {
		return nil, err
	}

	return &ResumeTenantResult{Success: true, Message: "tenant resumed successfully"}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas
func (a *QUICAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	path := fmt.Sprintf("/tenants/%s/quotas", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetQuotasResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "GetQuotas",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// UpdateQuotas updates tenant quotas
func (a *QUICAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	path := fmt.Sprintf("/tenants/%s/quotas", opts.TenantID)

	body, err := a.doRequest(ctx, "PUT", path, opts)
	if err != nil {
		return nil, err
	}

	var result UpdateQuotasResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "UpdateQuotas",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetUsage retrieves tenant resource usage
func (a *QUICAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	path := fmt.Sprintf("/tenants/%s/usage", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetUsageResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "GetUsage",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// CheckQuota checks if a resource request can be fulfilled
func (a *QUICAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	path := fmt.Sprintf("/tenants/%s/check-quota", opts.TenantID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return &CheckQuotaResult{
			TenantID: opts.TenantID,
			Resource: opts.Resource,
			Amount:   opts.Amount,
			Allowed:  false,
			Message:  err.Error(),
		}, nil
	}

	var result CheckQuotaResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "CheckQuota",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// ValidateVLAN validates a VLAN ID for a tenant
func (a *QUICAdapter) ValidateVLAN(ctx context.Context, opts ValidateVLANOptions) (*ValidateVLANResult, error) {
	path := fmt.Sprintf("/tenants/%s/validate-vlan", opts.TenantID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return &ValidateVLANResult{
			TenantID: opts.TenantID,
			VLANID:   opts.VLANID,
			Valid:    false,
			Message:  err.Error(),
		}, nil
	}

	var result ValidateVLANResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "ValidateVLAN",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetBridgeName retrieves the OVS bridge name for a tenant
func (a *QUICAdapter) GetBridgeName(ctx context.Context, opts GetBridgeNameOptions) (*GetBridgeNameResult, error) {
	path := fmt.Sprintf("/tenants/%s/bridge", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetBridgeNameResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "GetBridgeName",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Sync Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state
func (a *QUICAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	_, err := a.doRequest(ctx, "POST", "/tenants/sync", nil)
	if err != nil {
		return nil, err
	}

	return &SyncTenantsResult{Success: true, Message: "tenant manager synchronized successfully"}, nil
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier.
func (a *QUICAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	path := fmt.Sprintf("/tenants/%s/barrier/init", opts.TenantID)

	_, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	return &InitTenantBarrierResult{Success: true, Message: "tenant barrier initialized"}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier.
func (a *QUICAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	path := fmt.Sprintf("/tenants/%s/barrier/unseal", opts.TenantID)

	_, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	return &UnsealTenantBarrierResult{Success: true, Message: "tenant barrier unsealed"}, nil
}

// SealTenantBarrier seals a per-tenant barrier.
func (a *QUICAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	path := fmt.Sprintf("/tenants/%s/barrier/seal", opts.TenantID)

	_, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	return &SealTenantBarrierResult{Success: true, Message: "tenant barrier sealed"}, nil
}

// TenantBarrierStatus reports the current barrier state for a tenant.
func (a *QUICAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	path := fmt.Sprintf("/tenants/%s/barrier/status", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result TenantBarrierStatusResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrQUICRequestFailed{
			Operation: "TenantBarrierStatus",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify QUICAdapter implements TenantCommands
var _ TenantCommands = (*QUICAdapter)(nil)
