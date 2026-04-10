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
// This file implements the TenantCommands interface using the REST API.
package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"io"
	"net/http"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTRequestFailed indicates a REST request failed
type ErrRESTRequestFailed struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("REST request failed [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements TenantCommands using REST API
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		endpoint: GetRESTEndpoint(),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
	}
}

// Setup prepares the adapter for testing
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation: "Setup",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation: "Setup",
			Message:   "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request and returns the response body
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, ErrRESTRequestFailed{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrRESTRequestFailed{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrRESTRequestFailed{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant
func (a *RESTAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	body, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "CreateTenant",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateTenantResult{Tenant: &tenant}, nil
}

// GetTenant retrieves a tenant by ID
func (a *RESTAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "GetTenant",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetTenantResult{Tenant: &tenant}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *RESTAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/name/%s", opts.Name)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "GetTenantByName",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetTenantByNameResult{Tenant: &tenant}, nil
}

// UpdateTenant updates an existing tenant
func (a *RESTAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s", opts.TenantID)

	updateReq := map[string]interface{}{}
	if opts.DisplayName != nil {
		updateReq["display_name"] = *opts.DisplayName
	}
	if opts.Labels != nil {
		updateReq["labels"] = opts.Labels
	}
	if opts.Annotations != nil {
		updateReq["annotations"] = opts.Annotations
	}

	body, err := a.doRequest(ctx, http.MethodPut, path, updateReq)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(body, &tenant); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "UpdateTenant",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateTenantResult{Tenant: &tenant}, nil
}

// DeleteTenant removes a tenant
func (a *RESTAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var result DeleteTenantResult
	if err := json.Unmarshal(body, &result); err != nil {
		// Delete may return simple success
		return &DeleteTenantResult{Success: true, Message: "tenant deleted successfully"}, nil
	}

	return &result, nil
}

// ListTenants lists all tenants with optional pagination
func (a *RESTAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	path := "/api/v1/tenants"

	params := ""
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:]
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result ListTenantsResult
	if err := json.Unmarshal(body, &result); err != nil {
		var tenants []*TenantData
		if err := json.Unmarshal(body, &tenants); err != nil {
			return nil, ErrRESTRequestFailed{
				Operation: "ListTenants",
				Message:   "failed to parse response: " + err.Error(),
				Body:      string(body),
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
func (a *RESTAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/suspend", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var result SuspendTenantResult
	if err := json.Unmarshal(body, &result); err != nil {
		return &SuspendTenantResult{Success: true, Message: "tenant suspended successfully"}, nil
	}

	return &result, nil
}

// ResumeTenant resumes a suspended tenant
func (a *RESTAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/resume", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var result ResumeTenantResult
	if err := json.Unmarshal(body, &result); err != nil {
		return &ResumeTenantResult{Success: true, Message: "tenant resumed successfully"}, nil
	}

	return &result, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas
func (a *RESTAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/quotas", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetQuotasResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "GetQuotas",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// UpdateQuotas updates tenant quotas
func (a *RESTAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/quotas", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	var result UpdateQuotasResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "UpdateQuotas",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetUsage retrieves tenant resource usage
func (a *RESTAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/usage", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetUsageResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "GetUsage",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// CheckQuota checks if a resource request can be fulfilled
func (a *RESTAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/check-quota", opts.TenantID)

	reqBody := map[string]interface{}{
		"resource": opts.Resource,
		"amount":   opts.Amount,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
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
		return nil, ErrRESTRequestFailed{
			Operation: "CheckQuota",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// ValidateVLAN validates a VLAN ID for a tenant
func (a *RESTAdapter) ValidateVLAN(ctx context.Context, opts ValidateVLANOptions) (*ValidateVLANResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/validate-vlan", opts.TenantID)

	reqBody := map[string]interface{}{
		"vlan_id": opts.VLANID,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
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
		return nil, ErrRESTRequestFailed{
			Operation: "ValidateVLAN",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetBridgeName retrieves the OVS bridge name for a tenant
func (a *RESTAdapter) GetBridgeName(ctx context.Context, opts GetBridgeNameOptions) (*GetBridgeNameResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/bridge", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetBridgeNameResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ErrRESTRequestFailed{
			Operation: "GetBridgeName",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// =============================================================================
// Sync Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state
func (a *RESTAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	body, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants/sync", nil)
	if err != nil {
		return nil, err
	}

	var result SyncTenantsResult
	if err := json.Unmarshal(body, &result); err != nil {
		return &SyncTenantsResult{Success: true, Message: "tenant manager synchronized successfully"}, nil
	}

	return &result, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify RESTAdapter implements TenantCommands
var _ TenantCommands = (*RESTAdapter)(nil)
