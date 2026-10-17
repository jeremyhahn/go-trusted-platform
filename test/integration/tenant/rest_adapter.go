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
	"fmt"
	"io"
	"net/http"
	"net/url"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
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

// RESTAdapter implements TenantCommands using REST API. The v1 tenant
// handlers speak the platformv1 messages as protojson inside the response
// envelope, so the adapter sends and decodes the same messages the gRPC
// adapter does.
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

// tenantPath builds a /api/v1/tenants route with each segment escaped.
func tenantPath(segments ...string) string {
	path := "/api/v1/tenants"
	for _, segment := range segments {
		path += "/" + url.PathEscape(segment)
	}
	return path
}

// call sends req (nil for no body) as protojson, unwraps the response
// envelope and decodes its payload into resp.
func (a *RESTAdapter) call(ctx context.Context, method, path string, req, resp proto.Message) error {
	operation := method + " " + path

	var reqBody io.Reader
	if req != nil {
		data, err := protojson.Marshal(req)
		if err != nil {
			return ErrRESTRequestFailed{Operation: operation, Message: "failed to marshal request: " + err.Error()}
		}
		reqBody = bytes.NewReader(data)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return ErrRESTRequestFailed{Operation: operation, Message: "failed to create request: " + err.Error()}
	}
	if req != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := a.client.Do(httpReq)
	if err != nil {
		return ErrRESTRequestFailed{Operation: operation, Message: "request failed: " + err.Error()}
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: httpResp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: httpResp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	payload, err := helpers.RESTPayload(respBody)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: httpResp.StatusCode,
			Message:    err.Error(),
			Body:       string(respBody),
		}
	}
	if len(payload) == 0 {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: httpResp.StatusCode,
			Message:    "response envelope carries no payload",
			Body:       string(respBody),
		}
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(payload, resp); err != nil {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: httpResp.StatusCode,
			Message:    "failed to parse response: " + err.Error(),
			Body:       string(respBody),
		}
	}
	return nil
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant via REST
func (a *RESTAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	req := &platformv1.CreateTenantRequest{
		Name:        opts.Name,
		DisplayName: opts.DisplayName,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}

	resp := &platformv1.CreateTenantResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(), req, resp); err != nil {
		return nil, err
	}

	return &CreateTenantResult{Tenant: pbToTenantData(resp.GetTenant())}, nil
}

// GetTenant retrieves a tenant by ID via REST
func (a *RESTAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	resp := &platformv1.GetTenantResponse{}
	if err := a.call(ctx, http.MethodGet, tenantPath(opts.TenantID), nil, resp); err != nil {
		return nil, err
	}

	return &GetTenantResult{Tenant: pbToTenantData(resp.GetTenant())}, nil
}

// GetTenantByName retrieves a tenant by name via REST
func (a *RESTAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	resp := &platformv1.GetTenantByNameResponse{}
	if err := a.call(ctx, http.MethodGet, tenantPath("by-name", opts.Name), nil, resp); err != nil {
		return nil, err
	}

	return &GetTenantByNameResult{Tenant: pbToTenantData(resp.GetTenant())}, nil
}

// UpdateTenant updates a tenant via REST
func (a *RESTAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	req := &platformv1.UpdateTenantRequest{
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}
	if opts.DisplayName != nil {
		req.DisplayName = *opts.DisplayName
	}

	resp := &platformv1.UpdateTenantResponse{}
	if err := a.call(ctx, http.MethodPut, tenantPath(opts.TenantID), req, resp); err != nil {
		return nil, err
	}

	return &UpdateTenantResult{Tenant: pbToTenantData(resp.GetTenant())}, nil
}

// DeleteTenant deletes a tenant via REST
func (a *RESTAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	resp := &platformv1.DeleteTenantResponse{}
	if err := a.call(ctx, http.MethodDelete, tenantPath(opts.TenantID), nil, resp); err != nil {
		return nil, err
	}

	return &DeleteTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ListTenants lists tenants via REST
func (a *RESTAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	query := url.Values{}
	if opts.Limit > 0 {
		query.Set("limit", fmt.Sprint(opts.Limit))
	}
	if opts.Offset > 0 {
		query.Set("offset", fmt.Sprint(opts.Offset))
	}
	path := tenantPath()
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp := &platformv1.ListTenantsResponse{}
	if err := a.call(ctx, http.MethodGet, path, nil, resp); err != nil {
		return nil, err
	}

	tenants := make([]*TenantData, 0, len(resp.GetTenants()))
	for _, t := range resp.GetTenants() {
		tenants = append(tenants, pbToTenantData(t))
	}

	return &ListTenantsResult{
		Tenants: tenants,
		Total:   int(resp.GetTotal()),
	}, nil
}

// =============================================================================
// Tenant State Operations
// =============================================================================

// SuspendTenant suspends a tenant via REST
func (a *RESTAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	resp := &platformv1.SuspendTenantResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "suspend"), &platformv1.SuspendTenantRequest{}, resp); err != nil {
		return nil, err
	}

	return &SuspendTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ResumeTenant resumes a suspended tenant via REST
func (a *RESTAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	resp := &platformv1.ResumeTenantResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "resume"), nil, resp); err != nil {
		return nil, err
	}

	return &ResumeTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves quotas for a tenant via REST
func (a *RESTAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	resp := &platformv1.GetQuotasResponse{}
	if err := a.call(ctx, http.MethodGet, tenantPath(opts.TenantID, "quotas"), nil, resp); err != nil {
		return nil, err
	}

	return &GetQuotasResult{
		TenantID: resp.GetTenantId(),
		Compute:  pbToComputeQuotaData(resp.GetCompute()),
		Network:  pbToNetworkQuotaData(resp.GetNetwork()),
		Storage:  pbToStorageQuotaData(resp.GetStorage()),
	}, nil
}

// UpdateQuotas updates quotas for a tenant via REST
func (a *RESTAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	req := &platformv1.UpdateQuotasRequest{}
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

	if err := a.call(ctx, http.MethodPut, tenantPath(opts.TenantID, "quotas"), req, &platformv1.UpdateQuotasResponse{}); err != nil {
		return nil, err
	}

	// Read the quotas back, as the gRPC adapter does.
	quotas, err := a.GetQuotas(ctx, GetQuotasOptions{TenantID: opts.TenantID})
	if err != nil {
		return nil, err
	}

	return &UpdateQuotasResult{
		TenantID: quotas.TenantID,
		Compute:  quotas.Compute,
		Network:  quotas.Network,
		Storage:  quotas.Storage,
	}, nil
}

// GetUsage retrieves resource usage for a tenant via REST
func (a *RESTAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	resp := &platformv1.GetUsageResponse{}
	if err := a.call(ctx, http.MethodGet, tenantPath(opts.TenantID, "usage"), nil, resp); err != nil {
		return nil, err
	}

	usage := resp.GetUsage()
	return &GetUsageResult{
		TenantID:      usage.GetTenantId(),
		VMs:           usage.GetVms(),
		Containers:    usage.GetContainers(),
		VCPUs:         usage.GetVcpus(),
		MemoryMB:      usage.GetMemoryMb(),
		DiskGB:        usage.GetDiskGb(),
		Bridges:       usage.GetBridges(),
		Ports:         usage.GetPorts(),
		BandwidthMbps: usage.GetBandwidthMbps(),
		Volumes:       usage.GetVolumes(),
		Snapshots:     usage.GetSnapshots(),
	}, nil
}

// CheckQuota checks if a resource allocation would exceed quota via REST
func (a *RESTAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	req := &platformv1.CheckQuotaRequest{
		Resource: opts.Resource,
		Amount:   opts.Amount,
	}

	resp := &platformv1.CheckQuotaResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "quota-check"), req, resp); err != nil {
		return nil, err
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
// Sync Operations
// =============================================================================

// SyncTenants synchronizes tenants from config via REST
func (a *RESTAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	resp := &platformv1.SyncTenantsResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath("sync"), nil, resp); err != nil {
		return nil, err
	}

	return &SyncTenantsResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier initializes a tenant barrier via REST
func (a *RESTAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	if opts.TenantID == "" {
		return nil, ErrRESTRequestFailed{Operation: "InitTenantBarrier", Message: "tenant_id is required"}
	}

	req := &platformv1.InitTenantBarrierRequest{
		Threshold: opts.Threshold,
		Shares:    opts.Shares,
	}

	resp := &platformv1.InitTenantBarrierResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "barrier", "init"), req, resp); err != nil {
		return nil, err
	}

	return &InitTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// UnsealTenantBarrier unseals a tenant barrier via REST
func (a *RESTAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	if opts.TenantID == "" {
		return nil, ErrRESTRequestFailed{Operation: "UnsealTenantBarrier", Message: "tenant_id is required"}
	}

	req := &platformv1.UnsealTenantBarrierRequest{Key: opts.Key}

	resp := &platformv1.UnsealTenantBarrierResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "barrier", "unseal"), req, resp); err != nil {
		return nil, err
	}

	return &UnsealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// SealTenantBarrier seals a tenant barrier via REST
func (a *RESTAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	if opts.TenantID == "" {
		return nil, ErrRESTRequestFailed{Operation: "SealTenantBarrier", Message: "tenant_id is required"}
	}

	resp := &platformv1.SealTenantBarrierResponse{}
	if err := a.call(ctx, http.MethodPost, tenantPath(opts.TenantID, "barrier", "seal"), nil, resp); err != nil {
		return nil, err
	}

	return &SealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// TenantBarrierStatus returns the status of a tenant barrier via REST
func (a *RESTAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	if opts.TenantID == "" {
		return nil, ErrRESTRequestFailed{Operation: "TenantBarrierStatus", Message: "tenant_id is required"}
	}

	resp := &platformv1.GetTenantBarrierStatusResponse{}
	if err := a.call(ctx, http.MethodGet, tenantPath(opts.TenantID, "barrier"), nil, resp); err != nil {
		return nil, err
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
