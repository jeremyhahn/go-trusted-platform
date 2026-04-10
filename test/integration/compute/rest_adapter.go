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

//go:build integration

package compute_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTRequestFailed indicates a REST API request failure.
type ErrRESTRequestFailed struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("compute: REST error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// ErrRESTSetupFailed indicates the REST endpoint is unreachable.
type ErrRESTSetupFailed struct {
	Endpoint string
	Message  string
}

func (e ErrRESTSetupFailed) Error() string {
	return fmt.Sprintf("compute: REST setup failed for %s: %s", e.Endpoint, e.Message)
}

// =============================================================================
// REST Request/Response Types
// =============================================================================

// restCreateVMRequest represents the JSON body for creating a VM.
type restCreateVMRequest struct {
	Name       string            `json:"name"`
	CPUs       uint32            `json:"cpus"`
	MemoryMB   uint64            `json:"memory_mb"`
	DiskSizeGB uint64            `json:"disk_size_gb"`
	Firmware   string            `json:"firmware,omitempty"`
	SecureBoot bool              `json:"secure_boot,omitempty"`
	TPM        bool              `json:"tpm,omitempty"`
	Start      bool              `json:"start,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// restStopVMRequest represents the JSON body for stopping a VM.
type restStopVMRequest struct {
	Force          bool   `json:"force,omitempty"`
	TimeoutSeconds uint32 `json:"timeout_seconds,omitempty"`
}

// restDeleteVMQuery represents query parameters for deleting a VM.
type restDeleteVMQuery struct {
	DeleteDisks bool `json:"delete_disks,omitempty"`
}

// restVMResponse represents a VM in the REST API response.
type restVMResponse struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	State    string            `json:"state"`
	CPUs     uint32            `json:"cpus"`
	MemoryMB uint64            `json:"memory_mb"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// restStatusResponse represents a status response from the REST API.
type restStatusResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// restCreateResponse represents the response from creating a VM.
type restCreateResponse struct {
	Status *restStatusResponse `json:"status,omitempty"`
	VM     *restVMResponse     `json:"vm,omitempty"`
}

// restGetResponse represents the response from getting a VM.
type restGetResponse struct {
	VM *restVMResponse `json:"vm,omitempty"`
}

// restListResponse represents the response from listing VMs.
type restListResponse struct {
	VMs        []restVMResponse `json:"vms"`
	TotalItems uint64           `json:"total_items"`
}

// =============================================================================
// REST Adapter
// =============================================================================

// RESTAdapter implements ComputeCommands using the REST API.
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter.
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

// Setup verifies the REST endpoint is reachable.
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return ErrRESTSetupFailed{
			Endpoint: a.endpoint,
			Message:  "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return ErrRESTSetupFailed{
			Endpoint: a.endpoint,
			Message:  "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing.
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doJSON sends a JSON request and decodes the response body.
func (a *RESTAdapter) doJSON(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return ErrRESTRequestFailed{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, bodyReader)
	if err != nil {
		return ErrRESTRequestFailed{
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
		return ErrRESTRequestFailed{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrRESTRequestFailed{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "unexpected status code",
			Body:       string(respBody),
		}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return ErrRESTRequestFailed{
				Operation:  method + " " + path,
				StatusCode: resp.StatusCode,
				Message:    "failed to parse response: " + err.Error(),
				Body:       string(respBody),
			}
		}
	}

	return nil
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via REST.
func (a *RESTAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	reqBody := restCreateVMRequest{
		Name:       opts.Name,
		CPUs:       opts.CPUs,
		MemoryMB:   opts.MemoryMB,
		DiskSizeGB: opts.DiskSizeGB,
		Firmware:   opts.Firmware,
		SecureBoot: opts.SecureBoot,
		TPM:        opts.TPM,
		Start:      opts.Start,
		Labels:     opts.Labels,
	}

	var resp restCreateResponse
	if err := a.doJSON(ctx, http.MethodPost, "/api/v1/compute/vms", reqBody, &resp); err != nil {
		return nil, err
	}

	result := &CreateVMResult{}
	if resp.Status != nil {
		result.Success = resp.Status.Success
	}
	if resp.VM != nil {
		result.VMID = resp.VM.ID
		result.Name = resp.VM.Name
		result.State = resp.VM.State
		result.Labels = resp.VM.Labels
	}

	return result, nil
}

// StartVM starts a virtual machine via REST.
func (a *RESTAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	var resp restStatusResponse
	path := fmt.Sprintf("/api/v1/compute/vms/%s/start", opts.VMID)

	if err := a.doJSON(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}

	return &StartVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// StopVM stops a virtual machine via REST.
func (a *RESTAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	reqBody := restStopVMRequest{
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	}

	var resp restStatusResponse
	path := fmt.Sprintf("/api/v1/compute/vms/%s/stop", opts.VMID)

	if err := a.doJSON(ctx, http.MethodPost, path, reqBody, &resp); err != nil {
		return nil, err
	}

	return &StopVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// DeleteVM deletes a virtual machine via REST.
func (a *RESTAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	path := fmt.Sprintf("/api/v1/compute/vms/%s", opts.VMID)
	if opts.DeleteDisks {
		path += "?delete_disks=true"
	}

	var resp restStatusResponse
	if err := a.doJSON(ctx, http.MethodDelete, path, nil, &resp); err != nil {
		return nil, err
	}

	return &DeleteVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// GetVM retrieves a virtual machine via REST.
func (a *RESTAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	path := fmt.Sprintf("/api/v1/compute/vms/%s", opts.VMID)

	var resp restGetResponse
	if err := a.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}

	if resp.VM == nil {
		return nil, ErrVMNotFound{VMID: opts.VMID}
	}

	return &GetVMResult{
		VMID:     resp.VM.ID,
		Name:     resp.VM.Name,
		State:    resp.VM.State,
		CPUs:     resp.VM.CPUs,
		MemoryMB: resp.VM.MemoryMB,
		Labels:   resp.VM.Labels,
	}, nil
}

// ListVMs lists virtual machines via REST.
func (a *RESTAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	path := "/api/v1/compute/vms"
	sep := "?"

	if opts.StateFilter != "" {
		path += sep + "state=" + opts.StateFilter
		sep = "&"
	}
	if opts.PageSize > 0 {
		path += sep + fmt.Sprintf("page_size=%d", opts.PageSize)
		sep = "&"
	}
	for k, v := range opts.Labels {
		path += sep + "label=" + k + "=" + v
		sep = "&"
	}

	var resp restListResponse
	if err := a.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}

	vms := make([]VMSummary, len(resp.VMs))
	for i, vm := range resp.VMs {
		vms[i] = VMSummary{
			VMID:   vm.ID,
			Name:   vm.Name,
			State:  vm.State,
			Labels: vm.Labels,
		}
	}

	return &ListVMsResult{
		VMs:        vms,
		TotalItems: resp.TotalItems,
	}, nil
}
