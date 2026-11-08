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
// This file implements the TenantCommands interface using the platformctl CLI.
package tenant

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the CLI adapter
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return ErrCLINotFound{Path: a.cliPath}
	}
	dir, path, err := helpers.WriteTempLocalCLIConfig(GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		return err
	}
	a.configDir, a.configPath = dir, path
	return nil
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runTenant runs a CLI verb that prints one tenant and returns it.
func (a *CLIAdapter) runTenant(ctx context.Context, operation string, args ...string) (*TenantData, error) {
	var detail cliTenantDetail
	if err := a.runJSON(ctx, operation, &detail, args...); err != nil {
		return nil, err
	}
	data, err := detail.toTenantData()
	if err != nil {
		return nil, err
	}
	a.remember(data.ID, data.Name)
	return data, nil
}

// CreateTenant creates a new tenant. The CLI's create takes no labels or
// annotations, so they follow in an update.
func (a *CLIAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	args := []string{"tenant", "create", "--name", opts.Name}
	if opts.DisplayName != "" {
		args = append(args, "--display-name", opts.DisplayName)
	}
	t, err := a.runTenant(ctx, "CreateTenant", args...)
	if err != nil {
		return nil, err
	}
	if len(opts.Labels) == 0 && len(opts.Annotations) == 0 {
		return &CreateTenantResult{Tenant: t}, nil
	}

	updated, err := a.UpdateTenant(ctx, UpdateTenantOptions{
		TenantID:    t.ID,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	})
	if err != nil {
		return nil, err
	}
	return &CreateTenantResult{Tenant: updated.Tenant}, nil
}

// GetTenant retrieves a tenant by ID
func (a *CLIAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	t, err := a.runTenant(ctx, "GetTenant", "tenant", "show", name)
	if err != nil {
		return nil, err
	}
	return &GetTenantResult{Tenant: t}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *CLIAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	t, err := a.runTenant(ctx, "GetTenantByName", "tenant", "show", opts.Name)
	if err != nil {
		return nil, err
	}
	return &GetTenantByNameResult{Tenant: t}, nil
}

// UpdateTenant updates an existing tenant
func (a *CLIAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	args := []string{"tenant", "update", name}
	if opts.DisplayName != nil {
		args = append(args, "--display-name", *opts.DisplayName)
	}
	if len(opts.Labels) > 0 {
		args = append(args, "--labels", joinPairs(opts.Labels))
	}
	if len(opts.Annotations) > 0 {
		args = append(args, "--annotations", joinPairs(opts.Annotations))
	}
	t, err := a.runTenant(ctx, "UpdateTenant", args...)
	if err != nil {
		return nil, err
	}
	return &UpdateTenantResult{Tenant: t}, nil
}

// DeleteTenant removes a tenant
func (a *CLIAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Success bool `json:"success"`
	}
	if err := a.runJSON(ctx, "DeleteTenant", &resp, "tenant", "delete", name, "--force"); err != nil {
		return nil, err
	}
	a.names.Delete(opts.TenantID)
	return &DeleteTenantResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant %s deleted", name),
	}, nil
}

// ListTenants lists all tenants with optional pagination. The CLI lists
// IDs, names and creation times only.
func (a *CLIAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	page, err := a.listPage(ctx, opts.Limit, opts.Offset)
	if err != nil {
		return nil, err
	}
	tenants := make([]*TenantData, 0, len(page.Tenants))
	for _, item := range page.Tenants {
		created, err := parseCLITime("created_at", item.CreatedAt)
		if err != nil {
			return nil, err
		}
		a.remember(item.ID, item.Name)
		tenants = append(tenants, &TenantData{ID: item.ID, Name: item.Name, CreatedAt: created})
	}
	return &ListTenantsResult{Tenants: tenants, Total: page.Total}, nil
}

// cliStateChange mirrors the CLI's suspend and resume JSON.
type cliStateChange struct {
	State   string `json:"state"`
	Success bool   `json:"success"`
}

// SuspendTenant suspends a tenant
func (a *CLIAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var resp cliStateChange
	if err := a.runJSON(ctx, "SuspendTenant", &resp, "tenant", "suspend", name); err != nil {
		return nil, err
	}
	return &SuspendTenantResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant %s is %s", name, resp.State),
	}, nil
}

// ResumeTenant resumes a suspended tenant
func (a *CLIAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var resp cliStateChange
	if err := a.runJSON(ctx, "ResumeTenant", &resp, "tenant", "resume", name); err != nil {
		return nil, err
	}
	return &ResumeTenantResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant %s is %s", name, resp.State),
	}, nil
}

// GetQuotas retrieves tenant quotas. The CLI's quota JSON has the result's
// shape.
func (a *CLIAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var result GetQuotasResult
	if err := a.runJSON(ctx, "GetQuotas", &result, "tenant", "quotas", "get", name); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateQuotas updates tenant quotas
func (a *CLIAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	flags, err := quotaSetArgs(opts)
	if err != nil {
		return nil, err
	}
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var result UpdateQuotasResult
	args := append([]string{"tenant", "quotas", "set", name}, flags...)
	if err := a.runJSON(ctx, "UpdateQuotas", &result, args...); err != nil {
		return nil, err
	}
	return &result, nil
}

// cliUsageItem mirrors one resource of the CLI's usage JSON.
type cliUsageItem struct {
	Used int64 `json:"used"`
}

// cliUsage mirrors the CLI's `tenant usage` JSON.
type cliUsage struct {
	TenantID string `json:"tenant_id"`
	Compute  struct {
		VMs        cliUsageItem `json:"vms"`
		Containers cliUsageItem `json:"containers"`
		VCPUs      cliUsageItem `json:"vcpus"`
		MemoryMB   cliUsageItem `json:"memory_mb"`
	} `json:"compute"`
	Network struct {
		Bridges       cliUsageItem `json:"bridges"`
		Ports         cliUsageItem `json:"ports"`
		BandwidthMbps cliUsageItem `json:"bandwidth_mbps"`
	} `json:"network"`
	Storage struct {
		VolumesGB cliUsageItem `json:"volumes_gb"`
		Snapshots cliUsageItem `json:"snapshots"`
	} `json:"storage"`
}

// GetUsage retrieves tenant resource usage. The CLI reports storage in use as
// disk GB; it does not print the volume count, so Volumes stays zero.
func (a *CLIAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var usage cliUsage
	if err := a.runJSON(ctx, "GetUsage", &usage, "tenant", "usage", name); err != nil {
		return nil, err
	}
	return &GetUsageResult{
		TenantID:      usage.TenantID,
		VMs:           usage.Compute.VMs.Used,
		Containers:    usage.Compute.Containers.Used,
		VCPUs:         usage.Compute.VCPUs.Used,
		MemoryMB:      usage.Compute.MemoryMB.Used,
		DiskGB:        usage.Storage.VolumesGB.Used,
		Bridges:       usage.Network.Bridges.Used,
		Ports:         usage.Network.Ports.Used,
		BandwidthMbps: usage.Network.BandwidthMbps.Used,
		Snapshots:     usage.Storage.Snapshots.Used,
	}, nil
}

// CheckQuota checks if a resource request can be fulfilled. The CLI's check
// JSON has the result's shape.
func (a *CLIAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}
	var result CheckQuotaResult
	args := []string{
		"tenant", "quotas", "check", name,
		"--resource", opts.Resource,
		"--amount", strconv.FormatInt(opts.Amount, 10),
	}
	if err := a.runJSON(ctx, "CheckQuota", &result, args...); err != nil {
		return nil, err
	}
	return &result, nil
}

// SyncTenants synchronizes tenant manager state
func (a *CLIAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	var resp struct {
		Success bool `json:"success"`
	}
	if err := a.runJSON(ctx, "SyncTenants", &resp, "tenant", "sync"); err != nil {
		return nil, err
	}
	return &SyncTenantsResult{Success: resp.Success, Message: "tenants synchronized"}, nil
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier initializes a per-tenant barrier via
// `platformctl tenant barrier init <name>`.
func (a *CLIAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "init", name}
	if opts.Threshold > 0 {
		args = append(args, "--threshold", fmt.Sprintf("%d", opts.Threshold))
	}
	if opts.Shares > 0 {
		args = append(args, "--shares", fmt.Sprintf("%d", opts.Shares))
	}

	var resp struct {
		TenantName string `json:"tenant_name"`
		Success    bool   `json:"success"`
	}
	if err := a.runJSON(ctx, "InitTenantBarrier", &resp, args...); err != nil {
		return nil, err
	}
	return &InitTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier initialized for %s", resp.TenantName),
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier via
// `platformctl tenant barrier unseal <name>`.
func (a *CLIAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "unseal", name}
	if len(opts.Key) > 0 {
		args = append(args, "--key-base64", base64.StdEncoding.EncodeToString(opts.Key))
	}

	var resp struct {
		TenantName string `json:"tenant_name"`
		Success    bool   `json:"success"`
	}
	if err := a.runJSON(ctx, "UnsealTenantBarrier", &resp, args...); err != nil {
		return nil, err
	}
	return &UnsealTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier unsealed for %s", resp.TenantName),
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier via
// `platformctl tenant barrier seal <name>`.
func (a *CLIAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantName string `json:"tenant_name"`
		Success    bool   `json:"success"`
	}
	if err := a.runJSON(ctx, "SealTenantBarrier", &resp, "tenant", "barrier", "seal", name); err != nil {
		return nil, err
	}
	return &SealTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier sealed for %s", resp.TenantName),
	}, nil
}

// TenantBarrierStatus reports per-tenant barrier state via
// `platformctl tenant barrier status <name>`.
func (a *CLIAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	name, err := a.nameForID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantID       string `json:"tenant_id"`
		Sealed         bool   `json:"sealed"`
		Initialized    bool   `json:"initialized"`
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
	}
	if err := a.runJSON(ctx, "TenantBarrierStatus", &resp, "tenant", "barrier", "status", name); err != nil {
		return nil, err
	}
	return &TenantBarrierStatusResult{
		TenantID:       resp.TenantID,
		Sealed:         resp.Sealed,
		Initialized:    resp.Initialized,
		Strategy:       resp.Strategy,
		HardwareBacked: resp.HardwareBacked,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ TenantCommands = (*CLIAdapter)(nil)
