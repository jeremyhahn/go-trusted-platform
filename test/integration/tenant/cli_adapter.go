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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	tenantpkg "github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLINotFound indicates the CLI tool was not found
type ErrCLINotFound struct {
	Path string
}

func (e ErrCLINotFound) Error() string {
	return fmt.Sprintf("CLI not found: %s", e.Path)
}

// ErrCLICommandFailed indicates a CLI command failed
type ErrCLICommandFailed struct {
	Operation string
	Message   string
	Output    string
}

func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("CLI command failed [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements TenantCommands using the platformctl CLI
type CLIAdapter struct {
	cliPath    string
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return ErrCLINotFound{Path: a.cliPath}
	}
	dir, err := os.MkdirTemp("", "platformctl-tenant-test-*")
	if err != nil {
		return err
	}
	path, err := helpers.WriteLocalCLIConfig(dir, GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	a.configDir, a.configPath = dir, path
	return nil
}

// Teardown removes the platformctl config Setup wrote.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	return os.RemoveAll(a.configDir)
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if a.configPath != "" {
		args = append([]string{"--config", a.configPath}, args...)
	}
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, ErrCLICommandFailed{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant
func (a *CLIAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	args := []string{"tenant", "create",
		"--name", opts.Name,
		"--output", "json",
	}

	if opts.DisplayName != "" {
		args = append(args, "--display-name", opts.DisplayName)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(output, &tenant); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "CreateTenant",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateTenantResult{Tenant: &tenant}, nil
}

// GetTenant retrieves a tenant by ID
func (a *CLIAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	args := []string{"tenant", "show",
		"--id", opts.TenantID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(output, &tenant); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "GetTenant",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetTenantResult{Tenant: &tenant}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *CLIAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	args := []string{"tenant", "show",
		"--name", opts.Name,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(output, &tenant); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "GetTenantByName",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetTenantByNameResult{Tenant: &tenant}, nil
}

// UpdateTenant updates an existing tenant
func (a *CLIAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	args := []string{"tenant", "update",
		"--id", opts.TenantID,
		"--output", "json",
	}

	if opts.DisplayName != nil {
		args = append(args, "--display-name", *opts.DisplayName)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(output, &tenant); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "UpdateTenant",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateTenantResult{Tenant: &tenant}, nil
}

// DeleteTenant removes a tenant
func (a *CLIAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	args := []string{"tenant", "delete",
		"--id", opts.TenantID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteTenantResult{Success: true, Message: "tenant deleted successfully"}, nil
}

// ListTenants lists all tenants with optional pagination
func (a *CLIAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	args := []string{"tenant", "list",
		"--output", "json",
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListTenantsResult
	if err := json.Unmarshal(output, &result); err != nil {
		var tenants []*TenantData
		if err := json.Unmarshal(output, &tenants); err != nil {
			return nil, ErrCLICommandFailed{
				Operation: "ListTenants",
				Message:   "failed to parse response",
				Output:    string(output),
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
func (a *CLIAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	args := []string{"tenant", "suspend",
		"--id", opts.TenantID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &SuspendTenantResult{Success: true, Message: "tenant suspended successfully"}, nil
}

// ResumeTenant resumes a suspended tenant
func (a *CLIAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	args := []string{"tenant", "resume",
		"--id", opts.TenantID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &ResumeTenantResult{Success: true, Message: "tenant resumed successfully"}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas
func (a *CLIAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	args := []string{"tenant", "quotas", "show",
		"--id", opts.TenantID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetQuotasResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "GetQuotas",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// UpdateQuotas updates tenant quotas
func (a *CLIAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	args := []string{"tenant", "quotas", "update",
		"--id", opts.TenantID,
		"--output", "json",
	}

	if opts.Compute != nil {
		if opts.Compute.MaxVMs > 0 {
			args = append(args, "--max-vms", fmt.Sprintf("%d", opts.Compute.MaxVMs))
		}
		if opts.Compute.MaxContainers > 0 {
			args = append(args, "--max-containers", fmt.Sprintf("%d", opts.Compute.MaxContainers))
		}
		if opts.Compute.MaxVCPUs > 0 {
			args = append(args, "--max-vcpus", fmt.Sprintf("%d", opts.Compute.MaxVCPUs))
		}
		if opts.Compute.MaxMemoryMB > 0 {
			args = append(args, "--max-memory-mb", fmt.Sprintf("%d", opts.Compute.MaxMemoryMB))
		}
		if opts.Compute.MaxDiskGB > 0 {
			args = append(args, "--max-disk-gb", fmt.Sprintf("%d", opts.Compute.MaxDiskGB))
		}
	}

	if opts.Network != nil {
		if opts.Network.MaxBridges > 0 {
			args = append(args, "--max-bridges", fmt.Sprintf("%d", opts.Network.MaxBridges))
		}
		if opts.Network.MaxPorts > 0 {
			args = append(args, "--max-ports", fmt.Sprintf("%d", opts.Network.MaxPorts))
		}
		if opts.Network.MaxBandwidthMbps > 0 {
			args = append(args, "--max-bandwidth-mbps", fmt.Sprintf("%d", opts.Network.MaxBandwidthMbps))
		}
	}

	if opts.Storage != nil {
		if opts.Storage.MaxVolumesGB > 0 {
			args = append(args, "--max-volumes-gb", fmt.Sprintf("%d", opts.Storage.MaxVolumesGB))
		}
		if opts.Storage.MaxSnapshots > 0 {
			args = append(args, "--max-snapshots", fmt.Sprintf("%d", opts.Storage.MaxSnapshots))
		}
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result UpdateQuotasResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "UpdateQuotas",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetUsage retrieves tenant resource usage
func (a *CLIAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	args := []string{"tenant", "usage",
		"--id", opts.TenantID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetUsageResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "GetUsage",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// CheckQuota checks if a resource request can be fulfilled
func (a *CLIAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	args := []string{"tenant", "quotas", "check",
		"--id", opts.TenantID,
		"--resource", opts.Resource,
		"--amount", fmt.Sprintf("%d", opts.Amount),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		// Check quota may return error when quota is exceeded
		return &CheckQuotaResult{
			TenantID: opts.TenantID,
			Resource: opts.Resource,
			Amount:   opts.Amount,
			Allowed:  false,
			Message:  err.Error(),
		}, nil
	}

	var result CheckQuotaResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "CheckQuota",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state
func (a *CLIAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	args := []string{"tenant", "sync",
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &SyncTenantsResult{Success: true, Message: "tenant manager synchronized successfully"}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// tenantDataFromEntity converts a TenantEntity to TenantData
func tenantDataFromEntity(entity *tenantpkg.TenantEntity) *TenantData {
	if entity == nil {
		return nil
	}

	data := &TenantData{
		ID:          entity.ID,
		Name:        entity.Name,
		DisplayName: entity.DisplayName,
		State:       entity.State,
		Labels:      entity.Labels,
		Annotations: entity.Annotations,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
	}

	data.ComputeQuota = &ComputeQuotaData{
		MaxVMs:        entity.ComputeQuota.MaxVMs,
		MaxContainers: entity.ComputeQuota.MaxContainers,
		MaxVCPUs:      entity.ComputeQuota.MaxVCPUs,
		MaxMemoryMB:   entity.ComputeQuota.MaxMemoryMB,
		MaxDiskGB:     entity.ComputeQuota.MaxDiskGB,
	}

	data.NetworkQuota = &NetworkQuotaData{
		MaxBridges:       entity.NetworkQuota.MaxBridges,
		MaxPorts:         entity.NetworkQuota.MaxPorts,
		MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
	}

	data.StorageQuota = &StorageQuotaData{
		MaxVolumesGB: entity.StorageQuota.MaxVolumesGB,
		MaxSnapshots: entity.StorageQuota.MaxSnapshots,
	}

	return data
}

// =============================================================================
// Per-Tenant Barrier Operations (added 2026-04-28)
// =============================================================================
//
// The barrier CLI subcommands accept a tenant-name positional argument (not
// --id). The TenantCommands interface passes opts.TenantID (a UUID), so we
// resolve the tenant name first via GetTenant and pass that name to the
// barrier subcommand.

// resolveTenantNameByID resolves a tenant UUID to its name via the CLI's
// existing tenant show --id pathway.
func (a *CLIAdapter) resolveTenantNameByID(ctx context.Context, tenantID string) (string, error) {
	res, err := a.GetTenant(ctx, GetTenantOptions{TenantID: tenantID})
	if err != nil {
		return "", err
	}
	if res == nil || res.Tenant == nil {
		return "", ErrCLICommandFailed{
			Operation: "ResolveTenantName",
			Message:   "tenant not found",
			Output:    tenantID,
		}
	}
	return res.Tenant.Name, nil
}

// InitTenantBarrier explicitly initializes a per-tenant barrier.
func (a *CLIAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	name, err := a.resolveTenantNameByID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "init", name, "--output", "json"}
	if opts.Threshold > 0 {
		args = append(args, "--threshold", fmt.Sprintf("%d", opts.Threshold))
	}
	if opts.Shares > 0 {
		args = append(args, "--shares", fmt.Sprintf("%d", opts.Shares))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantID   string `json:"tenant_id"`
		TenantName string `json:"tenant_name"`
		Threshold  int32  `json:"threshold"`
		Shares     int32  `json:"shares"`
		Success    bool   `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "InitTenantBarrier",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &InitTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier initialized for %s", resp.TenantName),
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier with the supplied key bytes.
// An empty key falls back to the deterministic init credential.
func (a *CLIAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	name, err := a.resolveTenantNameByID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "unseal", name, "--output", "json"}
	if len(opts.Key) > 0 {
		args = append(args, "--key-base64", base64.StdEncoding.EncodeToString(opts.Key))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantID   string `json:"tenant_id"`
		TenantName string `json:"tenant_name"`
		Success    bool   `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "UnsealTenantBarrier",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UnsealTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier unsealed for %s", resp.TenantName),
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier.
func (a *CLIAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	name, err := a.resolveTenantNameByID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "seal", name, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantID   string `json:"tenant_id"`
		TenantName string `json:"tenant_name"`
		Success    bool   `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "SealTenantBarrier",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &SealTenantBarrierResult{
		Success: resp.Success,
		Message: fmt.Sprintf("tenant barrier sealed for %s", resp.TenantName),
	}, nil
}

// TenantBarrierStatus reports the current sealed/initialized state and active
// strategy metadata of a per-tenant barrier.
func (a *CLIAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	name, err := a.resolveTenantNameByID(ctx, opts.TenantID)
	if err != nil {
		return nil, err
	}

	args := []string{"tenant", "barrier", "status", name, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		TenantID       string `json:"tenant_id"`
		TenantName     string `json:"tenant_name"`
		Sealed         bool   `json:"sealed"`
		Initialized    bool   `json:"initialized"`
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "TenantBarrierStatus",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

// Verify CLIAdapter implements TenantCommands
var _ TenantCommands = (*CLIAdapter)(nil)
