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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// listPageSize is how many tenants one `tenant list` call asks for while
// looking a tenant ID up.
const listPageSize = 100

// mbPerGB converts the suite's megabyte memory quota to the CLI's
// --max-memory-gb flag.
const mbPerGB = 1024

// ErrCLINotFound is returned when the CLI binary is not found
type ErrCLINotFound struct {
	Path string
}

func (e ErrCLINotFound) Error() string {
	return fmt.Sprintf("CLI not found: %s", e.Path)
}

// ErrCLICommandFailed is returned when a CLI command fails
type ErrCLICommandFailed struct {
	Operation string
	Message   string
	Output    string
}

func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("CLI command failed [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// ErrTenantIDNotFound is returned when no tenant the CLI lists has the ID.
// The CLI is name-keyed, so every ID-keyed call resolves the name first.
type ErrTenantIDNotFound struct {
	ID string
}

func (e ErrTenantIDNotFound) Error() string {
	return fmt.Sprintf("no tenant with ID %s", e.ID)
}

// ErrCLIUnsupportedValue is returned when a value cannot be expressed in the
// CLI's flags.
type ErrCLIUnsupportedValue struct {
	Field  string
	Value  int64
	Reason string
}

func (e ErrCLIUnsupportedValue) Error() string {
	return fmt.Sprintf("%s=%d cannot be passed to the CLI: %s", e.Field, e.Value, e.Reason)
}

// CLIAdapter implements TenantCommands using the platformctl CLI.
//
// The CLI takes tenant names where the suite passes IDs, so the adapter
// remembers the name of every tenant it has seen (id → name) and falls back to
// paging `tenant list` for an ID it has not.
type CLIAdapter struct {
	cliPath    string
	configDir  string
	configPath string
	names      sync.Map
}

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

// Teardown cleans up the CLI adapter
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

// runCommand executes a CLI command and returns its stdout. Stderr is kept
// apart so warnings never corrupt JSON output, and reported on failure.
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if a.configPath != "" {
		args = append([]string{"--config", a.configPath}, args...)
	}
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, ErrCLICommandFailed{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    stderr.String() + string(output),
		}
	}
	return output, nil
}

// runJSON runs a CLI command with --output json and decodes stdout into out.
func (a *CLIAdapter) runJSON(ctx context.Context, operation string, out any, args ...string) error {
	output, err := a.runCommand(ctx, append(args, "--output", "json")...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, out); err != nil {
		return ErrCLICommandFailed{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
			Output:    string(output),
		}
	}
	return nil
}

// remember records a tenant's name under its ID.
func (a *CLIAdapter) remember(id, name string) {
	if id != "" && name != "" {
		a.names.Store(id, name)
	}
}

// nameForID returns the name of the tenant with the given ID, paging through
// `tenant list` when the adapter has not seen the tenant yet.
func (a *CLIAdapter) nameForID(ctx context.Context, id string) (string, error) {
	if name, ok := a.names.Load(id); ok {
		return name.(string), nil
	}
	for offset := 0; ; offset += listPageSize {
		page, err := a.listPage(ctx, listPageSize, offset)
		if err != nil {
			return "", err
		}
		for _, item := range page.Tenants {
			a.remember(item.ID, item.Name)
			if item.ID == id {
				return item.Name, nil
			}
		}
		if len(page.Tenants) == 0 || offset+len(page.Tenants) >= page.Total {
			return "", ErrTenantIDNotFound{ID: id}
		}
	}
}

// cliTenantList mirrors the CLI's `tenant list` JSON.
type cliTenantList struct {
	Tenants []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	} `json:"tenants"`
	Total int `json:"total"`
}

func (a *CLIAdapter) listPage(ctx context.Context, limit, offset int) (*cliTenantList, error) {
	args := []string{"tenant", "list"}
	if limit > 0 {
		args = append(args, "--limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		args = append(args, "--offset", strconv.Itoa(offset))
	}
	var page cliTenantList
	if err := a.runJSON(ctx, "ListTenants", &page, args...); err != nil {
		return nil, err
	}
	return &page, nil
}

// cliTenantDetail mirrors the CLI's tenant JSON (create, show, update).
type cliTenantDetail struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	Quotas      struct {
		Compute *ComputeQuotaData `json:"compute"`
		Network *NetworkQuotaData `json:"network"`
		Storage *StorageQuotaData `json:"storage"`
	} `json:"quotas"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

func (d *cliTenantDetail) toTenantData() (*TenantData, error) {
	created, err := parseCLITime("created_at", d.CreatedAt)
	if err != nil {
		return nil, err
	}
	updated, err := parseCLITime("updated_at", d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &TenantData{
		ID:           d.ID,
		Name:         d.Name,
		DisplayName:  d.DisplayName,
		State:        pbTenantStateToState(platformv1.TenantState(platformv1.TenantState_value[d.State])),
		ComputeQuota: d.Quotas.Compute,
		NetworkQuota: d.Quotas.Network,
		StorageQuota: d.Quotas.Storage,
		Labels:       d.Labels,
		Annotations:  d.Annotations,
		CreatedAt:    created,
		UpdatedAt:    updated,
	}, nil
}

// parseCLITime reads a CLI timestamp: RFC 3339, or "N/A" for an unset time.
func parseCLITime(field, value string) (time.Time, error) {
	if value == "" || value == "N/A" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, ErrCLICommandFailed{
			Operation: field,
			Message:   "failed to parse time: " + err.Error(),
			Output:    value,
		}
	}
	return t, nil
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

// joinPairs renders a map as the CLI's k=v,... flag value, sorted by key.
func joinPairs(m map[string]string) string {
	pairs := make([]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
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

// quotaSetArgs renders the sections given as `quotas set` flags. Every field
// of a given section is passed, zero included, as the other transports send
// it. MaxDiskGB is on no wire, so the CLI has no flag for it.
func quotaSetArgs(opts UpdateQuotasOptions) ([]string, error) {
	var args []string
	flag := func(name string, value int64) {
		args = append(args, "--"+name, strconv.FormatInt(value, 10))
	}
	if c := opts.Compute; c != nil {
		if c.MaxMemoryMB%mbPerGB != 0 {
			return nil, ErrCLIUnsupportedValue{
				Field:  "MaxMemoryMB",
				Value:  c.MaxMemoryMB,
				Reason: "--max-memory-gb takes whole gigabytes",
			}
		}
		flag("max-vms", c.MaxVMs)
		flag("max-containers", c.MaxContainers)
		flag("max-vcpus", c.MaxVCPUs)
		flag("max-memory-gb", c.MaxMemoryMB/mbPerGB)
	}
	if n := opts.Network; n != nil {
		flag("max-bridges", n.MaxBridges)
		flag("max-ports", n.MaxPorts)
		flag("max-bandwidth-mbps", n.MaxBandwidthMbps)
	}
	if s := opts.Storage; s != nil {
		flag("max-volumes-gb", s.MaxVolumesGB)
		flag("max-snapshots", s.MaxSnapshots)
	}
	return args, nil
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
