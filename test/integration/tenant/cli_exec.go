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

// This file holds how the CLI adapter runs platformctl and reads its output.
// It carries no build tag, so cli_exec_test.go runs in `make test` with no
// daemon; the adapter's daemon-facing operations stay in cli_adapter.go.
package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

// Teardown removes the CLI config directory Setup wrote.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	return os.RemoveAll(a.configDir)
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

// joinPairs renders a map as the CLI's k=v,... flag value, sorted by key.
func joinPairs(m map[string]string) string {
	pairs := make([]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
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

// pbTenantStateToState maps the wire tenant state to the platform's, for
// every adapter that reads a platform.v1 TenantState (the CLI prints its name).
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
