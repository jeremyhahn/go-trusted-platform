// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// These tests hold the tenant tools to the TenantService they call: for one
// input, a tool over MCP and its RPC over gRPC give the same answer and the
// same error class, leave the tenants in the same state, and keep a tenant
// to itself. Both transports run against the same in-memory DEK and barrier
// backends at the SDK interface, so a difference is a difference in the
// transport, never in the backend.

// The tenants are named by label; a harness maps each label to the id the
// manager gave it, and the names the tenants are created under.
const (
	paritySystemTenant = "system"
	parityTenantA      = "a"
	parityTenantB      = "b"
	parityNewTenant    = "tenant-c"
	parityGhostTenant  = "no-such-tenant"
)

// parityQuotaOverAsk is a VM count beyond any tenant's quota, so a check of it
// is answered "not available" whatever limits the harness tenant carries.
const parityQuotaOverAsk = 1 << 40

var parityTenantNames = map[string]string{
	paritySystemTenant: "tenant-system",
	parityTenantA:      "tenant-a",
	parityTenantB:      "tenant-b",
}

// errFakeUnknownTenant is what the in-memory backends answer for a tenant
// they hold nothing for.
type errFakeUnknownTenant struct {
	TenantID string
}

func (e errFakeUnknownTenant) Error() string {
	return "fake backend: nothing held for tenant " + e.TenantID
}

// memoryTenantDEKs is a tenant.TenantDEKClient holding one versioned DEK per
// tenant in memory.
type memoryTenantDEKs struct {
	mu       sync.Mutex
	versions map[string]uint64
	calls    []string
	// reencrypt holds AutoStartReencryption from each rotation, in order.
	reencrypt []bool
}

func newMemoryTenantDEKs() *memoryTenantDEKs {
	return &memoryTenantDEKs{versions: make(map[string]uint64)}
}

func (d *memoryTenantDEKs) record(op, tenantID string) {
	d.calls = append(d.calls, op+":"+tenantID)
}

func (d *memoryTenantDEKs) EnsureTenantDEK(_ context.Context, req *tenant.EnsureTenantDEKRequest) (*tenant.EnsureTenantDEKResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("ensure", req.TenantID)
	_, held := d.versions[req.TenantID]
	if !held {
		d.versions[req.TenantID] = 1
	}
	return &tenant.EnsureTenantDEKResponse{
		DEKID:     "dek/" + req.TenantID,
		Created:   !held,
		Algorithm: req.Algorithm,
	}, nil
}

func (d *memoryTenantDEKs) DeleteTenantDEK(_ context.Context, req *tenant.DeleteTenantDEKRequest) (*tenant.DeleteTenantDEKResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("delete", req.TenantID)
	if _, held := d.versions[req.TenantID]; !held {
		return nil, errFakeUnknownTenant{TenantID: req.TenantID}
	}
	delete(d.versions, req.TenantID)
	return &tenant.DeleteTenantDEKResponse{DEKID: "dek/" + req.TenantID}, nil
}

func (d *memoryTenantDEKs) RotateTenantDEK(_ context.Context, req *tenant.RotateTenantDEKRequest) (*tenant.RotateTenantDEKResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("rotate", req.TenantID)
	d.reencrypt = append(d.reencrypt, req.AutoStartReencryption)
	version, held := d.versions[req.TenantID]
	if !held {
		return nil, errFakeUnknownTenant{TenantID: req.TenantID}
	}
	d.versions[req.TenantID] = version + 1
	return &tenant.RotateTenantDEKResponse{OldVersion: version, NewVersion: version + 1}, nil
}

func (d *memoryTenantDEKs) TenantDEKStatus(_ context.Context, req *tenant.TenantDEKStatusRequest) (*tenant.TenantDEKStatusResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("status", req.TenantID)
	version, held := d.versions[req.TenantID]
	if !held {
		return nil, errFakeUnknownTenant{TenantID: req.TenantID}
	}
	return &tenant.TenantDEKStatusResponse{Algorithm: "AES-256-GCM", CurrentVersion: version}, nil
}

func (d *memoryTenantDEKs) state(tenantID string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	version, held := d.versions[tenantID]
	if !held {
		return "no-dek"
	}
	return fmt.Sprintf("dek-v%d", version)
}

func (d *memoryTenantDEKs) callsFor(tenantID string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return callsNaming(d.calls, tenantID)
}

// memoryTenantBarriers is a tenant.TenantBarrierClient holding one barrier
// per tenant in memory.
type memoryTenantBarriers struct {
	mu     sync.Mutex
	sealed map[string]bool
	calls  []string
}

func newMemoryTenantBarriers() *memoryTenantBarriers {
	return &memoryTenantBarriers{sealed: make(map[string]bool)}
}

func (b *memoryTenantBarriers) record(op, tenantID string) {
	b.calls = append(b.calls, op+":"+tenantID)
}

func (b *memoryTenantBarriers) TenantBarrierInit(_ context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("init", req.TenantID)
	if _, held := b.sealed[req.TenantID]; !held {
		b.sealed[req.TenantID] = false
	}
	return nil
}

func (b *memoryTenantBarriers) TenantBarrierUnseal(_ context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error {
	return b.setSealed("unseal", req.TenantID, false)
}

func (b *memoryTenantBarriers) TenantBarrierSeal(_ context.Context, req *quicbaassdk.QRDBTenantBarrierSealRequest) error {
	return b.setSealed("seal", req.TenantID, true)
}

func (b *memoryTenantBarriers) setSealed(op, tenantID string, sealed bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record(op, tenantID)
	if _, held := b.sealed[tenantID]; !held {
		return errFakeUnknownTenant{TenantID: tenantID}
	}
	b.sealed[tenantID] = sealed
	return nil
}

func (b *memoryTenantBarriers) TenantBarrierStatus(_ context.Context, req *quicbaassdk.QRDBTenantBarrierStatusRequest) (*quicbaassdk.QRDBTenantBarrierStatusResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("status", req.TenantID)
	sealed, held := b.sealed[req.TenantID]
	if !held {
		return nil, errFakeUnknownTenant{TenantID: req.TenantID}
	}
	return &quicbaassdk.QRDBTenantBarrierStatusResponse{
		TenantID:    req.TenantID,
		Sealed:      sealed,
		Initialized: true,
		Strategy:    "software",
	}, nil
}

func (b *memoryTenantBarriers) state(tenantID string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	sealed, held := b.sealed[tenantID]
	switch {
	case !held:
		return "no-barrier"
	case sealed:
		return "sealed"
	default:
		return "unsealed"
	}
}

func (b *memoryTenantBarriers) callsFor(tenantID string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return callsNaming(b.calls, tenantID)
}

func callsNaming(calls []string, tenantID string) []string {
	var named []string
	for _, call := range calls {
		if strings.HasSuffix(call, ":"+tenantID) {
			named = append(named, call)
		}
	}
	return named
}

// tenantParityHarness is one tenant service — manager, gRPC server and the
// MCP tools in front of it — holding a system tenant and tenants A and B.
type tenantParityHarness struct {
	ids      map[string]string
	manager  *tenant.Manager
	server   *TenantGRPCServer
	tools    *mcp.ToolRegistry
	iam      *mockIAMClientForServer
	deks     *memoryTenantDEKs
	barriers *memoryTenantBarriers
}

func newTenantParityHarness(t *testing.T) *tenantParityHarness {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = true
	h := &tenantParityHarness{
		ids:      make(map[string]string, len(parityTenantNames)),
		iam:      newMockIAMClientForServer(),
		deks:     newMemoryTenantDEKs(),
		barriers: newMemoryTenantBarriers(),
	}
	manager, err := tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient:     h.iam,
		IAMRoleClient:       newMockIAMClientForServer(),
		DEKClient:           h.deks,
		TenantBarrierClient: h.barriers,
		Config:              cfg,
		Logger:              quiet,
	})
	require.NoError(t, err)
	h.manager = manager

	h.server = NewTenantGRPCServer(WithTenantLogger(quiet))
	h.server.SetManager(manager)
	for label, name := range parityTenantNames {
		resp, err := h.server.CreateTenant(context.Background(), &platformv1.CreateTenantRequest{Name: name})
		require.NoError(t, err)
		h.ids[label] = resp.GetTenant().GetId()
	}
	h.server.SetSystemTenant(h.ids[paritySystemTenant])

	provider := &MCPServiceProvider{}
	provider.SetTenantService(h.server)
	h.tools = mcp.NewToolRegistry(provider, logging.DefaultLogger())
	return h
}

// id is the tenant id a label stands for; anything else (a tenant name, an
// unknown id, the empty string) is passed through as it is.
func (h *tenantParityHarness) id(label string) string {
	if id, ok := h.ids[label]; ok {
		return id
	}
	return label
}

// labelledIDs maps each label to its tenant id, including the tenant the
// create operation adds, once it exists.
func (h *tenantParityHarness) labelledIDs() map[string]string {
	ids := make(map[string]string, len(h.ids)+1)
	for label, id := range h.ids {
		ids[label] = id
	}
	if created, err := h.manager.GetTenantByName(context.Background(), parityNewTenant); err == nil {
		ids[parityNewTenant] = created.ID
	}
	return ids
}

// normalize writes every tenant id in a view as its label, so views from two
// harnesses, whose tenants have different ids, compare equal.
func (h *tenantParityHarness) normalize(view map[string]string) map[string]string {
	ids := h.labelledIDs()
	for key, value := range view {
		for label, id := range ids {
			value = strings.ReplaceAll(value, id, "<"+label+">")
		}
		view[key] = value
	}
	return view
}

// callGRPC runs op's RPC as caller and returns the answer as op's view.
func (h *tenantParityHarness) callGRPC(op tenantParityOp, caller, subject string) (map[string]string, error) {
	view, err := op.grpc(tokenCallerContext(h.id(caller)), h.server, h.id(subject))
	if err != nil {
		return nil, err
	}
	return h.normalize(view), nil
}

// callMCP runs op's tool as caller and returns the answer as op's view: the
// result fields the gRPC view names, at the same dotted paths.
func (h *tenantParityHarness) callMCP(t *testing.T, op tenantParityOp, caller, subject string) (map[string]string, error) {
	t.Helper()
	ctx := mcpTokenCtx(h.id(caller), "tenant:read", "tenant:write", "tenant:delete")
	out, err := h.tools.ExecuteTool(ctx, op.tool, op.args(h.id(subject)))
	if err != nil {
		return nil, err
	}
	result, ok := out.(map[string]interface{})
	require.True(t, ok, "%s answered %T, want a result map", op.tool, out)
	view := make(map[string]string, len(op.keys))
	for _, key := range op.keys {
		view[key] = lookupResultPath(result, key)
	}
	return h.normalize(view), nil
}

func lookupResultPath(result map[string]interface{}, path string) string {
	var value interface{} = result
	for _, part := range strings.Split(path, ".") {
		fields, ok := value.(map[string]interface{})
		if !ok {
			return "<missing>"
		}
		if value, ok = fields[part]; !ok {
			return "<missing>"
		}
	}
	return fmt.Sprint(value)
}

// snapshot is every tenant's record, DEK and barrier, so a test can tell
// whether a call changed anything.
func (h *tenantParityHarness) snapshot() map[string]string {
	ids := h.labelledIDs()
	snap := make(map[string]string, len(ids))
	for label, id := range ids {
		record := "absent"
		if entity, err := h.manager.GetTenant(context.Background(), id); err == nil {
			record = fmt.Sprintf("%s|%s|%s|vms=%d", entity.Name, entity.DisplayName, entity.State, entity.ComputeQuota.MaxVMs)
		}
		snap[label] = record + "|" + h.deks.state(id) + "|" + h.barriers.state(id)
	}
	return snap
}

func (h *tenantParityHarness) backendCalls(label string) []string {
	return append(h.deks.callsFor(h.id(label)), h.barriers.callsFor(h.id(label))...)
}

// parityStateNames is the tenant state each wire enum stands for, which the
// tools answer with.
var parityStateNames = map[platformv1.TenantState]tenant.State{
	platformv1.TenantState_TENANT_STATE_PENDING:   tenant.StateCreated,
	platformv1.TenantState_TENANT_STATE_ACTIVE:    tenant.StateActive,
	platformv1.TenantState_TENANT_STATE_SUSPENDED: tenant.StateSuspended,
	platformv1.TenantState_TENANT_STATE_DELETING:  tenant.StateDeleting,
	platformv1.TenantState_TENANT_STATE_DELETED:   tenant.StateDeleted,
}

func tenantView(prefix string, t *platformv1.Tenant) map[string]string {
	return map[string]string{
		prefix + "id":                    t.GetId(),
		prefix + "name":                  t.GetName(),
		prefix + "display_name":          t.GetDisplayName(),
		prefix + "state":                 string(parityStateNames[t.GetState()]),
		prefix + "dek_path":              t.GetDekPath(),
		prefix + "compute_quota.max_vms": fmt.Sprint(t.GetComputeQuota().GetMaxVms()),
	}
}

func statusView(st *platformv1.Status, fields map[string]string) map[string]string {
	view := map[string]string{"success": fmt.Sprint(st.GetSuccess()), "message": st.GetMessage()}
	for key, value := range fields {
		view[key] = value
	}
	return view
}

// tenantParityOp is one tenant tool and the RPC it stands for.
type tenantParityOp struct {
	tool string
	// caller and subject are the tenant the call is made as and the tenant
	// (or name) it names; subject is empty for a method naming none.
	caller, subject string
	// systemOnly marks a method only the system tenant may call.
	systemOnly bool
	args       func(subject string) map[string]interface{}
	grpc       func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error)
	// keys are the view fields, as dotted paths into the tool result.
	keys []string
	// before readies the harness, e.g. seals the barrier an unseal opens.
	before func(t *testing.T, h *tenantParityHarness)
	// missing is the class both transports answer for an unknown tenant;
	// codes.OK means the method answers rather than fails.
	missing codes.Code
	// gap marks a write the pinned go-quicbaas SDK cannot store: every
	// transport admits it and answers the declared gap,
	// tenant.ErrTenantFieldNotPersisted (docs/tenant/engineering.md §6).
	gap bool
}

func tenantIDArgs(subject string) map[string]interface{} {
	return map[string]interface{}{"tenant_id": subject}
}

func withTenantID(extra map[string]interface{}) func(string) map[string]interface{} {
	return func(subject string) map[string]interface{} {
		args := tenantIDArgs(subject)
		for key, value := range extra {
			args[key] = value
		}
		return args
	}
}

func viewKeys(view map[string]string) []string {
	keys := make([]string, 0, len(view))
	for key := range view {
		keys = append(keys, key)
	}
	return keys
}

func tenantParityOps() []tenantParityOp {
	tenantKeys := viewKeys(tenantView("", nil))
	createdKeys := append([]string{"success", "message"}, viewKeys(tenantView("tenant.", nil))...)
	statusKeys := []string{"success", "message", "tenant_id"}
	statusOnly := func(st *platformv1.Status, subject string) map[string]string {
		return statusView(st, map[string]string{"tenant_id": subject})
	}

	return []tenantParityOp{
		{
			tool: "tenant_get", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs, keys: tenantKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetTenant(ctx, &platformv1.GetTenantRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return tenantView("", resp.GetTenant()), nil
			},
		},
		{
			// Another tenant's name: a tenant may resolve only its own
			// (TestTenantGetByNameResolvesOwnTenantOnly).
			tool: "tenant_get_by_name", caller: paritySystemTenant, subject: "tenant-b", systemOnly: true, missing: codes.NotFound,
			args: func(subject string) map[string]interface{} { return map[string]interface{}{"name": subject} },
			keys: tenantKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: subject})
				if err != nil {
					return nil, err
				}
				return tenantView("", resp.GetTenant()), nil
			},
		},
		{
			tool: "tenant_list", caller: paritySystemTenant, systemOnly: true,
			args: func(string) map[string]interface{} { return map[string]interface{}{} },
			keys: []string{"total", "count"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, _ string) (map[string]string, error) {
				resp, err := s.ListTenants(ctx, &platformv1.ListTenantsRequest{})
				if err != nil {
					return nil, err
				}
				return map[string]string{"total": fmt.Sprint(resp.GetTotal()), "count": fmt.Sprint(len(resp.GetTenants()))}, nil
			},
		},
		{
			tool: "tenant_create", caller: paritySystemTenant, subject: parityNewTenant, systemOnly: true, gap: true,
			args: func(subject string) map[string]interface{} {
				return map[string]interface{}{"name": subject, "display_name": "Tenant C", "max_vms": 3}
			},
			keys: createdKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.CreateTenant(ctx, &platformv1.CreateTenantRequest{
					Name: subject, DisplayName: "Tenant C",
					ComputeQuota: &platformv1.ComputeQuota{MaxVms: 3},
				})
				if err != nil {
					return nil, err
				}
				view := tenantView("tenant.", resp.GetTenant())
				view["success"] = fmt.Sprint(resp.GetStatus().GetSuccess())
				view["message"] = resp.GetStatus().GetMessage()
				return view, nil
			},
		},
		{
			tool: "tenant_update", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound, gap: true,
			args: withTenantID(map[string]interface{}{"display_name": "Tenant A"}),
			keys: []string{"success", "message", "tenant.display_name"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{TenantId: subject, DisplayName: "Tenant A"})
				if err != nil {
					return nil, err
				}
				return statusView(resp.GetStatus(), map[string]string{"tenant.display_name": resp.GetTenant().GetDisplayName()}), nil
			},
		},
		{
			tool: "tenant_delete", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs, keys: statusKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			tool: "tenant_get_quotas", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs,
			keys: []string{"tenant_id", "compute.max_vms", "network.max_bridges", "storage.max_snapshots"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return map[string]string{
					"tenant_id":             resp.GetTenantId(),
					"compute.max_vms":       fmt.Sprint(resp.GetCompute().GetMaxVms()),
					"network.max_bridges":   fmt.Sprint(resp.GetNetwork().GetMaxBridges()),
					"storage.max_snapshots": fmt.Sprint(resp.GetStorage().GetMaxSnapshots()),
				}, nil
			},
		},
		{
			// The tool keeps every limit not given, so its RPC is the same
			// read-modify-write a gRPC client does.
			tool: "tenant_update_quotas", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound, gap: true,
			args: withTenantID(map[string]interface{}{"max_vms": 7}),
			keys: []string{"success", "message", "compute.max_vms", "network.max_bridges"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				current, err := s.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				current.Compute.MaxVms = 7
				resp, err := s.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
					TenantId: subject, Compute: current.GetCompute(), Network: current.GetNetwork(), Storage: current.GetStorage(),
				})
				if err != nil {
					return nil, err
				}
				return statusView(resp.GetStatus(), map[string]string{
					"compute.max_vms":     fmt.Sprint(current.GetCompute().GetMaxVms()),
					"network.max_bridges": fmt.Sprint(current.GetNetwork().GetMaxBridges()),
				}), nil
			},
		},
		{
			tool: "tenant_get_usage", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs, keys: []string{"tenant_id", "usage.vms", "usage.memory_mb"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return map[string]string{
					"tenant_id":       resp.GetUsage().GetTenantId(),
					"usage.vms":       fmt.Sprint(resp.GetUsage().GetVms()),
					"usage.memory_mb": fmt.Sprint(resp.GetUsage().GetMemoryMb()),
				}, nil
			},
		},
		{
			tool: "tenant_check_quota", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: withTenantID(map[string]interface{}{"resource_type": "vms", "amount": 1}),
			keys: []string{"tenant_id", "resource_type", "amount", "available", "message"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.CheckQuota(ctx, &platformv1.CheckQuotaRequest{TenantId: subject, Resource: "vms", Amount: 1})
				if err != nil {
					return nil, err
				}
				return map[string]string{
					"tenant_id":     resp.GetTenantId(),
					"resource_type": resp.GetResource(),
					"amount":        fmt.Sprint(resp.GetAmount()),
					"available":     fmt.Sprint(resp.GetAvailable()),
					"message":       resp.GetMessage(),
				}, nil
			},
		},
		{
			tool: "tenant_suspend", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound, gap: true,
			args: tenantIDArgs, keys: statusKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			// The tenants are suspended in IAM, the only place a
			// suspension survives a reload.
			tool: "tenant_resume", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound, gap: true,
			args: tenantIDArgs, keys: statusKeys,
			before: func(t *testing.T, h *tenantParityHarness) {
				for _, label := range []string{parityTenantA, parityTenantB} {
					h.iam.suspend(h.id(label))
					h.manager.InvalidateCache(h.id(label))
				}
			},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			tool: "tenant_sync", caller: paritySystemTenant, systemOnly: true,
			args: func(string) map[string]interface{} { return map[string]interface{}{} },
			keys: []string{"success", "message"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, _ string) (map[string]string, error) {
				resp, err := s.Sync(ctx, &platformv1.SyncTenantsRequest{})
				if err != nil {
					return nil, err
				}
				return statusView(resp.GetStatus(), nil), nil
			},
		},
		{
			tool: "tenant_rotate_dek", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: withTenantID(map[string]interface{}{"background": true}),
			keys: []string{"tenant_id", "old_version", "new_version"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: subject, Background: true})
				if err != nil {
					return nil, err
				}
				return map[string]string{
					"tenant_id":   resp.GetTenantId(),
					"old_version": fmt.Sprint(resp.GetOldVersion()),
					"new_version": fmt.Sprint(resp.GetNewVersion()),
				}, nil
			},
		},
		{
			tool: "tenant_get_dek_status", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs, keys: []string{"tenant_id", "path", "version", "algorithm"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				dek := resp.GetDekStatus()
				return map[string]string{
					"tenant_id": dek.GetTenantId(),
					"path":      dek.GetPath(),
					"version":   fmt.Sprint(dek.GetVersion()),
					"algorithm": dek.GetAlgorithm(),
				}, nil
			},
		},
		{
			tool: "platform_tenant_barrier_init", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: tenantIDArgs, keys: statusKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.InitTenantBarrier(ctx, &platformv1.InitTenantBarrierRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			// Seal does not look the tenant up; an unknown one fails in the
			// barrier backend.
			tool: "platform_tenant_barrier_seal", caller: parityTenantA, subject: parityTenantA, missing: codes.Internal,
			args: tenantIDArgs, keys: statusKeys,
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.SealTenantBarrier(ctx, &platformv1.SealTenantBarrierRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			tool: "platform_tenant_barrier_unseal", caller: parityTenantA, subject: parityTenantA, missing: codes.NotFound,
			args: withTenantID(map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("unseal-key"))}),
			keys: statusKeys,
			before: func(t *testing.T, h *tenantParityHarness) {
				require.NoError(t, h.manager.SealTenantBarrier(context.Background(), h.id(parityTenantA)))
				require.NoError(t, h.manager.SealTenantBarrier(context.Background(), h.id(parityTenantB)))
			},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.UnsealTenantBarrier(ctx, &platformv1.UnsealTenantBarrierRequest{TenantId: subject, Key: []byte("unseal-key")})
				if err != nil {
					return nil, err
				}
				return statusOnly(resp.GetStatus(), subject), nil
			},
		},
		{
			// Status does not look the tenant up either.
			tool: "platform_tenant_barrier_status", caller: parityTenantA, subject: parityTenantA, missing: codes.Internal,
			args: tenantIDArgs, keys: []string{"tenant_id", "sealed", "initialized", "strategy"},
			grpc: func(ctx context.Context, s *TenantGRPCServer, subject string) (map[string]string, error) {
				resp, err := s.GetTenantBarrierStatus(ctx, &platformv1.GetTenantBarrierStatusRequest{TenantId: subject})
				if err != nil {
					return nil, err
				}
				barrier := resp.GetBarrierStatus()
				return map[string]string{
					"tenant_id":   barrier.GetTenantId(),
					"sealed":      fmt.Sprint(barrier.GetSealed()),
					"initialized": fmt.Sprint(barrier.GetInitialized()),
					"strategy":    barrier.GetStrategy(),
				}, nil
			},
		},
	}
}

// parityHarnesses builds one harness per transport, each readied for op.
func parityHarnesses(t *testing.T, op tenantParityOp) (grpcSide, mcpSide *tenantParityHarness) {
	t.Helper()
	grpcSide, mcpSide = newTenantParityHarness(t), newTenantParityHarness(t)
	if op.before != nil {
		op.before(t, grpcSide)
		op.before(t, mcpSide)
	}
	return grpcSide, mcpSide
}

func TestTenantTransportsAgree(t *testing.T) {
	ops := tenantParityOps()
	require.Len(t, ops, 19, "every tenant tool has a parity case")
	for _, op := range ops {
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)
			before := grpcSide.snapshot()

			want, grpcErr := grpcSide.callGRPC(op, op.caller, op.subject)
			got, mcpErr := mcpSide.callMCP(t, op, op.caller, op.subject)

			if op.gap {
				assertSameDeclaredGap(t, grpcErr, mcpErr)
				assert.Equal(t, before, grpcSide.snapshot(), "the refused write changed nothing")
				assert.Equal(t, grpcSide.snapshot(), mcpSide.snapshot(), "both leave the tenants in the same state")
				return
			}
			require.NoError(t, grpcErr)
			require.NoError(t, mcpErr)

			require.Len(t, want, len(op.keys), "the gRPC view names every key")
			assert.Equal(t, want, got, "MCP answers what gRPC answers")
			assert.Equal(t, grpcSide.snapshot(), mcpSide.snapshot(), "both leave the tenants in the same state")
		})
	}
}

// assertSameDeclaredGap checks that gRPC and MCP both answer a write the
// pinned SDK cannot store with the declared gap and name the same fields, so
// an MCP tool that dropped or invented an argument names different ones.
func assertSameDeclaredGap(t *testing.T, grpcErr, mcpErr error) {
	t.Helper()
	require.Equal(t, codes.Unimplemented, status.Code(grpcErr), "gRPC: %v", grpcErr)
	require.Equal(t, codes.Unimplemented, status.Code(mcpErr), "MCP: %v", mcpErr)
	assert.Equal(t, declaredGapFields(grpcErr), declaredGapFields(mcpErr))
}

// declaredGapFields is a declared-gap message without its leading
// "tenant <id>: ", the one part that differs between two harnesses.
func declaredGapFields(err error) string {
	message := status.Convert(err).Message()
	if _, fields, found := strings.Cut(message, ": "); found {
		return fields
	}
	return message
}

func TestTenantTransportsAgreeOnMissingTenant(t *testing.T) {
	for _, op := range tenantParityOps() {
		if op.subject == "" {
			continue
		}
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)
			ghost := parityGhostTenant
			if op.tool == "tenant_create" {
				// A create names a tenant that does not exist yet; the
				// missing case for it is a name already taken.
				ghost = "tenant-b"
			}

			_, grpcErr := grpcSide.callGRPC(op, paritySystemTenant, ghost)
			_, mcpErr := mcpSide.callMCP(t, op, paritySystemTenant, ghost)

			want := op.missing
			if op.tool == "tenant_create" {
				want = codes.AlreadyExists
			}
			assert.Equal(t, want, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, want, status.Code(mcpErr), "MCP: %v", mcpErr)
		})
	}
}

func TestTenantTransportsAgreeOnInvalidInput(t *testing.T) {
	for _, op := range tenantParityOps() {
		if op.subject == "" {
			continue
		}
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)
			before := grpcSide.snapshot()

			_, grpcErr := grpcSide.callGRPC(op, paritySystemTenant, "")
			_, mcpErr := mcpSide.callMCP(t, op, paritySystemTenant, "")

			assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr), "MCP: %v", mcpErr)
			assert.Equal(t, before, grpcSide.snapshot())
			assert.Equal(t, before, mcpSide.snapshot())
		})
	}

	t.Run("tenant_check_quota/unknown resource", func(t *testing.T) {
		h := newTenantParityHarness(t)
		a := h.id(parityTenantA)
		_, grpcErr := h.server.CheckQuota(tokenCallerContext(a),
			&platformv1.CheckQuotaRequest{TenantId: a, Resource: "bogus", Amount: 1})
		_, mcpErr := h.tools.ExecuteTool(mcpTokenCtx(a, "tenant:read"), "tenant_check_quota",
			map[string]interface{}{"tenant_id": a, "resource_type": "bogus", "amount": 1})

		assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "gRPC: %v", grpcErr)
		assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr), "MCP: %v", mcpErr)
	})
}

// TestTenantCallerCannotReachAnotherTenant is the isolation rule: tenant A,
// holding every tenant scope, cannot read or change tenant B on either
// transport, and B's record, DEK and barrier backends are never reached.
func TestTenantCallerCannotReachAnotherTenant(t *testing.T) {
	for _, op := range tenantParityOps() {
		if op.systemOnly {
			continue
		}
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)
			before := grpcSide.snapshot()
			grpcCalls, mcpCalls := grpcSide.backendCalls(parityTenantB), mcpSide.backendCalls(parityTenantB)

			_, grpcErr := grpcSide.callGRPC(op, parityTenantA, parityTenantB)
			_, mcpErr := mcpSide.callMCP(t, op, parityTenantA, parityTenantB)

			assert.Equal(t, codes.PermissionDenied, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, codes.PermissionDenied, status.Code(mcpErr), "MCP: %v", mcpErr)
			assert.Equal(t, before, grpcSide.snapshot(), "gRPC changed nothing")
			assert.Equal(t, before, mcpSide.snapshot(), "MCP changed nothing")
			assert.Equal(t, grpcCalls, grpcSide.backendCalls(parityTenantB), "gRPC reached no backend for B")
			assert.Equal(t, mcpCalls, mcpSide.backendCalls(parityTenantB), "MCP reached no backend for B")
		})
	}
}

func TestTenantSystemOnlyMethodsRefuseOtherTenants(t *testing.T) {
	systemOnly := 0
	for _, op := range tenantParityOps() {
		if !op.systemOnly {
			continue
		}
		systemOnly++
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)
			before := grpcSide.snapshot()

			_, grpcErr := grpcSide.callGRPC(op, parityTenantA, op.subject)
			_, mcpErr := mcpSide.callMCP(t, op, parityTenantA, op.subject)

			assert.Equal(t, codes.PermissionDenied, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, codes.PermissionDenied, status.Code(mcpErr), "MCP: %v", mcpErr)
			// The by-name lookup answers with the own-name rule, which says
			// nothing about whether the name exists.
			want := "system tenant"
			if op.tool == "tenant_get_by_name" {
				want = tenant.ErrNameLookupDenied{}.Error()
			}
			assert.Contains(t, status.Convert(grpcErr).Message(), want)
			assert.Equal(t, before, grpcSide.snapshot())
			assert.Equal(t, before, mcpSide.snapshot())
		})
	}
	assert.Equal(t, 4, systemOnly, "list, get-by-name of another tenant, create and sync act across tenants")
}

func TestTenantSystemTenantActsOnEveryTenant(t *testing.T) {
	for _, op := range tenantParityOps() {
		if op.systemOnly {
			continue
		}
		t.Run(op.tool, func(t *testing.T) {
			grpcSide, mcpSide := parityHarnesses(t, op)

			want, grpcErr := grpcSide.callGRPC(op, paritySystemTenant, parityTenantB)
			got, mcpErr := mcpSide.callMCP(t, op, paritySystemTenant, parityTenantB)

			if op.gap {
				// Admitted: the refusal is the declared gap, not PermissionDenied.
				assertSameDeclaredGap(t, grpcErr, mcpErr)
			} else {
				require.NoError(t, grpcErr)
				require.NoError(t, mcpErr)
				assert.Equal(t, want, got)
			}
			assert.Equal(t, grpcSide.snapshot(), mcpSide.snapshot())
		})
	}
}

// TestTenantUpdateQuotasKeepsWhatTheRequestOmits: a quota update that changes
// one limit keeps every other limit, including MaxDiskGB, which has no wire
// field, on both transports. A tenant updates its own quotas here, as
// `platformctl tenant quotas set` sends only the sections it was given.
// The pinned SDK stores only the configured default limits, so each update
// restates the compute limits it carries and omits the network and storage
// sections and MaxDiskGB. It succeeds only if every omitted limit is kept: a
// transport that zeroed one would leave a limit the SDK cannot store and answer
// the declared gap instead.
func TestTenantUpdateQuotasKeepsWhatTheRequestOmits(t *testing.T) {
	cfg := tenant.DefaultConfig()
	want := tenant.TenantQuotas{
		Compute: cfg.DefaultComputeQuota,
		Network: cfg.DefaultNetworkQuota,
		Storage: cfg.DefaultStorageQuota,
	}
	compute := want.Compute

	update := map[string]func(h *tenantParityHarness, a string) error{
		"gRPC": func(h *tenantParityHarness, a string) error {
			_, err := h.server.UpdateQuotas(tokenCallerContext(a), &platformv1.UpdateQuotasRequest{
				TenantId: a,
				Compute: &platformv1.ComputeQuota{
					MaxVms: compute.MaxVMs, MaxContainers: compute.MaxContainers,
					MaxVcpus: compute.MaxVCPUs, MaxMemoryMb: compute.MaxMemoryMB,
				},
			})
			return err
		},
		"MCP": func(h *tenantParityHarness, a string) error {
			_, err := h.tools.ExecuteTool(mcpTokenCtx(a, "tenant:read", "tenant:write"), "tenant_update_quotas",
				map[string]interface{}{"tenant_id": a, "max_vms": compute.MaxVMs})
			return err
		},
	}
	for transport, call := range update {
		t.Run(transport, func(t *testing.T) {
			h := newTenantParityHarness(t)
			a := h.id(parityTenantA)

			require.NoError(t, call(h, a))

			got, err := h.manager.GetQuotas(context.Background(), a)
			require.NoError(t, err)
			assert.Equal(t, want, *got, "every omitted limit is kept")
		})
	}
}

// TestTenantUpdateQuotasMissingTenant: an update for a tenant that does not
// exist answers NotFound carrying the typed error, on both transports.
func TestTenantUpdateQuotasMissingTenant(t *testing.T) {
	h := newTenantParityHarness(t)
	system := h.id(paritySystemTenant)
	wantMessage := tenant.ErrTenantNotFound{ID: parityGhostTenant}.Error()

	_, grpcErr := h.server.UpdateQuotas(tokenCallerContext(system), &platformv1.UpdateQuotasRequest{
		TenantId: parityGhostTenant,
		Compute:  &platformv1.ComputeQuota{MaxVms: 25},
	})
	_, mcpErr := h.tools.ExecuteTool(mcpTokenCtx(system, "tenant:read", "tenant:write"), "tenant_update_quotas",
		map[string]interface{}{"tenant_id": parityGhostTenant, "max_vms": 25})

	assert.Equal(t, codes.NotFound, status.Code(grpcErr), "gRPC: %v", grpcErr)
	assert.Equal(t, codes.NotFound, status.Code(mcpErr), "MCP: %v", mcpErr)
	assert.Equal(t, wantMessage, status.Convert(grpcErr).Message())
	assert.Equal(t, wantMessage, status.Convert(mcpErr).Message())
}

// TestTenantBarrierInitRefusesShamir: a Shamir request used to be dropped and
// answered "initialized", so the caller believed it held shares it was never
// given. Both transports now refuse it before the barrier backend is called.
func TestTenantBarrierInitRefusesShamir(t *testing.T) {
	h := newTenantParityHarness(t)
	a := h.id(parityTenantA)
	calls := h.barriers.callsFor(a)

	_, grpcErr := h.server.InitTenantBarrier(tokenCallerContext(a),
		&platformv1.InitTenantBarrierRequest{TenantId: a, Threshold: 2, Shares: 3})
	_, mcpErr := h.tools.ExecuteTool(mcpTokenCtx(a, "tenant:write"), "platform_tenant_barrier_init",
		map[string]interface{}{"tenant_id": a, "threshold": 2, "shares": 3})

	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr), "gRPC: %v", grpcErr)
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr), "MCP: %v", mcpErr)
	assert.Contains(t, status.Convert(mcpErr).Message(), "threshold 2 of 3 shares")
	assert.Equal(t, calls, h.barriers.callsFor(a), "the barrier backend is never called")
}

// TestTenantServerAdmitsUnboundCaller: a caller with no tenant-bound identity
// (the Unix-socket operator) reaches any tenant and the cross-tenant methods.
func TestTenantServerAdmitsUnboundCaller(t *testing.T) {
	h := newTenantParityHarness(t)
	ctx := context.Background()

	_, err := h.server.GetTenant(ctx, &platformv1.GetTenantRequest{TenantId: h.id(parityTenantB)})
	require.NoError(t, err)
	_, err = h.server.ListTenants(ctx, &platformv1.ListTenantsRequest{})
	require.NoError(t, err)
}

// TestTenantServerWithoutSystemTenant: with no system tenant configured, no
// tenant-bound caller is taken for it, so the cross-tenant methods refuse
// everyone bound and a tenant reaches only itself.
func TestTenantServerWithoutSystemTenant(t *testing.T) {
	h := newTenantParityHarness(t)
	h.server.SetSystemTenant("")

	_, err := h.server.ListTenants(tokenCallerContext(""), &platformv1.ListTenantsRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "an empty tenant is not the unset system tenant")
	a := h.id(parityTenantA)
	_, err = h.server.GetTenant(tokenCallerContext(h.id(paritySystemTenant)), &platformv1.GetTenantRequest{TenantId: a})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = h.server.GetTenant(tokenCallerContext(a), &platformv1.GetTenantRequest{TenantId: a})
	assert.NoError(t, err)
}

// TestTenantGetByNameResolvesOwnTenantOnly: the name-keyed CLI resolves a
// name before every verb, so a tenant must resolve its own name, and then
// read its quotas by the ID it got back. Another tenant's name and a name
// that does not exist are refused alike, so the answer leaks no existence.
func TestTenantGetByNameResolvesOwnTenantOnly(t *testing.T) {
	h := newTenantParityHarness(t)
	a := h.id(parityTenantA)
	grpcCtx := tokenCallerContext(a)
	mcpCtx := mcpTokenCtx(a, "tenant:read")

	t.Run("own name over gRPC", func(t *testing.T) {
		resp, err := h.server.GetTenantByName(grpcCtx, &platformv1.GetTenantByNameRequest{Name: "tenant-a"})
		require.NoError(t, err)
		require.Equal(t, a, resp.GetTenant().GetId())

		_, err = h.server.GetQuotas(grpcCtx, &platformv1.GetQuotasRequest{TenantId: resp.GetTenant().GetId()})
		require.NoError(t, err)
	})

	t.Run("own name over MCP", func(t *testing.T) {
		out, err := h.tools.ExecuteTool(mcpCtx, "tenant_get_by_name", map[string]interface{}{"name": "tenant-a"})
		require.NoError(t, err)
		result, ok := out.(map[string]interface{})
		require.True(t, ok, "tenant_get_by_name answered %T", out)
		resolved := lookupResultPath(result, "id")
		require.Equal(t, a, resolved)

		_, err = h.tools.ExecuteTool(mcpCtx, "tenant_get_quotas", map[string]interface{}{"tenant_id": resolved})
		require.NoError(t, err)
	})

	denied := status.Error(codes.PermissionDenied, tenant.ErrNameLookupDenied{}.Error())
	for _, name := range []string{"tenant-b", parityGhostTenant} {
		t.Run("refuses "+name, func(t *testing.T) {
			_, grpcErr := h.server.GetTenantByName(grpcCtx, &platformv1.GetTenantByNameRequest{Name: name})
			_, mcpErr := h.tools.ExecuteTool(mcpCtx, "tenant_get_by_name", map[string]interface{}{"name": name})

			assert.Equal(t, denied.Error(), grpcErr.Error(), "gRPC")
			assert.Equal(t, denied.Error(), mcpErr.Error(), "MCP")
		})
	}

	t.Run("system tenant resolves every name", func(t *testing.T) {
		system := tokenCallerContext(h.id(paritySystemTenant))
		for _, label := range []string{paritySystemTenant, parityTenantA, parityTenantB} {
			resp, err := h.server.GetTenantByName(system, &platformv1.GetTenantByNameRequest{Name: parityTenantNames[label]})
			require.NoError(t, err, label)
			assert.Equal(t, h.id(label), resp.GetTenant().GetId())
		}
		_, err := h.server.GetTenantByName(system, &platformv1.GetTenantByNameRequest{Name: parityGhostTenant})
		assert.Equal(t, codes.NotFound, status.Code(err), "the system tenant learns a name is missing")
	})

	t.Run("without a system tenant a tenant still resolves its own name", func(t *testing.T) {
		h.server.SetSystemTenant("")
		_, err := h.server.GetTenantByName(grpcCtx, &platformv1.GetTenantByNameRequest{Name: "tenant-a"})
		assert.NoError(t, err)
		_, err = h.server.GetTenantByName(grpcCtx, &platformv1.GetTenantByNameRequest{Name: "tenant-b"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

// TestTenantCLIPathResolvesOwnTenant drives the calls `platformctl tenant
// show` and `quotas get` make — the SDK client's GetByNameDomain, then
// GetQuotas by the resolved ID — over a gRPC connection whose caller is bound
// to tenant A, as the daemon's auth interceptor binds a token.
func TestTenantCLIPathResolvesOwnTenant(t *testing.T) {
	h := newTenantParityHarness(t)
	a := h.id(parityTenantA)

	bindTenantA := func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(grpcapi.ContextWithAuthorizedContext(ctx, &platformtoken.AuthorizedContext{TenantID: a}), req)
	}
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer(grpc.UnaryInterceptor(bindTenantA))
	platformv1.RegisterTenantServiceServer(gs, h.server)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		assert.NoError(t, <-served)
	})

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(local.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	client := sdktenant.NewClientFromGRPC(platformv1.NewTenantServiceClient(conn))
	ctx := context.Background()

	own, err := client.GetByNameDomain(ctx, "tenant-a")
	require.NoError(t, err, "show resolves the caller's own tenant")
	require.Equal(t, a, own.ID)
	_, err = client.GetQuotas(ctx, own.ID)
	require.NoError(t, err, "quotas get reads it by the resolved ID")

	_, err = client.GetByNameDomain(ctx, "tenant-b")
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "another tenant's name stays refused")
}

func TestMCPServiceProviderTenantService(t *testing.T) {
	provider := &MCPServiceProvider{}
	assert.Nil(t, provider.TenantService(), "an unwired provider serves no TenantService")

	server := NewTenantGRPCServer()
	provider.SetTenantService(server)
	assert.Same(t, server, provider.TenantService())
}

func TestTenantIsolationErrorsNameWhatWasRefused(t *testing.T) {
	assert.Contains(t, tenant.ErrTenantForbidden{Requested: parityTenantB}.Error(), parityTenantB)
	assert.Contains(t, tenant.ErrTenantSystemOnly{Method: "ListTenants"}.Error(), "ListTenants")
	shamir := ErrTenantBarrierShamirUnsupported{Threshold: 2, Shares: 3}.Error()
	assert.Contains(t, shamir, "threshold 2 of 3 shares")
}

// The fakes must satisfy the SDK interfaces the manager calls.
var (
	_ tenant.TenantDEKClient     = (*memoryTenantDEKs)(nil)
	_ tenant.TenantBarrierClient = (*memoryTenantBarriers)(nil)
)
