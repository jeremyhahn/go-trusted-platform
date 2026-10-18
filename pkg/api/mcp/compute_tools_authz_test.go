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

package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// computeRecordingProvider answers every VM and container tool and records
// which provider method ran, so a test can tell a refused call (nothing
// recorded) from one that reached its handler.
type computeRecordingProvider struct {
	*mockServiceProvider
	calls []string
}

func (p *computeRecordingProvider) record(op string) map[string]interface{} {
	p.calls = append(p.calls, op)
	return map[string]interface{}{"op": op}
}

func (p *computeRecordingProvider) VMSnapshotCreate(context.Context, string, string) (interface{}, error) {
	return p.record("VMSnapshotCreate"), nil
}

func (p *computeRecordingProvider) VMSnapshotGet(context.Context, string, string) (interface{}, error) {
	return p.record("VMSnapshotGet"), nil
}

func (p *computeRecordingProvider) VMCreate(context.Context, VMCreateSpec) (interface{}, error) {
	return p.record("VMCreate"), nil
}

func (p *computeRecordingProvider) VMList(context.Context) (interface{}, error) {
	return p.record("VMList"), nil
}

func (p *computeRecordingProvider) VMGet(context.Context, string) (interface{}, error) {
	return p.record("VMGet"), nil
}

func (p *computeRecordingProvider) VMDelete(context.Context, string) (interface{}, error) {
	return p.record("VMDelete"), nil
}

func (p *computeRecordingProvider) VMStart(context.Context, string) (interface{}, error) {
	return p.record("VMStart"), nil
}

func (p *computeRecordingProvider) VMStop(context.Context, string) (interface{}, error) {
	return p.record("VMStop"), nil
}

func (p *computeRecordingProvider) VMReboot(context.Context, string) (interface{}, error) {
	return p.record("VMReboot"), nil
}

func (p *computeRecordingProvider) VMSnapshotList(context.Context, string) (interface{}, error) {
	return p.record("VMSnapshotList"), nil
}

func (p *computeRecordingProvider) VMSnapshotDelete(context.Context, string, string) error {
	p.record("VMSnapshotDelete")
	return nil
}

func (p *computeRecordingProvider) VMSnapshotRestore(context.Context, string, string) error {
	p.record("VMSnapshotRestore")
	return nil
}

func (p *computeRecordingProvider) VMAttest(context.Context, string, []byte, []int) (interface{}, error) {
	return p.record("VMAttest"), nil
}

func (p *computeRecordingProvider) VMAttestVerify(context.Context, string, *VMAttestVerifyMCPRequest) (interface{}, error) {
	return p.record("VMAttestVerify"), nil
}

func (p *computeRecordingProvider) VMMetrics(context.Context, string) (interface{}, error) {
	return p.record("VMMetrics"), nil
}

func (p *computeRecordingProvider) VMDiskAttach(context.Context, string, VMDiskAttachSpec) (interface{}, error) {
	return p.record("VMDiskAttach"), nil
}

func (p *computeRecordingProvider) VMDiskDetach(context.Context, string, string) error {
	p.record("VMDiskDetach")
	return nil
}

func (p *computeRecordingProvider) VMDiskResize(context.Context, string, string, uint64) error {
	p.record("VMDiskResize")
	return nil
}

func (p *computeRecordingProvider) VMLogsSnapshot(context.Context, string, int) (interface{}, error) {
	return p.record("VMLogsSnapshot"), nil
}

func (p *computeRecordingProvider) VMMigrate(context.Context, string, string, bool, uint64) (interface{}, error) {
	return p.record("VMMigrate"), nil
}

func (p *computeRecordingProvider) ContainerCreate(context.Context, string, string, map[string]interface{}) (interface{}, error) {
	return p.record("ContainerCreate"), nil
}

func (p *computeRecordingProvider) ContainerStart(context.Context, string) error {
	p.record("ContainerStart")
	return nil
}

func (p *computeRecordingProvider) ContainerStop(context.Context, string, int) error {
	p.record("ContainerStop")
	return nil
}

func (p *computeRecordingProvider) ContainerRemove(context.Context, string, bool) error {
	p.record("ContainerRemove")
	return nil
}

func (p *computeRecordingProvider) ContainerGet(context.Context, string) (interface{}, error) {
	return p.record("ContainerGet"), nil
}

func (p *computeRecordingProvider) ContainerList(context.Context, bool, map[string][]string, int) ([]interface{}, error) {
	return []interface{}{p.record("ContainerList")}, nil
}

func (p *computeRecordingProvider) ContainerLogs(context.Context, string, bool, bool, bool, string, bool) (string, error) {
	p.record("ContainerLogs")
	return "log line", nil
}

func (p *computeRecordingProvider) ContainerAttest(context.Context, string) (interface{}, error) {
	return p.record("ContainerAttest"), nil
}

func (p *computeRecordingProvider) ContainerExec(context.Context, string, []string, map[string]string, string, bool) (interface{}, error) {
	return p.record("ContainerExec"), nil
}

func (p *computeRecordingProvider) ContainerMetrics(context.Context, string) (interface{}, error) {
	return p.record("ContainerMetrics"), nil
}

var (
	_ VMProvider                  = (*computeRecordingProvider)(nil)
	_ VMOpsServiceProvider        = (*computeRecordingProvider)(nil)
	_ ContainerOpsServiceProvider = (*computeRecordingProvider)(nil)
)

// computeToolCase is one classified VM or container tool: the scope its gRPC
// ComputeService twin requires, arguments that pass the tool's validation,
// and the provider method it must reach.
type computeToolCase struct {
	tool     string
	resource string
	action   string
	args     map[string]interface{}
	reaches  string
}

var computeToolCases = []computeToolCase{
	{"vm_create", "vm", "write", map[string]interface{}{"name": "vm-1"}, "VMCreate"},
	{"vm_list", "vm", "read", map[string]interface{}{}, "VMList"},
	{"vm_get", "vm", "read", map[string]interface{}{"id": "vm-1"}, "VMGet"},
	{"vm_delete", "vm", "delete", map[string]interface{}{"id": "vm-1"}, "VMDelete"},
	{"vm_start", "vm", "write", map[string]interface{}{"id": "vm-1"}, "VMStart"},
	{"vm_stop", "vm", "write", map[string]interface{}{"id": "vm-1"}, "VMStop"},
	{"vm_reboot", "vm", "write", map[string]interface{}{"id": "vm-1"}, "VMReboot"},
	{"vm_snapshot_create", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "name": "snap-1"}, "VMSnapshotCreate"},
	{"vm_snapshot_list", "vm", "read", map[string]interface{}{"vm_id": "vm-1"}, "VMSnapshotList"},
	{"vm_snapshot_restore", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "snapshot_id": "snap-1"}, "VMSnapshotRestore"},
	{"vm_snapshot_delete", "vm", "delete", map[string]interface{}{"vm_id": "vm-1", "snapshot_id": "snap-1"}, "VMSnapshotDelete"},
	{"vm_attest", "vm", "read", map[string]interface{}{"vm_id": "vm-1", "nonce": "bm9uY2U="}, "VMAttest"},
	{"vm_attest_verify", "vm", "read", map[string]interface{}{
		"vm_id": "vm-1", "quote": "cXVvdGU=", "signature": "c2ln", "nonce": "bm9uY2U=",
	}, "VMAttestVerify"},
	{"vm_metrics", "vm", "read", map[string]interface{}{"vm_id": "vm-1"}, "VMMetrics"},
	{"vm_logs", "vm", "read", map[string]interface{}{"vm_id": "vm-1"}, "VMLogsSnapshot"},
	{"vm_disk_attach", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "path": "/var/lib/disk.qcow2"}, "VMDiskAttach"},
	{"vm_disk_detach", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "disk_id": "disk-1"}, "VMDiskDetach"},
	{"vm_disk_resize", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "disk_id": "disk-1", "new_size_gb": float64(20)}, "VMDiskResize"},
	{"vm_migrate", "vm", "write", map[string]interface{}{"vm_id": "vm-1", "destination_host": "node-2"}, "VMMigrate"},
	{"container_create", "container", "write", map[string]interface{}{"name": "web", "image": "nginx:latest"}, "ContainerCreate"},
	{"container_start", "container", "write", map[string]interface{}{"id": "c-1"}, "ContainerStart"},
	{"container_stop", "container", "write", map[string]interface{}{"id": "c-1"}, "ContainerStop"},
	{"container_exec", "container", "write", map[string]interface{}{"id": "c-1", "command": []interface{}{"ls"}}, "ContainerExec"},
	{"container_remove", "container", "delete", map[string]interface{}{"id": "c-1"}, "ContainerRemove"},
	{"container_get", "container", "read", map[string]interface{}{"id": "c-1"}, "ContainerGet"},
	{"container_list", "container", "read", map[string]interface{}{}, "ContainerList"},
	{"container_logs", "container", "read", map[string]interface{}{"id": "c-1"}, "ContainerLogs"},
	{"container_metrics", "container", "read", map[string]interface{}{"id": "c-1"}, "ContainerMetrics"},
	{"container_attest", "container", "read", map[string]interface{}{"id": "c-1"}, "ContainerAttest"},
}

// callComputeTool calls tool through the server's tools/call path, which
// authorizes before it executes, with a backend granting exactly granted.
func callComputeTool(t *testing.T, tc computeToolCase, granted string) (*mcpwire.JSONRPCResponse, *computeRecordingProvider, *mockAuthorizationService) {
	t.Helper()
	provider := &computeRecordingProvider{mockServiceProvider: newMockServiceProvider()}
	authz := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return resource+":"+action == granted, nil
		},
	}
	server := NewServer(provider, &Config{AuthorizationService: authz}, newTestLogger())

	resp := server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      tc.tool,
			"arguments": tc.args,
			"_token":    "caller-token",
		},
	})
	require.NotNil(t, resp)
	return resp, provider, authz
}

// TestComputeToolsAreClassified pins each classified VM and container tool
// to the scope of its gRPC ComputeService twin (#304).
func TestComputeToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for _, tc := range computeToolCases {
		got, ok := checker.toolPermissions[tc.tool]
		require.True(t, ok, "%s must have an explicit permission entry", tc.tool)
		assert.Equal(t, tc.resource+":"+tc.action, got, "%s", tc.tool)
	}
}

// TestComputeToolsAnswerUnderTheirScope: a caller holding the tool's scope
// reaches the provider and gets its answer.
func TestComputeToolsAnswerUnderTheirScope(t *testing.T) {
	for _, tc := range computeToolCases {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider, authz := callComputeTool(t, tc, tc.resource+":"+tc.action)

			require.Nil(t, resp.Error, "%s with %s:%s must be served", tc.tool, tc.resource, tc.action)
			assert.NotNil(t, resp.Result)
			assert.Equal(t, []string{tc.reaches}, provider.calls)
			assert.Equal(t, tc.resource, authz.lastResource)
			assert.Equal(t, tc.action, authz.lastAction)
		})
	}
}

// TestComputeToolsRefuseWithoutTheirScope: a caller holding a different
// action on the same resource is denied, and the handler never runs.
func TestComputeToolsRefuseWithoutTheirScope(t *testing.T) {
	otherAction := map[string]string{"read": "write", "write": "read", "delete": "write"}

	for _, tc := range computeToolCases {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider, _ := callComputeTool(t, tc, tc.resource+":"+otherAction[tc.action])

			require.NotNil(t, resp.Error, "%s must be refused without %s:%s", tc.tool, tc.resource, tc.action)
			assert.Empty(t, provider.calls, "a refused call must not reach the provider")
		})
	}
}

// TestComputeLifecycleToolsStayRefused: vm_update, vm_suspend, vm_resume and
// vm_snapshot_get have no gRPC twin, so each is refused as unclassified even
// by a backend that grants everything.
func TestComputeLifecycleToolsStayRefused(t *testing.T) {
	checker := NewAuthorizationChecker(allowAllAuthService{}, nil)

	for _, tool := range []string{
		"vm_update", "vm_suspend", "vm_resume", "vm_snapshot_get",
	} {
		_, err := checker.AuthorizeTool(context.Background(), tool, "any-token")
		require.NotNil(t, err, "%s must stay refused", tool)
		assert.Equal(t, AuthErrorToolNotClassified, err.Type, "%s", tool)
	}
}
