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

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// The switch, cluster and registry tools (#304) answer under the scope of
// their gRPC twin. None of the three gRPC services is tenant-scoped: switch
// ports, cluster nodes and registry artifacts are platform-level, so the MCP
// tools carry no tenancy either and these tests have no tenant A/B case.

// scopeGrantAuthz grants its caller exactly one scope, so a tool call
// passes the MCP server's authorization check only when the tool's catalog
// scope is that scope.
type scopeGrantAuthz struct{ scope string }

func (a scopeGrantAuthz) CheckPermission(_ context.Context, _, resource, action string) (bool, error) {
	return resource+":"+action == a.scope, nil
}

// callMCPTool sends one tools/call through the MCP server's HTTP handler,
// in memory, as a caller holding scope, and returns the JSON-RPC answer.
func callMCPTool(t *testing.T, provider mcp.ServiceProvider, scope, tool string, args map[string]interface{}) mcpwire.JSONRPCResponse {
	t.Helper()
	config := mcp.DefaultConfig()
	config.AuthorizationService = scopeGrantAuthz{scope: scope}
	handler := mcp.NewServer(provider, config, logging.DefaultLogger()).Handler()

	body, err := json.Marshal(mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": tool, "arguments": args},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer infra-tools-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp mcpwire.JSONRPCResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// mcpToolResult returns the output of a successful tool call, read from
// the CallToolResult's text block, as a JSON object.
func mcpToolResult(t *testing.T, resp mcpwire.JSONRPCResponse) map[string]interface{} {
	t.Helper()
	require.Nil(t, resp.Error, "tool answered an error")
	output, err := mcpwire.ToolOutput(resp.Result)
	require.NoError(t, err)
	result, ok := output.(map[string]interface{})
	require.True(t, ok, "tool output is %T, want an object", output)
	return result
}

// mcpToolErrorCode returns the JSON-RPC error code of a failed tool call.
func mcpToolErrorCode(t *testing.T, resp mcpwire.JSONRPCResponse) int {
	t.Helper()
	require.NotNil(t, resp.Error, "tool answered %v, want an error", resp.Result)
	return resp.Error.Code
}

// assertSameResponseClass checks that the MCP answer carries the class gRPC
// answered with for the same input.
func assertSameResponseClass(t *testing.T, grpcErr error, want codes.Code, resp mcpwire.JSONRPCResponse) {
	t.Helper()
	require.Equal(t, want, status.Code(grpcErr), "gRPC class: %v", grpcErr)
	assert.Equal(t, mcpwire.CodeForClass(want), mcpToolErrorCode(t, resp), "MCP class for %s", want)
}

// fakeSwitchManager is an in-memory switch with one access port, eth1, on
// VLAN 10. Ports it does not have answer ErrPortNotFound as pkg/switch does.
//
// mu guards ports and calls: a transport serves each call on its own
// goroutine while the test reads the record.
type fakeSwitchManager struct {
	mu    sync.Mutex
	ports map[string]*switchwire.PortStatus
	// calls records every port operation the manager was asked for, in
	// order, so two managers can be compared call for call.
	calls []string
}

func newFakeSwitchManager() *fakeSwitchManager {
	return &fakeSwitchManager{ports: map[string]*switchwire.PortStatus{
		"eth1": {Port: "eth1", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true},
	}}
}

// record appends call to the call log and returns the named port. The
// caller holds m.mu.
func (m *fakeSwitchManager) record(call, name string) (*switchwire.PortStatus, error) {
	m.calls = append(m.calls, call)
	p, ok := m.ports[name]
	if !ok {
		return nil, switchmgmt.ErrPortNotFound{Port: name}
	}
	return p, nil
}

// snapshot returns a copy of the call log and of every port's state, taken
// under the lock.
func (m *fakeSwitchManager) snapshot() ([]string, map[string]switchwire.PortStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ports := make(map[string]switchwire.PortStatus, len(m.ports))
	for name, port := range m.ports {
		ports[name] = *port
	}
	return slices.Clone(m.calls), ports
}

func (m *fakeSwitchManager) SetPortVLAN(_ context.Context, port string, vlanID uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.record(fmt.Sprintf("SetPortVLAN %s %d", port, vlanID), port)
	if err != nil {
		return err
	}
	p.AccessVLAN = vlanID
	return nil
}

func (m *fakeSwitchManager) GetPortVLAN(_ context.Context, port string) (uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.ports[port]
	if !ok {
		return 0, switchmgmt.ErrPortNotFound{Port: port}
	}
	return p.AccessVLAN, nil
}

func (m *fakeSwitchManager) GetPortStatus(_ context.Context, port string) (*switchwire.PortStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.record("GetPortStatus "+port, port)
	if err != nil {
		return nil, err
	}
	snapshot := *p
	return &snapshot, nil
}

func (m *fakeSwitchManager) ListPorts(_ context.Context) ([]*switchwire.PortStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "ListPorts")
	ports := make([]*switchwire.PortStatus, 0, len(m.ports))
	for _, p := range m.ports {
		snapshot := *p
		ports = append(ports, &snapshot)
	}
	return ports, nil
}

func (m *fakeSwitchManager) EnablePort(_ context.Context, port string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.record("EnablePort "+port, port)
	if err != nil {
		return err
	}
	p.Enabled = true
	return nil
}

func (m *fakeSwitchManager) DisablePort(_ context.Context, port string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.record("DisablePort "+port, port)
	if err != nil {
		return err
	}
	p.Enabled = false
	return nil
}

func (m *fakeSwitchManager) Close() error { return nil }

// fakeSwitchService knows one switch, core-1, and answers ErrManagerNotFound
// for any other name, as switchmgmt.Service does. managerCalls counts the
// lookups every switch tool makes before it touches a port; mu guards it.
type fakeSwitchService struct {
	mu           sync.Mutex
	managers     map[string]*fakeSwitchManager
	managerCalls int
}

func newFakeSwitchService() *fakeSwitchService {
	return &fakeSwitchService{managers: map[string]*fakeSwitchManager{"core-1": newFakeSwitchManager()}}
}

// lookups returns the number of Manager calls, read under the lock.
func (s *fakeSwitchService) lookups() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.managerCalls
}

func (s *fakeSwitchService) Manager(name string) (switchmgmt.Manager, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.managerCalls++
	m, ok := s.managers[name]
	if !ok {
		return nil, switchmgmt.ErrManagerNotFound{Name: name}
	}
	return m, nil
}

// countingRegistryService counts the calls the registry tools make into a
// registry service.
type countingRegistryService struct {
	grpcapi.RegistryService
	calls int
}

func (s *countingRegistryService) List(ctx context.Context, req *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	s.calls++
	return s.RegistryService.List(ctx, req)
}

func (s *countingRegistryService) Inspect(ctx context.Context, req *grpcapi.RegistryInspectRequest) (*grpcapi.RegistryInspectResponse, error) {
	s.calls++
	return s.RegistryService.Inspect(ctx, req)
}

func (s *countingRegistryService) Delete(ctx context.Context, req *grpcapi.RegistryDeleteRequest) (*grpcapi.RegistryDeleteResponse, error) {
	s.calls++
	return s.RegistryService.Delete(ctx, req)
}

func (s *countingRegistryService) Status(ctx context.Context) (*grpcapi.RegistryStatusResponse, error) {
	s.calls++
	return s.RegistryService.Status(ctx)
}

// newSeededRegistry returns an in-memory registry holding one artifact,
// platform/firmware:v1.
func newSeededRegistry(*testing.T) *seededRegistryService {
	return &seededRegistryService{artifact: &grpcapi.RegistryArtifact{
		ID:         "platform/firmware:v1",
		Repository: "platform/firmware",
		Tag:        "v1",
		Digest:     "sha256:f1rmware",
		Size:       int64(len("firmware image")),
		State:      grpcapi.ArtifactStateAvailable,
	}}
}

// seededRegistryService holds one artifact and answers the four calls the
// registry tools make. A lookup that misses answers ErrArtifactNotFound, as
// pkg/registry's gRPC adapter does; the tools never push or pull, so those
// calls are left to the embedded interface.
type seededRegistryService struct {
	grpcapi.RegistryService
	artifact *grpcapi.RegistryArtifact
}

func (s *seededRegistryService) find(repository, reference, digest string) (*grpcapi.RegistryArtifact, error) {
	a := s.artifact
	if repository == a.Repository && (reference == a.Tag || digest == a.Digest) {
		return a, nil
	}
	return nil, grpcapi.ErrArtifactNotFound{Repository: repository, Reference: reference}
}

func (s *seededRegistryService) List(context.Context, *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	return &grpcapi.RegistryListResponse{Artifacts: []*grpcapi.RegistryArtifact{s.artifact}, Total: 1}, nil
}

func (s *seededRegistryService) Inspect(_ context.Context, req *grpcapi.RegistryInspectRequest) (*grpcapi.RegistryInspectResponse, error) {
	a, err := s.find(req.Repository, req.Reference, req.Digest)
	if err != nil {
		return nil, err
	}
	return &grpcapi.RegistryInspectResponse{Detail: &grpcapi.RegistryArtifactDetail{Artifact: a, Tags: []string{a.Tag}}}, nil
}

func (s *seededRegistryService) Delete(_ context.Context, req *grpcapi.RegistryDeleteRequest) (*grpcapi.RegistryDeleteResponse, error) {
	a, err := s.find(req.Repository, req.Reference, req.Digest)
	if err != nil {
		return nil, err
	}
	return &grpcapi.RegistryDeleteResponse{Digest: a.Digest, BytesFreed: a.Size}, nil
}

func (s *seededRegistryService) Status(context.Context) (*grpcapi.RegistryStatusResponse, error) {
	return &grpcapi.RegistryStatusResponse{
		Health:  grpcapi.RegistryHealthStatusHealthy,
		Storage: &grpcapi.RegistryStorageStats{ArtifactCount: 1},
	}, nil
}

// infraToolHarness is one tool group's MCP provider and a count of the
// calls that reached the group's backing service.
type infraToolHarness struct {
	provider mcp.ServiceProvider
	calls    func() int
}

func newSwitchToolHarness(*testing.T) infraToolHarness {
	switches := newFakeSwitchService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	provider.SetSwitchServer(NewSwitchGRPCService(logging.DefaultLogger(), switches))
	return infraToolHarness{
		provider: provider,
		calls:    switches.lookups,
	}
}

func newClusterToolHarness(*testing.T) infraToolHarness {
	fake := &fakeClusterServicer{statusInfo: runningStatus(), nodes: stockNodes(), nodeID: 1, leader: true}
	return infraToolHarness{
		provider: newProviderWithCluster(fake),
		calls: func() int {
			return fake.bootstrapCalled + fake.joinCalled + fake.leaveCalled + fake.statusCalls + fake.nodeCalls
		},
	}
}

func newRegistryToolHarness(t *testing.T) infraToolHarness {
	reg := &countingRegistryService{RegistryService: newSeededRegistry(t)}
	return infraToolHarness{
		provider: newProviderWithRegistry(reg),
		calls:    func() int { return reg.calls },
	}
}

// TestInfraToolsAnswerOnlyUnderTheirScope calls every switch, cluster and
// registry tool twice through the MCP server: as a caller holding the
// tool's scope, which gets the answer, and as a caller holding a
// neighbouring scope, which is refused before the tool's handler runs.
func TestInfraToolsAnswerOnlyUnderTheirScope(t *testing.T) {
	port := map[string]interface{}{"switch_name": "core-1", "port_name": "eth1"}
	artifact := map[string]interface{}{"repository": "platform/firmware", "reference": "v1"}

	cases := []struct {
		tool    string
		scope   string
		denied  string
		args    map[string]interface{}
		harness func(*testing.T) infraToolHarness
	}{
		{"switch_list_ports", "switch:read", "cluster:read", map[string]interface{}{"switch_name": "core-1"}, newSwitchToolHarness},
		{"switch_port_status", "switch:read", "cluster:read", port, newSwitchToolHarness},
		{"switch_enable_port", "switch:write", "switch:read", port, newSwitchToolHarness},
		{"switch_disable_port", "switch:write", "switch:read", port, newSwitchToolHarness},
		{"switch_set_vlan", "switch:write", "switch:read",
			map[string]interface{}{"switch_name": "core-1", "port_name": "eth1", "vlan_id": 20}, newSwitchToolHarness},

		{"platform_cluster_status", "cluster:read", "switch:read", nil, newClusterToolHarness},
		{"platform_cluster_list_nodes", "cluster:read", "switch:read", nil, newClusterToolHarness},
		{"platform_cluster_bootstrap", "cluster:write", "cluster:read",
			map[string]interface{}{"cluster_name": "alpha", "node_name": "node-1"}, newClusterToolHarness},
		{"platform_cluster_join", "cluster:write", "cluster:read",
			map[string]interface{}{"node_name": "node-2", "seed_addresses": []string{"10.0.0.2:7001"}}, newClusterToolHarness},
		{"platform_cluster_leave", "cluster:write", "cluster:read", nil, newClusterToolHarness},

		{"platform_registry_status", "registry:read", "cluster:read", nil, newRegistryToolHarness},
		{"platform_registry_list", "registry:read", "cluster:read", nil, newRegistryToolHarness},
		{"platform_registry_inspect", "registry:read", "cluster:read", artifact, newRegistryToolHarness},
		{"platform_registry_delete", "registry:delete", "registry:write", artifact, newRegistryToolHarness},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			allowed := tc.harness(t)
			mcpToolResult(t, callMCPTool(t, allowed.provider, tc.scope, tc.tool, tc.args))
			assert.Positive(t, allowed.calls(), "the tool's handler never reached its service")

			denied := tc.harness(t)
			resp := callMCPTool(t, denied.provider, tc.denied, tc.tool, tc.args)
			assert.Equal(t, mcpwire.PermissionDenied, mcpToolErrorCode(t, resp))
			assert.Zero(t, denied.calls(), "a refused call reached the tool's service")
		})
	}
}

// TestInfraToolsUnwiredAnswerUnavailable pins the class the cluster and
// registry tools answer with while their service is not wired into the
// daemon to Unavailable, the class every other MCP tool, REST (503) and QUIC
// give for an unwired service. The switch tools answer Unimplemented instead,
// as a host without SwitchService does on every transport
// (TestSwitchMCPUnwiredAnswersUnimplemented).
func TestInfraToolsUnwiredAnswerUnavailable(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	for tool, scope := range map[string]string{
		"platform_cluster_status":  "cluster:read",
		"platform_registry_status": "registry:read",
	} {
		t.Run(tool, func(t *testing.T) {
			resp := callMCPTool(t, provider, scope, tool, map[string]interface{}{"switch_name": "core-1"})
			assert.Equal(t, mcpwire.CodeForClass(codes.Unavailable), mcpToolErrorCode(t, resp))
		})
	}
}

// TestClusterToolsMatchGRPC drives the cluster tools and the gRPC
// ClusterService against the same cluster servicer and compares their
// answers.
func TestClusterToolsMatchGRPC(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClusterServicer{statusInfo: runningStatus(), nodes: stockNodes(), nodeID: 1, leader: true}
	grpcSvc := grpcapi.NewClusterGRPCService(logging.DefaultLogger(), newTestClusterBackend(fake))
	provider := newProviderWithCluster(fake)

	t.Run("not found", func(t *testing.T) {
		fake.leaveErr = grpcapi.ErrNodeNotInCluster{}
		t.Cleanup(func() { fake.leaveErr = nil })

		_, err := grpcSvc.Leave(ctx, &platformv1.LeaveClusterRequest{})
		resp := callMCPTool(t, provider, "cluster:write", "platform_cluster_leave", nil)
		assertSameResponseClass(t, err, codes.NotFound, resp)
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err := grpcSvc.Join(ctx, &platformv1.JoinClusterRequest{NodeName: "node-2"})
		resp := callMCPTool(t, provider, "cluster:write", "platform_cluster_join", map[string]interface{}{"node_name": "node-2"})
		assertSameResponseClass(t, err, codes.InvalidArgument, resp)
	})

	t.Run("not initialized", func(t *testing.T) {
		fake.nodesErr = grpcapi.ErrClusterNotInitialized{}
		t.Cleanup(func() { fake.nodesErr = nil })

		_, err := grpcSvc.ListNodes(ctx, &platformv1.ListClusterNodesRequest{})
		resp := callMCPTool(t, provider, "cluster:read", "platform_cluster_list_nodes", nil)
		assertSameResponseClass(t, err, codes.FailedPrecondition, resp)
	})

	t.Run("leader cannot leave", func(t *testing.T) {
		fake.leaveErr = grpcapi.ErrCannotLeaveAsLeader{}
		t.Cleanup(func() { fake.leaveErr = nil })

		_, err := grpcSvc.Leave(ctx, &platformv1.LeaveClusterRequest{})
		resp := callMCPTool(t, provider, "cluster:write", "platform_cluster_leave", nil)
		assertSameResponseClass(t, err, codes.FailedPrecondition, resp)
	})
}

// TestRegistryToolsMatchGRPC drives the registry tools and the gRPC
// RegistryService against the same in-memory registry and compares their
// answers.
func TestRegistryToolsMatchGRPC(t *testing.T) {
	ctx := context.Background()
	reg := newSeededRegistry(t)
	grpcSvc := grpcapi.NewRegistryGRPCService(logging.DefaultLogger(), reg)
	provider := newProviderWithRegistry(reg)

	t.Run("success", func(t *testing.T) {
		list, err := grpcSvc.List(ctx, &platformv1.ListArtifactsRequest{})
		require.NoError(t, err)
		result := mcpToolResult(t, callMCPTool(t, provider, "registry:read", "platform_registry_list", nil))
		assert.EqualValues(t, list.GetTotal(), result["total"])

		inspect, err := grpcSvc.Inspect(ctx, &platformv1.InspectArtifactRequest{Repository: "platform/firmware", Reference: "v1"})
		require.NoError(t, err)
		result = mcpToolResult(t, callMCPTool(t, provider, "registry:read", "platform_registry_inspect",
			map[string]interface{}{"repository": "platform/firmware", "reference": "v1"}))
		artifact, ok := result["artifact"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, inspect.GetDetail().GetArtifact().GetDigest(), artifact["digest"])
		assert.Equal(t, inspect.GetDetail().GetArtifact().GetTag(), artifact["tag"])
	})

	t.Run("not found", func(t *testing.T) {
		_, err := grpcSvc.Inspect(ctx, &platformv1.InspectArtifactRequest{Repository: "platform/missing", Reference: "v1"})
		resp := callMCPTool(t, provider, "registry:read", "platform_registry_inspect",
			map[string]interface{}{"repository": "platform/missing", "reference": "v1"})
		assertSameResponseClass(t, err, codes.NotFound, resp)

		_, err = grpcSvc.Delete(ctx, &platformv1.DeleteArtifactRequest{Repository: "platform/missing", Reference: "v1"})
		resp = callMCPTool(t, provider, "registry:delete", "platform_registry_delete",
			map[string]interface{}{"repository": "platform/missing", "reference": "v1"})
		assertSameResponseClass(t, err, codes.NotFound, resp)
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err := grpcSvc.Inspect(ctx, &platformv1.InspectArtifactRequest{Reference: "v1"})
		resp := callMCPTool(t, provider, "registry:read", "platform_registry_inspect",
			map[string]interface{}{"reference": "v1"})
		assertSameResponseClass(t, err, codes.InvalidArgument, resp)

		_, err = grpcSvc.Delete(ctx, &platformv1.DeleteArtifactRequest{Repository: "platform/firmware"})
		resp = callMCPTool(t, provider, "registry:delete", "platform_registry_delete",
			map[string]interface{}{"repository": "platform/firmware"})
		assertSameResponseClass(t, err, codes.InvalidArgument, resp)
	})
}

// TestDaemonInfraErrorsCarryGRPCClass covers the daemon provider's own
// errors, which a tool returns without passing the mcp package's sentinel
// table: they must carry the class gRPC answers with for the same fault.
func TestDaemonInfraErrorsCarryGRPCClass(t *testing.T) {
	ctx := context.Background()
	unwired := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := unwired.RegistryStatus(ctx)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	registry := newProviderWithRegistry(newSeededRegistry(t))
	_, err = registry.RegistryInspect(ctx, "", "v1", "", false, false)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = registry.RegistryDelete(ctx, "platform/firmware", "", "", false)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = registry.RegistryInspect(ctx, "platform/missing", "v1", "", false, false)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// A failure gRPC has no class for is Internal.
	unclassified := errors.New("registry: disk full")
	assert.Equal(t, codes.Internal, status.Code(ErrRegistryServiceFailed{Cause: unclassified}))
}
