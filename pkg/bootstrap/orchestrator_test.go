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

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
)

// --- mock deployer ---

type mockDeployer struct {
	deployErr   error
	teardownErr error
	deployCalls atomic.Int64
	manifest    *container.Manifest
}

func (m *mockDeployer) Deploy(_ context.Context, manifest *container.Manifest) error {
	m.deployCalls.Add(1)
	m.manifest = manifest
	return m.deployErr
}

func (m *mockDeployer) Teardown(_ context.Context) error {
	return m.teardownErr
}

// --- mock health checker ---

type mockHealthChecker struct {
	err error
}

func (m *mockHealthChecker) Check(_ context.Context, _ string) error {
	return m.err
}

// --- mock BMC factory ---

type mockBMCFactory struct {
	client bmc.Client
	err    error
}

func (m *mockBMCFactory) NewClient(_ *bmc.Config) (bmc.Client, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

// --- helpers ---

func orchTestLogger() *slog.Logger {
	return slog.Default()
}

func minimalConfig() *BootstrapConfig {
	return &BootstrapConfig{
		Deployer: DeployerConfig{Host: "deploy-host"},
		ProvisioningNetwork: ProvisioningNetwork{
			Subnet: "172.16.0.0/24",
		},
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp1",
				Role:     RoleControlPlane,
				MACs:      []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}
}

func multiNodeConfig() *BootstrapConfig {
	cfg := minimalConfig()
	cfg.Nodes = append(cfg.Nodes,
		NodeConfig{
			Hostname: "gw1",
			Role:     RoleGateway,
			MACs:      []string{"aa:bb:cc:dd:ee:02"},
		},
		NodeConfig{
			Hostname: "w1",
			Role:     RoleWorker,
			MACs:      []string{"aa:bb:cc:dd:ee:03"},
		},
	)
	return cfg
}

// --- NewOrchestrator tests ---

func TestNewOrchestrator_NilConfig(t *testing.T) {
	_, err := NewOrchestrator(OrchestratorParams{
		Config:     nil,
		BMCFactory: &mockBMCFactory{},
		Logger:     orchTestLogger(),
	})
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	var target ErrNilOrchestratorConfig
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrNilOrchestratorConfig, got %T: %v", err, err)
	}
}

func TestNewOrchestrator_NilBMCFactory(t *testing.T) {
	_, err := NewOrchestrator(OrchestratorParams{
		Config:     minimalConfig(),
		BMCFactory: nil,
		Logger:     orchTestLogger(),
	})
	if err == nil {
		t.Fatal("expected error for nil BMC factory")
	}
	var target ErrNilBMCFactory
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrNilBMCFactory, got %T: %v", err, err)
	}
}

func TestNewOrchestrator_Valid(t *testing.T) {
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     minimalConfig(),
		BMCFactory: &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:     orchTestLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o == nil {
		t.Fatal("orchestrator should not be nil")
	}
	if o.config == nil {
		t.Fatal("config should be set")
	}
	if o.healthChk == nil {
		t.Fatal("health checker should default to httpHealthChecker")
	}
}

func TestNewOrchestrator_DefaultLogger(t *testing.T) {
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     minimalConfig(),
		BMCFactory: &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:     nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.logger == nil {
		t.Fatal("logger should default when nil")
	}
}

// --- Discover tests ---

func TestOrchestrator_Discover_ManualNodes(t *testing.T) {
	cfg := minimalConfig()
	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	discovered, err := o.Discover(ctx)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(discovered) != 1 {
		t.Fatalf("expected 1 discovered node, got %d", len(discovered))
	}
	if discovered[0].Hostname != "cp1" {
		t.Errorf("expected hostname cp1, got %s", discovered[0].Hostname)
	}
	if len(discovered[0].DiscoveredMACs) != 1 || discovered[0].DiscoveredMACs[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("expected MACs [aa:bb:cc:dd:ee:01], got %v", discovered[0].DiscoveredMACs)
	}
	if discovered[0].BMCManaged {
		t.Error("manual node should not be BMC managed")
	}
}

func TestOrchestrator_Discover_EmptyNodes(t *testing.T) {
	cfg := minimalConfig()
	cfg.Nodes = nil

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = o.Discover(ctx)
	if err == nil {
		t.Fatal("expected error for empty nodes")
	}
}

// --- Run tests ---

func TestOrchestrator_Run_MinimalConfig(t *testing.T) {
	cfg := minimalConfig()
	deployer := &mockDeployer{}
	healthChk := &mockHealthChecker{err: nil}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if result.Phase != "complete" {
		t.Errorf("expected phase complete, got %s", result.Phase)
	}
	if !result.ControlPlaneReady {
		t.Error("control plane should be ready")
	}
	if !result.ContainerDeployed {
		t.Error("container should be deployed")
	}
	if !result.ContainerTornDown {
		t.Error("container should be torn down")
	}
	if result.Duration == 0 {
		t.Error("duration should be non-zero")
	}
	if len(result.Nodes) != 1 {
		t.Fatalf("expected 1 node result, got %d", len(result.Nodes))
	}
	if result.Nodes[0].Status != nodeStatusInstalled {
		t.Errorf("expected status installed, got %s", result.Nodes[0].Status)
	}
}

func TestOrchestrator_Run_DeployFailure(t *testing.T) {
	cfg := minimalConfig()
	deployErr := errors.New("deploy boom")
	deployer := &mockDeployer{deployErr: deployErr}
	healthChk := &mockHealthChecker{}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err == nil {
		t.Fatal("expected error from deploy failure")
	}

	var bf ErrBootstrapFailed
	if !errors.As(err, &bf) {
		t.Fatalf("expected ErrBootstrapFailed, got %T: %v", err, err)
	}
	if bf.Phase != phaseDeploy {
		t.Errorf("expected phase %s, got %s", phaseDeploy, bf.Phase)
	}
	if result.ContainerDeployed {
		t.Error("container should not be marked deployed on failure")
	}
}

func TestOrchestrator_Run_HealthCheckFailure(t *testing.T) {
	cfg := minimalConfig()
	deployer := &mockDeployer{}
	healthChk := &mockHealthChecker{err: errors.New("unhealthy")}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cancel immediately to make the context.Done() fire on first tick.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := o.Run(ctx)
	if err == nil {
		t.Fatal("expected error from health check failure")
	}

	var bf ErrBootstrapFailed
	if !errors.As(err, &bf) {
		t.Fatalf("expected ErrBootstrapFailed, got %T: %v", err, err)
	}

	// The node should be marked as failed.
	found := false
	for _, n := range result.Nodes {
		if n.Hostname == "cp1" && n.Status == nodeStatusFailed {
			found = true
		}
	}
	if !found {
		t.Error("expected cp1 to have failed status")
	}
}

func TestOrchestrator_Run_NoDeployer(t *testing.T) {
	cfg := minimalConfig()
	healthChk := &mockHealthChecker{err: nil}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      nil,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if result.ContainerDeployed {
		t.Error("container should not be deployed when deployer is nil")
	}
	if result.Phase != "complete" {
		t.Errorf("expected phase complete, got %s", result.Phase)
	}
}

func TestOrchestrator_Run_TeardownFailureNonFatal(t *testing.T) {
	cfg := minimalConfig()
	deployer := &mockDeployer{teardownErr: errors.New("teardown boom")}
	healthChk := &mockHealthChecker{err: nil}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err != nil {
		t.Fatalf("teardown failure should not be fatal, got: %v", err)
	}

	if result.ContainerTornDown {
		t.Error("container should not be marked torn down on failure")
	}
	if result.Phase != "complete" {
		t.Errorf("expected phase complete, got %s", result.Phase)
	}
}

func TestOrchestrator_Validate_NoControlPlane(t *testing.T) {
	cfg := minimalConfig()
	cfg.Nodes = []NodeConfig{
		{
			Hostname: "w1",
			Role:     RoleWorker,
			MACs:      []string{"aa:bb:cc:dd:ee:01"},
		},
	}

	deployer := &mockDeployer{}
	healthChk := &mockHealthChecker{err: nil}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err == nil {
		t.Fatal("expected error when no control plane node")
	}

	var bf ErrBootstrapFailed
	if !errors.As(err, &bf) {
		t.Fatalf("expected ErrBootstrapFailed, got %T: %v", err, err)
	}
	if bf.Phase != phaseControlPlane {
		t.Errorf("expected phase %s, got %s", phaseControlPlane, bf.Phase)
	}

	// Verify result still has node data from discovery.
	if len(result.Nodes) != 1 {
		t.Fatalf("expected 1 node result, got %d", len(result.Nodes))
	}
}

func TestOrchestrator_Run_MultiNode(t *testing.T) {
	cfg := multiNodeConfig()
	deployer := &mockDeployer{}
	healthChk := &mockHealthChecker{err: nil}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		Deployer:      deployer,
		HealthChecker: healthChk,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.Run(ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if !result.GatewaysReady {
		t.Error("gateways should be ready")
	}
	if !result.WorkersReady {
		t.Error("workers should be ready")
	}
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 node results, got %d", len(result.Nodes))
	}

	// All nodes should be installed.
	for _, n := range result.Nodes {
		if n.Status != nodeStatusInstalled {
			t.Errorf("node %s expected installed, got %s", n.Hostname, n.Status)
		}
	}
}

// --- buildSwitchConfig test ---

func TestBuildSwitchConfig(t *testing.T) {
	sc := &SwitchConfig{
		Vendor: "cisco-nexus",
		Host:   "switch.local",
		User:   "admin",
		SSHKey: "/path/to/key",
		VLANs: map[string]NetworkDef{
			"mgmt": {VLAN: 10, Subnet: "10.0.0.0/24"},
		},
		PortAssignments: []PortAssignment{
			{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10, 20}, Description: "uplink"},
		},
	}

	swCfg := buildSwitchConfig(sc)
	if swCfg.Host != "switch.local" {
		t.Errorf("expected host switch.local, got %s", swCfg.Host)
	}
	if len(swCfg.VLANs) != 1 {
		t.Fatalf("expected 1 VLAN, got %d", len(swCfg.VLANs))
	}
	if swCfg.VLANs[0].ID != 10 {
		t.Errorf("expected VLAN ID 10, got %d", swCfg.VLANs[0].ID)
	}
	if len(swCfg.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(swCfg.Ports))
	}
	if swCfg.Ports[0].Mode != "trunk" {
		t.Errorf("expected mode trunk, got %s", swCfg.Ports[0].Mode)
	}
}

func TestBuildSwitchConfig_Empty(t *testing.T) {
	sc := &SwitchConfig{
		Vendor: "noop",
		Host:   "sw1",
	}
	swCfg := buildSwitchConfig(sc)
	if len(swCfg.VLANs) != 0 {
		t.Errorf("expected 0 VLANs, got %d", len(swCfg.VLANs))
	}
	if len(swCfg.Ports) != 0 {
		t.Errorf("expected 0 ports, got %d", len(swCfg.Ports))
	}
}

// --- nodesByRole test ---

func TestOrchestrator_NodesByRole(t *testing.T) {
	o := &Orchestrator{
		discovered: []DiscoveredNode{
			{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}},
			{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}},
			{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}},
			{NodeConfig: NodeConfig{Hostname: "w2", Role: RoleWorker}},
		},
	}

	cpNodes := o.nodesByRole(RoleControlPlane)
	if len(cpNodes) != 1 {
		t.Errorf("expected 1 control-plane, got %d", len(cpNodes))
	}

	workers := o.nodesByRole(RoleWorker)
	if len(workers) != 2 {
		t.Errorf("expected 2 workers, got %d", len(workers))
	}

	empty := o.nodesByRole("nonexistent")
	if len(empty) != 0 {
		t.Errorf("expected 0 for nonexistent role, got %d", len(empty))
	}
}

// --- toDiscoveredNodeInfos test ---

func TestToDiscoveredNodeInfos(t *testing.T) {
	nodes := []DiscoveredNode{
		{
			NodeConfig:    NodeConfig{Hostname: "cp1", Role: RoleControlPlane},
			DiscoveredMACs: []string{"aa:bb:cc:dd:ee:01"},
		},
		{
			NodeConfig:    NodeConfig{Hostname: "w1", Role: RoleWorker},
			DiscoveredMACs: []string{"aa:bb:cc:dd:ee:02"},
		},
	}

	infos := toDiscoveredNodeInfos(nodes)
	if len(infos) != 2 {
		t.Fatalf("expected 2 infos, got %d", len(infos))
	}
	if len(infos[0].MACs) != 1 || infos[0].MACs[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("expected MACs [aa:bb:cc:dd:ee:01], got %v", infos[0].MACs)
	}
	if infos[1].Hostname != "w1" {
		t.Errorf("expected hostname w1, got %s", infos[1].Hostname)
	}
}

func TestToDiscoveredNodeInfos_Empty(t *testing.T) {
	infos := toDiscoveredNodeInfos(nil)
	if len(infos) != 0 {
		t.Errorf("expected 0 infos for nil input, got %d", len(infos))
	}
}

// --- error type tests ---

func TestOrchestratorErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrBootstrapFailed with cause",
			err:  ErrBootstrapFailed{Phase: "discovery", Cause: errors.New("boom")},
			want: "bootstrap: phase discovery failed: boom",
		},
		{
			name: "ErrBootstrapFailed without cause",
			err:  ErrBootstrapFailed{Phase: "discovery"},
			want: "bootstrap: phase discovery failed",
		},
		{
			name: "ErrPhaseTimeout",
			err:  ErrPhaseTimeout{Phase: "deploy", Timeout: 5 * 60000000000},
			want: "bootstrap: phase deploy timed out after 5m0s",
		},
		{
			name: "ErrNodeProvisionFailed",
			err:  ErrNodeProvisionFailed{Hostname: "cp1", Role: "control-plane", Cause: errors.New("fail")},
			want: "bootstrap: provisioning failed for node cp1 (role=control-plane): fail",
		},
		{
			name: "ErrNodeProvisionFailed without cause",
			err:  ErrNodeProvisionFailed{Hostname: "cp1", Role: "control-plane"},
			want: "bootstrap: provisioning failed for node cp1 (role=control-plane)",
		},
		{
			name: "ErrHealthCheckFailed without cause",
			err:  ErrHealthCheckFailed{Address: "10.0.0.1"},
			want: "bootstrap: health check failed for 10.0.0.1",
		},
		{
			name: "ErrHealthCheckFailed with cause",
			err:  ErrHealthCheckFailed{Address: "10.0.0.1", Cause: errors.New("timeout")},
			want: "bootstrap: health check failed for 10.0.0.1: timeout",
		},
		{
			name: "ErrContainerDeployFailed with cause",
			err:  ErrContainerDeployFailed{Host: "host1", Cause: errors.New("fail")},
			want: "bootstrap: container deploy failed on host host1: fail",
		},
		{
			name: "ErrContainerDeployFailed without cause",
			err:  ErrContainerDeployFailed{Host: "host1"},
			want: "bootstrap: container deploy failed on host host1",
		},
		{
			name: "ErrContainerTeardownFailed without cause",
			err:  ErrContainerTeardownFailed{Host: "host1"},
			want: "bootstrap: container teardown failed on host host1",
		},
		{
			name: "ErrContainerTeardownFailed with cause",
			err:  ErrContainerTeardownFailed{Host: "host1", Cause: errors.New("boom")},
			want: "bootstrap: container teardown failed on host host1: boom",
		},
		{
			name: "ErrNilOrchestratorConfig",
			err:  ErrNilOrchestratorConfig{},
			want: "bootstrap: orchestrator config cannot be nil",
		},
		{
			name: "ErrNilBMCFactory",
			err:  ErrNilBMCFactory{},
			want: "bootstrap: BMC client factory cannot be nil",
		},
		{
			name: "ErrNoControlPlaneNode",
			err:  ErrNoControlPlaneNode{},
			want: "bootstrap: no control-plane node found in discovered nodes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOrchestratorErrors_Unwrap(t *testing.T) {
	cause := errors.New("root cause")

	tests := []struct {
		name string
		err  error
	}{
		{"ErrBootstrapFailed", ErrBootstrapFailed{Cause: cause}},
		{"ErrNodeProvisionFailed", ErrNodeProvisionFailed{Cause: cause}},
		{"ErrHealthCheckFailed", ErrHealthCheckFailed{Cause: cause}},
		{"ErrSeedFailed", ErrSeedFailed{Cause: cause}},
		{"ErrContainerDeployFailed", ErrContainerDeployFailed{Cause: cause}},
		{"ErrContainerTeardownFailed", ErrContainerTeardownFailed{Cause: cause}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, cause) {
				t.Errorf("Unwrap should return root cause")
			}
		})
	}
}
