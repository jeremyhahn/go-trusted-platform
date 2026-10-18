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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// --- DryRun tests ---

// unreachableMACDiscovery stands in for a BMC whose MAC walk fails. The
// real walk would dial the fleet address the test config names and wait
// out its network timeout (#284).
func unreachableMACDiscovery(_ context.Context, config *bmc.Config, _ *slog.Logger) ([]string, error) {
	return nil, bmc.ErrMACNotFound{Address: config.Address}
}

func TestOrchestrator_DryRun_AllBMCReachable(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer: DeployerConfig{
			Host:            "10.4.6.91",
			NetbootMediaDir: fleetMedia,
		},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname:    "cp-01",
				Role:        RoleControlPlane,
				BMCAddress:  "10.4.2.103",
				BMCUser:     "admin",
				BMCPassword: "pass",
				BMCProtocol: "ipmi",
			},
			{
				Hostname:    "gw-01",
				Role:        RoleGateway,
				BMCAddress:  "10.4.2.102",
				BMCUser:     "admin",
				BMCPassword: "pass",
				BMCProtocol: "ipmi",
			},
			{
				Hostname:    "compute-01",
				Role:        RoleWorker,
				BMCAddress:  "10.4.2.104",
				BMCUser:     "admin",
				BMCPassword: "pass",
				BMCProtocol: "ipmi",
			},
		},
	}

	mockClient := bmc.NewMockClient()
	factory := &bmc.MockClientFactory{Client: mockClient}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    factory,
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o.discoverMACs = unreachableMACDiscovery

	ctx := context.Background()
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if !result.ConfigValid {
		t.Error("config should be valid")
	}
	if result.NodeCount != 3 {
		t.Errorf("expected 3 nodes, got %d", result.NodeCount)
	}
	if result.ControlPlaneCount != 1 {
		t.Errorf("expected 1 control-plane, got %d", result.ControlPlaneCount)
	}
	if result.GatewayCount != 1 {
		t.Errorf("expected 1 gateway, got %d", result.GatewayCount)
	}
	if result.WorkerCount != 1 {
		t.Errorf("expected 1 worker, got %d", result.WorkerCount)
	}
	if result.DeployerHost != "10.4.6.91" {
		t.Errorf("expected deployer host 10.4.6.91, got %s", result.DeployerHost)
	}
	if result.SwitchConfigured {
		t.Error("switch should not be configured")
	}
	// 1 switch warning + 3 config resolution warnings (no templates configured).
	if len(result.Warnings) != 4 {
		t.Errorf("expected 4 warnings (1 switch + 3 config resolution), got %d: %v", len(result.Warnings), result.Warnings)
	}
	if result.Duration == 0 {
		t.Error("duration should be non-zero")
	}

	// All nodes should be reachable and ready.
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 node results, got %d", len(result.Nodes))
	}
	for _, n := range result.Nodes {
		if !n.BMCManaged {
			t.Errorf("node %s should be BMC managed", n.Hostname)
		}
		if !n.BMCReachable {
			t.Errorf("node %s should be BMC reachable", n.Hostname)
		}
		if n.Status != dryRunStatusReady {
			t.Errorf("node %s expected status ready, got %s", n.Hostname, n.Status)
		}
	}

	// No errors expected (no templates configured, so config resolution warnings
	// are present but not fatal BMC errors).
	if mockClient.PowerStatusCalls() != 3 {
		t.Errorf("expected 3 PowerStatus calls, got %d", mockClient.PowerStatusCalls())
	}
	if mockClient.PowerOnCalls() != 0 {
		t.Errorf("dry-run should not call PowerOn, got %d calls", mockClient.PowerOnCalls())
	}
	if mockClient.SetBootDeviceCalls() != 0 {
		t.Errorf("dry-run should not call SetBootDevice, got %d calls", mockClient.SetBootDeviceCalls())
	}
}

func TestOrchestrator_DryRun_BMCUnreachable(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname:    "cp-01",
				Role:        RoleControlPlane,
				BMCAddress:  "10.4.2.100",
				BMCProtocol: "ipmi",
			},
			{
				Hostname:    "gw-01",
				Role:        RoleGateway,
				BMCAddress:  "10.4.2.101",
				BMCProtocol: "ipmi",
			},
		},
	}

	// Use ClientFn to return different behavior per node.
	reachableClient := bmc.NewMockClient()
	unreachableClient := bmc.NewMockClient()
	unreachableClient.PowerStatusErr = errors.New("connection refused")

	factory := &bmc.MockClientFactory{
		ClientFn: func(config *bmc.Config) (bmc.Client, error) {
			if config.Address == "10.4.2.101" {
				return unreachableClient, nil
			}
			return reachableClient, nil
		},
	}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    factory,
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o.discoverMACs = unreachableMACDiscovery

	ctx := context.Background()
	result, err := o.DryRun(ctx)

	// Dry-run is advisory: it does NOT return an error for unreachable BMCs.
	if err != nil {
		t.Fatalf("dry-run should not fail for unreachable BMC: %v", err)
	}

	if !result.ConfigValid {
		t.Error("config should be valid")
	}

	// Find the unreachable node.
	var unreachableNode *DryRunNodeResult
	var reachableNode *DryRunNodeResult
	for i := range result.Nodes {
		if result.Nodes[i].Hostname == "gw-01" {
			unreachableNode = &result.Nodes[i]
		}
		if result.Nodes[i].Hostname == "cp-01" {
			reachableNode = &result.Nodes[i]
		}
	}

	if unreachableNode == nil {
		t.Fatal("gw-01 node result not found")
	}
	if unreachableNode.BMCReachable {
		t.Error("gw-01 should not be BMC reachable")
	}
	if unreachableNode.Status != dryRunStatusUnreachable {
		t.Errorf("gw-01 expected status unreachable, got %s", unreachableNode.Status)
	}
	if unreachableNode.Error == "" {
		t.Error("gw-01 should have an error message")
	}

	if reachableNode == nil {
		t.Fatal("cp-01 node result not found")
	}
	if !reachableNode.BMCReachable {
		t.Error("cp-01 should be BMC reachable")
	}
	if reachableNode.Status != dryRunStatusReady {
		t.Errorf("cp-01 expected status ready, got %s", reachableNode.Status)
	}
}

func TestOrchestrator_DryRun_BMCFactoryError(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname:    "cp-01",
				Role:        RoleControlPlane,
				BMCAddress:  "10.4.2.100",
				BMCProtocol: "ipmi",
			},
		},
	}

	factory := &bmc.MockClientFactory{
		Err: errors.New("factory creation failed"),
	}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    factory,
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := o.DryRun(ctx)

	// Advisory: does not fail.
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if len(result.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(result.Nodes))
	}
	if result.Nodes[0].BMCReachable {
		t.Error("node should not be reachable when factory fails")
	}
	if result.Nodes[0].Status != dryRunStatusUnreachable {
		t.Errorf("expected status unreachable, got %s", result.Nodes[0].Status)
	}
}

func TestOrchestrator_DryRun_ManualNodes(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
			{
				Hostname: "w-01",
				Role:     RoleWorker,
				MACs:     []string{"aa:bb:cc:dd:ee:02"},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if !result.ConfigValid {
		t.Error("config should be valid")
	}
	if result.NodeCount != 2 {
		t.Errorf("expected 2 nodes, got %d", result.NodeCount)
	}

	for _, n := range result.Nodes {
		if n.BMCManaged {
			t.Errorf("node %s should not be BMC managed", n.Hostname)
		}
		if n.BMCReachable {
			t.Errorf("node %s should not have BMC reachable set", n.Hostname)
		}
		if n.Status != dryRunStatusManual {
			t.Errorf("node %s expected status manual, got %s", n.Hostname, n.Status)
		}
		if len(n.MACs) == 0 {
			t.Errorf("node %s should have MAC set", n.Hostname)
		}
	}
}

func TestOrchestrator_DryRun_ReportsDisklessBootModel(t *testing.T) {
	o := &Orchestrator{}
	node := &NodeConfig{
		Hostname:  "w-diskless",
		Role:      RoleWorker,
		BootModel: BootModelDiskless,
		MACs:      []string{"aa:bb:cc:dd:ee:10"},
	}
	result := o.dryRunSingleNode(context.Background(), node)
	if result.BootModel != BootModelDiskless {
		t.Fatalf("boot model = %q, want %q", result.BootModel, BootModelDiskless)
	}
	if result.Status != dryRunStatusManual {
		t.Fatalf("status = %q", result.Status)
	}
}

func TestOrchestrator_DryRun_NoNodes(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}
	// Override nodes to empty after creating valid config structure.
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
	result, err := o.DryRun(ctx)

	// Validate() will fail because at least one node is required.
	if err == nil {
		t.Fatal("expected error for empty nodes")
	}

	if result.ConfigValid {
		t.Error("config should not be valid with no nodes")
	}
}

func TestOrchestrator_DryRun_WithSwitch(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Switch: &SwitchConfig{
			Vendor: "cisco-nexus",
			Host:   "10.4.2.4",
			PortAssignments: []PortAssignment{
				{Port: "Eth1/1", Class: zone.PortClassGateway},
			},
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if !result.SwitchConfigured {
		t.Error("switch should be configured")
	}
	if result.SwitchVendor != "cisco-nexus" {
		t.Errorf("expected switch vendor cisco-nexus, got %s", result.SwitchVendor)
	}

	// No switch warning when switch is configured.
	for _, w := range result.Warnings {
		if w == "switch management is optional, not configured" {
			t.Error("should not have switch warning when switch is configured")
		}
	}
}

func TestOrchestrator_DryRun_MixedNodes(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Nodes: []NodeConfig{
			{
				Hostname:    "cp-01",
				Role:        RoleControlPlane,
				BMCAddress:  "10.4.2.100",
				BMCProtocol: "ipmi",
			},
			{
				Hostname: "gw-01",
				Role:     RoleGateway,
				MACs:     []string{"aa:bb:cc:dd:ee:02"},
			},
			{
				Hostname: "w-01",
				Role:     RoleWorker,
				MACs:     []string{"aa:bb:cc:dd:ee:03"},
			},
		},
	}

	mockClient := bmc.NewMockClient()
	factory := &bmc.MockClientFactory{Client: mockClient}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    factory,
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o.discoverMACs = unreachableMACDiscovery

	ctx := context.Background()
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if result.NodeCount != 3 {
		t.Errorf("expected 3 nodes, got %d", result.NodeCount)
	}

	// Verify the BMC-managed node.
	cpNode := result.Nodes[0]
	if !cpNode.BMCManaged {
		t.Error("cp-01 should be BMC managed")
	}
	if !cpNode.BMCReachable {
		t.Error("cp-01 should be BMC reachable")
	}
	if cpNode.Status != dryRunStatusReady {
		t.Errorf("cp-01 expected status ready, got %s", cpNode.Status)
	}

	// Verify manual nodes.
	gwNode := result.Nodes[1]
	if gwNode.BMCManaged {
		t.Error("gw-01 should not be BMC managed")
	}
	if gwNode.Status != dryRunStatusManual {
		t.Errorf("gw-01 expected status manual, got %s", gwNode.Status)
	}

	wNode := result.Nodes[2]
	if wNode.BMCManaged {
		t.Error("w-01 should not be BMC managed")
	}
	if wNode.Status != dryRunStatusManual {
		t.Errorf("w-01 expected status manual, got %s", wNode.Status)
	}

	// Only 1 PowerStatus call (for the BMC-managed node).
	if mockClient.PowerStatusCalls() != 1 {
		t.Errorf("expected 1 PowerStatus call, got %d", mockClient.PowerStatusCalls())
	}
}

// --- DryRun error type tests ---

func TestDryRunErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrDryRunBMCUnreachable",
			err: ErrDryRunBMCUnreachable{
				Hostname:   "cp-01",
				BMCAddress: "10.4.2.100",
				Cause:      errors.New("connection refused"),
			},
			want: "bootstrap: dry-run: bmc unreachable for cp-01 at 10.4.2.100: connection refused",
		},
		{
			name: "ErrDryRunNoNodes",
			err:  ErrDryRunNoNodes{},
			want: "bootstrap: dry-run: no nodes configured",
		},
		{
			name: "ErrTemplateNotFoundForRole",
			err:  ErrTemplateNotFoundForRole{Role: "worker"},
			want: "bootstrap: no template configured for role worker",
		},
		{
			name: "ErrTemplateReadFailed",
			err: ErrTemplateReadFailed{
				Role:  "gateway",
				Path:  "/tmp/gw.yaml",
				Cause: errors.New("permission denied"),
			},
			want: "bootstrap: failed to read template for role gateway at /tmp/gw.yaml: permission denied",
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

func TestDryRunErrors_Unwrap(t *testing.T) {
	cause := errors.New("root cause")

	err := ErrDryRunBMCUnreachable{
		Hostname:   "cp-01",
		BMCAddress: "10.0.0.1",
		Cause:      cause,
	}
	if !errors.Is(err, cause) {
		t.Error("ErrDryRunBMCUnreachable Unwrap should return root cause")
	}

	readErr := ErrTemplateReadFailed{
		Role:  "worker",
		Path:  "/tmp/w.yaml",
		Cause: cause,
	}
	if !errors.Is(readErr, cause) {
		t.Error("ErrTemplateReadFailed Unwrap should return root cause")
	}
}

// --- countNodesByRole test ---

func TestOrchestrator_CountNodesByRole(t *testing.T) {
	cfg := multiNodeConfig()
	o := &Orchestrator{config: cfg}

	counts := o.countNodesByRole()
	if counts[RoleControlPlane] != 1 {
		t.Errorf("expected 1 control-plane, got %d", counts[RoleControlPlane])
	}
	if counts[RoleGateway] != 1 {
		t.Errorf("expected 1 gateway, got %d", counts[RoleGateway])
	}
	if counts[RoleWorker] != 1 {
		t.Errorf("expected 1 worker, got %d", counts[RoleWorker])
	}
}

func TestOrchestrator_CountNodesByRole_Empty(t *testing.T) {
	cfg := minimalConfig()
	cfg.Nodes = nil
	o := &Orchestrator{config: cfg}

	counts := o.countNodesByRole()
	if counts[RoleControlPlane] != 0 {
		t.Errorf("expected 0 control-plane, got %d", counts[RoleControlPlane])
	}
}

// --- Config resolution tests ---

func TestOrchestrator_DryRun_ResolvesConfigs(t *testing.T) {
	templateDir := t.TempDir()
	cpTemplatePath := filepath.Join(templateDir, "control-plane.yaml")

	templateContent := `domain: "placeholder.example.com"
hostmaster: "hostmaster@placeholder.example.com"
tenant-id: "placeholder-tenant"
os:
    hostname: template-host
    timezone: UTC
network:
    interfaces:
        - name: eth0
          address: "0.0.0.0"
`
	if err := os.WriteFile(cpTemplatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain:     "prod.example.com",
			Hostmaster: "ops@example.com",
			TenantID:   "tenant-42",
		},
		Templates: map[string]string{
			RoleControlPlane: cpTemplatePath,
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
				Interfaces: []installer.InterfaceConfig{
					{
						Name:        "eth0",
						Type:        installer.InterfaceTypeStatic,
						IPv4Address: "10.0.0.5/24",
					},
				},
				Overrides: map[string]interface{}{
					"os": map[string]interface{}{
						"timezone": "America/New_York",
					},
				},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if len(result.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(result.Nodes))
	}

	resolved := result.Nodes[0].ResolvedConfig
	if resolved == "" {
		t.Fatal("resolved config should not be empty")
	}

	// Verify global identity replaced the template's non-empty placeholders.
	if !strings.Contains(resolved, "prod.example.com") {
		t.Error("resolved config should contain domain from platform global config")
	}
	if strings.Contains(resolved, "placeholder.example.com") {
		t.Error("resolved config should not retain the template's domain placeholder")
	}
	if !strings.Contains(resolved, "ops@example.com") {
		t.Error("resolved config should contain hostmaster from platform global config")
	}
	if !strings.Contains(resolved, "tenant-42") {
		t.Error("resolved config should contain tenant-id from platform global config")
	}

	// Verify legal overrides were applied.
	if !strings.Contains(resolved, "America/New_York") {
		t.Error("resolved config should contain overridden timezone")
	}

	// Verify node identity injection from the first-class fields.
	if !strings.Contains(resolved, "hostname: cp-01") {
		t.Error("resolved config should contain the injected node hostname")
	}
	if strings.Contains(resolved, "template-host") {
		t.Error("resolved config should not retain the template hostname placeholder")
	}
	if !strings.Contains(resolved, "10.0.0.5/24") {
		t.Error("resolved config should contain the injected interface address")
	}
}

// TestOrchestrator_ResolveNodeConfig_OverrideBeatsGlobalIdentity locks the
// precedence chain template -> platform global -> per-node override: a node
// override differing from the platform global must survive resolution.
func TestOrchestrator_ResolveNodeConfig_OverrideBeatsGlobalIdentity(t *testing.T) {
	templateDir := t.TempDir()
	cpTemplatePath := filepath.Join(templateDir, "control-plane.yaml")
	templateContent := `domain: "placeholder.example.com"
os:
    hostname: template-host
`
	if err := os.WriteFile(cpTemplatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "prod.example.com"},
		Templates: map[string]string{
			RoleControlPlane: cpTemplatePath,
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
				Overrides: map[string]interface{}{
					"domain": "gw.example.com",
				},
			},
		},
	}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, nil)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(resolved), &parsed); err != nil {
		t.Fatalf("resolved config should be valid YAML: %v", err)
	}
	if parsed["domain"] != "gw.example.com" {
		t.Errorf("domain = %v, want gw.example.com (per-node override wins over platform global)", parsed["domain"])
	}
}

// TestOrchestrator_ResolveNodeConfig_SearchDomainsAreDeterministic locks the
// resolv.conf search list to configuration order. It was built from a Go map,
// so `platformctl bootstrap resolve` printed a different order run to run and
// an installed node's resolver tried its zones in an arbitrary order.
func TestOrchestrator_ResolveNodeConfig_SearchDomainsAreDeterministic(t *testing.T) {
	templateDir := t.TempDir()
	cpTemplatePath := filepath.Join(templateDir, "control-plane.yaml")
	if err := os.WriteFile(cpTemplatePath, []byte("domain: \"placeholder.example.com\"\n"), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "prod.example.com", InternalDomain: "example.internal"},
		Templates:   map[string]string{RoleControlPlane: cpTemplatePath},
		Nodes: []NodeConfig{{
			Hostname: "cp-01",
			Role:     RoleControlPlane,
			MACs:     []string{"aa:bb:cc:dd:ee:01"},
			Overrides: map[string]interface{}{
				"domain":          "gw.example.com",
				"internal-domain": "zone.example.internal",
			},
		}},
	}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	first, err := o.resolveNodeConfig("cp-01", RoleControlPlane, nil)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := o.resolveNodeConfig("cp-01", RoleControlPlane, nil)
		if err != nil {
			t.Fatalf("resolveNodeConfig run %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("run %d resolved differently:\n%s\nvs\n%s", i, again, first)
		}
	}

	var parsed struct {
		Network struct {
			DNS struct {
				SearchDomains []string `yaml:"search-domains"`
			} `yaml:"dns"`
		} `yaml:"network"`
	}
	if err := yaml.Unmarshal([]byte(first), &parsed); err != nil {
		t.Fatalf("resolved config should be valid YAML: %v", err)
	}
	want := []string{"gw.example.com", "zone.example.internal", "prod.example.com", "example.internal"}
	if !reflect.DeepEqual(parsed.Network.DNS.SearchDomains, want) {
		t.Errorf("search-domains = %v, want %v (node domain, node internal domain, platform domain, platform internal domain)",
			parsed.Network.DNS.SearchDomains, want)
	}
}

func TestOrchestrator_SetSearchDomains_DedupesAndSkipsBlanks(t *testing.T) {
	o := &Orchestrator{config: &BootstrapConfig{Platform: PlatformGlobalConfig{Domain: " example.com ", InternalDomain: "example.internal"}}}
	dns := map[string]interface{}{}
	o.setSearchDomains(dns, map[string]interface{}{
		"domain":          "example.com",
		"internal-domain": "  ",
		"internal_domain": "example.internal",
	})
	want := []interface{}{"example.com", "example.internal"}
	if !reflect.DeepEqual(dns["search-domains"], want) {
		t.Errorf("search-domains = %v, want %v: a repeat keeps its first position and blanks are dropped", dns["search-domains"], want)
	}

	empty := &Orchestrator{config: &BootstrapConfig{}}
	none := map[string]interface{}{}
	empty.setSearchDomains(none, map[string]interface{}{"domain": 42})
	if _, set := none["search-domains"]; set {
		t.Errorf("with no domain configured the key must stay unset, got %v", none["search-domains"])
	}
}

func TestOrchestrator_DryRun_ResolveConfigMissingTemplate(t *testing.T) {
	templateDir := t.TempDir()
	missingPath := filepath.Join(templateDir, "nonexistent.yaml")

	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Templates: map[string]string{
			RoleControlPlane: missingPath,
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail for missing template: %v", err)
	}

	// Resolved config should be empty for the node with missing template.
	if result.Nodes[0].ResolvedConfig != "" {
		t.Error("resolved config should be empty when template file is missing")
	}

	// A warning should be present.
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "could not resolve config for cp-01") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning about missing template for cp-01")
	}
}

func TestOrchestrator_DryRun_ResolveConfigNoTemplateForRole(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Templates: map[string]string{
			// No template for control-plane role.
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if result.Nodes[0].ResolvedConfig != "" {
		t.Error("resolved config should be empty when no template for role")
	}

	// Warning should mention the failure.
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "could not resolve config for cp-01") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning about missing template for role")
	}
}

// --- Switch plan tests ---

func TestOrchestrator_DryRun_SwitchPlan(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain: "test.local",
		},
		Switch: &SwitchConfig{
			Vendor: "cisco-nexus",
			Host:   "10.4.2.4",
			PortAssignments: []PortAssignment{
				{Port: "Eth1/3", Class: zone.PortClassGateway, Description: "gw-01"},
				{Port: "Eth1/25", Class: zone.PortClassHypervisor, Description: "cp-01"},
				{Port: "Eth1/41", Class: zone.PortClassBMC, Description: "gw-01 bmc"},
			},
		},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
			},
		},
	}

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
	result, err := o.DryRun(ctx)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	if result.SwitchPlan == nil {
		t.Fatal("switch plan should not be nil")
	}

	plan := result.SwitchPlan
	if plan.Vendor != "cisco-nexus" {
		t.Errorf("expected vendor cisco-nexus, got %s", plan.Vendor)
	}
	if plan.Host != "10.4.2.4" {
		t.Errorf("expected host 10.4.2.4, got %s", plan.Host)
	}

	// One VLAN per zone of environment 4, sorted by ID and named after the
	// zone, with its derived subnet.
	if len(plan.VLANs) != 9 {
		t.Fatalf("expected 9 VLANs, got %d", len(plan.VLANs))
	}
	for i, v := range plan.VLANs {
		if v.ID != 400+i {
			t.Errorf("VLAN %d: ID %d, want %d", i, v.ID, 400+i)
		}
	}
	if plan.VLANs[6].Name != "control-plane" || plan.VLANs[6].Subnet != "10.4.6.0/24" {
		t.Errorf("unexpected control-plane VLAN %+v", plan.VLANs[6])
	}

	// Each port carries what its class carries.
	if len(plan.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(plan.Ports))
	}
	gw, hv, bmcPort := plan.Ports[0], plan.Ports[1], plan.Ports[2]
	if gw.Class != "gateway" || gw.Mode != "trunk" || len(gw.VLANs) != 6 || gw.NativeVLAN != 0 || gw.MTU != 9216 {
		t.Errorf("unexpected gateway port %+v", gw)
	}
	if hv.Class != "hypervisor" || len(hv.VLANs) != 7 || hv.NativeVLAN != 405 {
		t.Errorf("unexpected hypervisor port %+v", hv)
	}
	if bmcPort.Mode != "access" || len(bmcPort.VLANs) != 1 || bmcPort.VLANs[0] != 402 {
		t.Errorf("unexpected bmc port %+v", bmcPort)
	}
	if gw.Description != "gw-01" {
		t.Errorf("expected description gw-01, got %s", gw.Description)
	}
}

func TestOrchestrator_DryRun_SwitchPlanNil(t *testing.T) {
	cfg := minimalConfig()
	o := &Orchestrator{config: cfg, logger: orchTestLogger()}

	plan, err := o.buildSwitchPlan()
	if err != nil || plan != nil {
		t.Errorf("switch plan should be nil when no switch configured, got %+v, %v", plan, err)
	}
}

// TestOrchestrator_BuildSwitchPlan_Errors reports a missing environment and
// a port class the plan cannot realise.
func TestOrchestrator_BuildSwitchPlan_Errors(t *testing.T) {
	o := &Orchestrator{config: &BootstrapConfig{Switch: &SwitchConfig{}}, logger: orchTestLogger()}
	var missing ErrMissingRequiredField
	if _, err := o.buildSwitchPlan(); !errors.As(err, &missing) {
		t.Fatalf("want ErrMissingRequiredField, got %v", err)
	}
	o.config = &BootstrapConfig{Environment: testEnvironment(), Switch: &SwitchConfig{
		PortAssignments: []PortAssignment{{Port: "Eth1/1", Class: "uplink"}},
	}}
	var classErr ErrSwitchPortClass
	if _, err := o.buildSwitchPlan(); !errors.As(err, &classErr) {
		t.Fatalf("want ErrSwitchPortClass, got %v", err)
	}
}

// --- Deep merge tests ---

func TestDeepMerge(t *testing.T) {
	t.Run("simple override", func(t *testing.T) {
		dst := map[string]interface{}{
			"key1": "original",
			"key2": "keep",
		}
		src := map[string]interface{}{
			"key1": "overridden",
		}
		result := deepMerge(dst, src)
		if result["key1"] != "overridden" {
			t.Errorf("expected key1=overridden, got %v", result["key1"])
		}
		if result["key2"] != "keep" {
			t.Errorf("expected key2=keep, got %v", result["key2"])
		}
	})

	t.Run("nested merge", func(t *testing.T) {
		dst := map[string]interface{}{
			"outer": map[string]interface{}{
				"inner1": "original",
				"inner2": "keep",
			},
		}
		src := map[string]interface{}{
			"outer": map[string]interface{}{
				"inner1": "overridden",
				"inner3": "new",
			},
		}
		result := deepMerge(dst, src)
		outer, ok := result["outer"].(map[string]interface{})
		if !ok {
			t.Fatal("outer should be a map")
		}
		if outer["inner1"] != "overridden" {
			t.Errorf("expected inner1=overridden, got %v", outer["inner1"])
		}
		if outer["inner2"] != "keep" {
			t.Errorf("expected inner2=keep, got %v", outer["inner2"])
		}
		if outer["inner3"] != "new" {
			t.Errorf("expected inner3=new, got %v", outer["inner3"])
		}
	})

	t.Run("deep nested merge", func(t *testing.T) {
		dst := map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"value": "original",
					"keep":  "preserved",
				},
			},
		}
		src := map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"value": "updated",
				},
			},
		}
		result := deepMerge(dst, src)
		l1, ok := result["level1"].(map[string]interface{})
		if !ok {
			t.Fatal("level1 should be a map")
		}
		l2, ok := l1["level2"].(map[string]interface{})
		if !ok {
			t.Fatal("level2 should be a map")
		}
		if l2["value"] != "updated" {
			t.Errorf("expected value=updated, got %v", l2["value"])
		}
		if l2["keep"] != "preserved" {
			t.Errorf("expected keep=preserved, got %v", l2["keep"])
		}
	})

	t.Run("src replaces non-map with map", func(t *testing.T) {
		dst := map[string]interface{}{
			"key": "scalar",
		}
		src := map[string]interface{}{
			"key": map[string]interface{}{"nested": "value"},
		}
		result := deepMerge(dst, src)
		m, ok := result["key"].(map[string]interface{})
		if !ok {
			t.Fatal("key should become a map")
		}
		if m["nested"] != "value" {
			t.Errorf("expected nested=value, got %v", m["nested"])
		}
	})

	t.Run("src replaces map with scalar", func(t *testing.T) {
		dst := map[string]interface{}{
			"key": map[string]interface{}{"nested": "value"},
		}
		src := map[string]interface{}{
			"key": "scalar-override",
		}
		result := deepMerge(dst, src)
		if result["key"] != "scalar-override" {
			t.Errorf("expected key=scalar-override, got %v", result["key"])
		}
	})

	t.Run("empty src", func(t *testing.T) {
		dst := map[string]interface{}{
			"key": "value",
		}
		src := map[string]interface{}{}
		result := deepMerge(dst, src)
		if result["key"] != "value" {
			t.Errorf("expected key=value, got %v", result["key"])
		}
	})

	t.Run("new keys from src", func(t *testing.T) {
		dst := map[string]interface{}{}
		src := map[string]interface{}{
			"new_key": "new_value",
		}
		result := deepMerge(dst, src)
		if result["new_key"] != "new_value" {
			t.Errorf("expected new_key=new_value, got %v", result["new_key"])
		}
	})
}
