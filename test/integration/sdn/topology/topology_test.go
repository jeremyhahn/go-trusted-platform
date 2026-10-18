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

package topology

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// =============================================================================
// Test Environment Setup
// =============================================================================

// requireDockerCompose fails the test with ErrDockerComposeMissing when
// docker-compose is not in PATH. These tests start the multi-node topology
// with docker-compose, which the devcontainer does not install
// (build/docker/devcontainer/Dockerfile) and cannot run without a Docker
// daemon inside it; they run only on a host with docker-compose, and fail
// anywhere else rather than report a pass they never earned.
func requireDockerCompose(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker-compose"); err != nil {
		t.Fatalf("missing prerequisite: %v", ErrDockerComposeMissing{Err: err})
	}
}

func testWorkDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "sdn-topology-test", t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}
	return dir
}

func TestBuilder_Build_DuplicateNetworkNames(t *testing.T) {
	_, err := NewBuilder().
		SetName("test-topology").
		AddNetwork(Network{
			Name:   "test-net",
			Subnet: "10.0.0.0/24",
		}).
		AddNetwork(Network{
			Name:   "test-net",
			Subnet: "10.1.0.0/24",
		}).
		AddNode(Node{
			Name:     "node-1",
			Type:     NodeTypeGateway,
			Networks: []string{"test-net"},
		}).
		Build()

	if err == nil {
		t.Fatal("expected error for duplicate network names")
	}
}

func TestBuilder_Build_UnknownNetwork(t *testing.T) {
	_, err := NewBuilder().
		SetName("test-topology").
		AddNetwork(Network{
			Name:   "test-net",
			Subnet: "10.0.0.0/24",
		}).
		AddNode(Node{
			Name:     "node-1",
			Type:     NodeTypeGateway,
			Networks: []string{"unknown-net"},
		}).
		Build()

	if err == nil {
		t.Fatal("expected error for unknown network reference")
	}
}

func TestBuilder_Build_SelfDependency(t *testing.T) {
	_, err := NewBuilder().
		SetName("test-topology").
		AddNetwork(Network{
			Name:   "test-net",
			Subnet: "10.0.0.0/24",
		}).
		AddNode(Node{
			Name:      "node-1",
			Type:      NodeTypeGateway,
			Networks:  []string{"test-net"},
			DependsOn: []string{"node-1"},
		}).
		Build()

	if err == nil {
		t.Fatal("expected error for self dependency")
	}
}

func TestBuilder_Build_UnknownDependency(t *testing.T) {
	_, err := NewBuilder().
		SetName("test-topology").
		AddNetwork(Network{
			Name:   "test-net",
			Subnet: "10.0.0.0/24",
		}).
		AddNode(Node{
			Name:      "node-1",
			Type:      NodeTypeGateway,
			Networks:  []string{"test-net"},
			DependsOn: []string{"unknown-node"},
		}).
		Build()

	if err == nil {
		t.Fatal("expected error for unknown dependency")
	}
}

// =============================================================================
// Node Builder Tests
// =============================================================================

func TestNodeBuilder_Build(t *testing.T) {
	node := NewNodeBuilder().
		SetName("gateway-1").
		SetType(NodeTypeGateway).
		SetImage("custom-image:v1").
		AddNetwork("underlay").
		AddNetwork("management").
		SetConfig("key1", "value1").
		SetEnvironment("ENV_VAR", "value").
		AddCapability("NET_ADMIN").
		SetPrivileged(true).
		AddPort(PortMapping{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}).
		AddDependency("other-node").
		SetHealthCheck(&HealthCheck{
			Command:  []string{"healthcheck"},
			Interval: 10 * time.Second,
		}).
		SetResources(&NodeResources{CPULimit: "1.0", MemoryLimit: "512m"}).
		AddLabel("role", "gateway").
		Build()

	if node.Name != "gateway-1" {
		t.Errorf("expected name 'gateway-1', got %q", node.Name)
	}

	if node.Type != NodeTypeGateway {
		t.Errorf("expected type gateway, got %s", node.Type)
	}

	if node.Image != "custom-image:v1" {
		t.Errorf("expected image 'custom-image:v1', got %q", node.Image)
	}

	if len(node.Networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(node.Networks))
	}

	if node.Config["key1"] != "value1" {
		t.Errorf("expected config key1=value1")
	}

	if node.Environment["ENV_VAR"] != "value" {
		t.Errorf("expected environment ENV_VAR=value")
	}

	if !node.Privileged {
		t.Error("expected privileged=true")
	}

	if len(node.Capabilities) != 1 || node.Capabilities[0] != "NET_ADMIN" {
		t.Errorf("expected capability NET_ADMIN")
	}

	if len(node.Ports) != 1 {
		t.Errorf("expected 1 port mapping")
	}

	if len(node.DependsOn) != 1 || node.DependsOn[0] != "other-node" {
		t.Errorf("expected dependency on other-node")
	}

	if node.HealthCheck == nil {
		t.Error("expected health check")
	}

	if node.Resources == nil {
		t.Error("expected resources")
	}

	if node.Labels["role"] != "gateway" {
		t.Errorf("expected label role=gateway")
	}
}

// =============================================================================
// Network Builder Tests
// =============================================================================

func TestNetworkBuilder_Build(t *testing.T) {
	network := NewNetworkBuilder().
		SetName("test-network").
		SetSubnet("10.0.0.0/24").
		SetGateway("10.0.0.1").
		SetDriver(NetworkDriverOverlay).
		SetVNI(100).
		SetIPRange("10.0.0.10/28").
		SetOption("encrypted", "true").
		SetInternal(true).
		SetEnableIPv6(true).
		SetIPv6Subnet("fd00::/64").
		AddLabel("type", "overlay").
		Build()

	if network.Name != "test-network" {
		t.Errorf("expected name 'test-network', got %q", network.Name)
	}

	if network.Subnet != "10.0.0.0/24" {
		t.Errorf("expected subnet '10.0.0.0/24', got %q", network.Subnet)
	}

	if network.Gateway != "10.0.0.1" {
		t.Errorf("expected gateway '10.0.0.1', got %q", network.Gateway)
	}

	if network.Driver != NetworkDriverOverlay {
		t.Errorf("expected driver overlay, got %s", network.Driver)
	}

	if network.VNI != 100 {
		t.Errorf("expected VNI 100, got %d", network.VNI)
	}

	if network.IPRange != "10.0.0.10/28" {
		t.Errorf("expected IP range '10.0.0.10/28', got %q", network.IPRange)
	}

	if network.Options["encrypted"] != "true" {
		t.Errorf("expected option encrypted=true")
	}

	if !network.Internal {
		t.Error("expected internal=true")
	}

	if !network.EnableIPv6 {
		t.Error("expected IPv6 enabled")
	}

	if network.IPv6Subnet != "fd00::/64" {
		t.Errorf("expected IPv6 subnet 'fd00::/64', got %q", network.IPv6Subnet)
	}

	if network.Labels["type"] != "overlay" {
		t.Errorf("expected label type=overlay")
	}
}

// =============================================================================
// BGP Peer Builder Tests
// =============================================================================

func TestBGPPeerBuilder_Build(t *testing.T) {
	peer := NewBGPPeerBuilder().
		SetName("test-peer").
		SetLocalASN(64512).
		SetRemoteASN(64513).
		SetLocalAddress(netip.MustParseAddr("10.0.0.1")).
		SetRemoteAddress(netip.MustParseAddr("10.0.0.2")).
		SetLocalNodeName("gateway-1").
		SetRemoteNodeName("gateway-2").
		SetEnableEVPN(true).
		SetEnableIPv4(true).
		SetEnableIPv6(false).
		AddPrefix("10.100.0.0/24").
		AddPrefix("192.168.0.0/16").
		SetHoldTime(180).
		SetKeepaliveInterval(60).
		SetDescription("Test BGP peering").
		Build()

	if peer.Name != "test-peer" {
		t.Errorf("expected name 'test-peer', got %q", peer.Name)
	}

	if peer.LocalASN != 64512 {
		t.Errorf("expected local ASN 64512, got %d", peer.LocalASN)
	}

	if peer.RemoteASN != 64513 {
		t.Errorf("expected remote ASN 64513, got %d", peer.RemoteASN)
	}

	if !peer.EnableEVPN {
		t.Error("expected EVPN enabled")
	}

	if !peer.EnableIPv4 {
		t.Error("expected IPv4 enabled")
	}

	if peer.EnableIPv6 {
		t.Error("expected IPv6 disabled")
	}

	if len(peer.Prefixes) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(peer.Prefixes))
	}

	if peer.HoldTime != 180 {
		t.Errorf("expected hold time 180, got %d", peer.HoldTime)
	}

	if peer.KeepaliveInterval != 60 {
		t.Errorf("expected keepalive 60, got %d", peer.KeepaliveInterval)
	}
}

// =============================================================================
// Preset Topology Tests
// =============================================================================

func TestPresetTopologies_Valid(t *testing.T) {
	presets := ListPresetTopologies()
	if len(presets) == 0 {
		t.Fatal("expected at least one preset topology")
	}

	for _, name := range presets {
		t.Run(name, func(t *testing.T) {
			topology, err := GetPresetTopology(name)
			if err != nil {
				t.Fatalf("failed to get preset topology %s: %v", name, err)
			}

			if topology == nil {
				t.Fatalf("expected topology, got nil")
			}

			if topology.Name == "" {
				t.Error("expected topology name")
			}

			if len(topology.Nodes) == 0 {
				t.Error("expected at least one node")
			}

			if len(topology.Networks) == 0 {
				t.Error("expected at least one network")
			}
		})
	}
}

func TestPresetTopology_NotFound(t *testing.T) {
	_, err := GetPresetTopology("non-existent")
	if err == nil {
		t.Fatal("expected error for non-existent preset")
	}

	if _, ok := err.(ErrTopologyNotFound); !ok {
		t.Errorf("expected ErrTopologyNotFound, got %T", err)
	}
}

func TestSingleNodeTopology(t *testing.T) {
	topology := SingleNodeTopology()

	if topology.Name != "single-node" {
		t.Errorf("expected name 'single-node', got %q", topology.Name)
	}

	if len(topology.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(topology.Nodes))
	}

	node := topology.Nodes[0]
	if node.Type != NodeTypeGateway {
		t.Errorf("expected gateway node, got %s", node.Type)
	}

	if topology.DHCPConfig == nil {
		t.Error("expected DHCP config")
	}

	if topology.VXLANConfig == nil {
		t.Error("expected VXLAN config")
	}

	if len(topology.IPAMPools) == 0 {
		t.Error("expected IPAM pool")
	}
}

func TestThreeNodeTopology(t *testing.T) {
	topology := ThreeNodeTopology()

	if topology.Name != "three-node" {
		t.Errorf("expected name 'three-node', got %q", topology.Name)
	}

	if len(topology.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(topology.Nodes))
	}

	var gatewayCount, computeCount int
	for _, node := range topology.Nodes {
		switch node.Type {
		case NodeTypeGateway:
			gatewayCount++
		case NodeTypeCompute:
			computeCount++
		}
	}

	if gatewayCount != 1 {
		t.Errorf("expected 1 gateway, got %d", gatewayCount)
	}

	if computeCount != 2 {
		t.Errorf("expected 2 compute nodes, got %d", computeCount)
	}
}

func TestMultiGatewayTopology(t *testing.T) {
	topology := MultiGatewayTopology()

	if topology.Name != "multi-gateway" {
		t.Errorf("expected name 'multi-gateway', got %q", topology.Name)
	}

	if len(topology.Nodes) != 5 {
		t.Errorf("expected 5 nodes, got %d", len(topology.Nodes))
	}

	var gatewayCount, computeCount int
	for _, node := range topology.Nodes {
		switch node.Type {
		case NodeTypeGateway:
			gatewayCount++
		case NodeTypeCompute:
			computeCount++
		}
	}

	if gatewayCount != 2 {
		t.Errorf("expected 2 gateways, got %d", gatewayCount)
	}

	if computeCount != 3 {
		t.Errorf("expected 3 compute nodes, got %d", computeCount)
	}

	if len(topology.BGPPeers) == 0 {
		t.Error("expected BGP peer configuration")
	}
}

func TestBGPTransitTopology(t *testing.T) {
	topology := BGPTransitTopology()

	if topology.Name != "bgp-transit" {
		t.Errorf("expected name 'bgp-transit', got %q", topology.Name)
	}

	var hasGateway, hasMockISP, hasCompute bool
	for _, node := range topology.Nodes {
		switch node.Type {
		case NodeTypeGateway:
			hasGateway = true
		case NodeTypeMockISP:
			hasMockISP = true
		case NodeTypeCompute:
			hasCompute = true
		}
	}

	if !hasGateway {
		t.Error("expected gateway node")
	}

	if !hasMockISP {
		t.Error("expected mock ISP node")
	}

	if !hasCompute {
		t.Error("expected compute node")
	}

	if len(topology.BGPPeers) == 0 {
		t.Error("expected BGP peer configuration")
	}

	// Check that prefixes are configured
	peer := topology.BGPPeers[0]
	if len(peer.Prefixes) == 0 {
		t.Error("expected prefix announcements in BGP peer config")
	}
}

func TestEdgeTopology(t *testing.T) {
	topology := EdgeTopology()

	if topology.Name != "edge" {
		t.Errorf("expected name 'edge', got %q", topology.Name)
	}

	var hasEdge, hasClient bool
	for _, node := range topology.Nodes {
		switch node.Type {
		case NodeTypeEdge:
			hasEdge = true
		case NodeTypeClient:
			hasClient = true
		}
	}

	if !hasEdge {
		t.Error("expected edge node")
	}

	if !hasClient {
		t.Error("expected client nodes")
	}

	if topology.DHCPConfig == nil {
		t.Error("expected DHCP config for edge topology")
	}
}

func TestMinimalTopology(t *testing.T) {
	topology := MinimalTopology()

	if topology.Name != "minimal" {
		t.Errorf("expected name 'minimal', got %q", topology.Name)
	}

	if len(topology.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(topology.Nodes))
	}

	if len(topology.Networks) != 1 {
		t.Errorf("expected 1 network, got %d", len(topology.Networks))
	}

	// Minimal should have shorter timeouts
	if topology.Timeouts.StartupTimeout >= 5*time.Minute {
		t.Error("expected shorter startup timeout for minimal topology")
	}
}

// =============================================================================
// Default Configuration Tests
// =============================================================================

func TestDefaultTimeouts(t *testing.T) {
	timeouts := DefaultTimeouts()

	if timeouts.StartupTimeout == 0 {
		t.Error("expected non-zero startup timeout")
	}

	if timeouts.ShutdownTimeout == 0 {
		t.Error("expected non-zero shutdown timeout")
	}

	if timeouts.HealthCheckTimeout == 0 {
		t.Error("expected non-zero health check timeout")
	}

	if timeouts.NodeStartTimeout == 0 {
		t.Error("expected non-zero node start timeout")
	}

	if timeouts.NetworkTimeout == 0 {
		t.Error("expected non-zero network timeout")
	}

	if timeouts.BGPConvergenceTimeout == 0 {
		t.Error("expected non-zero BGP convergence timeout")
	}
}

func TestDefaultVXLANConfig(t *testing.T) {
	config := DefaultVXLANConfig()

	if config.VNI == 0 {
		t.Error("expected non-zero VNI")
	}

	if config.DestPort == 0 {
		t.Error("expected non-zero dest port")
	}

	if config.DestPort != 4789 {
		t.Errorf("expected dest port 4789, got %d", config.DestPort)
	}

	if config.TTL == 0 {
		t.Error("expected non-zero TTL")
	}
}

func TestDefaultDHCPConfig(t *testing.T) {
	config := DefaultDHCPConfig("gateway-1", "eth0")

	if !config.Enabled {
		t.Error("expected DHCP enabled")
	}

	if config.NodeName != "gateway-1" {
		t.Errorf("expected node name 'gateway-1', got %q", config.NodeName)
	}

	if config.Interface != "eth0" {
		t.Errorf("expected interface 'eth0', got %q", config.Interface)
	}

	if config.LeaseTime == 0 {
		t.Error("expected non-zero lease time")
	}

	if len(config.DNS) == 0 {
		t.Error("expected DNS servers")
	}
}

func TestDefaultHealthCheck(t *testing.T) {
	hc := DefaultHealthCheck()

	if len(hc.Command) == 0 {
		t.Error("expected health check command")
	}

	if hc.Interval == 0 {
		t.Error("expected non-zero interval")
	}

	if hc.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}

	if hc.Retries == 0 {
		t.Error("expected non-zero retries")
	}
}

func TestDefaultNodeResources(t *testing.T) {
	resources := DefaultNodeResources()

	if resources.CPULimit == "" {
		t.Error("expected CPU limit")
	}

	if resources.MemoryLimit == "" {
		t.Error("expected memory limit")
	}
}

func TestDefaultCapabilities(t *testing.T) {
	gatewayCaps := DefaultGatewayCapabilities()
	if len(gatewayCaps) == 0 {
		t.Error("expected gateway capabilities")
	}

	// Gateway should have NET_ADMIN
	hasNetAdmin := false
	for _, cap := range gatewayCaps {
		if cap == "NET_ADMIN" {
			hasNetAdmin = true
			break
		}
	}
	if !hasNetAdmin {
		t.Error("expected NET_ADMIN capability for gateway")
	}

	computeCaps := DefaultComputeCapabilities()
	if len(computeCaps) == 0 {
		t.Error("expected compute capabilities")
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrTopologyNotFound",
			err:      ErrTopologyNotFound{Name: "test"},
			expected: "topology not found: test",
		},
		{
			name:     "ErrTopologyAlreadyExists",
			err:      ErrTopologyAlreadyExists{Name: "test"},
			expected: "topology already exists: test",
		},
		{
			name:     "ErrNodeNotFound",
			err:      ErrNodeNotFound{TopologyName: "topo", NodeName: "node"},
			expected: "node node not found in topology topo",
		},
		{
			name:     "ErrNetworkNotFound",
			err:      ErrNetworkNotFound{TopologyName: "topo", NetworkName: "net"},
			expected: "network net not found in topology topo",
		},
		{
			name:     "ErrTopologyStartFailed",
			err:      ErrTopologyStartFailed{Name: "test", Reason: "error"},
			expected: "failed to start topology test: error",
		},
		{
			name:     "ErrTopologyStopFailed",
			err:      ErrTopologyStopFailed{Name: "test", Reason: "error"},
			expected: "failed to stop topology test: error",
		},
		{
			name:     "ErrHealthCheckFailed",
			err:      ErrHealthCheckFailed{NodeName: "node", Reason: "timeout"},
			expected: "health check failed for node node: timeout",
		},
		{
			name:     "ErrInvalidTopology",
			err:      ErrInvalidTopology{Name: "test", Reason: "missing nodes"},
			expected: "invalid topology test: missing nodes",
		},
		{
			name:     "ErrResourceLimitExceeded",
			err:      ErrResourceLimitExceeded{Resource: "cpu", Limit: "1.0", Actual: "2.0"},
			expected: "resource limit exceeded for cpu: limit=1.0, actual=2.0",
		},
		{
			name:     "ErrBGPConvergenceFailed",
			err:      ErrBGPConvergenceFailed{Reason: "timeout"},
			expected: "BGP convergence failed: timeout",
		},
		{
			name:     "ErrDockerComposeMissing",
			err:      ErrDockerComposeMissing{Err: exec.ErrNotFound},
			expected: "docker-compose is not in PATH, so no topology can be started (run on a host with docker-compose and a Docker daemon): executable file not found in $PATH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// =============================================================================
// Manager Tests (Integration)
// =============================================================================

func TestManager_NewManager(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewManager(config)

	if manager == nil {
		t.Fatal("expected manager, got nil")
	}
}

func TestManager_List_Empty(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewManager(config)

	ctx := context.Background()
	topologies, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(topologies) != 0 {
		t.Errorf("expected empty list, got %d", len(topologies))
	}
}

func TestManager_Status_NotFound(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewManager(config)

	ctx := context.Background()
	_, err := manager.Status(ctx, "non-existent")

	if err == nil {
		t.Fatal("expected error for non-existent topology")
	}

	if _, ok := err.(ErrTopologyNotFound); !ok {
		t.Errorf("expected ErrTopologyNotFound, got %T", err)
	}
}

func TestManager_IsRunning_NotFound(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewManager(config)

	ctx := context.Background()
	running, err := manager.IsRunning(ctx, "non-existent")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if running {
		t.Error("expected not running for non-existent topology")
	}
}

// =============================================================================
// Full Integration Tests (require Docker)
// =============================================================================

func TestManager_StartAndDestroy_Integration(t *testing.T) {
	requireDockerCompose(t)

	config := DefaultManagerConfig()
	config.WorkDir = testWorkDir(t)
	manager := NewManager(config)

	topology := MinimalTopology()
	topology.Name = "test-integration-" + time.Now().Format("20060102150405")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start topology
	if err := manager.Start(ctx, topology); err != nil {
		t.Fatalf("failed to start topology: %v", err)
	}

	// Verify it's in the list
	topologies, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("failed to list topologies: %v", err)
	}

	found := false
	for _, name := range topologies {
		if name == topology.Name {
			found = true
			break
		}
	}
	if !found {
		t.Error("topology not found in list after start")
	}

	// Check status
	status, err := manager.Status(ctx, topology.Name)
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}

	if status.State != TopologyStateRunning {
		t.Errorf("expected running state, got %s", status.State)
	}

	// Destroy topology
	if err := manager.Destroy(ctx, topology.Name); err != nil {
		t.Fatalf("failed to destroy topology: %v", err)
	}

	// Verify it's removed from the list
	topologies, err = manager.List(ctx)
	if err != nil {
		t.Fatalf("failed to list topologies after destroy: %v", err)
	}

	for _, name := range topologies {
		if name == topology.Name {
			t.Error("topology still in list after destroy")
		}
	}
}

func TestManager_WaitHealthy_Integration(t *testing.T) {
	requireDockerCompose(t)

	config := DefaultManagerConfig()
	config.WorkDir = testWorkDir(t)
	manager := NewManager(config)

	topology := MinimalTopology()
	topology.Name = "test-health-" + time.Now().Format("20060102150405")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start topology
	if err := manager.Start(ctx, topology); err != nil {
		t.Fatalf("failed to start topology: %v", err)
	}

	// Cleanup
	defer func() {
		cleanCtx := context.Background()
		_ = manager.Destroy(cleanCtx, topology.Name)
	}()

	// Wait for healthy
	if err := manager.WaitHealthy(ctx, topology.Name); err != nil {
		t.Fatalf("failed waiting for healthy: %v", err)
	}
}

func TestManager_CaptureLogs_Integration(t *testing.T) {
	requireDockerCompose(t)

	config := DefaultManagerConfig()
	config.WorkDir = testWorkDir(t)
	manager := NewManager(config)

	topology := MinimalTopology()
	topology.Name = "test-logs-" + time.Now().Format("20060102150405")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start topology
	if err := manager.Start(ctx, topology); err != nil {
		t.Fatalf("failed to start topology: %v", err)
	}

	// Cleanup
	defer func() {
		cleanCtx := context.Background()
		_ = manager.Destroy(cleanCtx, topology.Name)
	}()

	// Wait for healthy
	if err := manager.WaitHealthy(ctx, topology.Name); err != nil {
		t.Fatalf("failed waiting for healthy: %v", err)
	}

	// Capture logs
	logDir := filepath.Join(testWorkDir(t), "logs")
	if err := manager.CaptureLogs(ctx, topology.Name, logDir); err != nil {
		t.Fatalf("failed to capture logs: %v", err)
	}

	// Verify log file exists
	for _, node := range topology.Nodes {
		logFile := filepath.Join(logDir, node.Name+".log")
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			t.Errorf("log file not found for node %s", node.Name)
		}
	}
}

// =============================================================================
// Cleanup Manager Tests
// =============================================================================

func TestCleanupManager(t *testing.T) {
	config := DefaultManagerConfig()
	manager := NewManager(config)

	logsDir := filepath.Join(os.TempDir(), "cleanup-test-logs")
	cleanup := NewCleanupManager(manager, logsDir)

	// Register some topologies
	cleanup.RegisterTopology("topo-1")
	cleanup.RegisterTopology("topo-2")

	// Note: Cleanup will fail because topologies don't exist,
	// but the mechanism is tested
	ctx := context.Background()
	_ = cleanup.Cleanup(ctx, false)
}

// =============================================================================
// Register Custom Preset Test
// =============================================================================

func TestRegisterPresetTopology(t *testing.T) {
	customFn := func() *Topology {
		topology, _ := NewBuilder().
			SetName("custom-preset").
			SetDescription("Custom test preset").
			AddNetwork(Network{
				Name:   "custom-net",
				Subnet: "10.99.0.0/24",
			}).
			AddNode(Node{
				Name:     "custom-node",
				Type:     NodeTypeGateway,
				Networks: []string{"custom-net"},
			}).
			Build()
		return topology
	}

	RegisterPresetTopology("custom-test", customFn)

	topology, err := GetPresetTopology("custom-test")
	if err != nil {
		t.Fatalf("failed to get custom preset: %v", err)
	}

	if topology.Name != "custom-preset" {
		t.Errorf("expected name 'custom-preset', got %q", topology.Name)
	}
}
