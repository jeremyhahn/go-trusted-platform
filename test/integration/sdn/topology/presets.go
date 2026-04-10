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

//go:build integration

package topology

import (
	"net/netip"
	"time"
)

// =============================================================================
// Default Images
// =============================================================================

const (
	// DefaultGatewayImage is the default image for gateway nodes.
	DefaultGatewayImage = "go-trusted-platform-sdn:latest"

	// DefaultComputeImage is the default image for compute nodes.
	DefaultComputeImage = "go-trusted-platform-sdn:latest"

	// DefaultEdgeImage is the default image for edge nodes.
	DefaultEdgeImage = "go-trusted-platform-sdn:latest"

	// DefaultMockISPImage is the default image for mock ISP nodes.
	DefaultMockISPImage = "frrouting/frr:latest"

	// DefaultClientImage is the default image for client nodes.
	DefaultClientImage = "alpine:latest"
)

// =============================================================================
// Network Constants
// =============================================================================

const (
	// UnderlayNetwork is the name of the underlay network.
	UnderlayNetwork = "underlay"

	// OverlayNetwork is the name of the overlay network.
	OverlayNetwork = "overlay"

	// ManagementNetwork is the name of the management network.
	ManagementNetwork = "management"

	// TransitNetwork is the name of the transit network.
	TransitNetwork = "transit"
)

// =============================================================================
// ASN Constants
// =============================================================================

const (
	// DefaultLocalASN is the default local ASN for gateways.
	DefaultLocalASN uint32 = 64512

	// DefaultMockISPASN is the default ASN for mock ISP peers.
	DefaultMockISPASN uint32 = 64496
)

// =============================================================================
// Preset Topologies
// =============================================================================

// SingleNodeTopology creates a single gateway node with all modes enabled.
// This topology is suitable for testing all SDN features on a single node.
//
// Topology:
//
//	+-------------------+
//	|     Gateway       |
//	|  (overlay/edge/   |
//	|   transit)        |
//	+-------------------+
//	        |
//	    [underlay]
func SingleNodeTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("single-node").
		SetDescription("Single gateway with all modes enabled").
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "underlay").
			Build()).
		AddNetwork(NewNetworkBuilder().
			SetName(ManagementNetwork).
			SetSubnet("10.200.0.0/24").
			SetGateway("10.200.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "management").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("gateway-1").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay,edge,transit").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			Build()).
		AddIPAMPool(IPAMPoolConfig{
			ID:            "default-pool",
			Name:          "Default Pool",
			CIDR:          "10.100.0.0/24",
			Gateway:       "10.100.0.1",
			RangeStart:    "10.100.0.10",
			RangeEnd:      "10.100.0.250",
			DNS:           []string{"8.8.8.8", "8.8.4.4"},
			LeaseDuration: time.Hour,
			NodeName:      "gateway-1",
		}).
		SetDHCPConfig(&DHCPConfig{
			Enabled:     true,
			NodeName:    "gateway-1",
			Interface:   "eth0",
			LeaseTime:   3600,
			RenewalTime: 1800,
			RebindTime:  3150,
			DNS:         []string{"8.8.8.8", "8.8.4.4"},
			Domain:      "single-node.test",
		}).
		SetVXLANConfig(DefaultVXLANConfig()).
		AddLabel("preset", "single-node").
		AddLabel("purpose", "all-in-one-testing").
		Build()

	return topology
}

// ThreeNodeTopology creates a gateway with two compute nodes using VXLAN overlay.
// This topology is suitable for testing east-west traffic between compute nodes.
//
// Topology:
//
//	       [underlay: 10.100.0.0/24]
//	               |
//	+--------------|---------------+
//	|              |               |
//
// +----------+  +---------+  +---------+
// | Gateway  |  | Compute |  | Compute |
// |   (1)    |  |   (2)   |  |   (3)   |
// +----------+  +---------+  +---------+
//
//	\         |         /
//	 \        |        /
//	  [VXLAN tunnels]
//	   \      |      /
//	    [overlay VNI]
func ThreeNodeTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("three-node").
		SetDescription("Gateway + 2 compute nodes with VXLAN overlay").
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "underlay").
			Build()).
		AddNetwork(NewNetworkBuilder().
			SetName(ManagementNetwork).
			SetSubnet("10.200.0.0/24").
			SetGateway("10.200.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "management").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("gateway-1").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetEnvironment("NODE_IP", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("compute-1").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.11").
			SetEnvironment("GATEWAY_IP", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("compute-2").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.12").
			SetEnvironment("GATEWAY_IP", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		AddIPAMPool(IPAMPoolConfig{
			ID:            "overlay-pool",
			Name:          "Overlay Pool",
			CIDR:          "192.168.100.0/24",
			Gateway:       "192.168.100.1",
			RangeStart:    "192.168.100.10",
			RangeEnd:      "192.168.100.250",
			DNS:           []string{"8.8.8.8"},
			LeaseDuration: time.Hour,
			NodeName:      "gateway-1",
		}).
		SetVXLANConfig(&VXLANConfig{
			VNI:         100,
			DestPort:    4789,
			TTL:         64,
			Learning:    true,
			L2Miss:      true,
			L3Miss:      true,
			EVPNEnabled: true,
		}).
		SetDHCPConfig(&DHCPConfig{
			Enabled:     true,
			NodeName:    "gateway-1",
			Interface:   "vxlan100",
			LeaseTime:   3600,
			RenewalTime: 1800,
			RebindTime:  3150,
			DNS:         []string{"8.8.8.8"},
			Domain:      "three-node.test",
		}).
		AddLabel("preset", "three-node").
		AddLabel("purpose", "east-west-traffic-testing").
		Build()

	return topology
}

// MultiGatewayTopology creates a high-availability topology with 2 gateways and 3 compute nodes.
// This topology is suitable for testing gateway failover and HA scenarios.
//
// Topology:
//
//	                [underlay: 10.100.0.0/24]
//	                         |
//	+----------+-------------|-------------+----------+
//	|          |             |             |          |
//
// +--------+ +--------+ +---------+ +---------+ +---------+
// |Gateway1| |Gateway2| |Compute1 | |Compute2 | |Compute3 |
// | Active | |Standby | |         | |         | |         |
// +--------+ +--------+ +---------+ +---------+ +---------+
//
//	\        /            \           |           /
//	 [iBGP peer]           [VXLAN tunnels]
func MultiGatewayTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("multi-gateway").
		SetDescription("2 gateways + 3 compute nodes for HA testing").
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "underlay").
			Build()).
		AddNetwork(NewNetworkBuilder().
			SetName(ManagementNetwork).
			SetSubnet("10.200.0.0/24").
			SetGateway("10.200.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "management").
			Build()).
		// Gateway 1 - Primary/Active
		AddNode(NewNodeBuilder().
			SetName("gateway-1").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetEnvironment("NODE_IP", "10.100.0.10").
			SetEnvironment("HA_ROLE", "primary").
			SetEnvironment("PEER_GATEWAY", "10.100.0.11").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			AddLabel("ha-role", "primary").
			Build()).
		// Gateway 2 - Secondary/Standby
		AddNode(NewNodeBuilder().
			SetName("gateway-2").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetEnvironment("NODE_IP", "10.100.0.11").
			SetEnvironment("HA_ROLE", "secondary").
			SetEnvironment("PEER_GATEWAY", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			AddLabel("ha-role", "secondary").
			Build()).
		// Compute nodes
		AddNode(NewNodeBuilder().
			SetName("compute-1").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			AddDependency("gateway-2").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.20").
			SetEnvironment("GATEWAY_IPS", "10.100.0.10,10.100.0.11").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("compute-2").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			AddDependency("gateway-2").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.21").
			SetEnvironment("GATEWAY_IPS", "10.100.0.10,10.100.0.11").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("compute-3").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			AddDependency("gateway-2").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.22").
			SetEnvironment("GATEWAY_IPS", "10.100.0.10,10.100.0.11").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		// iBGP peering between gateways
		AddBGPPeer(NewBGPPeerBuilder().
			SetName("gateway-peer").
			SetLocalASN(DefaultLocalASN).
			SetRemoteASN(DefaultLocalASN).
			SetLocalAddress(netip.MustParseAddr("10.100.0.10")).
			SetRemoteAddress(netip.MustParseAddr("10.100.0.11")).
			SetLocalNodeName("gateway-1").
			SetRemoteNodeName("gateway-2").
			SetEnableEVPN(true).
			SetEnableIPv4(true).
			SetDescription("iBGP peering for EVPN route synchronization").
			Build()).
		AddIPAMPool(IPAMPoolConfig{
			ID:            "overlay-pool",
			Name:          "Overlay Pool",
			CIDR:          "192.168.100.0/24",
			Gateway:       "192.168.100.1",
			RangeStart:    "192.168.100.10",
			RangeEnd:      "192.168.100.250",
			DNS:           []string{"8.8.8.8"},
			LeaseDuration: time.Hour,
			NodeName:      "gateway-1",
		}).
		SetVXLANConfig(&VXLANConfig{
			VNI:         100,
			DestPort:    4789,
			TTL:         64,
			Learning:    true,
			L2Miss:      true,
			L3Miss:      true,
			EVPNEnabled: true,
		}).
		SetTimeouts(TopologyTimeouts{
			StartupTimeout:        5 * time.Minute,
			ShutdownTimeout:       2 * time.Minute,
			HealthCheckTimeout:    60 * time.Second,
			NodeStartTimeout:      60 * time.Second,
			NetworkTimeout:        30 * time.Second,
			BGPConvergenceTimeout: 3 * time.Minute,
		}).
		AddLabel("preset", "multi-gateway").
		AddLabel("purpose", "ha-testing").
		Build()

	return topology
}

// BGPTransitTopology creates a gateway with a mock ISP peer for testing BGP transit.
// This topology is suitable for testing BGP prefix announcements to upstream providers.
//
// Topology:
//
//	            [transit: 10.254.0.0/24]
//	                     |
//	       +-------------|-------------+
//	       |                           |
//	 +-----------+               +-----------+
//	 |  Gateway  |     eBGP      |  Mock ISP |
//	 | AS 64512  |<------------->| AS 64496  |
//	 +-----------+               +-----------+
//	       |
//	[underlay: 10.100.0.0/24]
//	       |
//	 +-----------+
//	 |  Compute  |
//	 +-----------+
func BGPTransitTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("bgp-transit").
		SetDescription("Gateway + mock ISP for BGP transit testing").
		// Transit network for eBGP peering
		AddNetwork(NewNetworkBuilder().
			SetName(TransitNetwork).
			SetSubnet("10.254.0.0/24").
			SetGateway("10.254.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "transit").
			Build()).
		// Underlay network for compute
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "underlay").
			Build()).
		// Management network
		AddNetwork(NewNetworkBuilder().
			SetName(ManagementNetwork).
			SetSubnet("10.200.0.0/24").
			SetGateway("10.200.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "management").
			Build()).
		// Gateway node with transit mode
		AddNode(NewNodeBuilder().
			SetName("gateway-1").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(TransitNetwork).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay,transit").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetEnvironment("TRANSIT_ENABLED", "true").
			SetEnvironment("NODE_IP", "10.100.0.10").
			SetEnvironment("TRANSIT_IP", "10.254.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			AddLabel("transit", "enabled").
			Build()).
		// Mock ISP router
		AddNode(NewNodeBuilder().
			SetName("mock-isp").
			SetType(NodeTypeMockISP).
			SetImage(DefaultMockISPImage).
			AddNetwork(TransitNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			SetEnvironment("BGP_ASN", "64496").
			SetEnvironment("ROUTER_ID", "10.254.0.100").
			SetEnvironment("NEIGHBOR_IP", "10.254.0.10").
			SetEnvironment("NEIGHBOR_ASN", "64512").
			SetHealthCheck(&HealthCheck{
				Command:     []string{"vtysh", "-c", "show bgp summary"},
				Interval:    10 * time.Second,
				Timeout:     5 * time.Second,
				StartPeriod: 30 * time.Second,
				Retries:     3,
			}).
			AddLabel("role", "mock-isp").
			Build()).
		// Compute node
		AddNode(NewNodeBuilder().
			SetName("compute-1").
			SetType(NodeTypeCompute).
			SetImage(DefaultComputeImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-1").
			SetEnvironment("NODE_TYPE", "compute").
			SetEnvironment("VTEP_IP", "10.100.0.11").
			SetEnvironment("GATEWAY_IP", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "compute").
			Build()).
		// eBGP peering to mock ISP
		AddBGPPeer(NewBGPPeerBuilder().
			SetName("isp-peer").
			SetLocalASN(DefaultLocalASN).
			SetRemoteASN(DefaultMockISPASN).
			SetLocalAddress(netip.MustParseAddr("10.254.0.10")).
			SetRemoteAddress(netip.MustParseAddr("10.254.0.100")).
			SetLocalNodeName("gateway-1").
			SetRemoteNodeName("mock-isp").
			SetEnableEVPN(false).
			SetEnableIPv4(true).
			AddPrefix("10.100.0.0/24").
			AddPrefix("192.168.100.0/24").
			SetDescription("eBGP peering to mock ISP for transit testing").
			Build()).
		AddIPAMPool(IPAMPoolConfig{
			ID:            "overlay-pool",
			Name:          "Overlay Pool",
			CIDR:          "192.168.100.0/24",
			Gateway:       "192.168.100.1",
			RangeStart:    "192.168.100.10",
			RangeEnd:      "192.168.100.250",
			DNS:           []string{"8.8.8.8"},
			LeaseDuration: time.Hour,
			NodeName:      "gateway-1",
		}).
		SetVXLANConfig(&VXLANConfig{
			VNI:         100,
			DestPort:    4789,
			TTL:         64,
			Learning:    true,
			EVPNEnabled: true,
		}).
		SetTimeouts(TopologyTimeouts{
			StartupTimeout:        5 * time.Minute,
			ShutdownTimeout:       2 * time.Minute,
			HealthCheckTimeout:    60 * time.Second,
			NodeStartTimeout:      60 * time.Second,
			NetworkTimeout:        30 * time.Second,
			BGPConvergenceTimeout: 3 * time.Minute,
		}).
		AddLabel("preset", "bgp-transit").
		AddLabel("purpose", "transit-testing").
		Build()

	return topology
}

// EdgeTopology creates a topology for testing edge/IoT device onboarding.
// This topology includes an edge gateway and simulated IoT clients.
//
// Topology:
//
//	   [edge-lan: 192.168.1.0/24]
//	             |
//	+------------|------------+
//	|            |            |
//
// +---------+  +--------+  +--------+
// |  Edge   |  | Client |  | Client |
// | Gateway |  |   1    |  |   2    |
// +---------+  +--------+  +--------+
//
//	    |
//	[underlay: 10.100.0.0/24]
//	    |
//
// +---------+
// |  Core   |
// | Gateway |
// +---------+
func EdgeTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("edge").
		SetDescription("Edge gateway with IoT clients for device onboarding testing").
		// Edge LAN for IoT devices
		AddNetwork(NewNetworkBuilder().
			SetName("edge-lan").
			SetSubnet("192.168.1.0/24").
			SetGateway("192.168.1.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "edge-lan").
			Build()).
		// Underlay network
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "underlay").
			Build()).
		// Management network
		AddNetwork(NewNetworkBuilder().
			SetName(ManagementNetwork).
			SetSubnet("10.200.0.0/24").
			SetGateway("10.200.0.1").
			SetDriver(NetworkDriverBridge).
			AddLabel("type", "management").
			Build()).
		// Core gateway
		AddNode(NewNodeBuilder().
			SetName("gateway-core").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			SetEnvironment("NODE_TYPE", "gateway").
			SetEnvironment("GATEWAY_MODES", "overlay").
			SetEnvironment("BGP_ASN", "64512").
			SetEnvironment("EVPN_ENABLED", "true").
			SetEnvironment("NODE_IP", "10.100.0.10").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			AddLabel("tier", "core").
			Build()).
		// Edge gateway
		AddNode(NewNodeBuilder().
			SetName("gateway-edge").
			SetType(NodeTypeEdge).
			SetImage(DefaultEdgeImage).
			AddNetwork("edge-lan").
			AddNetwork(UnderlayNetwork).
			AddNetwork(ManagementNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			AddCapability("NET_RAW").
			AddDependency("gateway-core").
			SetEnvironment("NODE_TYPE", "edge").
			SetEnvironment("GATEWAY_MODES", "edge").
			SetEnvironment("EDGE_LAN_IP", "192.168.1.1").
			SetEnvironment("CORE_GATEWAY", "10.100.0.10").
			SetEnvironment("DHCP_ENABLED", "true").
			SetHealthCheck(DefaultHealthCheck()).
			AddLabel("role", "gateway").
			AddLabel("tier", "edge").
			Build()).
		// IoT clients
		AddNode(NewNodeBuilder().
			SetName("client-1").
			SetType(NodeTypeClient).
			SetImage(DefaultClientImage).
			AddNetwork("edge-lan").
			AddDependency("gateway-edge").
			SetEnvironment("DHCP_CLIENT", "true").
			AddLabel("role", "client").
			AddLabel("device-type", "iot").
			Build()).
		AddNode(NewNodeBuilder().
			SetName("client-2").
			SetType(NodeTypeClient).
			SetImage(DefaultClientImage).
			AddNetwork("edge-lan").
			AddDependency("gateway-edge").
			SetEnvironment("DHCP_CLIENT", "true").
			AddLabel("role", "client").
			AddLabel("device-type", "iot").
			Build()).
		// IPAM pool for edge LAN
		AddIPAMPool(IPAMPoolConfig{
			ID:            "edge-pool",
			Name:          "Edge LAN Pool",
			CIDR:          "192.168.1.0/24",
			Gateway:       "192.168.1.1",
			RangeStart:    "192.168.1.100",
			RangeEnd:      "192.168.1.200",
			DNS:           []string{"192.168.1.1", "8.8.8.8"},
			LeaseDuration: 24 * time.Hour,
			NodeName:      "gateway-edge",
		}).
		// DHCP for edge LAN
		SetDHCPConfig(&DHCPConfig{
			Enabled:     true,
			NodeName:    "gateway-edge",
			Interface:   "eth0",
			LeaseTime:   86400,
			RenewalTime: 43200,
			RebindTime:  75600,
			DNS:         []string{"192.168.1.1", "8.8.8.8"},
			Domain:      "edge.test",
		}).
		SetVXLANConfig(&VXLANConfig{
			VNI:         100,
			DestPort:    4789,
			TTL:         64,
			Learning:    true,
			EVPNEnabled: true,
		}).
		AddLabel("preset", "edge").
		AddLabel("purpose", "iot-onboarding-testing").
		Build()

	return topology
}

// MinimalTopology creates the smallest possible topology for quick tests.
// This topology is suitable for smoke tests and basic connectivity verification.
func MinimalTopology() *Topology {
	topology, _ := NewBuilder().
		SetName("minimal").
		SetDescription("Minimal topology for smoke tests").
		AddNetwork(NewNetworkBuilder().
			SetName(UnderlayNetwork).
			SetSubnet("10.100.0.0/24").
			SetGateway("10.100.0.1").
			SetDriver(NetworkDriverBridge).
			Build()).
		AddNode(NewNodeBuilder().
			SetName("gateway-1").
			SetType(NodeTypeGateway).
			SetImage(DefaultGatewayImage).
			AddNetwork(UnderlayNetwork).
			SetPrivileged(true).
			AddCapability("NET_ADMIN").
			AddCapability("SYS_ADMIN").
			SetEnvironment("NODE_TYPE", "gateway").
			Build()).
		SetTimeouts(TopologyTimeouts{
			StartupTimeout:     2 * time.Minute,
			ShutdownTimeout:    1 * time.Minute,
			HealthCheckTimeout: 30 * time.Second,
			NodeStartTimeout:   30 * time.Second,
			NetworkTimeout:     15 * time.Second,
		}).
		AddLabel("preset", "minimal").
		AddLabel("purpose", "smoke-testing").
		Build()

	return topology
}

// =============================================================================
// Preset Topology Registry
// =============================================================================

// PresetTopologyFunc is a function that creates a preset topology.
type PresetTopologyFunc func() *Topology

// presetTopologies is the registry of preset topology functions.
var presetTopologies = map[string]PresetTopologyFunc{
	"single-node":   SingleNodeTopology,
	"three-node":    ThreeNodeTopology,
	"multi-gateway": MultiGatewayTopology,
	"bgp-transit":   BGPTransitTopology,
	"edge":          EdgeTopology,
	"minimal":       MinimalTopology,
}

// GetPresetTopology returns a preset topology by name.
func GetPresetTopology(name string) (*Topology, error) {
	fn, exists := presetTopologies[name]
	if !exists {
		return nil, ErrTopologyNotFound{Name: name}
	}
	return fn(), nil
}

// ListPresetTopologies returns the names of all available preset topologies.
func ListPresetTopologies() []string {
	names := make([]string, 0, len(presetTopologies))
	for name := range presetTopologies {
		names = append(names, name)
	}
	return names
}

// RegisterPresetTopology registers a custom preset topology.
func RegisterPresetTopology(name string, fn PresetTopologyFunc) {
	presetTopologies[name] = fn
}
