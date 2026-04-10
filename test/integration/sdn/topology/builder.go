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
// Topology Builder Interface
// =============================================================================

// Builder provides a fluent interface for constructing test topologies.
type Builder interface {
	// SetName sets the topology name.
	SetName(name string) Builder

	// SetDescription sets the topology description.
	SetDescription(description string) Builder

	// AddNode adds a node to the topology.
	AddNode(node Node) Builder

	// AddNetwork adds a network to the topology.
	AddNetwork(network Network) Builder

	// AddBGPPeer adds a BGP peering configuration.
	AddBGPPeer(peer BGPPeerConfig) Builder

	// AddIPAMPool adds an IPAM pool configuration.
	AddIPAMPool(pool IPAMPoolConfig) Builder

	// SetDHCPConfig sets the DHCP configuration.
	SetDHCPConfig(config *DHCPConfig) Builder

	// SetVXLANConfig sets the VXLAN configuration.
	SetVXLANConfig(config *VXLANConfig) Builder

	// SetTimeouts sets the topology timeouts.
	SetTimeouts(timeouts TopologyTimeouts) Builder

	// SetResourceLimits sets the resource limits.
	SetResourceLimits(limits *ResourceLimits) Builder

	// AddLabel adds a label to the topology.
	AddLabel(key, value string) Builder

	// Build validates and returns the constructed topology.
	Build() (*Topology, error)
}

// =============================================================================
// Builder Implementation
// =============================================================================

// topologyBuilder implements the Builder interface.
type topologyBuilder struct {
	topology *Topology
	errors   []error
}

// NewBuilder creates a new topology builder.
func NewBuilder() Builder {
	return &topologyBuilder{
		topology: &Topology{
			Nodes:     make([]Node, 0),
			Networks:  make([]Network, 0),
			BGPPeers:  make([]BGPPeerConfig, 0),
			IPAMPools: make([]IPAMPoolConfig, 0),
			Labels:    make(map[string]string),
			Timeouts:  DefaultTimeouts(),
		},
		errors: make([]error, 0),
	}
}

// SetName sets the topology name.
func (b *topologyBuilder) SetName(name string) Builder {
	b.topology.Name = name
	return b
}

// SetDescription sets the topology description.
func (b *topologyBuilder) SetDescription(description string) Builder {
	b.topology.Description = description
	return b
}

// AddNode adds a node to the topology.
func (b *topologyBuilder) AddNode(node Node) Builder {
	b.topology.Nodes = append(b.topology.Nodes, node)
	return b
}

// AddNetwork adds a network to the topology.
func (b *topologyBuilder) AddNetwork(network Network) Builder {
	b.topology.Networks = append(b.topology.Networks, network)
	return b
}

// AddBGPPeer adds a BGP peering configuration.
func (b *topologyBuilder) AddBGPPeer(peer BGPPeerConfig) Builder {
	b.topology.BGPPeers = append(b.topology.BGPPeers, peer)
	return b
}

// AddIPAMPool adds an IPAM pool configuration.
func (b *topologyBuilder) AddIPAMPool(pool IPAMPoolConfig) Builder {
	b.topology.IPAMPools = append(b.topology.IPAMPools, pool)
	return b
}

// SetDHCPConfig sets the DHCP configuration.
func (b *topologyBuilder) SetDHCPConfig(config *DHCPConfig) Builder {
	b.topology.DHCPConfig = config
	return b
}

// SetVXLANConfig sets the VXLAN configuration.
func (b *topologyBuilder) SetVXLANConfig(config *VXLANConfig) Builder {
	b.topology.VXLANConfig = config
	return b
}

// SetTimeouts sets the topology timeouts.
func (b *topologyBuilder) SetTimeouts(timeouts TopologyTimeouts) Builder {
	b.topology.Timeouts = timeouts
	return b
}

// SetResourceLimits sets the resource limits.
func (b *topologyBuilder) SetResourceLimits(limits *ResourceLimits) Builder {
	b.topology.ResourceLimits = limits
	return b
}

// AddLabel adds a label to the topology.
func (b *topologyBuilder) AddLabel(key, value string) Builder {
	b.topology.Labels[key] = value
	return b
}

// Build validates and returns the constructed topology.
func (b *topologyBuilder) Build() (*Topology, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b.topology, nil
}

// validate validates the topology configuration.
func (b *topologyBuilder) validate() error {
	if b.topology.Name == "" {
		return ErrInvalidTopology{Name: "", Reason: "topology name is required"}
	}

	if len(b.topology.Nodes) == 0 {
		return ErrInvalidTopology{Name: b.topology.Name, Reason: "at least one node is required"}
	}

	// Check for duplicate node names
	nodeNames := make(map[string]struct{})
	for _, node := range b.topology.Nodes {
		if node.Name == "" {
			return ErrInvalidTopology{Name: b.topology.Name, Reason: "node name is required"}
		}
		if _, exists := nodeNames[node.Name]; exists {
			return ErrInvalidTopology{Name: b.topology.Name, Reason: "duplicate node name: " + node.Name}
		}
		nodeNames[node.Name] = struct{}{}
	}

	// Check for duplicate network names
	networkNames := make(map[string]struct{})
	for _, network := range b.topology.Networks {
		if network.Name == "" {
			return ErrInvalidTopology{Name: b.topology.Name, Reason: "network name is required"}
		}
		if _, exists := networkNames[network.Name]; exists {
			return ErrInvalidTopology{Name: b.topology.Name, Reason: "duplicate network name: " + network.Name}
		}
		networkNames[network.Name] = struct{}{}
	}

	// Validate node network references
	for _, node := range b.topology.Nodes {
		for _, netName := range node.Networks {
			if _, exists := networkNames[netName]; !exists {
				return ErrInvalidTopology{
					Name:   b.topology.Name,
					Reason: "node " + node.Name + " references unknown network: " + netName,
				}
			}
		}
	}

	// Validate node dependencies
	for _, node := range b.topology.Nodes {
		for _, depName := range node.DependsOn {
			if _, exists := nodeNames[depName]; !exists {
				return ErrInvalidTopology{
					Name:   b.topology.Name,
					Reason: "node " + node.Name + " depends on unknown node: " + depName,
				}
			}
			if depName == node.Name {
				return ErrInvalidTopology{
					Name:   b.topology.Name,
					Reason: "node " + node.Name + " cannot depend on itself",
				}
			}
		}
	}

	// Validate resource limits if specified
	if b.topology.ResourceLimits != nil {
		if b.topology.ResourceLimits.MaxNodes > 0 && len(b.topology.Nodes) > b.topology.ResourceLimits.MaxNodes {
			return ErrResourceLimitExceeded{
				Resource: "nodes",
				Limit:    string(rune(b.topology.ResourceLimits.MaxNodes)),
				Actual:   string(rune(len(b.topology.Nodes))),
			}
		}
		if b.topology.ResourceLimits.MaxNetworks > 0 && len(b.topology.Networks) > b.topology.ResourceLimits.MaxNetworks {
			return ErrResourceLimitExceeded{
				Resource: "networks",
				Limit:    string(rune(b.topology.ResourceLimits.MaxNetworks)),
				Actual:   string(rune(len(b.topology.Networks))),
			}
		}
	}

	return nil
}

// =============================================================================
// Node Builder
// =============================================================================

// NodeBuilder provides a fluent interface for constructing nodes.
type NodeBuilder interface {
	// SetName sets the node name.
	SetName(name string) NodeBuilder

	// SetType sets the node type.
	SetType(nodeType NodeType) NodeBuilder

	// SetImage sets the Docker image.
	SetImage(image string) NodeBuilder

	// AddNetwork adds a network to the node.
	AddNetwork(network string) NodeBuilder

	// SetConfig sets a configuration value.
	SetConfig(key, value string) NodeBuilder

	// SetEnvironment sets an environment variable.
	SetEnvironment(key, value string) NodeBuilder

	// AddVolume adds a volume mount.
	AddVolume(mount VolumeMount) NodeBuilder

	// AddCapability adds a Linux capability.
	AddCapability(cap string) NodeBuilder

	// SetPrivileged sets the privileged flag.
	SetPrivileged(privileged bool) NodeBuilder

	// AddPort adds a port mapping.
	AddPort(mapping PortMapping) NodeBuilder

	// AddDependency adds a dependency on another node.
	AddDependency(nodeName string) NodeBuilder

	// SetHealthCheck sets the health check configuration.
	SetHealthCheck(healthCheck *HealthCheck) NodeBuilder

	// SetResources sets the resource limits.
	SetResources(resources *NodeResources) NodeBuilder

	// AddLabel adds a label.
	AddLabel(key, value string) NodeBuilder

	// Build returns the constructed node.
	Build() Node
}

// nodeBuilder implements the NodeBuilder interface.
type nodeBuilder struct {
	node Node
}

// NewNodeBuilder creates a new node builder.
func NewNodeBuilder() NodeBuilder {
	return &nodeBuilder{
		node: Node{
			Networks:     make([]string, 0),
			Config:       make(map[string]string),
			Environment:  make(map[string]string),
			Volumes:      make([]VolumeMount, 0),
			Capabilities: make([]string, 0),
			Ports:        make([]PortMapping, 0),
			DependsOn:    make([]string, 0),
			Labels:       make(map[string]string),
		},
	}
}

// SetName sets the node name.
func (b *nodeBuilder) SetName(name string) NodeBuilder {
	b.node.Name = name
	return b
}

// SetType sets the node type.
func (b *nodeBuilder) SetType(nodeType NodeType) NodeBuilder {
	b.node.Type = nodeType
	return b
}

// SetImage sets the Docker image.
func (b *nodeBuilder) SetImage(image string) NodeBuilder {
	b.node.Image = image
	return b
}

// AddNetwork adds a network to the node.
func (b *nodeBuilder) AddNetwork(network string) NodeBuilder {
	b.node.Networks = append(b.node.Networks, network)
	return b
}

// SetConfig sets a configuration value.
func (b *nodeBuilder) SetConfig(key, value string) NodeBuilder {
	b.node.Config[key] = value
	return b
}

// SetEnvironment sets an environment variable.
func (b *nodeBuilder) SetEnvironment(key, value string) NodeBuilder {
	b.node.Environment[key] = value
	return b
}

// AddVolume adds a volume mount.
func (b *nodeBuilder) AddVolume(mount VolumeMount) NodeBuilder {
	b.node.Volumes = append(b.node.Volumes, mount)
	return b
}

// AddCapability adds a Linux capability.
func (b *nodeBuilder) AddCapability(cap string) NodeBuilder {
	b.node.Capabilities = append(b.node.Capabilities, cap)
	return b
}

// SetPrivileged sets the privileged flag.
func (b *nodeBuilder) SetPrivileged(privileged bool) NodeBuilder {
	b.node.Privileged = privileged
	return b
}

// AddPort adds a port mapping.
func (b *nodeBuilder) AddPort(mapping PortMapping) NodeBuilder {
	b.node.Ports = append(b.node.Ports, mapping)
	return b
}

// AddDependency adds a dependency on another node.
func (b *nodeBuilder) AddDependency(nodeName string) NodeBuilder {
	b.node.DependsOn = append(b.node.DependsOn, nodeName)
	return b
}

// SetHealthCheck sets the health check configuration.
func (b *nodeBuilder) SetHealthCheck(healthCheck *HealthCheck) NodeBuilder {
	b.node.HealthCheck = healthCheck
	return b
}

// SetResources sets the resource limits.
func (b *nodeBuilder) SetResources(resources *NodeResources) NodeBuilder {
	b.node.Resources = resources
	return b
}

// AddLabel adds a label.
func (b *nodeBuilder) AddLabel(key, value string) NodeBuilder {
	b.node.Labels[key] = value
	return b
}

// Build returns the constructed node.
func (b *nodeBuilder) Build() Node {
	return b.node
}

// =============================================================================
// Network Builder
// =============================================================================

// NetworkBuilder provides a fluent interface for constructing networks.
type NetworkBuilder interface {
	// SetName sets the network name.
	SetName(name string) NetworkBuilder

	// SetSubnet sets the network subnet.
	SetSubnet(subnet string) NetworkBuilder

	// SetGateway sets the network gateway.
	SetGateway(gateway string) NetworkBuilder

	// SetDriver sets the network driver.
	SetDriver(driver NetworkDriver) NetworkBuilder

	// SetVNI sets the VXLAN Network Identifier.
	SetVNI(vni uint32) NetworkBuilder

	// SetIPRange sets the IP allocation range.
	SetIPRange(ipRange string) NetworkBuilder

	// SetOption sets a driver-specific option.
	SetOption(key, value string) NetworkBuilder

	// SetInternal sets the internal flag.
	SetInternal(internal bool) NetworkBuilder

	// SetEnableIPv6 enables IPv6.
	SetEnableIPv6(enable bool) NetworkBuilder

	// SetIPv6Subnet sets the IPv6 subnet.
	SetIPv6Subnet(subnet string) NetworkBuilder

	// AddLabel adds a label.
	AddLabel(key, value string) NetworkBuilder

	// Build returns the constructed network.
	Build() Network
}

// networkBuilder implements the NetworkBuilder interface.
type networkBuilder struct {
	network Network
}

// NewNetworkBuilder creates a new network builder.
func NewNetworkBuilder() NetworkBuilder {
	return &networkBuilder{
		network: Network{
			Driver:  NetworkDriverBridge,
			Options: make(map[string]string),
			Labels:  make(map[string]string),
		},
	}
}

// SetName sets the network name.
func (b *networkBuilder) SetName(name string) NetworkBuilder {
	b.network.Name = name
	return b
}

// SetSubnet sets the network subnet.
func (b *networkBuilder) SetSubnet(subnet string) NetworkBuilder {
	b.network.Subnet = subnet
	return b
}

// SetGateway sets the network gateway.
func (b *networkBuilder) SetGateway(gateway string) NetworkBuilder {
	b.network.Gateway = gateway
	return b
}

// SetDriver sets the network driver.
func (b *networkBuilder) SetDriver(driver NetworkDriver) NetworkBuilder {
	b.network.Driver = driver
	return b
}

// SetVNI sets the VXLAN Network Identifier.
func (b *networkBuilder) SetVNI(vni uint32) NetworkBuilder {
	b.network.VNI = vni
	return b
}

// SetIPRange sets the IP allocation range.
func (b *networkBuilder) SetIPRange(ipRange string) NetworkBuilder {
	b.network.IPRange = ipRange
	return b
}

// SetOption sets a driver-specific option.
func (b *networkBuilder) SetOption(key, value string) NetworkBuilder {
	b.network.Options[key] = value
	return b
}

// SetInternal sets the internal flag.
func (b *networkBuilder) SetInternal(internal bool) NetworkBuilder {
	b.network.Internal = internal
	return b
}

// SetEnableIPv6 enables IPv6.
func (b *networkBuilder) SetEnableIPv6(enable bool) NetworkBuilder {
	b.network.EnableIPv6 = enable
	return b
}

// SetIPv6Subnet sets the IPv6 subnet.
func (b *networkBuilder) SetIPv6Subnet(subnet string) NetworkBuilder {
	b.network.IPv6Subnet = subnet
	return b
}

// AddLabel adds a label.
func (b *networkBuilder) AddLabel(key, value string) NetworkBuilder {
	b.network.Labels[key] = value
	return b
}

// Build returns the constructed network.
func (b *networkBuilder) Build() Network {
	return b.network
}

// =============================================================================
// BGP Peer Builder
// =============================================================================

// BGPPeerBuilder provides a fluent interface for constructing BGP peer configs.
type BGPPeerBuilder interface {
	// SetName sets the peer name.
	SetName(name string) BGPPeerBuilder

	// SetLocalASN sets the local ASN.
	SetLocalASN(asn uint32) BGPPeerBuilder

	// SetRemoteASN sets the remote ASN.
	SetRemoteASN(asn uint32) BGPPeerBuilder

	// SetLocalAddress sets the local address.
	SetLocalAddress(addr netip.Addr) BGPPeerBuilder

	// SetRemoteAddress sets the remote address.
	SetRemoteAddress(addr netip.Addr) BGPPeerBuilder

	// SetLocalNodeName sets the local node name.
	SetLocalNodeName(name string) BGPPeerBuilder

	// SetRemoteNodeName sets the remote node name.
	SetRemoteNodeName(name string) BGPPeerBuilder

	// SetEnableEVPN enables EVPN.
	SetEnableEVPN(enable bool) BGPPeerBuilder

	// SetEnableIPv4 enables IPv4 unicast.
	SetEnableIPv4(enable bool) BGPPeerBuilder

	// SetEnableIPv6 enables IPv6 unicast.
	SetEnableIPv6(enable bool) BGPPeerBuilder

	// AddPrefix adds a prefix to announce.
	AddPrefix(prefix string) BGPPeerBuilder

	// SetHoldTime sets the hold time.
	SetHoldTime(seconds uint16) BGPPeerBuilder

	// SetKeepaliveInterval sets the keepalive interval.
	SetKeepaliveInterval(seconds uint16) BGPPeerBuilder

	// SetDescription sets the description.
	SetDescription(description string) BGPPeerBuilder

	// Build returns the constructed BGP peer config.
	Build() BGPPeerConfig
}

// bgpPeerBuilder implements the BGPPeerBuilder interface.
type bgpPeerBuilder struct {
	peer BGPPeerConfig
}

// NewBGPPeerBuilder creates a new BGP peer builder.
func NewBGPPeerBuilder() BGPPeerBuilder {
	return &bgpPeerBuilder{
		peer: BGPPeerConfig{
			Prefixes:          make([]string, 0),
			HoldTime:          90,
			KeepaliveInterval: 30,
			ConnectRetryTime:  120,
			EnableIPv4:        true,
		},
	}
}

// SetName sets the peer name.
func (b *bgpPeerBuilder) SetName(name string) BGPPeerBuilder {
	b.peer.Name = name
	return b
}

// SetLocalASN sets the local ASN.
func (b *bgpPeerBuilder) SetLocalASN(asn uint32) BGPPeerBuilder {
	b.peer.LocalASN = asn
	return b
}

// SetRemoteASN sets the remote ASN.
func (b *bgpPeerBuilder) SetRemoteASN(asn uint32) BGPPeerBuilder {
	b.peer.RemoteASN = asn
	return b
}

// SetLocalAddress sets the local address.
func (b *bgpPeerBuilder) SetLocalAddress(addr netip.Addr) BGPPeerBuilder {
	b.peer.LocalAddress = addr
	return b
}

// SetRemoteAddress sets the remote address.
func (b *bgpPeerBuilder) SetRemoteAddress(addr netip.Addr) BGPPeerBuilder {
	b.peer.RemoteAddress = addr
	return b
}

// SetLocalNodeName sets the local node name.
func (b *bgpPeerBuilder) SetLocalNodeName(name string) BGPPeerBuilder {
	b.peer.LocalNodeName = name
	return b
}

// SetRemoteNodeName sets the remote node name.
func (b *bgpPeerBuilder) SetRemoteNodeName(name string) BGPPeerBuilder {
	b.peer.RemoteNodeName = name
	return b
}

// SetEnableEVPN enables EVPN.
func (b *bgpPeerBuilder) SetEnableEVPN(enable bool) BGPPeerBuilder {
	b.peer.EnableEVPN = enable
	return b
}

// SetEnableIPv4 enables IPv4 unicast.
func (b *bgpPeerBuilder) SetEnableIPv4(enable bool) BGPPeerBuilder {
	b.peer.EnableIPv4 = enable
	return b
}

// SetEnableIPv6 enables IPv6 unicast.
func (b *bgpPeerBuilder) SetEnableIPv6(enable bool) BGPPeerBuilder {
	b.peer.EnableIPv6 = enable
	return b
}

// AddPrefix adds a prefix to announce.
func (b *bgpPeerBuilder) AddPrefix(prefix string) BGPPeerBuilder {
	b.peer.Prefixes = append(b.peer.Prefixes, prefix)
	return b
}

// SetHoldTime sets the hold time.
func (b *bgpPeerBuilder) SetHoldTime(seconds uint16) BGPPeerBuilder {
	b.peer.HoldTime = seconds
	return b
}

// SetKeepaliveInterval sets the keepalive interval.
func (b *bgpPeerBuilder) SetKeepaliveInterval(seconds uint16) BGPPeerBuilder {
	b.peer.KeepaliveInterval = seconds
	return b
}

// SetDescription sets the description.
func (b *bgpPeerBuilder) SetDescription(description string) BGPPeerBuilder {
	b.peer.Description = description
	return b
}

// Build returns the constructed BGP peer config.
func (b *bgpPeerBuilder) Build() BGPPeerConfig {
	return b.peer
}

// =============================================================================
// Default Configurations
// =============================================================================

// DefaultTimeouts returns the default topology timeouts.
func DefaultTimeouts() TopologyTimeouts {
	return TopologyTimeouts{
		StartupTimeout:        5 * time.Minute,
		ShutdownTimeout:       2 * time.Minute,
		HealthCheckTimeout:    30 * time.Second,
		NodeStartTimeout:      60 * time.Second,
		NetworkTimeout:        30 * time.Second,
		BGPConvergenceTimeout: 2 * time.Minute,
	}
}

// DefaultVXLANConfig returns the default VXLAN configuration.
func DefaultVXLANConfig() *VXLANConfig {
	return &VXLANConfig{
		VNI:         100,
		DestPort:    4789,
		TOS:         0,
		TTL:         64,
		Learning:    true,
		L2Miss:      true,
		L3Miss:      true,
		RSC:         false,
		GBP:         false,
		EVPNEnabled: true,
	}
}

// DefaultDHCPConfig returns the default DHCP configuration.
func DefaultDHCPConfig(nodeName, iface string) *DHCPConfig {
	return &DHCPConfig{
		Enabled:     true,
		NodeName:    nodeName,
		Interface:   iface,
		LeaseTime:   3600,
		RenewalTime: 1800,
		RebindTime:  3150,
		DNS:         []string{"8.8.8.8", "8.8.4.4"},
		Domain:      "test.local",
	}
}

// DefaultHealthCheck returns a default health check configuration.
func DefaultHealthCheck() *HealthCheck {
	return &HealthCheck{
		Command:     []string{"ovs-vsctl", "show"},
		Interval:    10 * time.Second,
		Timeout:     5 * time.Second,
		StartPeriod: 30 * time.Second,
		Retries:     3,
	}
}

// DefaultNodeResources returns default resource limits for a node.
func DefaultNodeResources() *NodeResources {
	return &NodeResources{
		CPULimit:          "1.0",
		MemoryLimit:       "512m",
		CPUReservation:    "0.25",
		MemoryReservation: "128m",
	}
}

// DefaultGatewayCapabilities returns the default capabilities for a gateway node.
func DefaultGatewayCapabilities() []string {
	return []string{
		"NET_ADMIN",
		"SYS_ADMIN",
		"NET_RAW",
		"SYS_PTRACE",
	}
}

// DefaultComputeCapabilities returns the default capabilities for a compute node.
func DefaultComputeCapabilities() []string {
	return []string{
		"NET_ADMIN",
		"NET_RAW",
	}
}
