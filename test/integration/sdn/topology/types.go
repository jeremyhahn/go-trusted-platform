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

// Package topology provides test topology automation for SDN integration tests.
// It enables programmatic creation of multi-node network topologies with VXLAN
// tunnels, BGP peering, IPAM pools, and DHCP services for comprehensive testing.

//go:build integration

package topology

import (
	"net/netip"
	"time"
)

// =============================================================================
// Node Types
// =============================================================================

// NodeType represents the type of node in a test topology.
type NodeType uint8

const (
	// NodeTypeGateway represents a gateway node with full SDN capabilities.
	// Gateway nodes can operate in overlay, edge, and transit modes.
	NodeTypeGateway NodeType = iota

	// NodeTypeCompute represents a compute node that hosts workloads.
	// Compute nodes participate in overlay networking via VXLAN.
	NodeTypeCompute

	// NodeTypeEdge represents an edge node for IoT device onboarding.
	// Edge nodes handle device provisioning and P2P services.
	NodeTypeEdge

	// NodeTypeMockISP represents a mock ISP router for BGP transit testing.
	// Mock ISPs simulate external BGP peers for prefix announcement testing.
	NodeTypeMockISP

	// NodeTypeClient represents a client node for testing connectivity.
	// Client nodes are simple endpoints for validating network connectivity.
	NodeTypeClient
)

// String returns the string representation of the node type.
func (t NodeType) String() string {
	switch t {
	case NodeTypeGateway:
		return "gateway"
	case NodeTypeCompute:
		return "compute"
	case NodeTypeEdge:
		return "edge"
	case NodeTypeMockISP:
		return "mock-isp"
	case NodeTypeClient:
		return "client"
	default:
		return "unknown"
	}
}

// =============================================================================
// Network Types
// =============================================================================

// NetworkDriver represents the network driver type for Docker networks.
type NetworkDriver string

const (
	// NetworkDriverBridge uses Docker's bridge networking.
	NetworkDriverBridge NetworkDriver = "bridge"

	// NetworkDriverOverlay uses Docker's overlay networking for multi-host.
	NetworkDriverOverlay NetworkDriver = "overlay"

	// NetworkDriverMacvlan uses macvlan for direct L2 access.
	NetworkDriverMacvlan NetworkDriver = "macvlan"

	// NetworkDriverIPvlan uses ipvlan for shared MAC address.
	NetworkDriverIPvlan NetworkDriver = "ipvlan"

	// NetworkDriverHost uses the host's networking namespace.
	NetworkDriverHost NetworkDriver = "host"

	// NetworkDriverNone disables networking.
	NetworkDriverNone NetworkDriver = "none"
)

// =============================================================================
// Core Topology Types
// =============================================================================

// Topology represents a complete test network topology.
// A topology consists of nodes, networks, BGP peers, IPAM pools, and DHCP configs.
type Topology struct {
	// Name is the unique identifier for this topology.
	Name string

	// Description provides a human-readable description.
	Description string

	// Nodes is the list of nodes in this topology.
	Nodes []Node

	// Networks is the list of networks in this topology.
	Networks []Network

	// BGPPeers is the list of BGP peering configurations.
	BGPPeers []BGPPeerConfig

	// IPAMPools is the list of IPAM pool configurations.
	IPAMPools []IPAMPoolConfig

	// DHCPConfig is the DHCP server configuration.
	DHCPConfig *DHCPConfig

	// VXLANConfig is the VXLAN overlay configuration.
	VXLANConfig *VXLANConfig

	// Labels are arbitrary labels for topology identification.
	Labels map[string]string

	// Timeouts defines various timeout values for the topology.
	Timeouts TopologyTimeouts

	// ResourceLimits defines resource constraints for nodes.
	ResourceLimits *ResourceLimits
}

// Node represents a single node in the test topology.
type Node struct {
	// Name is the unique name for this node within the topology.
	Name string

	// Type is the node type (gateway, compute, edge, etc.).
	Type NodeType

	// Image is the Docker image to use for this node.
	Image string

	// Networks is the list of network names this node connects to.
	Networks []string

	// Config contains node-specific configuration.
	Config map[string]string

	// Environment contains environment variables for the container.
	Environment map[string]string

	// Volumes contains volume mounts for the container.
	Volumes []VolumeMount

	// Capabilities contains Linux capabilities to add.
	Capabilities []string

	// Privileged indicates if the container runs in privileged mode.
	Privileged bool

	// Ports contains port mappings for the container.
	Ports []PortMapping

	// DependsOn contains node names this node depends on.
	DependsOn []string

	// HealthCheck defines how to verify node health.
	HealthCheck *HealthCheck

	// Resources defines resource limits for this node.
	Resources *NodeResources

	// Labels are arbitrary labels for node identification.
	Labels map[string]string
}

// Network represents a network in the test topology.
type Network struct {
	// Name is the unique name for this network.
	Name string

	// Subnet is the network subnet in CIDR notation.
	Subnet string

	// Gateway is the gateway IP address for this network.
	Gateway string

	// Driver is the network driver to use.
	Driver NetworkDriver

	// VNI is the VXLAN Network Identifier (only for overlay networks).
	VNI uint32

	// IPRange is the IP allocation range within the subnet.
	IPRange string

	// Options contains driver-specific options.
	Options map[string]string

	// Internal indicates if this is an internal network.
	Internal bool

	// EnableIPv6 enables IPv6 on this network.
	EnableIPv6 bool

	// IPv6Subnet is the IPv6 subnet in CIDR notation.
	IPv6Subnet string

	// Labels are arbitrary labels for network identification.
	Labels map[string]string
}

// =============================================================================
// BGP Configuration Types
// =============================================================================

// BGPPeerConfig represents a BGP peering configuration.
type BGPPeerConfig struct {
	// Name is a unique identifier for this peer configuration.
	Name string

	// LocalASN is the local Autonomous System Number.
	LocalASN uint32

	// RemoteASN is the remote Autonomous System Number.
	RemoteASN uint32

	// LocalAddress is the local IP address for the BGP session.
	LocalAddress netip.Addr

	// RemoteAddress is the remote IP address for the BGP session.
	RemoteAddress netip.Addr

	// LocalNodeName is the name of the local node.
	LocalNodeName string

	// RemoteNodeName is the name of the remote node.
	RemoteNodeName string

	// EnableEVPN enables EVPN address family.
	EnableEVPN bool

	// EnableIPv4 enables IPv4 unicast address family.
	EnableIPv4 bool

	// EnableIPv6 enables IPv6 unicast address family.
	EnableIPv6 bool

	// Prefixes is the list of prefixes to announce.
	Prefixes []string

	// HoldTime is the BGP hold time in seconds.
	HoldTime uint16

	// KeepaliveInterval is the keepalive interval in seconds.
	KeepaliveInterval uint16

	// ConnectRetryTime is the connect retry time in seconds.
	ConnectRetryTime uint16

	// Description is a human-readable description.
	Description string
}

// =============================================================================
// IPAM Configuration Types
// =============================================================================

// IPAMPoolConfig represents an IPAM pool configuration for testing.
type IPAMPoolConfig struct {
	// ID is the unique pool identifier.
	ID string

	// Name is the human-readable pool name.
	Name string

	// CIDR is the IP range in CIDR notation.
	CIDR string

	// Gateway is the gateway address for this pool.
	Gateway string

	// RangeStart is the start of the allocation range.
	RangeStart string

	// RangeEnd is the end of the allocation range.
	RangeEnd string

	// DNS is the list of DNS servers.
	DNS []string

	// LeaseDuration is the default lease duration.
	LeaseDuration time.Duration

	// Reserved is the list of reserved IP addresses.
	Reserved []string

	// NodeName is the node that manages this pool.
	NodeName string
}

// =============================================================================
// DHCP Configuration Types
// =============================================================================

// DHCPConfig represents DHCP server configuration for testing.
type DHCPConfig struct {
	// Enabled indicates if DHCP is enabled.
	Enabled bool

	// NodeName is the node that runs the DHCP server.
	NodeName string

	// Interface is the network interface to bind to.
	Interface string

	// ServerID is the DHCP server identifier.
	ServerID string

	// LeaseTime is the default lease time in seconds.
	LeaseTime uint32

	// RenewalTime is the renewal time (T1) in seconds.
	RenewalTime uint32

	// RebindTime is the rebind time (T2) in seconds.
	RebindTime uint32

	// DNS is the list of DNS servers.
	DNS []string

	// Domain is the DNS domain name.
	Domain string

	// NTPServers is the list of NTP servers.
	NTPServers []string

	// Options contains additional DHCP options.
	Options map[uint8][]byte
}

// =============================================================================
// VXLAN Configuration Types
// =============================================================================

// VXLANConfig represents VXLAN overlay configuration for testing.
type VXLANConfig struct {
	// VNI is the default Virtual Network Identifier.
	VNI uint32

	// DestPort is the VXLAN UDP destination port (default 4789).
	DestPort uint16

	// TOS is the IP TOS field value.
	TOS uint8

	// TTL is the IP TTL field value.
	TTL uint8

	// Learning enables MAC address learning in the datapath.
	Learning bool

	// L2Miss enables L2 miss notifications.
	L2Miss bool

	// L3Miss enables L3 miss notifications.
	L3Miss bool

	// RSC enables route short-circuit.
	RSC bool

	// GBP enables VXLAN Group Based Policy.
	GBP bool

	// EVPNEnabled enables EVPN control plane.
	EVPNEnabled bool
}

// =============================================================================
// Container Configuration Types
// =============================================================================

// VolumeMount represents a volume mount for a container.
type VolumeMount struct {
	// Source is the source path or volume name.
	Source string

	// Target is the target path inside the container.
	Target string

	// ReadOnly indicates if the mount is read-only.
	ReadOnly bool

	// Type is the mount type (bind, volume, tmpfs).
	Type string
}

// PortMapping represents a port mapping for a container.
type PortMapping struct {
	// HostPort is the port on the host.
	HostPort uint16

	// ContainerPort is the port inside the container.
	ContainerPort uint16

	// Protocol is the protocol (tcp, udp).
	Protocol string

	// HostIP is the host IP to bind to.
	HostIP string
}

// HealthCheck defines health check configuration for a node.
type HealthCheck struct {
	// Command is the command to run for health check.
	Command []string

	// Interval is the interval between health checks.
	Interval time.Duration

	// Timeout is the maximum time to wait for a health check.
	Timeout time.Duration

	// StartPeriod is the time to wait before starting health checks.
	StartPeriod time.Duration

	// Retries is the number of retries before marking unhealthy.
	Retries int
}

// NodeResources defines resource limits for a node.
type NodeResources struct {
	// CPULimit is the CPU limit (e.g., "1.0" for 1 CPU).
	CPULimit string

	// MemoryLimit is the memory limit (e.g., "512m", "1g").
	MemoryLimit string

	// CPUReservation is the CPU reservation.
	CPUReservation string

	// MemoryReservation is the memory reservation.
	MemoryReservation string
}

// ResourceLimits defines global resource constraints for a topology.
type ResourceLimits struct {
	// MaxNodes is the maximum number of nodes.
	MaxNodes int

	// MaxNetworks is the maximum number of networks.
	MaxNetworks int

	// MaxTotalCPU is the maximum total CPU allocation.
	MaxTotalCPU string

	// MaxTotalMemory is the maximum total memory allocation.
	MaxTotalMemory string
}

// TopologyTimeouts defines timeout values for topology operations.
type TopologyTimeouts struct {
	// StartupTimeout is the maximum time to wait for topology startup.
	StartupTimeout time.Duration

	// ShutdownTimeout is the maximum time to wait for topology shutdown.
	ShutdownTimeout time.Duration

	// HealthCheckTimeout is the timeout for health checks.
	HealthCheckTimeout time.Duration

	// NodeStartTimeout is the timeout for individual node startup.
	NodeStartTimeout time.Duration

	// NetworkTimeout is the timeout for network operations.
	NetworkTimeout time.Duration

	// BGPConvergenceTimeout is the timeout for BGP convergence.
	BGPConvergenceTimeout time.Duration
}

// =============================================================================
// Topology Status Types
// =============================================================================

// TopologyState represents the current state of a topology.
type TopologyState uint8

const (
	// TopologyStateUnknown indicates unknown state.
	TopologyStateUnknown TopologyState = iota

	// TopologyStateCreating indicates topology is being created.
	TopologyStateCreating

	// TopologyStateStarting indicates topology is starting up.
	TopologyStateStarting

	// TopologyStateRunning indicates topology is running.
	TopologyStateRunning

	// TopologyStateStopping indicates topology is stopping.
	TopologyStateStopping

	// TopologyStateStopped indicates topology is stopped.
	TopologyStateStopped

	// TopologyStateFailed indicates topology failed.
	TopologyStateFailed

	// TopologyStateDestroying indicates topology is being destroyed.
	TopologyStateDestroying

	// TopologyStateDestroyed indicates topology was destroyed.
	TopologyStateDestroyed
)

// String returns the string representation of the topology state.
func (s TopologyState) String() string {
	switch s {
	case TopologyStateUnknown:
		return "unknown"
	case TopologyStateCreating:
		return "creating"
	case TopologyStateStarting:
		return "starting"
	case TopologyStateRunning:
		return "running"
	case TopologyStateStopping:
		return "stopping"
	case TopologyStateStopped:
		return "stopped"
	case TopologyStateFailed:
		return "failed"
	case TopologyStateDestroying:
		return "destroying"
	case TopologyStateDestroyed:
		return "destroyed"
	default:
		return "unknown"
	}
}

// TopologyStatus represents the status of a running topology.
type TopologyStatus struct {
	// Name is the topology name.
	Name string

	// State is the current topology state.
	State TopologyState

	// StartedAt is when the topology was started.
	StartedAt time.Time

	// NodeStatuses contains the status of each node.
	NodeStatuses map[string]NodeStatus

	// NetworkStatuses contains the status of each network.
	NetworkStatuses map[string]NetworkStatus

	// Error is the last error (if state is Failed).
	Error error
}

// NodeStatus represents the status of a running node.
type NodeStatus struct {
	// Name is the node name.
	Name string

	// ContainerID is the Docker container ID.
	ContainerID string

	// State is the container state (running, stopped, etc.).
	State string

	// IPAddresses contains IP addresses per network.
	IPAddresses map[string]string

	// Healthy indicates if the node is healthy.
	Healthy bool

	// StartedAt is when the node was started.
	StartedAt time.Time

	// ExitCode is the exit code (if stopped).
	ExitCode int

	// Error is any error message.
	Error string
}

// NetworkStatus represents the status of a network.
type NetworkStatus struct {
	// Name is the network name.
	Name string

	// NetworkID is the Docker network ID.
	NetworkID string

	// Subnet is the network subnet.
	Subnet string

	// Gateway is the network gateway.
	Gateway string

	// Created indicates if the network was created.
	Created bool
}

// =============================================================================
// Error Types
// =============================================================================

// ErrTopologyNotFound indicates the topology was not found.
type ErrTopologyNotFound struct {
	Name string
}

func (e ErrTopologyNotFound) Error() string {
	return "topology not found: " + e.Name
}

// ErrTopologyAlreadyExists indicates the topology already exists.
type ErrTopologyAlreadyExists struct {
	Name string
}

func (e ErrTopologyAlreadyExists) Error() string {
	return "topology already exists: " + e.Name
}

// ErrNodeNotFound indicates a node was not found.
type ErrNodeNotFound struct {
	TopologyName string
	NodeName     string
}

func (e ErrNodeNotFound) Error() string {
	return "node " + e.NodeName + " not found in topology " + e.TopologyName
}

// ErrNetworkNotFound indicates a network was not found.
type ErrNetworkNotFound struct {
	TopologyName string
	NetworkName  string
}

func (e ErrNetworkNotFound) Error() string {
	return "network " + e.NetworkName + " not found in topology " + e.TopologyName
}

// ErrTopologyStartFailed indicates topology start failed.
type ErrTopologyStartFailed struct {
	Name   string
	Reason string
}

func (e ErrTopologyStartFailed) Error() string {
	return "failed to start topology " + e.Name + ": " + e.Reason
}

// ErrTopologyStopFailed indicates topology stop failed.
type ErrTopologyStopFailed struct {
	Name   string
	Reason string
}

func (e ErrTopologyStopFailed) Error() string {
	return "failed to stop topology " + e.Name + ": " + e.Reason
}

// ErrHealthCheckFailed indicates health check failed.
type ErrHealthCheckFailed struct {
	NodeName string
	Reason   string
}

func (e ErrHealthCheckFailed) Error() string {
	return "health check failed for node " + e.NodeName + ": " + e.Reason
}

// ErrInvalidTopology indicates the topology configuration is invalid.
type ErrInvalidTopology struct {
	Name   string
	Reason string
}

func (e ErrInvalidTopology) Error() string {
	return "invalid topology " + e.Name + ": " + e.Reason
}

// ErrResourceLimitExceeded indicates a resource limit was exceeded.
type ErrResourceLimitExceeded struct {
	Resource string
	Limit    string
	Actual   string
}

func (e ErrResourceLimitExceeded) Error() string {
	return "resource limit exceeded for " + e.Resource + ": limit=" + e.Limit + ", actual=" + e.Actual
}

// ErrBGPConvergenceFailed indicates BGP convergence failed.
type ErrBGPConvergenceFailed struct {
	Reason string
}

func (e ErrBGPConvergenceFailed) Error() string {
	return "BGP convergence failed: " + e.Reason
}
