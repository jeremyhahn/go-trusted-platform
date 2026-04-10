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

package container

import (
	"regexp"
	"strings"
)

// ContainerServiceMode defines how a container is managed.
type ContainerServiceMode string

const (
	// ServiceModeEmbedded means platformd manages the container directly.
	// Container lifecycle is tied to platformd process.
	// Shares TPM/attestation context with platformd.
	ServiceModeEmbedded ContainerServiceMode = "embedded"

	// ServiceModeStandalone means the container runs as an independent systemd/rc service.
	// platformd generates and manages the service file.
	// Container survives platformd restarts.
	ServiceModeStandalone ContainerServiceMode = "standalone"
)

// String returns the string representation of ContainerServiceMode.
func (m ContainerServiceMode) String() string {
	return string(m)
}

// IsValid returns true if the service mode is valid.
func (m ContainerServiceMode) IsValid() bool {
	return m == ServiceModeEmbedded || m == ServiceModeStandalone
}

// NetworkMode defines the container network mode.
type NetworkMode string

const (
	// NetworkModeBridge uses the default bridge network.
	NetworkModeBridge NetworkMode = "bridge"

	// NetworkModeHost uses the host network namespace.
	NetworkModeHost NetworkMode = "host"

	// NetworkModeNone disables networking.
	NetworkModeNone NetworkMode = "none"

	// NetworkModeSDN uses SDN/OVS/OpenFlow networking.
	NetworkModeSDN NetworkMode = "sdn"
)

// String returns the string representation of NetworkMode.
func (m NetworkMode) String() string {
	return string(m)
}

// IsValid returns true if the network mode is valid.
func (m NetworkMode) IsValid() bool {
	switch m {
	case NetworkModeBridge, NetworkModeHost, NetworkModeNone, NetworkModeSDN:
		return true
	default:
		return false
	}
}

// OrchestratorContainerSpec defines the specification for creating a container
// through the orchestrator. This is distinct from ContainerSpec in attestation.go
// which is used for computing measurement digests.
type OrchestratorContainerSpec struct {
	// Name is the container name (required).
	Name string `json:"name" yaml:"name"`

	// Image is the container image reference (required).
	// Format: [registry/]repository[:tag|@digest]
	Image string `json:"image" yaml:"image"`

	// Command overrides the image's default command.
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`

	// Args are arguments to the command.
	Args []string `json:"args,omitempty" yaml:"args,omitempty"`

	// Env are environment variables for the container.
	Env map[string]string `json:"env,omitempty" yaml:"env,omitempty"`

	// Mounts are filesystem mounts for the container.
	Mounts []MountConfig `json:"mounts,omitempty" yaml:"mounts,omitempty"`

	// Resources define CPU and memory limits.
	Resources ResourceConfig `json:"resources,omitempty" yaml:"resources,omitempty"`

	// Network is the network configuration.
	Network ContainerNetworkConfig `json:"network,omitempty" yaml:"network,omitempty"`

	// Service is the service mode configuration.
	Service ServiceConfig `json:"service,omitempty" yaml:"service,omitempty"`

	// Labels are metadata labels for the container.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Annotations are additional metadata annotations.
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`

	// User specifies the user to run the container as.
	User string `json:"user,omitempty" yaml:"user,omitempty"`

	// WorkingDir sets the working directory inside the container.
	WorkingDir string `json:"working_dir,omitempty" yaml:"working_dir,omitempty"`

	// Privileged runs the container in privileged mode.
	// This should be avoided unless absolutely necessary.
	Privileged bool `json:"privileged,omitempty" yaml:"privileged,omitempty"`

	// Capabilities are Linux capabilities to add or drop.
	Capabilities CapabilityConfig `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`

	// RestartPolicy defines the restart behavior.
	RestartPolicy RestartPolicy `json:"restart_policy,omitempty" yaml:"restart_policy,omitempty"`

	// HealthCheck defines the container health check.
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty" yaml:"health_check,omitempty"`

	// Ports are port mappings for the container.
	Ports []PortMapping `json:"ports,omitempty" yaml:"ports,omitempty"`
}

// ContainerConfig represents a container definition within a Device Profile.
type ContainerConfig struct {
	// Name is the container name (required).
	Name string `json:"name" yaml:"name"`

	// Image is the container image reference (required).
	Image string `json:"image" yaml:"image"`

	// Command overrides the image's default command.
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`

	// Args are arguments to the command.
	Args []string `json:"args,omitempty" yaml:"args,omitempty"`

	// Env are environment variables for the container.
	Env map[string]string `json:"env,omitempty" yaml:"env,omitempty"`

	// Mounts are filesystem mounts for the container.
	Mounts []MountConfig `json:"mounts,omitempty" yaml:"mounts,omitempty"`

	// Resources define CPU and memory limits.
	Resources ResourceConfig `json:"resources,omitempty" yaml:"resources,omitempty"`

	// Network is the network configuration.
	Network ContainerNetworkConfig `json:"network,omitempty" yaml:"network,omitempty"`

	// Service is the service mode configuration.
	Service ServiceConfig `json:"service,omitempty" yaml:"service,omitempty"`

	// Labels are metadata labels for the container.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Privileged runs the container in privileged mode.
	Privileged bool `json:"privileged,omitempty" yaml:"privileged,omitempty"`

	// Capabilities are Linux capabilities to add or drop.
	Capabilities CapabilityConfig `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`

	// Ports are port mappings for the container.
	Ports []PortMapping `json:"ports,omitempty" yaml:"ports,omitempty"`
}

// ServiceConfig defines the service mode for a container.
type ServiceConfig struct {
	// Mode is the service mode (embedded or standalone).
	// Default is embedded.
	Mode ContainerServiceMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// Standalone contains standalone-specific configuration.
	// Only used when Mode is standalone.
	Standalone *StandaloneConfig `json:"standalone,omitempty" yaml:"standalone,omitempty"`
}

// StandaloneConfig contains configuration for standalone service mode.
type StandaloneConfig struct {
	// InitSystemOverride overrides the auto-detected init system.
	// Values: "systemd", "rc", "runit"
	// If empty, the init system is auto-detected from the OS.
	InitSystemOverride string `json:"init_system,omitempty" yaml:"init_system,omitempty"`

	// ServicePath is the path where the service file is written.
	// If empty, a default path is used based on the init system.
	ServicePath string `json:"service_path,omitempty" yaml:"service_path,omitempty"`

	// Restart is the restart policy for the service.
	// Values: "always", "on-failure", "no"
	Restart string `json:"restart,omitempty" yaml:"restart,omitempty"`

	// After lists services this container should start after.
	After []string `json:"after,omitempty" yaml:"after,omitempty"`

	// Wants lists services this container wants.
	Wants []string `json:"wants,omitempty" yaml:"wants,omitempty"`

	// CPUQuota is the CPU quota for the service (systemd format, e.g., "200%").
	CPUQuota string `json:"cpu_quota,omitempty" yaml:"cpu_quota,omitempty"`

	// MemoryMax is the memory limit for the service (e.g., "4G").
	MemoryMax string `json:"memory_max,omitempty" yaml:"memory_max,omitempty"`
}

// ContainerNetworkConfig defines network configuration for a container.
type ContainerNetworkConfig struct {
	// Mode is the network mode.
	// Default is bridge.
	Mode NetworkMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// SDN contains SDN/OVS-specific configuration.
	// Only used when Mode is sdn.
	SDN *SDNConfig `json:"sdn,omitempty" yaml:"sdn,omitempty"`

	// DNSServers are custom DNS servers for the container.
	DNSServers []string `json:"dns_servers,omitempty" yaml:"dns_servers,omitempty"`

	// DNSSearch are DNS search domains.
	DNSSearch []string `json:"dns_search,omitempty" yaml:"dns_search,omitempty"`

	// Hostname is the container hostname.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`

	// ExtraHosts are additional /etc/hosts entries.
	// Format: hostname:ip
	ExtraHosts []string `json:"extra_hosts,omitempty" yaml:"extra_hosts,omitempty"`
}

// SDNConfig contains SDN/OVS-specific network configuration.
type SDNConfig struct {
	// Bridge is the OVS bridge to attach the container to.
	Bridge string `json:"bridge" yaml:"bridge"`

	// VLANID is the VLAN ID for isolation.
	VLANID uint16 `json:"vlan_id" yaml:"vlan_id"`

	// OVSPort is the OVS port name for the container.
	// If empty, a name is auto-generated.
	OVSPort string `json:"ovs_port,omitempty" yaml:"ovs_port,omitempty"`

	// FlowTable is the OpenFlow table for this container's rules.
	FlowTable int `json:"flow_table,omitempty" yaml:"flow_table,omitempty"`

	// FlowPriority is the priority for OpenFlow rules.
	FlowPriority int `json:"flow_priority,omitempty" yaml:"flow_priority,omitempty"`

	// SecurityGroups are security group names to apply.
	SecurityGroups []string `json:"security_groups,omitempty" yaml:"security_groups,omitempty"`

	// OpenFlowRules are custom OpenFlow rules for this container.
	OpenFlowRules []OpenFlowRule `json:"openflow_rules,omitempty" yaml:"openflow_rules,omitempty"`

	// IPAddress is a static IP address for the container.
	// If empty, DHCP or auto-assignment is used.
	IPAddress string `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`

	// MACAddress is a static MAC address for the container.
	// If empty, a MAC is auto-generated.
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`
}

// OpenFlowRule defines an OpenFlow rule for container traffic control.
type OpenFlowRule struct {
	// Match is the match criteria for the rule.
	Match OpenFlowMatch `json:"match" yaml:"match"`

	// Actions are the actions to take when the rule matches.
	Actions []OpenFlowAction `json:"actions" yaml:"actions"`

	// Priority is the rule priority (higher = more specific).
	Priority int `json:"priority" yaml:"priority"`

	// Table is the OpenFlow table for this rule.
	Table int `json:"table" yaml:"table"`
}

// OpenFlowMatch defines match criteria for an OpenFlow rule.
type OpenFlowMatch struct {
	// InPort is the input port to match.
	InPort string `json:"in_port,omitempty" yaml:"in_port,omitempty"`

	// DLType is the Ethernet type to match (e.g., 0x0800 for IPv4).
	DLType uint16 `json:"dl_type,omitempty" yaml:"dl_type,omitempty"`

	// NWProto is the IP protocol to match (e.g., 6 for TCP).
	NWProto uint8 `json:"nw_proto,omitempty" yaml:"nw_proto,omitempty"`

	// TPSrc is the source port to match.
	TPSrc uint16 `json:"tp_src,omitempty" yaml:"tp_src,omitempty"`

	// TPDst is the destination port to match.
	TPDst uint16 `json:"tp_dst,omitempty" yaml:"tp_dst,omitempty"`

	// NWSrc is the source IP to match (CIDR format).
	NWSrc string `json:"nw_src,omitempty" yaml:"nw_src,omitempty"`

	// NWDst is the destination IP to match (CIDR format).
	NWDst string `json:"nw_dst,omitempty" yaml:"nw_dst,omitempty"`

	// DLSrc is the source MAC address to match.
	DLSrc string `json:"dl_src,omitempty" yaml:"dl_src,omitempty"`

	// DLDst is the destination MAC address to match.
	DLDst string `json:"dl_dst,omitempty" yaml:"dl_dst,omitempty"`
}

// OpenFlowAction defines an action for an OpenFlow rule.
type OpenFlowAction struct {
	// Type is the action type.
	Type OpenFlowActionType `json:"type" yaml:"type"`

	// Port is the output port for forward actions.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`

	// Table is the table to goto for goto actions.
	Table int `json:"table,omitempty" yaml:"table,omitempty"`
}

// OpenFlowActionType defines the type of OpenFlow action.
type OpenFlowActionType string

const (
	// ActionAllow allows the packet.
	ActionAllow OpenFlowActionType = "allow"

	// ActionDrop drops the packet.
	ActionDrop OpenFlowActionType = "drop"

	// ActionForward forwards the packet to a port.
	ActionForward OpenFlowActionType = "forward"

	// ActionGoto goes to another table.
	ActionGoto OpenFlowActionType = "goto"
)

// ResourceConfig defines resource limits for a container.
type ResourceConfig struct {
	// CPULimit is the CPU limit (number of cores, e.g., "2" or "0.5").
	CPULimit string `json:"cpu_limit,omitempty" yaml:"cpu_limit,omitempty"`

	// CPUShares is the CPU shares (relative weight).
	CPUShares int64 `json:"cpu_shares,omitempty" yaml:"cpu_shares,omitempty"`

	// MemoryLimit is the memory limit (e.g., "512M", "2G").
	MemoryLimit string `json:"memory_limit,omitempty" yaml:"memory_limit,omitempty"`

	// MemorySwap is the total memory + swap limit.
	MemorySwap string `json:"memory_swap,omitempty" yaml:"memory_swap,omitempty"`

	// MemoryReservation is the soft memory limit.
	MemoryReservation string `json:"memory_reservation,omitempty" yaml:"memory_reservation,omitempty"`

	// PidsLimit is the maximum number of processes.
	PidsLimit int64 `json:"pids_limit,omitempty" yaml:"pids_limit,omitempty"`
}

// MountConfig defines a filesystem mount for a container.
type MountConfig struct {
	// Source is the source path on the host.
	Source string `json:"source" yaml:"source"`

	// Target is the target path inside the container.
	Target string `json:"target" yaml:"target"`

	// ReadOnly makes the mount read-only.
	ReadOnly bool `json:"read_only,omitempty" yaml:"read_only,omitempty"`

	// Type is the mount type (bind, volume, tmpfs).
	Type MountType `json:"type,omitempty" yaml:"type,omitempty"`

	// Propagation is the mount propagation mode.
	Propagation MountPropagation `json:"propagation,omitempty" yaml:"propagation,omitempty"`
}

// MountType defines the type of mount.
type MountType string

const (
	// MountTypeBind is a bind mount from the host.
	MountTypeBind MountType = "bind"

	// MountTypeVolume is a named volume.
	MountTypeVolume MountType = "volume"

	// MountTypeTmpfs is a tmpfs mount.
	MountTypeTmpfs MountType = "tmpfs"
)

// MountPropagation defines mount propagation modes.
type MountPropagation string

const (
	// PropagationPrivate is private mount propagation.
	PropagationPrivate MountPropagation = "private"

	// PropagationRPrivate is recursive private mount propagation.
	PropagationRPrivate MountPropagation = "rprivate"

	// PropagationShared is shared mount propagation.
	PropagationShared MountPropagation = "shared"

	// PropagationRShared is recursive shared mount propagation.
	PropagationRShared MountPropagation = "rshared"

	// PropagationSlave is slave mount propagation.
	PropagationSlave MountPropagation = "slave"

	// PropagationRSlave is recursive slave mount propagation.
	PropagationRSlave MountPropagation = "rslave"
)

// CapabilityConfig defines Linux capabilities to add or drop.
type CapabilityConfig struct {
	// Add are capabilities to add.
	Add []string `json:"add,omitempty" yaml:"add,omitempty"`

	// Drop are capabilities to drop.
	Drop []string `json:"drop,omitempty" yaml:"drop,omitempty"`
}

// RestartPolicy defines the container restart policy.
type RestartPolicy string

const (
	// RestartNever never restarts the container.
	RestartNever RestartPolicy = "never"

	// RestartOnFailure restarts only on failure.
	RestartOnFailure RestartPolicy = "on-failure"

	// RestartAlways always restarts the container.
	RestartAlways RestartPolicy = "always"

	// RestartUnlessStopped restarts unless explicitly stopped.
	RestartUnlessStopped RestartPolicy = "unless-stopped"
)

// HealthCheckConfig defines a container health check.
type HealthCheckConfig struct {
	// Command is the command to run for the health check.
	Command []string `json:"command" yaml:"command"`

	// Interval is the time between health checks.
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`

	// Timeout is the maximum time for a health check to complete.
	Timeout string `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	// Retries is the number of consecutive failures before unhealthy.
	Retries int `json:"retries,omitempty" yaml:"retries,omitempty"`

	// StartPeriod is the initialization time before health checks start.
	StartPeriod string `json:"start_period,omitempty" yaml:"start_period,omitempty"`
}

// PortMapping defines a port mapping for a container.
type PortMapping struct {
	// ContainerPort is the port inside the container.
	ContainerPort uint16 `json:"container_port" yaml:"container_port"`

	// HostPort is the port on the host.
	HostPort uint16 `json:"host_port,omitempty" yaml:"host_port,omitempty"`

	// HostIP is the host IP to bind to.
	HostIP string `json:"host_ip,omitempty" yaml:"host_ip,omitempty"`

	// Protocol is the protocol (tcp, udp).
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

// containerNameRegex matches valid container names.
// Container names must start with a letter, contain only alphanumeric characters,
// hyphens, and underscores, and be between 1 and 128 characters.
var containerNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,127}$`)

// Validate validates the OrchestratorContainerSpec.
func (s *OrchestratorContainerSpec) Validate() error {
	if s == nil {
		return ErrInvalidSpec
	}

	if s.Name == "" {
		return ErrInvalidName
	}

	if !containerNameRegex.MatchString(s.Name) {
		return ErrInvalidName
	}

	if s.Image == "" {
		return ErrInvalidImage
	}

	if err := validateImageReference(s.Image); err != nil {
		return err
	}

	// Validate network configuration
	if err := s.Network.Validate(); err != nil {
		return err
	}

	// Validate service configuration
	if err := s.Service.Validate(); err != nil {
		return err
	}

	// Validate resources
	if err := s.Resources.Validate(); err != nil {
		return err
	}

	// Validate mounts
	for i := range s.Mounts {
		if err := s.Mounts[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the ContainerConfig.
func (c *ContainerConfig) Validate() error {
	if c == nil {
		return ErrInvalidSpec
	}

	if c.Name == "" {
		return ErrInvalidName
	}

	if !containerNameRegex.MatchString(c.Name) {
		return ErrInvalidName
	}

	if c.Image == "" {
		return ErrInvalidImage
	}

	if err := validateImageReference(c.Image); err != nil {
		return err
	}

	// Validate network configuration
	if err := c.Network.Validate(); err != nil {
		return err
	}

	// Validate service configuration
	if err := c.Service.Validate(); err != nil {
		return err
	}

	// Validate resources
	if err := c.Resources.Validate(); err != nil {
		return err
	}

	// Validate mounts
	for i := range c.Mounts {
		if err := c.Mounts[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the ServiceConfig.
func (c *ServiceConfig) Validate() error {
	// Empty mode defaults to embedded
	if c.Mode == "" {
		return nil
	}

	if !c.Mode.IsValid() {
		return ErrInvalidServiceMode
	}

	// Standalone config validation
	if c.Mode == ServiceModeStandalone && c.Standalone != nil {
		if err := c.Standalone.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the StandaloneConfig.
func (c *StandaloneConfig) Validate() error {
	if c == nil {
		return nil
	}

	// Validate init system override if specified
	if c.InitSystemOverride != "" {
		validInitSystems := map[string]bool{
			"systemd": true,
			"rc":      true,
			"runit":   true,
		}
		if !validInitSystems[c.InitSystemOverride] {
			return ErrUnsupportedInitSystem
		}
	}

	// Validate restart policy if specified
	if c.Restart != "" {
		validRestart := map[string]bool{
			"always":     true,
			"on-failure": true,
			"no":         true,
		}
		if !validRestart[c.Restart] {
			return ErrInvalidSpec
		}
	}

	return nil
}

// Validate validates the ContainerNetworkConfig.
func (c *ContainerNetworkConfig) Validate() error {
	// Empty mode defaults to bridge
	if c.Mode == "" {
		return nil
	}

	if !c.Mode.IsValid() {
		return ErrInvalidNetworkMode
	}

	// SDN mode requires SDN config
	if c.Mode == NetworkModeSDN {
		if c.SDN == nil {
			return ErrInvalidNetworkMode
		}
		if err := c.SDN.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the SDNConfig.
func (c *SDNConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.Bridge == "" {
		return ErrNetworkSetupFailed
	}

	// VLAN ID 0 is untagged, 1-4094 are valid tagged VLANs
	if c.VLANID > 4094 {
		return ErrVLANConfigFailed
	}

	return nil
}

// Validate validates the ResourceConfig.
func (c *ResourceConfig) Validate() error {
	// All fields are optional, so empty config is valid

	// Validate memory limit format if specified
	if c.MemoryLimit != "" {
		if !isValidMemoryFormat(c.MemoryLimit) {
			return ErrInvalidResourceConfig
		}
	}

	// Validate memory reservation format if specified
	if c.MemoryReservation != "" {
		if !isValidMemoryFormat(c.MemoryReservation) {
			return ErrInvalidResourceConfig
		}
	}

	// Validate memory swap format if specified
	if c.MemorySwap != "" {
		if !isValidMemoryFormat(c.MemorySwap) {
			return ErrInvalidResourceConfig
		}
	}

	// CPU shares must be positive if specified
	if c.CPUShares < 0 {
		return ErrInvalidResourceConfig
	}

	// Pids limit must be positive if specified
	if c.PidsLimit < 0 {
		return ErrInvalidResourceConfig
	}

	return nil
}

// Validate validates the MountConfig.
func (c *MountConfig) Validate() error {
	if c.Target == "" {
		return ErrInvalidMountConfig
	}

	// Source is required for bind and volume mounts
	if c.Type != MountTypeTmpfs && c.Source == "" {
		return ErrInvalidMountConfig
	}

	// Validate mount type if specified
	if c.Type != "" {
		switch c.Type {
		case MountTypeBind, MountTypeVolume, MountTypeTmpfs:
			// Valid
		default:
			return ErrInvalidMountConfig
		}
	}

	return nil
}

// validateImageReference validates an image reference.
func validateImageReference(ref string) error {
	if ref == "" {
		return ErrInvalidImage
	}

	// Basic validation: must have at least a repository name
	// Full format: [registry/][repository/]image[:tag|@digest]
	parts := strings.Split(ref, "/")
	if len(parts) == 0 {
		return ErrInvalidImage
	}

	// Get the last part which contains the image name
	imagePart := parts[len(parts)-1]
	if imagePart == "" {
		return ErrInvalidImage
	}

	// Check for tag or digest
	if strings.Contains(imagePart, "@") {
		// Digest format
		digestParts := strings.Split(imagePart, "@")
		if len(digestParts) != 2 || digestParts[0] == "" || digestParts[1] == "" {
			return ErrInvalidImage
		}
	} else if strings.Contains(imagePart, ":") {
		// Tag format
		tagParts := strings.Split(imagePart, ":")
		if len(tagParts) != 2 || tagParts[0] == "" {
			return ErrInvalidImage
		}
		// Empty tag is allowed (defaults to "latest")
	}

	return nil
}

// isValidMemoryFormat validates a memory format string (e.g., "512M", "2G").
func isValidMemoryFormat(mem string) bool {
	if mem == "" {
		return false
	}

	// Must end with a valid suffix - check longer suffixes first to avoid
	// partial matches (e.g., "MB" ending with "B")
	validSuffixes := []string{
		"TB", "GB", "MB", "KB", // Two-letter uppercase first
		"tb", "gb", "mb", "kb", // Two-letter lowercase
		"T", "G", "M", "K", "B", // Single-letter uppercase
		"t", "g", "m", "k", "b", // Single-letter lowercase
	}

	for _, suffix := range validSuffixes {
		if strings.HasSuffix(mem, suffix) {
			// Check that the prefix is a valid number
			prefix := strings.TrimSuffix(mem, suffix)
			if prefix == "" {
				return false
			}
			for _, c := range prefix {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}
	}

	// Check if it's just a number (bytes)
	for _, c := range mem {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ToOrchestratorContainerSpec converts a ContainerConfig to an OrchestratorContainerSpec.
func (c *ContainerConfig) ToOrchestratorContainerSpec() *OrchestratorContainerSpec {
	if c == nil {
		return nil
	}

	return &OrchestratorContainerSpec{
		Name:         c.Name,
		Image:        c.Image,
		Command:      c.Command,
		Args:         c.Args,
		Env:          c.Env,
		Mounts:       c.Mounts,
		Resources:    c.Resources,
		Network:      c.Network,
		Service:      c.Service,
		Labels:       c.Labels,
		Privileged:   c.Privileged,
		Capabilities: c.Capabilities,
		Ports:        c.Ports,
	}
}

// ToAttestationSpec converts an OrchestratorContainerSpec to a ContainerSpec
// for use with the attestation subsystem.
func (s *OrchestratorContainerSpec) ToAttestationSpec() *ContainerSpec {
	if s == nil {
		return nil
	}

	// Convert mounts to attestation format
	var mounts []MountSpec
	for _, m := range s.Mounts {
		mounts = append(mounts, MountSpec{
			Source:   m.Source,
			Target:   m.Target,
			Type:     string(m.Type),
			ReadOnly: m.ReadOnly,
		})
	}

	return &ContainerSpec{
		Name:       s.Name,
		Image:      s.Image,
		Command:    s.Command,
		User:       s.User,
		WorkingDir: s.WorkingDir,
		Privileged: s.Privileged,
		Mounts:     mounts,
		Capabilities: CapabilitySpec{
			Add:  s.Capabilities.Add,
			Drop: s.Capabilities.Drop,
		},
		Environment: s.Env,
	}
}

// GetMode returns the effective service mode, defaulting to embedded.
func (c *ServiceConfig) GetMode() ContainerServiceMode {
	if c.Mode == "" {
		return ServiceModeEmbedded
	}
	return c.Mode
}

// GetNetworkMode returns the effective network mode, defaulting to bridge.
func (c *ContainerNetworkConfig) GetNetworkMode() NetworkMode {
	if c.Mode == "" {
		return NetworkModeBridge
	}
	return c.Mode
}
