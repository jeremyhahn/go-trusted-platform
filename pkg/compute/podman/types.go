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

package podman

import "time"

// ContainerState represents the lifecycle state of a container
type ContainerState string

const (
	// ContainerStateCreated represents a container that has been created but not started
	ContainerStateCreated ContainerState = "created"

	// ContainerStateRunning represents a running container
	ContainerStateRunning ContainerState = "running"

	// ContainerStatePaused represents a paused container
	ContainerStatePaused ContainerState = "paused"

	// ContainerStateStopped represents a stopped container
	ContainerStateStopped ContainerState = "stopped"

	// ContainerStateExited represents a container that has exited
	ContainerStateExited ContainerState = "exited"

	// ContainerStateUnknown represents an unknown container state
	ContainerStateUnknown ContainerState = "unknown"
)

// String returns the string representation of ContainerState
func (s ContainerState) String() string {
	return string(s)
}

// IsValid checks if the ContainerState is valid
func (s ContainerState) IsValid() bool {
	switch s {
	case ContainerStateCreated, ContainerStateRunning, ContainerStatePaused,
		ContainerStateStopped, ContainerStateExited, ContainerStateUnknown:
		return true
	default:
		return false
	}
}

// IsRunning returns true if the container state indicates it is running
func (s ContainerState) IsRunning() bool {
	return s == ContainerStateRunning
}

// Container represents a Podman container
type Container struct {
	// ID is the unique container identifier
	ID string `json:"id" yaml:"id"`

	// Name is the human-readable container name
	Name string `json:"name" yaml:"name"`

	// Image is the image reference used to create the container
	Image string `json:"image" yaml:"image"`

	// ImageDigest is the digest of the image
	ImageDigest string `json:"image_digest" yaml:"image_digest"`

	// State is the current container state
	State ContainerState `json:"state" yaml:"state"`

	// CreatedAt is the timestamp when the container was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// StartedAt is the timestamp when the container was started
	StartedAt *time.Time `json:"started_at,omitempty" yaml:"started_at,omitempty"`

	// FinishedAt is the timestamp when the container stopped
	FinishedAt *time.Time `json:"finished_at,omitempty" yaml:"finished_at,omitempty"`

	// ExitCode is the exit code from the container process
	ExitCode int `json:"exit_code,omitempty" yaml:"exit_code,omitempty"`

	// Labels are key-value pairs attached to the container
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Mounts are the container mount points
	Mounts []Mount `json:"mounts,omitempty" yaml:"mounts,omitempty"`

	// Ports are the port mappings for the container
	Ports []PortMapping `json:"ports,omitempty" yaml:"ports,omitempty"`

	// Environment variables set in the container
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// PID is the process ID of the container's init process
	PID int `json:"pid,omitempty" yaml:"pid,omitempty"`

	// Command is the command being run in the container
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`

	// NetworkMode is the network mode of the container
	NetworkMode string `json:"network_mode,omitempty" yaml:"network_mode,omitempty"`
}

// ContainerConfig holds configuration for creating a container
type ContainerConfig struct {
	// Name is the container name (must be unique)
	Name string `json:"name" yaml:"name"`

	// Image is the image reference to use
	Image string `json:"image" yaml:"image"`

	// Command is the command to run in the container
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`

	// Entrypoint overrides the image entrypoint
	Entrypoint []string `json:"entrypoint,omitempty" yaml:"entrypoint,omitempty"`

	// Environment is a map of environment variables
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// Labels is a map of labels to attach to the container
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Mounts specifies bind mounts and volumes
	Mounts []Mount `json:"mounts,omitempty" yaml:"mounts,omitempty"`

	// Ports specifies port mappings
	Ports []PortMapping `json:"ports,omitempty" yaml:"ports,omitempty"`

	// Resources specifies resource limits
	Resources *ResourceLimits `json:"resources,omitempty" yaml:"resources,omitempty"`

	// TPMAccess enables mounting /dev/tpm0 into the container
	TPMAccess bool `json:"tpm_access" yaml:"tpm_access"`

	// NetworkMode specifies the network mode (bridge, host, none, slirp4netns)
	NetworkMode string `json:"network_mode,omitempty" yaml:"network_mode,omitempty"`

	// User specifies the user to run as (uid or username)
	User string `json:"user,omitempty" yaml:"user,omitempty"`

	// WorkDir specifies the working directory inside the container
	WorkDir string `json:"work_dir,omitempty" yaml:"work_dir,omitempty"`

	// Hostname sets the container hostname
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`

	// Privileged runs the container in privileged mode
	Privileged bool `json:"privileged" yaml:"privileged"`

	// ReadOnly makes the container root filesystem read-only
	ReadOnly bool `json:"read_only" yaml:"read_only"`

	// AutoRemove removes the container when it exits
	AutoRemove bool `json:"auto_remove" yaml:"auto_remove"`

	// StopTimeout is the timeout in seconds for stopping the container
	StopTimeout *int `json:"stop_timeout,omitempty" yaml:"stop_timeout,omitempty"`

	// CapAdd adds Linux capabilities
	CapAdd []string `json:"cap_add,omitempty" yaml:"cap_add,omitempty"`

	// CapDrop drops Linux capabilities
	CapDrop []string `json:"cap_drop,omitempty" yaml:"cap_drop,omitempty"`

	// SecurityOpt specifies security options
	SecurityOpt []string `json:"security_opt,omitempty" yaml:"security_opt,omitempty"`

	// DNS servers for the container
	DNS []string `json:"dns,omitempty" yaml:"dns,omitempty"`

	// DNSSearch domains for the container
	DNSSearch []string `json:"dns_search,omitempty" yaml:"dns_search,omitempty"`
}

// Validate validates the container configuration
func (c *ContainerConfig) Validate() error {
	if c.Name == "" {
		return NewConfigValidationError("name", "container name is required")
	}

	if c.Image == "" {
		return NewConfigValidationError("image", "image reference is required")
	}

	// Validate mounts
	for i, m := range c.Mounts {
		if err := m.Validate(); err != nil {
			return NewConfigValidationError("mounts["+string(rune('0'+i))+"]", err.Error())
		}
	}

	// Validate ports
	for i, p := range c.Ports {
		if err := p.Validate(); err != nil {
			return NewConfigValidationError("ports["+string(rune('0'+i))+"]", err.Error())
		}
	}

	// Validate resources if provided
	if c.Resources != nil {
		if err := c.Resources.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Mount represents a container mount point
type Mount struct {
	// Source is the host path or volume name
	Source string `json:"source" yaml:"source"`

	// Target is the container path
	Target string `json:"target" yaml:"target"`

	// Type is the mount type (bind, volume, tmpfs)
	Type string `json:"type" yaml:"type"`

	// ReadOnly makes the mount read-only
	ReadOnly bool `json:"read_only" yaml:"read_only"`

	// Options are mount-specific options
	Options []string `json:"options,omitempty" yaml:"options,omitempty"`
}

// Validate validates the mount configuration
func (m *Mount) Validate() error {
	if m.Target == "" {
		return NewConfigValidationError("target", "mount target is required")
	}

	validTypes := map[string]bool{
		"bind":   true,
		"volume": true,
		"tmpfs":  true,
	}

	if m.Type == "" {
		m.Type = "bind" // Default to bind mount
	}

	if !validTypes[m.Type] {
		return NewConfigValidationError("type", "invalid mount type: "+m.Type)
	}

	// Source is required for bind and volume mounts
	if (m.Type == "bind" || m.Type == "volume") && m.Source == "" {
		return NewConfigValidationError("source", "source is required for "+m.Type+" mounts")
	}

	return nil
}

// PortMapping represents a container port mapping
type PortMapping struct {
	// HostIP is the host IP to bind to (optional)
	HostIP string `json:"host_ip,omitempty" yaml:"host_ip,omitempty"`

	// HostPort is the port on the host
	HostPort uint16 `json:"host_port" yaml:"host_port"`

	// ContainerPort is the port inside the container
	ContainerPort uint16 `json:"container_port" yaml:"container_port"`

	// Protocol is the protocol (tcp, udp)
	Protocol string `json:"protocol" yaml:"protocol"`
}

// Validate validates the port mapping
func (p *PortMapping) Validate() error {
	if p.ContainerPort == 0 {
		return NewConfigValidationError("container_port", "container port is required")
	}

	if p.Protocol == "" {
		p.Protocol = "tcp" // Default to TCP
	}

	validProtocols := map[string]bool{
		"tcp": true,
		"udp": true,
	}

	if !validProtocols[p.Protocol] {
		return NewConfigValidationError("protocol", "invalid protocol: "+p.Protocol)
	}

	return nil
}

// ResourceLimits specifies container resource limits
type ResourceLimits struct {
	// MemoryLimit is the memory limit in bytes
	MemoryLimit int64 `json:"memory_limit" yaml:"memory_limit"`

	// MemoryReservation is the memory soft limit in bytes
	MemoryReservation int64 `json:"memory_reservation,omitempty" yaml:"memory_reservation,omitempty"`

	// MemorySwap is the combined memory and swap limit in bytes, which is what
	// the OCI memory.swap field and podman's --memory-swap both express.
	MemorySwap int64 `json:"memory_swap,omitempty" yaml:"memory_swap,omitempty"`

	// CPUQuota is CPU quota in microseconds per period
	CPUQuota int64 `json:"cpu_quota" yaml:"cpu_quota"`

	// CPUPeriod is the CPU CFS period in microseconds
	CPUPeriod int64 `json:"cpu_period" yaml:"cpu_period"`

	// CPUShares is the relative CPU weight
	CPUShares int64 `json:"cpu_shares,omitempty" yaml:"cpu_shares,omitempty"`

	// CPUs is the number of CPUs (e.g., 1.5 for 1.5 CPUs)
	CPUs float64 `json:"cpus,omitempty" yaml:"cpus,omitempty"`

	// PidsLimit limits the number of processes
	PidsLimit int64 `json:"pids_limit,omitempty" yaml:"pids_limit,omitempty"`
}

// Validate validates the resource limits
func (r *ResourceLimits) Validate() error {
	if r.MemoryLimit < 0 {
		return NewConfigValidationError("memory_limit", "memory limit cannot be negative")
	}

	if r.MemoryReservation < 0 {
		return NewConfigValidationError("memory_reservation", "memory reservation cannot be negative")
	}

	if r.MemorySwap < 0 {
		return NewConfigValidationError("memory_swap", "memory swap limit cannot be negative")
	}

	if r.CPUQuota < 0 {
		return NewConfigValidationError("cpu_quota", "CPU quota cannot be negative")
	}

	if r.CPUPeriod < 0 {
		return NewConfigValidationError("cpu_period", "CPU period cannot be negative")
	}

	if r.CPUs < 0 {
		return NewConfigValidationError("cpus", "CPUs cannot be negative")
	}

	if r.PidsLimit < 0 {
		return NewConfigValidationError("pids_limit", "PIDs limit cannot be negative")
	}

	return nil
}

// Image represents a container image
type Image struct {
	// ID is the image identifier
	ID string `json:"id" yaml:"id"`

	// Names are the image names/tags
	Names []string `json:"names" yaml:"names"`

	// Digest is the image digest
	Digest string `json:"digest" yaml:"digest"`

	// Size is the image size in bytes
	Size int64 `json:"size" yaml:"size"`

	// Created is the image creation timestamp
	Created time.Time `json:"created" yaml:"created"`

	// Labels are image labels
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Architecture is the image architecture
	Architecture string `json:"architecture,omitempty" yaml:"architecture,omitempty"`

	// OS is the image operating system
	OS string `json:"os,omitempty" yaml:"os,omitempty"`
}

// ContainerStats represents container resource usage statistics
type ContainerStats struct {
	// ContainerID is the container identifier
	ContainerID string `json:"container_id" yaml:"container_id"`

	// Name is the container name
	Name string `json:"name" yaml:"name"`

	// CPUPercent is the CPU usage percentage
	CPUPercent float64 `json:"cpu_percent" yaml:"cpu_percent"`

	// MemoryUsage is the memory usage in bytes
	MemoryUsage int64 `json:"memory_usage" yaml:"memory_usage"`

	// MemoryLimit is the memory limit in bytes
	MemoryLimit int64 `json:"memory_limit" yaml:"memory_limit"`

	// MemoryPercent is the memory usage percentage
	MemoryPercent float64 `json:"memory_percent" yaml:"memory_percent"`

	// NetworkRxBytes is the network bytes received
	NetworkRxBytes int64 `json:"network_rx_bytes" yaml:"network_rx_bytes"`

	// NetworkTxBytes is the network bytes transmitted
	NetworkTxBytes int64 `json:"network_tx_bytes" yaml:"network_tx_bytes"`

	// BlockRead is the block bytes read
	BlockRead int64 `json:"block_read" yaml:"block_read"`

	// BlockWrite is the block bytes written
	BlockWrite int64 `json:"block_write" yaml:"block_write"`

	// PIDs is the number of processes in the container
	PIDs int64 `json:"pids" yaml:"pids"`

	// Timestamp is when the stats were collected
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

// ExecConfig holds configuration for executing a command in a container
type ExecConfig struct {
	// Command is the command to execute
	Command []string `json:"command" yaml:"command"`

	// User is the user to run the command as
	User string `json:"user,omitempty" yaml:"user,omitempty"`

	// WorkDir is the working directory
	WorkDir string `json:"work_dir,omitempty" yaml:"work_dir,omitempty"`

	// Environment variables
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// Privileged runs the command in privileged mode
	Privileged bool `json:"privileged" yaml:"privileged"`

	// AttachStdout attaches stdout
	AttachStdout bool `json:"attach_stdout" yaml:"attach_stdout"`

	// AttachStderr attaches stderr
	AttachStderr bool `json:"attach_stderr" yaml:"attach_stderr"`
}

// ExecResult holds the result of executing a command in a container
type ExecResult struct {
	// ExitCode is the command exit code
	ExitCode int `json:"exit_code" yaml:"exit_code"`

	// Stdout is the standard output
	Stdout []byte `json:"stdout,omitempty" yaml:"stdout,omitempty"`

	// Stderr is the standard error
	Stderr []byte `json:"stderr,omitempty" yaml:"stderr,omitempty"`
}

// ContainerLogs holds container log data
type ContainerLogs struct {
	// ContainerID is the container identifier
	ContainerID string `json:"container_id" yaml:"container_id"`

	// Stdout is the stdout log data
	Stdout []byte `json:"stdout,omitempty" yaml:"stdout,omitempty"`

	// Stderr is the stderr log data
	Stderr []byte `json:"stderr,omitempty" yaml:"stderr,omitempty"`

	// Since is the timestamp of the earliest log
	Since time.Time `json:"since" yaml:"since"`

	// Until is the timestamp of the latest log
	Until time.Time `json:"until" yaml:"until"`
}
