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

// Package container provides multi-protocol integration tests for the container orchestrator.
// These tests verify that container operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified ContainerCommands interface.
//
// Run tests via:
//
//	make integration-test-container
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package container

import (
	"context"
	"time"
)

// ContainerCommands defines the central command set for container integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type ContainerCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Container Lifecycle Commands (platformctl container ...)
	Create(ctx context.Context, opts CreateOptions) (*Container, error)
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string, timeout time.Duration) error
	Remove(ctx context.Context, id string, force bool) error
	Get(ctx context.Context, id string) (*Container, error)
	List(ctx context.Context, opts ListOptions) ([]*Container, error)
	Attest(ctx context.Context, id string) (*AttestationReport, error)
}

// =============================================================================
// Container Types
// =============================================================================

// Container represents a container instance returned from API calls.
type Container struct {
	// ID is the unique identifier for the container.
	ID string `json:"id"`

	// Name is the container name.
	Name string `json:"name"`

	// Image is the container image reference.
	Image string `json:"image"`

	// ImageID is the image digest.
	ImageID string `json:"image_id,omitempty"`

	// State is the current container state.
	State ContainerState `json:"state"`

	// PID is the container's main process ID.
	PID int `json:"pid,omitempty"`

	// ExitCode is the container's exit code if stopped.
	ExitCode int `json:"exit_code,omitempty"`

	// CreatedAt is when the container was created.
	CreatedAt time.Time `json:"created_at"`

	// StartedAt is when the container was last started.
	StartedAt time.Time `json:"started_at,omitempty"`

	// StoppedAt is when the container was stopped.
	StoppedAt time.Time `json:"stopped_at,omitempty"`

	// Labels are user-defined container labels.
	Labels map[string]string `json:"labels,omitempty"`

	// Environment are the container environment variables.
	Environment map[string]string `json:"environment,omitempty"`
}

// ContainerState represents the lifecycle state of a container.
type ContainerState string

const (
	// StateCreated means the container has been created but not started.
	StateCreated ContainerState = "created"

	// StateRunning means the container is running.
	StateRunning ContainerState = "running"

	// StateStopped means the container has stopped.
	StateStopped ContainerState = "stopped"

	// StateExited means the container has exited.
	StateExited ContainerState = "exited"

	// StatePaused means the container is paused.
	StatePaused ContainerState = "paused"

	// StateRemoving means the container is being removed.
	StateRemoving ContainerState = "removing"
)

// String returns the string representation of ContainerState.
func (s ContainerState) String() string {
	return string(s)
}

// IsRunning returns true if the container is in a running state.
func (s ContainerState) IsRunning() bool {
	return s == StateRunning
}

// IsStopped returns true if the container is in a stopped or exited state.
func (s ContainerState) IsStopped() bool {
	return s == StateStopped || s == StateExited
}

// =============================================================================
// Container Options
// =============================================================================

// CreateOptions contains options for creating a container.
type CreateOptions struct {
	// Name is the container name (required).
	Name string `json:"name"`

	// Image is the container image reference (required).
	Image string `json:"image"`

	// Command overrides the default container command.
	Command []string `json:"command,omitempty"`

	// Environment are environment variables for the container.
	Environment map[string]string `json:"environment,omitempty"`

	// Labels are user-defined container labels.
	Labels map[string]string `json:"labels,omitempty"`

	// WorkingDir is the working directory inside the container.
	WorkingDir string `json:"working_dir,omitempty"`

	// User is the user to run as inside the container.
	User string `json:"user,omitempty"`

	// Privileged runs the container in privileged mode.
	Privileged bool `json:"privileged,omitempty"`

	// NetworkMode specifies the container network mode.
	NetworkMode string `json:"network_mode,omitempty"`

	// Memory is the memory limit in bytes.
	Memory int64 `json:"memory,omitempty"`

	// CPUs is the number of CPUs to allocate.
	CPUs float64 `json:"cpus,omitempty"`

	// Mounts are volume mounts for the container.
	Mounts []Mount `json:"mounts,omitempty"`

	// ExposedPorts are ports to expose from the container.
	ExposedPorts []PortMapping `json:"exposed_ports,omitempty"`

	// RestartPolicy specifies the container restart policy.
	RestartPolicy string `json:"restart_policy,omitempty"`

	// AttestOnCreate enables attestation measurement on create.
	AttestOnCreate bool `json:"attest_on_create,omitempty"`
}

// Mount represents a volume mount.
type Mount struct {
	// Source is the host path or volume name.
	Source string `json:"source"`

	// Target is the container path.
	Target string `json:"target"`

	// ReadOnly makes the mount read-only.
	ReadOnly bool `json:"read_only,omitempty"`

	// Type is the mount type (bind, volume, tmpfs).
	Type string `json:"type,omitempty"`
}

// PortMapping represents a port mapping.
type PortMapping struct {
	// ContainerPort is the port inside the container.
	ContainerPort int `json:"container_port"`

	// HostPort is the port on the host.
	HostPort int `json:"host_port,omitempty"`

	// Protocol is the protocol (tcp, udp).
	Protocol string `json:"protocol,omitempty"`
}

// ListOptions contains options for listing containers.
type ListOptions struct {
	// All includes stopped containers.
	All bool `json:"all,omitempty"`

	// Limit is the maximum number of containers to return.
	Limit int `json:"limit,omitempty"`

	// Filters are label-based filters for containers.
	Filters map[string]string `json:"filters,omitempty"`

	// StateFilter filters by container state.
	StateFilter ContainerState `json:"state_filter,omitempty"`

	// NameFilter filters by container name prefix.
	NameFilter string `json:"name_filter,omitempty"`
}

// =============================================================================
// Attestation Types
// =============================================================================

// AttestationReport represents a container attestation report.
type AttestationReport struct {
	// ContainerID is the attested container ID.
	ContainerID string `json:"container_id"`

	// ContainerName is the attested container name.
	ContainerName string `json:"container_name"`

	// ImageDigest is the digest of the container image.
	ImageDigest string `json:"image_digest"`

	// ConfigDigest is the digest of the container config.
	ConfigDigest string `json:"config_digest"`

	// Quote is the TPM quote data.
	Quote []byte `json:"quote"`

	// Signature is the TPM signature over the quote.
	Signature []byte `json:"signature"`

	// Log is the measurement log.
	Log []MeasurementLogEntry `json:"log,omitempty"`

	// PCRValues are the PCR values included in the quote.
	PCRValues map[int][]byte `json:"pcr_values,omitempty"`

	// Timestamp is when the attestation was performed.
	Timestamp time.Time `json:"timestamp"`

	// Verified indicates if the attestation was verified.
	Verified bool `json:"verified"`

	// Nonce is the nonce used in the attestation.
	Nonce []byte `json:"nonce,omitempty"`
}

// MeasurementLogEntry represents an entry in the measurement log.
type MeasurementLogEntry struct {
	// PCRIndex is the PCR that was extended.
	PCRIndex int `json:"pcr_index"`

	// EventType is the type of measurement event.
	EventType string `json:"event_type"`

	// Digest is the hash that was extended into the PCR.
	Digest []byte `json:"digest"`

	// Data is the event data.
	Data []byte `json:"data,omitempty"`

	// Timestamp is when the measurement occurred.
	Timestamp time.Time `json:"timestamp"`
}
