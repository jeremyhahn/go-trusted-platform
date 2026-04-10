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
	"context"
	"io"
	"time"
)

// ContainerState represents the lifecycle state of a container.
type ContainerState string

const (
	// StateCreated means the container has been created but not started.
	StateCreated ContainerState = "created"

	// StateRunning means the container is running.
	StateRunning ContainerState = "running"

	// StateStopped means the container has stopped.
	StateStopped ContainerState = "stopped"

	// StateRemoving means the container is being removed.
	StateRemoving ContainerState = "removing"

	// StatePaused means the container is paused.
	StatePaused ContainerState = "paused"

	// StateRestarting means the container is restarting.
	StateRestarting ContainerState = "restarting"

	// StateExited means the container has exited.
	StateExited ContainerState = "exited"

	// StateDead means the container is in a dead state.
	StateDead ContainerState = "dead"
)

// String returns the string representation of ContainerState.
func (s ContainerState) String() string {
	return string(s)
}

// IsValid returns true if the container state is valid.
func (s ContainerState) IsValid() bool {
	switch s {
	case StateCreated, StateRunning, StateStopped, StateRemoving,
		StatePaused, StateRestarting, StateExited, StateDead:
		return true
	default:
		return false
	}
}

// IsRunning returns true if the container is in a running state.
func (s ContainerState) IsRunning() bool {
	return s == StateRunning
}

// IsStopped returns true if the container is in a stopped or exited state.
func (s ContainerState) IsStopped() bool {
	return s == StateStopped || s == StateExited
}

// ContainerOrchestrator manages container lifecycle with TPM attestation.
type ContainerOrchestrator interface {
	// Create creates a new container from a specification.
	// The container is created but not started.
	Create(ctx context.Context, spec *OrchestratorContainerSpec) (*Container, error)

	// Start starts a stopped container.
	Start(ctx context.Context, id string) error

	// Stop stops a running container.
	// The timeout specifies how long to wait before force-killing.
	Stop(ctx context.Context, id string, timeout time.Duration) error

	// Remove removes a container.
	// If force is true, a running container will be stopped first.
	Remove(ctx context.Context, id string, force bool) error

	// Get retrieves a container by ID.
	Get(ctx context.Context, id string) (*Container, error)

	// List returns containers matching the filter options.
	List(ctx context.Context, opts ListOptions) ([]*Container, error)

	// Logs returns a stream of container logs.
	Logs(ctx context.Context, id string, opts LogOptions) (io.ReadCloser, error)

	// Attest performs TPM attestation for a container.
	// Returns an attestation report that can be verified remotely.
	Attest(ctx context.Context, id string) (*AttestationReport, error)

	// VerifyAttestation verifies attestation evidence for a container.
	// The evidence should include a TPM quote and measurement log.
	VerifyAttestation(ctx context.Context, id string, evidence []byte) error

	// EvaluatePolicy evaluates OPA policies against a container specification.
	// Returns a policy decision indicating whether the container is allowed.
	EvaluatePolicy(ctx context.Context, spec *OrchestratorContainerSpec) (*PolicyDecision, error)

	// PullImage pulls a container image from a registry.
	PullImage(ctx context.Context, ref string, opts PullOptions) error

	// VerifyImage verifies the signature of a container image.
	VerifyImage(ctx context.Context, ref string) (*ImageVerification, error)

	// Close closes the orchestrator and releases resources.
	Close() error
}

// Container represents a container instance.
type Container struct {
	// ID is the unique identifier for the container.
	ID string `json:"id"`

	// Name is the container name.
	Name string `json:"name"`

	// Image is the container image reference.
	Image string `json:"image"`

	// ImageID is the image digest.
	ImageID string `json:"image_id"`

	// State is the current container state.
	State ContainerState `json:"state"`

	// Spec is the container specification used to create it.
	Spec *OrchestratorContainerSpec `json:"spec,omitempty"`

	// CreatedAt is when the container was created.
	CreatedAt time.Time `json:"created_at"`

	// StartedAt is when the container was last started.
	StartedAt time.Time `json:"started_at,omitempty"`

	// FinishedAt is when the container finished.
	FinishedAt time.Time `json:"finished_at,omitempty"`

	// ExitCode is the container exit code.
	ExitCode int `json:"exit_code,omitempty"`

	// Pid is the process ID of the container.
	Pid int `json:"pid,omitempty"`

	// Labels are metadata labels.
	Labels map[string]string `json:"labels,omitempty"`

	// NetworkSettings contains network information.
	NetworkSettings *NetworkSettings `json:"network_settings,omitempty"`

	// Mounts are the container's mounts.
	Mounts []MountInfo `json:"mounts,omitempty"`

	// Platform contains platform-specific information.
	Platform string `json:"platform,omitempty"`

	// Health contains health check information.
	Health *HealthStatus `json:"health,omitempty"`
}

// NetworkSettings contains container network information.
type NetworkSettings struct {
	// IPAddress is the container's IP address.
	IPAddress string `json:"ip_address,omitempty"`

	// Gateway is the network gateway.
	Gateway string `json:"gateway,omitempty"`

	// MACAddress is the container's MAC address.
	MACAddress string `json:"mac_address,omitempty"`

	// Ports are port mappings.
	Ports map[string][]PortBinding `json:"ports,omitempty"`

	// Networks are the networks the container is connected to.
	Networks map[string]*NetworkInfo `json:"networks,omitempty"`
}

// PortBinding represents a port binding.
type PortBinding struct {
	// HostIP is the host IP address.
	HostIP string `json:"host_ip,omitempty"`

	// HostPort is the host port.
	HostPort string `json:"host_port,omitempty"`
}

// NetworkInfo contains information about a container's connection to a network.
type NetworkInfo struct {
	// NetworkID is the network ID.
	NetworkID string `json:"network_id,omitempty"`

	// IPAddress is the container's IP on this network.
	IPAddress string `json:"ip_address,omitempty"`

	// Gateway is the gateway for this network.
	Gateway string `json:"gateway,omitempty"`

	// MACAddress is the MAC address for this network.
	MACAddress string `json:"mac_address,omitempty"`
}

// MountInfo contains information about a container mount.
type MountInfo struct {
	// Source is the source path on the host.
	Source string `json:"source"`

	// Destination is the target path in the container.
	Destination string `json:"destination"`

	// Mode is the mount mode (ro, rw).
	Mode string `json:"mode,omitempty"`

	// RW indicates if the mount is read-write.
	RW bool `json:"rw"`

	// Propagation is the mount propagation mode.
	Propagation string `json:"propagation,omitempty"`
}

// HealthStatus contains container health check information.
type HealthStatus struct {
	// Status is the health status (healthy, unhealthy, starting).
	Status string `json:"status"`

	// FailingStreak is the number of consecutive failures.
	FailingStreak int `json:"failing_streak"`

	// Log contains recent health check results.
	Log []HealthLog `json:"log,omitempty"`
}

// HealthLog contains a single health check result.
type HealthLog struct {
	// Start is when the health check started.
	Start time.Time `json:"start"`

	// End is when the health check ended.
	End time.Time `json:"end"`

	// ExitCode is the health check exit code.
	ExitCode int `json:"exit_code"`

	// Output is the health check output.
	Output string `json:"output,omitempty"`
}

// ListOptions defines options for listing containers.
type ListOptions struct {
	// All includes stopped containers.
	All bool `json:"all,omitempty"`

	// Filters are label-based filters.
	Filters map[string][]string `json:"filters,omitempty"`

	// Limit is the maximum number of containers to return.
	Limit int `json:"limit,omitempty"`
}

// LogOptions defines options for retrieving container logs.
type LogOptions struct {
	// Follow streams logs in real-time.
	Follow bool `json:"follow,omitempty"`

	// Stdout includes stdout logs.
	Stdout bool `json:"stdout,omitempty"`

	// Stderr includes stderr logs.
	Stderr bool `json:"stderr,omitempty"`

	// Since only returns logs after this time.
	Since time.Time `json:"since,omitempty"`

	// Until only returns logs before this time.
	Until time.Time `json:"until,omitempty"`

	// Tail is the number of lines from the end to return.
	Tail string `json:"tail,omitempty"`

	// Timestamps includes timestamps in the output.
	Timestamps bool `json:"timestamps,omitempty"`
}

// PullOptions defines options for pulling container images.
type PullOptions struct {
	// RegistryAuth is the authentication credentials.
	RegistryAuth string `json:"registry_auth,omitempty"`

	// Platform is the target platform (e.g., "linux/amd64").
	Platform string `json:"platform,omitempty"`

	// VerifySignature requires image signature verification.
	VerifySignature bool `json:"verify_signature,omitempty"`

	// TrustedRootCA is the path to the trusted root CA for verification.
	TrustedRootCA string `json:"trusted_root_ca,omitempty"`
}

// AttestationReport contains the results of container attestation.
type AttestationReport struct {
	// ContainerID is the container being attested.
	ContainerID string `json:"container_id"`

	// ContainerName is the container name.
	ContainerName string `json:"container_name"`

	// Timestamp is when the attestation was performed.
	Timestamp time.Time `json:"timestamp"`

	// Quote is the TPM quote over the WorkloadPCR.
	Quote []byte `json:"quote"`

	// Signature is the TPM signature over the quote.
	Signature []byte `json:"signature"`

	// Log is the container measurement log.
	Log *MeasurementLog `json:"measurement_log"`

	// ImageDigest is the digest of the container image.
	ImageDigest []byte `json:"image_digest"`

	// ConfigDigest is the digest of the container configuration.
	ConfigDigest []byte `json:"config_digest"`

	// PCRValues are the PCR values at attestation time.
	PCRValues map[int][]byte `json:"pcr_values,omitempty"`

	// AIKCertificate is the AIK certificate used for signing.
	AIKCertificate []byte `json:"aik_certificate,omitempty"`

	// Verified indicates if the attestation has been verified.
	Verified bool `json:"verified"`
}

// PolicyDecision contains the result of policy evaluation.
type PolicyDecision struct {
	// Allowed indicates if the operation is allowed.
	Allowed bool `json:"allowed"`

	// Reasons contains the reasons for the decision.
	Reasons []string `json:"reasons,omitempty"`

	// Warnings contains non-blocking warnings.
	Warnings []string `json:"warnings,omitempty"`

	// PolicyName is the name of the evaluated policy.
	PolicyName string `json:"policy_name,omitempty"`

	// Timestamp is when the evaluation was performed.
	Timestamp time.Time `json:"timestamp"`

	// Input is the input that was evaluated (for audit).
	Input interface{} `json:"input,omitempty"`
}

// ImageVerification contains the result of image verification.
type ImageVerification struct {
	// ImageRef is the image reference.
	ImageRef string `json:"image_ref"`

	// Digest is the image digest.
	Digest string `json:"digest"`

	// Verified indicates if the image signature is valid.
	Verified bool `json:"verified"`

	// Signer is the identity of the signer.
	Signer string `json:"signer,omitempty"`

	// SignatureType is the type of signature (cosign, notation, etc.).
	SignatureType string `json:"signature_type,omitempty"`

	// Timestamp is when verification was performed.
	Timestamp time.Time `json:"timestamp"`

	// Certificate is the signing certificate.
	Certificate []byte `json:"certificate,omitempty"`

	// SignaturePayload is the signature payload.
	SignaturePayload []byte `json:"signature_payload,omitempty"`

	// Annotations are signature annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PolicyInput is the input structure for OPA policy evaluation.
type PolicyInput struct {
	// Container is the container specification.
	Container *OrchestratorContainerSpec `json:"container"`

	// Image is the image information.
	Image *ImageInfo `json:"image,omitempty"`

	// Signature is the image signature information.
	Signature *SignatureInfo `json:"signature,omitempty"`

	// Network is the network configuration.
	Network *ContainerNetworkConfig `json:"network,omitempty"`

	// Attestation is the attestation state.
	Attestation *AttestationState `json:"attestation,omitempty"`

	// User is the user making the request.
	User string `json:"user,omitempty"`

	// Groups are the user's groups.
	Groups []string `json:"groups,omitempty"`

	// Namespace is the container namespace.
	Namespace string `json:"namespace,omitempty"`
}

// ImageInfo contains information about a container image.
type ImageInfo struct {
	// Registry is the registry host.
	Registry string `json:"registry"`

	// Repository is the image repository.
	Repository string `json:"repository"`

	// Tag is the image tag.
	Tag string `json:"tag,omitempty"`

	// Digest is the image digest.
	Digest string `json:"digest,omitempty"`

	// Labels are the image labels.
	Labels map[string]string `json:"labels,omitempty"`
}

// SignatureInfo contains image signature information.
type SignatureInfo struct {
	// Verified indicates if the signature is verified.
	Verified bool `json:"verified"`

	// Signer is the signer identity.
	Signer string `json:"signer,omitempty"`

	// Issuer is the certificate issuer.
	Issuer string `json:"issuer,omitempty"`
}

// AttestationState contains the current attestation state.
type AttestationState struct {
	// Attested indicates if attestation has been performed.
	Attested bool `json:"attested"`

	// LastAttested is when attestation was last performed.
	LastAttested time.Time `json:"last_attested,omitempty"`

	// PCRValues are the current PCR values.
	PCRValues map[int][]byte `json:"pcr_values,omitempty"`
}
