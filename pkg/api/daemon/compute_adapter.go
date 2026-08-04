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

package daemon

import (
	"context"
	"io"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// OrchestratorAdapter bridges the interface mismatch between compute.Orchestrator
// and container.ContainerOrchestrator. The daemon has a compute.Orchestrator but
// the Unix handler expects a container.ContainerOrchestrator.
type OrchestratorAdapter struct {
	orchestrator compute.Orchestrator
}

// NewOrchestratorAdapter creates a new adapter that wraps a compute.Orchestrator
// and implements the container.ContainerOrchestrator interface.
func NewOrchestratorAdapter(orchestrator compute.Orchestrator) (*OrchestratorAdapter, error) {
	if orchestrator == nil {
		return nil, ErrNilOrchestrator{}
	}
	return &OrchestratorAdapter{
		orchestrator: orchestrator,
	}, nil
}

// Capability interfaces used to forward rich container verbs when the
// wrapped compute.Orchestrator supports them (the consolidated
// container.ComputeOrchestrator does; a QEMU orchestrator does not).

// containerLogStreamer is the orchestrator capability required for
// container log access.
type containerLogStreamer interface {
	Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error)
}

// containerAttestVerifier is the orchestrator capability required for
// verifying container attestation evidence.
type containerAttestVerifier interface {
	VerifyAttestation(ctx context.Context, id string, evidence []byte) error
}

// containerPolicyEvaluator is the orchestrator capability required for OPA
// policy evaluation of container specifications.
type containerPolicyEvaluator interface {
	EvaluatePolicy(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error)
}

// containerImagePuller is the orchestrator capability required for pulling
// container images.
type containerImagePuller interface {
	PullImage(ctx context.Context, ref string, opts container.PullOptions) error
}

// containerImageVerifier is the orchestrator capability required for
// verifying container image signatures.
type containerImageVerifier interface {
	VerifyImage(ctx context.Context, ref string) (*container.ImageVerification, error)
}

// Create creates a new container from a specification.
// This method converts OrchestratorContainerSpec to DeviceProfile and delegates
// to the underlying orchestrator.
func (a *OrchestratorAdapter) Create(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.Container, error) {
	if spec == nil {
		return nil, container.ErrInvalidSpec
	}

	if err := spec.Validate(); err != nil {
		return nil, err
	}

	profile := specToDeviceProfile(spec)

	instance, err := a.orchestrator.Create(ctx, profile)
	if err != nil {
		return nil, &ErrContainerOperationFailed{
			Operation: "create",
			Cause:     err,
		}
	}

	return instanceToContainer(instance, spec), nil
}

// Start starts a stopped container.
func (a *OrchestratorAdapter) Start(ctx context.Context, id string) error {
	if id == "" {
		return container.ErrInvalidContainerID
	}

	if err := a.orchestrator.Start(ctx, id); err != nil {
		return &ErrContainerOperationFailed{
			Operation: "start",
			Cause:     err,
		}
	}

	return nil
}

// Stop stops a running container.
// The timeout parameter is ignored as the underlying orchestrator does not support it.
func (a *OrchestratorAdapter) Stop(ctx context.Context, id string, _ time.Duration) error {
	if id == "" {
		return container.ErrInvalidContainerID
	}

	if err := a.orchestrator.Stop(ctx, id); err != nil {
		return &ErrContainerOperationFailed{
			Operation: "stop",
			Cause:     err,
		}
	}

	return nil
}

// Remove removes a container.
// The force parameter is ignored as the underlying orchestrator does not support it.
func (a *OrchestratorAdapter) Remove(ctx context.Context, id string, _ bool) error {
	if id == "" {
		return container.ErrInvalidContainerID
	}

	if err := a.orchestrator.Delete(ctx, id); err != nil {
		return &ErrContainerOperationFailed{
			Operation: "remove",
			Cause:     err,
		}
	}

	return nil
}

// Get retrieves a container by ID.
func (a *OrchestratorAdapter) Get(ctx context.Context, id string) (*container.Container, error) {
	if id == "" {
		return nil, container.ErrInvalidContainerID
	}

	instance, err := a.orchestrator.Get(ctx, id)
	if err != nil {
		return nil, &ErrContainerOperationFailed{
			Operation: "get",
			Cause:     err,
		}
	}

	return instanceToContainer(instance, nil), nil
}

// List returns containers matching the filter options.
func (a *OrchestratorAdapter) List(ctx context.Context, opts container.ListOptions) ([]*container.Container, error) {
	filter := listOptionsToInstanceFilter(opts)

	instances, err := a.orchestrator.List(ctx, filter)
	if err != nil {
		return nil, &ErrContainerOperationFailed{
			Operation: "list",
			Cause:     err,
		}
	}

	containers := make([]*container.Container, 0, len(instances))
	for _, instance := range instances {
		if instance.Type == compute.ComputeTypeContainer {
			containers = append(containers, instanceToContainer(instance, nil))
		}
	}

	// Apply limit if specified
	if opts.Limit > 0 && len(containers) > opts.Limit {
		containers = containers[:opts.Limit]
	}

	return containers, nil
}

// Logs returns a stream of container logs when the wrapped orchestrator
// supports log access; otherwise a typed capability error is returned.
func (a *OrchestratorAdapter) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if id == "" {
		return nil, container.ErrInvalidContainerID
	}
	if streamer, ok := a.orchestrator.(containerLogStreamer); ok {
		return streamer.Logs(ctx, id, opts)
	}
	return nil, ErrLogsNotSupported{}
}

// Attest performs TPM attestation for a container when the wrapped
// orchestrator supports attestation; otherwise a typed capability error is
// returned.
func (a *OrchestratorAdapter) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	if id == "" {
		return nil, container.ErrInvalidContainerID
	}
	if attester, ok := a.orchestrator.(containerAttester); ok {
		return attester.Attest(ctx, id)
	}
	return nil, ErrAttestNotSupported{}
}

// VerifyAttestation verifies attestation evidence for a container when the
// wrapped orchestrator supports it; otherwise a typed capability error is
// returned.
func (a *OrchestratorAdapter) VerifyAttestation(ctx context.Context, id string, evidence []byte) error {
	if id == "" {
		return container.ErrInvalidContainerID
	}
	if verifier, ok := a.orchestrator.(containerAttestVerifier); ok {
		return verifier.VerifyAttestation(ctx, id, evidence)
	}
	return ErrVerifyAttestationNotSupported{}
}

// EvaluatePolicy evaluates OPA policies against a container specification
// when the wrapped orchestrator supports policy evaluation; otherwise a
// typed capability error is returned.
func (a *OrchestratorAdapter) EvaluatePolicy(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error) {
	if spec == nil {
		return nil, container.ErrInvalidSpec
	}
	if evaluator, ok := a.orchestrator.(containerPolicyEvaluator); ok {
		return evaluator.EvaluatePolicy(ctx, spec)
	}
	return nil, ErrEvaluatePolicyNotSupported{}
}

// PullImage pulls a container image from a registry when the wrapped
// orchestrator supports image pulls; otherwise a typed capability error is
// returned.
func (a *OrchestratorAdapter) PullImage(ctx context.Context, ref string, opts container.PullOptions) error {
	if ref == "" {
		return container.ErrInvalidImage
	}
	if puller, ok := a.orchestrator.(containerImagePuller); ok {
		return puller.PullImage(ctx, ref, opts)
	}
	return ErrPullImageNotSupported{}
}

// VerifyImage verifies the signature of a container image when the wrapped
// orchestrator supports image verification; otherwise a typed capability
// error is returned.
func (a *OrchestratorAdapter) VerifyImage(ctx context.Context, ref string) (*container.ImageVerification, error) {
	if ref == "" {
		return nil, container.ErrInvalidImage
	}
	if verifier, ok := a.orchestrator.(containerImageVerifier); ok {
		return verifier.VerifyImage(ctx, ref)
	}
	return nil, ErrVerifyImageNotSupported{}
}

// Close closes the orchestrator and releases resources.
func (a *OrchestratorAdapter) Close() error {
	return a.orchestrator.Close()
}

// specToDeviceProfile converts an OrchestratorContainerSpec to a DeviceProfile.
func specToDeviceProfile(spec *container.OrchestratorContainerSpec) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		Name:  spec.Name,
		Model: spec.Image,
		Role:  entities.DeviceRoleServer,
	}
}

// instanceToContainer converts a compute.Instance to a container.Container.
func instanceToContainer(instance *compute.Instance, spec *container.OrchestratorContainerSpec) *container.Container {
	if instance == nil {
		return nil
	}

	c := &container.Container{
		ID:        instance.ID,
		Name:      instance.Name,
		State:     instanceStateToContainerState(instance.State),
		CreatedAt: instance.CreatedAt,
		Labels:    instance.Metadata,
		Pid:       instance.PID,
		Spec:      spec,
	}

	// Extract image from profile if available
	if instance.Profile != nil {
		c.Image = instance.Profile.Model
	}

	// Convert network attachments to network settings
	if len(instance.NetworkAttachments) > 0 {
		c.NetworkSettings = &container.NetworkSettings{
			Networks: make(map[string]*container.NetworkInfo),
		}
		for _, attachment := range instance.NetworkAttachments {
			if c.NetworkSettings.IPAddress == "" {
				c.NetworkSettings.IPAddress = attachment.IPAddress
				c.NetworkSettings.MACAddress = attachment.MACAddress
			}
			c.NetworkSettings.Networks[attachment.PortName] = &container.NetworkInfo{
				NetworkID:  attachment.BridgeName,
				IPAddress:  attachment.IPAddress,
				MACAddress: attachment.MACAddress,
			}
		}
	}

	return c
}

// instanceStateToContainerState converts compute.InstanceState to container.ContainerState.
func instanceStateToContainerState(state compute.InstanceState) container.ContainerState {
	stateMap := map[compute.InstanceState]container.ContainerState{
		compute.StateUnknown:  container.StateCreated,
		compute.StateCreating: container.StateCreated,
		compute.StateStopped:  container.StateStopped,
		compute.StateStarting: container.StateRestarting,
		compute.StateRunning:  container.StateRunning,
		compute.StateStopping: container.StateStopped,
		compute.StateError:    container.StateDead,
		compute.StateDeleting: container.StateRemoving,
	}

	if containerState, ok := stateMap[state]; ok {
		return containerState
	}
	return container.StateCreated
}

// listOptionsToInstanceFilter converts container.ListOptions to compute.InstanceFilter.
func listOptionsToInstanceFilter(opts container.ListOptions) *compute.InstanceFilter {
	filter := &compute.InstanceFilter{}

	// Filter by container type
	containerType := compute.ComputeTypeContainer
	filter.Type = &containerType

	// If not showing all, only show running containers
	if !opts.All {
		runningState := compute.StateRunning
		filter.State = &runningState
	}

	// Apply name filter from labels if present
	if opts.Filters != nil {
		if names, ok := opts.Filters["name"]; ok && len(names) > 0 {
			filter.Name = names[0]
		}
	}

	return filter
}

// ErrNilOrchestrator is returned when a nil orchestrator is provided.
type ErrNilOrchestrator struct{}

func (e ErrNilOrchestrator) Error() string {
	return "orchestrator cannot be nil"
}

// ErrLogsNotSupported is returned when the Logs operation is not supported.
type ErrLogsNotSupported struct{}

func (e ErrLogsNotSupported) Error() string {
	return "container logs operation not supported by orchestrator adapter"
}

// ErrAttestNotSupported is returned when the Attest operation is not supported.
type ErrAttestNotSupported struct{}

func (e ErrAttestNotSupported) Error() string {
	return "container attestation operation not supported by orchestrator adapter"
}

// ErrVerifyAttestationNotSupported is returned when the VerifyAttestation operation is not supported.
type ErrVerifyAttestationNotSupported struct{}

func (e ErrVerifyAttestationNotSupported) Error() string {
	return "verify attestation operation not supported by orchestrator adapter"
}

// ErrEvaluatePolicyNotSupported is returned when the EvaluatePolicy operation is not supported.
type ErrEvaluatePolicyNotSupported struct{}

func (e ErrEvaluatePolicyNotSupported) Error() string {
	return "evaluate policy operation not supported by orchestrator adapter"
}

// ErrPullImageNotSupported is returned when the PullImage operation is not supported.
type ErrPullImageNotSupported struct{}

func (e ErrPullImageNotSupported) Error() string {
	return "pull image operation not supported by orchestrator adapter"
}

// ErrVerifyImageNotSupported is returned when the VerifyImage operation is not supported.
type ErrVerifyImageNotSupported struct{}

func (e ErrVerifyImageNotSupported) Error() string {
	return "verify image operation not supported by orchestrator adapter"
}
