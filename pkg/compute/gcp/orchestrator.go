//go:build gcpcompute

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

// Package gcp implements the platform compute Orchestrator over Google Compute
// Engine, launching and managing Shielded VM instances with a vTPM. It is
// compiled only when the gcpcompute build tag is present; without the tag a
// stub keeps the package buildable and the provider factory fails closed with
// a typed ErrComputeProviderNotCompiled.
//
// The orchestrator provides lifecycle parity with the local QEMU orchestrator
// (create/start/stop/delete/list/get/wait/state), persistent-disk VM snapshots
// (VMSnapshotter), and Shielded VM endorsement-key attestation (VMAttester).
// Capabilities that have no honest GCE equivalent — 802.1X OVS port
// activation, hot NIC attach/detach, and control-plane PCR-quote verification —
// return the typed ErrCapabilityNotSupported and are documented in
// docs/compute/cloud-providers.md.
//
// All GCE access flows through the narrow gceAPI interface so unit tests fake
// the cloud at the seam; there are no live GCP calls in unit tests.
package gcp

import (
	"context"
	"time"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// Label keys mark resources created by the platform so List/ListSnapshots can
// filter to platform-managed resources. GCE labels are lowercase and may not
// contain colons, so the platform namespace uses hyphens.
const (
	managedLabelKey   = "trusted-platform-managed"
	managedLabelValue = "true"
	vmIDLabelKey      = "trusted-platform-vm-id"
	nameLabelKey      = "trusted-platform-name"
	snapNameLabelKey  = "trusted-platform-snapshot-name"
)

// defaultPollInterval and defaultPollTimeout bound the state-transition
// polling used by Wait. They are overridable on the orchestrator for tests.
const (
	defaultPollInterval = 5 * time.Second
	defaultPollTimeout  = 10 * time.Minute
)

// GCE instance status strings (the computepb Status field is a *string whose
// value is the status name).
const (
	statusProvisioning = "PROVISIONING"
	statusStaging      = "STAGING"
	statusRunning      = "RUNNING"
	statusStopping     = "STOPPING"
	statusStopped      = "STOPPED"
	statusSuspending   = "SUSPENDING"
	statusSuspended    = "SUSPENDED"
	statusTerminated   = "TERMINATED"
	statusRepairing    = "REPAIRING"
)

// Compile-time proof the orchestrator satisfies the compute contracts.
var (
	_ compute.Orchestrator  = (*GCPOrchestrator)(nil)
	_ compute.VMSnapshotter = (*GCPOrchestrator)(nil)
	_ compute.VMAttester    = (*GCPOrchestrator)(nil)
)

// GCPOrchestrator launches and manages Shielded VM instances with a vTPM.
type GCPOrchestrator struct {
	config *compute.OrchestratorConfig
	gcp    *compute.GCPProviderConfig
	logger *logging.Logger
	client gceAPI

	// verifier validates Shielded VM endorsement-key material during
	// attestation. Reuses the platform VM attestation verifier.
	verifier vm.VMVerifier

	// pollInterval and pollTimeout bound state-transition polling. Tests
	// shrink them so waits complete instantly against the fake API.
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// New constructs a GCPOrchestrator with live GCE clients built from the
// provider configuration. It is the factory registered with the compute
// provider registry under ProviderGCP.
func New(ctx context.Context, cfg *compute.OrchestratorConfig, deps *compute.Deps) (compute.Orchestrator, error) {
	if cfg == nil {
		return nil, &ConfigError{Msg: "orchestrator config is required"}
	}
	if cfg.GCP == nil {
		return nil, &ConfigError{Msg: "gcp provider config is required (set compute.gcp)"}
	}
	if err := validateGCPConfig(cfg.GCP); err != nil {
		return nil, err
	}

	logger := logging.DefaultLogger()
	if deps != nil && deps.Logger != nil {
		logger = deps.Logger
	}

	client, err := newGCEClients(ctx, cfg.GCP.ProjectID, cfg.GCP.Zone, cfg.GCP.CredentialsFile)
	if err != nil {
		return nil, err
	}
	return newOrchestrator(cfg, logger, client), nil
}

// newOrchestrator wires an orchestrator around a supplied gceAPI. It is the
// seam unit tests use to inject a fake client.
func newOrchestrator(cfg *compute.OrchestratorConfig, logger *logging.Logger, client gceAPI) *GCPOrchestrator {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &GCPOrchestrator{
		config:       cfg,
		gcp:          cfg.GCP,
		logger:       logger,
		client:       client,
		verifier:     vm.NewVMVerifier(vm.WithVerifierLogger(logger.Slog())),
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

// validateGCPConfig enforces the minimum fields required to launch a Shielded
// VM.
func validateGCPConfig(c *compute.GCPProviderConfig) error {
	if c.ProjectID == "" {
		return &ConfigError{Msg: "project_id is required"}
	}
	if c.Zone == "" {
		return &ConfigError{Msg: "zone is required"}
	}
	if c.MachineType == "" {
		return &ConfigError{Msg: "machine_type is required"}
	}
	if c.SourceImage == "" {
		return &ConfigError{Msg: "source_image is required"}
	}
	return nil
}

// Create launches a Shielded VM from the device profile. The vTPM is requested
// explicitly through ShieldedInstanceConfig (EnableVtpm + integrity monitoring
// + Secure Boot), so the guest is guaranteed a vTPM device — GCE rejects the
// insert if the source image is not UEFI/Shielded compatible, keeping the
// launch honest.
func (o *GCPOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if profile == nil {
		return nil, compute.ErrInvalidProfile
	}

	name := sanitizeInstanceName(profile.Name)
	enable := true
	inst := &computepb.Instance{
		Name:        ptr(name),
		MachineType: ptr(o.machineTypeURL()),
		Labels:      o.resourceLabels(profile.Name, ""),
		ShieldedInstanceConfig: &computepb.ShieldedInstanceConfig{
			EnableVtpm:                &enable,
			EnableIntegrityMonitoring: &enable,
			EnableSecureBoot:          &enable,
		},
		Disks: []*computepb.AttachedDisk{{
			Boot:       &enable,
			AutoDelete: &enable,
			InitializeParams: &computepb.AttachedDiskInitializeParams{
				SourceImage: ptr(o.gcp.SourceImage),
			},
		}},
		NetworkInterfaces: []*computepb.NetworkInterface{o.networkInterface()},
	}

	created, err := o.client.InsertInstance(ctx, inst)
	if err != nil {
		return nil, &APIError{Op: "InsertInstance", Err: err}
	}
	instance := o.toInstance(created, profile.Name)
	o.logger.Infof("Launched Shielded VM %s (machine=%s, image=%s)", instance.ID, o.gcp.MachineType, o.gcp.SourceImage)
	return instance, nil
}

// Start starts a stopped instance.
func (o *GCPOrchestrator) Start(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.StartInstance(ctx, instanceID); err != nil {
		return &APIError{Op: "StartInstance", Err: err}
	}
	o.logger.Infof("Started instance %s", instanceID)
	return nil
}

// Stop stops a running instance.
func (o *GCPOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.StopInstance(ctx, instanceID); err != nil {
		return &APIError{Op: "StopInstance", Err: err}
	}
	o.logger.Infof("Stopped instance %s", instanceID)
	return nil
}

// Delete deletes an instance. GCE releases the instance's resources on delete.
func (o *GCPOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.DeleteInstance(ctx, instanceID); err != nil {
		return &APIError{Op: "DeleteInstance", Err: err}
	}
	o.logger.Infof("Deleted instance %s", instanceID)
	return nil
}

// List returns platform-managed instances, applying the supplied filter
// client-side after fetching by the managed label.
func (o *GCPOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	gceInsts, err := o.client.ListInstances(ctx, "labels."+managedLabelKey+"="+managedLabelValue)
	if err != nil {
		return nil, &APIError{Op: "ListInstances", Err: err}
	}
	var instances []*compute.Instance
	for _, gi := range gceInsts {
		instance := o.toInstance(gi, labelValue(gi.GetLabels(), nameLabelKey))
		if filter == nil || filter.Matches(instance) {
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

// Get retrieves a single instance by ID (its GCE instance name).
func (o *GCPOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	gi, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	return o.toInstance(gi, labelValue(gi.GetLabels(), nameLabelKey)), nil
}

// GetState returns the current lifecycle state of an instance.
func (o *GCPOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	gi, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return compute.StateUnknown, err
	}
	return mapInstanceState(gi.GetStatus()), nil
}

// Wait blocks until the instance reaches a powered-off state (STOPPED or
// TERMINATED), mirroring the QEMU orchestrator's Wait which blocks until the
// VM exits.
func (o *GCPOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	return o.pollInstanceUntil(ctx, instanceID, func(status string) bool {
		return status == statusStopped || status == statusTerminated
	})
}

// AttachNetwork has no honest GCE equivalent. Unlike an EC2 Elastic Network
// Interface, a Compute Engine network interface is bound at instance creation
// and there is no control-plane primitive to hot-attach an existing NIC to a
// running instance. The operation is honestly rejected with a typed error
// rather than silently succeeding. See docs/compute/cloud-providers.md.
func (o *GCPOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	return &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "AttachNetwork has no GCE equivalent; network interfaces are fixed at instance creation"},
	}
}

// DetachNetwork has no honest GCE equivalent, for the same reason as
// AttachNetwork. See docs/compute/cloud-providers.md.
func (o *GCPOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	return &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "DetachNetwork has no GCE equivalent; network interfaces are fixed at instance creation"},
	}
}

// ActivateInstance has no honest GCE equivalent: it transitions an OVS port
// from an enrolled (provisioning) to an authorized (production) 802.1X state,
// a construct that does not exist in GCE networking. The operation is honestly
// rejected with a typed error. See docs/compute/cloud-providers.md.
func (o *GCPOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	return &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "ActivateInstance (802.1X OVS port authorization) has no GCE equivalent; manage instance access via firewall rules"},
	}
}

// Close releases the GCE clients.
func (o *GCPOrchestrator) Close() error {
	if o.client == nil {
		return nil
	}
	return o.client.Close()
}

// describeInstance fetches a single GCE instance by name, mapping a not-found
// condition to compute.ErrInstanceNotFound so callers can use errors.Is
// uniformly across orchestrators.
func (o *GCPOrchestrator) describeInstance(ctx context.Context, instanceID string) (*computepb.Instance, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	gi, err := o.client.GetInstance(ctx, instanceID)
	if err != nil {
		if isNotFound(err) {
			return nil, compute.ErrInstanceNotFound
		}
		return nil, &APIError{Op: "GetInstance", Err: err}
	}
	if gi == nil {
		return nil, compute.ErrInstanceNotFound
	}
	return gi, nil
}

// pollInstanceUntil polls the instance status on a ticker (never time.Sleep)
// until pred is satisfied, ctx is cancelled, or the poll timeout elapses.
func (o *GCPOrchestrator) pollInstanceUntil(ctx context.Context, instanceID string, pred func(status string) bool) error {
	deadline := time.NewTimer(o.pollTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	check := func() (bool, error) {
		gi, err := o.describeInstance(ctx, instanceID)
		if err != nil {
			return false, err
		}
		if pred(gi.GetStatus()) {
			return true, nil
		}
		return false, nil
	}

	// Evaluate immediately so an already-terminal instance returns without
	// waiting a full tick.
	if done, err := check(); err != nil || done {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrWaitTimeout
		case <-ticker.C:
			if done, err := check(); err != nil || done {
				return err
			}
		}
	}
}

// machineTypeURL returns the zonal machine-type partial URL GCE expects.
func (o *GCPOrchestrator) machineTypeURL() string {
	return "zones/" + o.gcp.Zone + "/machineTypes/" + o.gcp.MachineType
}

// networkInterface builds the primary NIC from the optional network/subnetwork
// configuration. An empty configuration launches on the project default VPC.
func (o *GCPOrchestrator) networkInterface() *computepb.NetworkInterface {
	ni := &computepb.NetworkInterface{}
	if o.gcp.Network != "" {
		ni.Network = ptr(o.gcp.Network)
	}
	if o.gcp.Subnetwork != "" {
		ni.Subnetwork = ptr(o.gcp.Subnetwork)
	}
	return ni
}

// resourceLabels returns the standard label set applied to platform-managed
// resources. vmID is included when non-empty. The original (unsanitized) name
// is preserved for display via the name label.
func (o *GCPOrchestrator) resourceLabels(name, vmID string) map[string]string {
	labels := map[string]string{managedLabelKey: managedLabelValue}
	if name != "" {
		labels[nameLabelKey] = sanitizeInstanceName(name)
	}
	if vmID != "" {
		labels[vmIDLabelKey] = vmID
	}
	return labels
}

// toInstance maps a GCE instance to the platform compute.Instance model.
func (o *GCPOrchestrator) toInstance(gi *computepb.Instance, name string) *compute.Instance {
	id := gi.GetName()
	if name == "" {
		name = id
	}
	instance := &compute.Instance{
		ID:    id,
		Name:  name,
		Type:  compute.ComputeTypeVM,
		State: mapInstanceState(gi.GetStatus()),
		Metadata: map[string]string{
			"provider":     string(compute.ProviderGCP),
			"machine_type": resourceName(gi.GetMachineType()),
			"zone":         resourceName(gi.GetZone()),
		},
	}
	for _, ni := range gi.GetNetworkInterfaces() {
		if ni.GetNetworkIP() != "" {
			instance.Metadata["private_ip"] = ni.GetNetworkIP()
		}
		for _, ac := range ni.GetAccessConfigs() {
			if ac.GetNatIP() != "" {
				instance.Metadata["public_ip"] = ac.GetNatIP()
			}
		}
	}
	return instance
}

// mapInstanceState translates a GCE instance status string to the platform
// lifecycle state. A GCE "TERMINATED" instance is powered off (not deleted),
// so it maps to StateStopped.
func mapInstanceState(status string) compute.InstanceState {
	switch status {
	case statusProvisioning, statusStaging:
		return compute.StateCreating
	case statusRunning:
		return compute.StateRunning
	case statusStopping, statusSuspending:
		return compute.StateStopping
	case statusStopped, statusSuspended, statusTerminated:
		return compute.StateStopped
	case statusRepairing:
		return compute.StateError
	default:
		return compute.StateUnknown
	}
}

// labelValue returns the value of the named label, or "" when absent.
func labelValue(labels map[string]string, key string) string {
	if labels == nil {
		return ""
	}
	return labels[key]
}

// ptr returns a pointer to v. GCE protobuf setters use optional (pointer)
// fields throughout.
func ptr[T any](v T) *T { return &v }
