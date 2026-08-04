//go:build azurecompute

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

// Package azure implements the platform compute Orchestrator over Azure
// Virtual Machines, launching and managing Trusted Launch VMs with a vTPM. It
// is compiled only when the azurecompute build tag is present; without the tag
// a stub keeps the package buildable and the provider factory fails closed
// with a typed ErrComputeProviderNotCompiled.
//
// The orchestrator provides lifecycle parity with the local QEMU orchestrator
// (create/start/stop/delete/list/get/wait/state), managed-disk VM snapshots
// (VMSnapshotter), and NIC attach/detach. Capabilities that have no honest
// Azure control-plane equivalent — 802.1X OVS port activation and vTPM
// endorsement-key / PCR-quote attestation (guest-driven via Microsoft Azure
// Attestation) — return the typed ErrCapabilityNotSupported and are documented
// in docs/compute/cloud-providers.md.
//
// All ARM access flows through the narrow vmAPI interface so unit tests fake
// the cloud at the seam; there are no live Azure calls in unit tests.
package azure

import (
	"context"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// Tag keys mark resources created by the platform so List/ListSnapshots can
// filter to platform-managed resources.
const (
	managedTagKey   = "trusted-platform-managed"
	managedTagValue = "true"
	vmIDTagKey      = "trusted-platform-vm-id"
	nameTagKey      = "trusted-platform-name"
	snapNameTagKey  = "trusted-platform-snapshot-name"
)

// adminUsername is the OSProfile admin user set on created VMs. Access is
// through the platform's own trust mechanisms; the account exists only to
// satisfy Azure's image-based provisioning contract (which mandates an admin
// credential) alongside an ephemeral, discarded SSH key.
const adminUsername = "platform"

// defaultPollInterval and defaultPollTimeout bound the power-state polling used
// by Wait. They are overridable on the orchestrator for tests.
const (
	defaultPollInterval = 5 * time.Second
	defaultPollTimeout  = 10 * time.Minute
)

// Azure power-state status code prefix and values (InstanceView statuses carry
// codes like "PowerState/running").
const (
	powerStatePrefix       = "PowerState/"
	powerStateRunning      = "running"
	powerStateStarting     = "starting"
	powerStateStopping     = "stopping"
	powerStateStopped      = "stopped"
	powerStateDeallocating = "deallocating"
	powerStateDeallocated  = "deallocated"
)

// Compile-time proof the orchestrator satisfies the compute contracts.
var (
	_ compute.Orchestrator  = (*AzureOrchestrator)(nil)
	_ compute.VMSnapshotter = (*AzureOrchestrator)(nil)
	_ compute.VMAttester    = (*AzureOrchestrator)(nil)
)

// AzureOrchestrator launches and manages Trusted Launch VMs with a vTPM.
type AzureOrchestrator struct {
	config *compute.OrchestratorConfig
	azure  *compute.AzureProviderConfig
	logger *logging.Logger
	client vmAPI

	// verifier is retained for parity with the other cloud orchestrators; on
	// Azure the vTPM quote is verified by the in-guest agent + pkg/attestation/vm
	// (see attest.go), not the control plane.
	verifier vm.VMVerifier

	// pollInterval and pollTimeout bound power-state polling. Tests shrink them
	// so waits complete instantly against the fake API.
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// New constructs an AzureOrchestrator with live ARM clients built from the
// provider configuration. It is the factory registered with the compute
// provider registry under ProviderAzure.
func New(ctx context.Context, cfg *compute.OrchestratorConfig, deps *compute.Deps) (compute.Orchestrator, error) {
	if cfg == nil {
		return nil, &ConfigError{Msg: "orchestrator config is required"}
	}
	if cfg.Azure == nil {
		return nil, &ConfigError{Msg: "azure provider config is required (set compute.azure)"}
	}
	if err := validateAzureConfig(cfg.Azure); err != nil {
		return nil, err
	}

	logger := logging.DefaultLogger()
	if deps != nil && deps.Logger != nil {
		logger = deps.Logger
	}

	client, err := newARMClients(cfg.Azure.SubscriptionID, cfg.Azure.ResourceGroup, cfg.Azure.TenantID)
	if err != nil {
		return nil, err
	}
	return newOrchestrator(cfg, logger, client), nil
}

// newOrchestrator wires an orchestrator around a supplied vmAPI. It is the seam
// unit tests use to inject a fake client.
func newOrchestrator(cfg *compute.OrchestratorConfig, logger *logging.Logger, client vmAPI) *AzureOrchestrator {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &AzureOrchestrator{
		config:       cfg,
		azure:        cfg.Azure,
		logger:       logger,
		client:       client,
		verifier:     vm.NewVMVerifier(vm.WithVerifierLogger(logger.Slog())),
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

// validateAzureConfig enforces the minimum fields required to launch a Trusted
// Launch VM.
func validateAzureConfig(c *compute.AzureProviderConfig) error {
	if c.SubscriptionID == "" {
		return &ConfigError{Msg: "subscription_id is required"}
	}
	if c.ResourceGroup == "" {
		return &ConfigError{Msg: "resource_group is required"}
	}
	if c.Location == "" {
		return &ConfigError{Msg: "location is required"}
	}
	if c.VMSize == "" {
		return &ConfigError{Msg: "vm_size is required"}
	}
	if c.ImageReference == "" {
		return &ConfigError{Msg: "image_reference is required"}
	}
	return nil
}

// Create launches a Trusted Launch VM from the device profile. The vTPM is
// requested explicitly through the SecurityProfile (SecurityType=TrustedLaunch
// + UefiSettings.VTpmEnabled + SecureBootEnabled), so the guest is guaranteed a
// vTPM device — Azure rejects the create if the VM size or image is not Trusted
// Launch capable, keeping the launch honest.
func (o *AzureOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if profile == nil {
		return nil, compute.ErrInvalidProfile
	}

	name := profile.Name
	sshKey, err := generateSSHAuthorizedKey()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustedLaunchUnsupported, Cause: err}
	}

	params := armcompute.VirtualMachine{
		Location: to.Ptr(o.azure.Location),
		Tags:     o.resourceTags(name, ""),
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(o.azure.VMSize)),
			},
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: o.imageReference(),
				OSDisk: &armcompute.OSDisk{
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesPremiumLRS),
					},
				},
			},
			SecurityProfile: &armcompute.SecurityProfile{
				SecurityType: to.Ptr(armcompute.SecurityTypesTrustedLaunch),
				UefiSettings: &armcompute.UefiSettings{
					VTpmEnabled:       to.Ptr(true),
					SecureBootEnabled: to.Ptr(true),
				},
			},
			OSProfile: &armcompute.OSProfile{
				ComputerName:  to.Ptr(computerName(name)),
				AdminUsername: to.Ptr(adminUsername),
				LinuxConfiguration: &armcompute.LinuxConfiguration{
					DisablePasswordAuthentication: to.Ptr(true),
					SSH: &armcompute.SSHConfiguration{
						PublicKeys: []*armcompute.SSHPublicKey{{
							Path:    to.Ptr("/home/" + adminUsername + "/.ssh/authorized_keys"),
							KeyData: to.Ptr(sshKey),
						}},
					},
				},
			},
		},
	}
	if nic := o.primaryNIC(); nic != nil {
		params.Properties.NetworkProfile = &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{nic},
		}
	}

	created, err := o.client.CreateVM(ctx, name, params)
	if err != nil {
		return nil, &APIError{Op: "CreateVM", Err: err}
	}
	instance := o.toInstance(created, powerStateStarting)
	o.logger.Infof("Launched Trusted Launch VM %s (size=%s, image=%s)", instance.ID, o.azure.VMSize, o.azure.ImageReference)
	return instance, nil
}

// Start starts a stopped/deallocated VM.
func (o *AzureOrchestrator) Start(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.StartVM(ctx, instanceID); err != nil {
		return &APIError{Op: "StartVM", Err: err}
	}
	o.logger.Infof("Started VM %s", instanceID)
	return nil
}

// Stop powers off a running VM. The VM remains allocated (billed for compute
// reservation); Delete releases it. Restore uses full deallocation.
func (o *AzureOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.PowerOffVM(ctx, instanceID); err != nil {
		return &APIError{Op: "PowerOffVM", Err: err}
	}
	o.logger.Infof("Powered off VM %s", instanceID)
	return nil
}

// Delete deletes a VM. Azure releases the VM's compute resources on delete.
func (o *AzureOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if err := o.client.DeleteVM(ctx, instanceID); err != nil {
		return &APIError{Op: "DeleteVM", Err: err}
	}
	o.logger.Infof("Deleted VM %s", instanceID)
	return nil
}

// List returns platform-managed VMs, filtering by the managed tag and applying
// the supplied filter client-side.
func (o *AzureOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	vms, err := o.client.ListVMs(ctx)
	if err != nil {
		return nil, &APIError{Op: "ListVMs", Err: err}
	}
	var instances []*compute.Instance
	for _, azVM := range vms {
		if tagValue(azVM.Tags, managedTagKey) != managedTagValue {
			continue
		}
		state, _ := o.powerState(ctx, derefStr(azVM.Name))
		instance := o.toInstance(azVM, state)
		if filter == nil || filter.Matches(instance) {
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

// Get retrieves a single VM by ID (its Azure VM name).
func (o *AzureOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	azVM, err := o.describeVM(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	state, err := o.powerState(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	return o.toInstance(azVM, state), nil
}

// GetState returns the current lifecycle state of a VM, derived from its power
// state.
func (o *AzureOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if instanceID == "" {
		return compute.StateUnknown, compute.ErrInvalidInstanceID
	}
	state, err := o.powerState(ctx, instanceID)
	if err != nil {
		return compute.StateUnknown, err
	}
	return mapPowerState(state), nil
}

// Wait blocks until the VM reaches a powered-off state (stopped or
// deallocated), mirroring the QEMU orchestrator's Wait which blocks until the
// VM exits.
func (o *AzureOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	return o.pollPowerUntil(ctx, instanceID, func(state string) bool {
		return state == powerStateStopped || state == powerStateDeallocated
	})
}

// AttachNetwork attaches an existing network interface (portName is the NIC
// resource ID) to the VM. This is the Azure equivalent of attaching an OVS
// port: the NIC is added to the VM's network profile via an update. Azure
// enforces its own running-state constraints for secondary NICs.
func (o *AzureOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if portName == "" {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkAttachmentFailed, Cause: &compute.MessageError{Msg: "portName (NIC resource ID) is required"}}
	}

	azVM, err := o.describeVM(ctx, instanceID)
	if err != nil {
		return err
	}
	nics := existingNICs(azVM)
	for _, nic := range nics {
		if strings.EqualFold(derefStr(nic.ID), portName) {
			return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkAttachmentFailed, Cause: &compute.MessageError{Msg: "NIC " + portName + " already attached"}}
		}
	}
	// The first NIC on a VM is primary; subsequent NICs are secondary.
	primary := len(nics) == 0
	nics = append(nics, &armcompute.NetworkInterfaceReference{
		ID:         to.Ptr(portName),
		Properties: &armcompute.NetworkInterfaceReferenceProperties{Primary: to.Ptr(primary)},
	})

	update := armcompute.VirtualMachineUpdate{
		Properties: &armcompute.VirtualMachineProperties{
			NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: nics},
		},
	}
	if _, err := o.client.UpdateVM(ctx, instanceID, update); err != nil {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkAttachmentFailed, Cause: &APIError{Op: "UpdateVM", Err: err}}
	}
	o.logger.Infof("Attached NIC %s to VM %s", portName, instanceID)
	return nil
}

// DetachNetwork detaches the network interface (portName is the NIC resource
// ID) from the VM by removing it from the VM's network profile.
func (o *AzureOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if portName == "" {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &compute.MessageError{Msg: "portName (NIC resource ID) is required"}}
	}

	azVM, err := o.describeVM(ctx, instanceID)
	if err != nil {
		return err
	}
	var remaining []*armcompute.NetworkInterfaceReference
	found := false
	for _, nic := range existingNICs(azVM) {
		if strings.EqualFold(derefStr(nic.ID), portName) {
			found = true
			continue
		}
		remaining = append(remaining, nic)
	}
	if !found {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &compute.MessageError{Msg: "NIC " + portName + " not attached to VM " + instanceID}}
	}

	update := armcompute.VirtualMachineUpdate{
		Properties: &armcompute.VirtualMachineProperties{
			NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: remaining},
		},
	}
	if _, err := o.client.UpdateVM(ctx, instanceID, update); err != nil {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &APIError{Op: "UpdateVM", Err: err}}
	}
	o.logger.Infof("Detached NIC %s from VM %s", portName, instanceID)
	return nil
}

// ActivateInstance has no honest Azure equivalent: it transitions an OVS port
// from an enrolled (provisioning) to an authorized (production) 802.1X state, a
// construct that does not exist in Azure networking. The operation is honestly
// rejected with a typed error. See docs/compute/cloud-providers.md.
func (o *AzureOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	return &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "ActivateInstance (802.1X OVS port authorization) has no Azure equivalent; manage instance access via network security groups"},
	}
}

// Close releases the ARM clients.
func (o *AzureOrchestrator) Close() error {
	if o.client == nil {
		return nil
	}
	return o.client.Close()
}

// describeVM fetches a single Azure VM by name, mapping a not-found condition
// to compute.ErrInstanceNotFound so callers can use errors.Is uniformly across
// orchestrators.
func (o *AzureOrchestrator) describeVM(ctx context.Context, instanceID string) (*armcompute.VirtualMachine, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	azVM, err := o.client.GetVM(ctx, instanceID)
	if err != nil {
		if isNotFound(err) {
			return nil, compute.ErrInstanceNotFound
		}
		return nil, &APIError{Op: "GetVM", Err: err}
	}
	if azVM == nil {
		return nil, compute.ErrInstanceNotFound
	}
	return azVM, nil
}

// powerState returns the VM's current power-state value (e.g. "running"),
// mapping a not-found condition to compute.ErrInstanceNotFound.
func (o *AzureOrchestrator) powerState(ctx context.Context, instanceID string) (string, error) {
	view, err := o.client.InstanceView(ctx, instanceID)
	if err != nil {
		if isNotFound(err) {
			return "", compute.ErrInstanceNotFound
		}
		return "", &APIError{Op: "InstanceView", Err: err}
	}
	if view == nil {
		return "", nil
	}
	for _, status := range view.Statuses {
		code := derefStr(status.Code)
		if strings.HasPrefix(code, powerStatePrefix) {
			return strings.TrimPrefix(code, powerStatePrefix), nil
		}
	}
	return "", nil
}

// pollPowerUntil polls the VM power state on a ticker (never time.Sleep) until
// pred is satisfied, ctx is cancelled, or the poll timeout elapses.
func (o *AzureOrchestrator) pollPowerUntil(ctx context.Context, instanceID string, pred func(state string) bool) error {
	deadline := time.NewTimer(o.pollTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	check := func() (bool, error) {
		state, err := o.powerState(ctx, instanceID)
		if err != nil {
			return false, err
		}
		if pred(state) {
			return true, nil
		}
		return false, nil
	}

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

// imageReference builds the source ImageReference from the configured value.
// A colon-delimited "publisher:offer:sku:version" is treated as a marketplace
// image; any other value is treated as a resource / gallery image ID.
func (o *AzureOrchestrator) imageReference() *armcompute.ImageReference {
	ref := o.azure.ImageReference
	parts := strings.Split(ref, ":")
	if len(parts) == 4 {
		return &armcompute.ImageReference{
			Publisher: to.Ptr(parts[0]),
			Offer:     to.Ptr(parts[1]),
			SKU:       to.Ptr(parts[2]),
			Version:   to.Ptr(parts[3]),
		}
	}
	return &armcompute.ImageReference{ID: to.Ptr(ref)}
}

// primaryNIC returns nil (Azure requires a pre-created NIC resource ID which is
// not part of the provider config); callers attach NICs post-create via
// AttachNetwork. When the platform later carries a default NIC ID this is where
// it is wired.
func (o *AzureOrchestrator) primaryNIC() *armcompute.NetworkInterfaceReference {
	return nil
}

// resourceTags returns the standard tag set applied to platform-managed
// resources. vmID is included when non-empty.
func (o *AzureOrchestrator) resourceTags(name, vmID string) map[string]*string {
	tags := map[string]*string{managedTagKey: to.Ptr(managedTagValue)}
	if name != "" {
		tags[nameTagKey] = to.Ptr(name)
	}
	if vmID != "" {
		tags[vmIDTagKey] = to.Ptr(vmID)
	}
	return tags
}

// toInstance maps an Azure VM to the platform compute.Instance model.
func (o *AzureOrchestrator) toInstance(azVM *armcompute.VirtualMachine, powerState string) *compute.Instance {
	id := derefStr(azVM.Name)
	name := tagValue(azVM.Tags, nameTagKey)
	if name == "" {
		name = id
	}
	instance := &compute.Instance{
		ID:    id,
		Name:  name,
		Type:  compute.ComputeTypeVM,
		State: mapPowerState(powerState),
		Metadata: map[string]string{
			"provider": string(compute.ProviderAzure),
			"location": derefStr(azVM.Location),
		},
	}
	if azVM.Properties != nil && azVM.Properties.HardwareProfile != nil && azVM.Properties.HardwareProfile.VMSize != nil {
		instance.Metadata["vm_size"] = string(*azVM.Properties.HardwareProfile.VMSize)
	}
	return instance
}

// mapPowerState translates an Azure power-state value to the platform lifecycle
// state. An empty state (VM provisioning, no power state yet) maps to
// StateCreating.
func mapPowerState(state string) compute.InstanceState {
	switch state {
	case "":
		return compute.StateCreating
	case powerStateStarting:
		return compute.StateStarting
	case powerStateRunning:
		return compute.StateRunning
	case powerStateStopping, powerStateDeallocating:
		return compute.StateStopping
	case powerStateStopped, powerStateDeallocated:
		return compute.StateStopped
	default:
		return compute.StateUnknown
	}
}

// existingNICs returns the VM's current network interface references, or nil.
func existingNICs(azVM *armcompute.VirtualMachine) []*armcompute.NetworkInterfaceReference {
	if azVM == nil || azVM.Properties == nil || azVM.Properties.NetworkProfile == nil {
		return nil
	}
	return azVM.Properties.NetworkProfile.NetworkInterfaces
}

// tagValue returns the value of the named tag, or "" when absent.
func tagValue(tags map[string]*string, key string) string {
	if tags == nil {
		return ""
	}
	return derefStr(tags[key])
}

// computerName derives an Azure-valid Linux computer name (<= 64 chars,
// trimmed) from the instance name.
func computerName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" {
		name = "platform-vm"
	}
	return name
}
