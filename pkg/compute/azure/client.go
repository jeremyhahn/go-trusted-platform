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

package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
)

// vmAPI is the narrow slice of the Azure Resource Manager compute API used by
// the orchestrator. Every long-running Poller is driven to completion inside
// the concrete implementation so the seam exposes only settled values; unit
// tests provide a fake that never touches the network or the Poller machinery.
type vmAPI interface {
	CreateVM(ctx context.Context, name string, params armcompute.VirtualMachine) (*armcompute.VirtualMachine, error)
	StartVM(ctx context.Context, name string) error
	PowerOffVM(ctx context.Context, name string) error
	DeallocateVM(ctx context.Context, name string) error
	DeleteVM(ctx context.Context, name string) error
	GetVM(ctx context.Context, name string) (*armcompute.VirtualMachine, error)
	InstanceView(ctx context.Context, name string) (*armcompute.VirtualMachineInstanceView, error)
	ListVMs(ctx context.Context) ([]*armcompute.VirtualMachine, error)
	UpdateVM(ctx context.Context, name string, params armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error)

	CreateSnapshot(ctx context.Context, name string, params armcompute.Snapshot) (*armcompute.Snapshot, error)
	DeleteSnapshot(ctx context.Context, name string) error
	ListSnapshots(ctx context.Context) ([]*armcompute.Snapshot, error)

	CreateDisk(ctx context.Context, name string, params armcompute.Disk) (*armcompute.Disk, error)

	Close() error
}

// armClients is the production vmAPI backed by the ARM compute clients. It owns
// the resource-group scope so orchestrator call sites stay terse.
type armClients struct {
	resourceGroup string
	vms           *armcompute.VirtualMachinesClient
	snapshots     *armcompute.SnapshotsClient
	disks         *armcompute.DisksClient
}

// newARMClients builds the compute clients from the provider configuration,
// using the default Azure credential chain (optionally scoped to a tenant).
func newARMClients(subscriptionID, resourceGroup, tenantID string) (*armClients, error) {
	var credOpts *azidentity.DefaultAzureCredentialOptions
	if tenantID != "" {
		credOpts = &azidentity.DefaultAzureCredentialOptions{TenantID: tenantID}
	}
	cred, err := azidentity.NewDefaultAzureCredential(credOpts)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustedLaunchUnsupported, Cause: err}
	}

	vms, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustedLaunchUnsupported, Cause: err}
	}
	snapshots, err := armcompute.NewSnapshotsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustedLaunchUnsupported, Cause: err}
	}
	disks, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustedLaunchUnsupported, Cause: err}
	}
	return &armClients{
		resourceGroup: resourceGroup,
		vms:           vms,
		snapshots:     snapshots,
		disks:         disks,
	}, nil
}

// CreateVM implements vmAPI.
func (c *armClients) CreateVM(ctx context.Context, name string, params armcompute.VirtualMachine) (*armcompute.VirtualMachine, error) {
	poller, err := c.vms.BeginCreateOrUpdate(ctx, c.resourceGroup, name, params, nil)
	if err != nil {
		return nil, err
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachine, nil
}

// StartVM implements vmAPI.
func (c *armClients) StartVM(ctx context.Context, name string) error {
	poller, err := c.vms.BeginStart(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

// PowerOffVM implements vmAPI.
func (c *armClients) PowerOffVM(ctx context.Context, name string) error {
	poller, err := c.vms.BeginPowerOff(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

// DeallocateVM implements vmAPI.
func (c *armClients) DeallocateVM(ctx context.Context, name string) error {
	poller, err := c.vms.BeginDeallocate(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

// DeleteVM implements vmAPI.
func (c *armClients) DeleteVM(ctx context.Context, name string) error {
	poller, err := c.vms.BeginDelete(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

// GetVM implements vmAPI.
func (c *armClients) GetVM(ctx context.Context, name string) (*armcompute.VirtualMachine, error) {
	resp, err := c.vms.Get(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachine, nil
}

// InstanceView implements vmAPI.
func (c *armClients) InstanceView(ctx context.Context, name string) (*armcompute.VirtualMachineInstanceView, error) {
	resp, err := c.vms.InstanceView(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachineInstanceView, nil
}

// ListVMs implements vmAPI.
func (c *armClients) ListVMs(ctx context.Context) ([]*armcompute.VirtualMachine, error) {
	pager := c.vms.NewListPager(c.resourceGroup, nil)
	var out []*armcompute.VirtualMachine
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// UpdateVM implements vmAPI.
func (c *armClients) UpdateVM(ctx context.Context, name string, params armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error) {
	poller, err := c.vms.BeginUpdate(ctx, c.resourceGroup, name, params, nil)
	if err != nil {
		return nil, err
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachine, nil
}

// CreateSnapshot implements vmAPI.
func (c *armClients) CreateSnapshot(ctx context.Context, name string, params armcompute.Snapshot) (*armcompute.Snapshot, error) {
	poller, err := c.snapshots.BeginCreateOrUpdate(ctx, c.resourceGroup, name, params, nil)
	if err != nil {
		return nil, err
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Snapshot, nil
}

// DeleteSnapshot implements vmAPI.
func (c *armClients) DeleteSnapshot(ctx context.Context, name string) error {
	poller, err := c.snapshots.BeginDelete(ctx, c.resourceGroup, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

// ListSnapshots implements vmAPI.
func (c *armClients) ListSnapshots(ctx context.Context) ([]*armcompute.Snapshot, error) {
	pager := c.snapshots.NewListByResourceGroupPager(c.resourceGroup, nil)
	var out []*armcompute.Snapshot
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// CreateDisk implements vmAPI.
func (c *armClients) CreateDisk(ctx context.Context, name string, params armcompute.Disk) (*armcompute.Disk, error) {
	poller, err := c.disks.BeginCreateOrUpdate(ctx, c.resourceGroup, name, params, nil)
	if err != nil {
		return nil, err
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Disk, nil
}

// Close releases the clients. The ARM clients hold no closable resources.
func (c *armClients) Close() error { return nil }
