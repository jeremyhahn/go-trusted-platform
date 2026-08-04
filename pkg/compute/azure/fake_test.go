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
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeARM implements vmAPI with per-method function seams. A nil seam returns a
// benign empty output so tests set only the calls they exercise.
type fakeARM struct {
	createVM       func(context.Context, string, armcompute.VirtualMachine) (*armcompute.VirtualMachine, error)
	startVM        func(context.Context, string) error
	powerOffVM     func(context.Context, string) error
	deallocateVM   func(context.Context, string) error
	deleteVM       func(context.Context, string) error
	getVM          func(context.Context, string) (*armcompute.VirtualMachine, error)
	instanceView   func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error)
	listVMs        func(context.Context) ([]*armcompute.VirtualMachine, error)
	updateVM       func(context.Context, string, armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error)
	createSnapshot func(context.Context, string, armcompute.Snapshot) (*armcompute.Snapshot, error)
	deleteSnapshot func(context.Context, string) error
	listSnapshots  func(context.Context) ([]*armcompute.Snapshot, error)
	createDisk     func(context.Context, string, armcompute.Disk) (*armcompute.Disk, error)
	closed         bool
}

func (f *fakeARM) CreateVM(ctx context.Context, name string, params armcompute.VirtualMachine) (*armcompute.VirtualMachine, error) {
	if f.createVM != nil {
		return f.createVM(ctx, name, params)
	}
	return &armcompute.VirtualMachine{Name: to.Ptr(name)}, nil
}

func (f *fakeARM) StartVM(ctx context.Context, name string) error {
	if f.startVM != nil {
		return f.startVM(ctx, name)
	}
	return nil
}

func (f *fakeARM) PowerOffVM(ctx context.Context, name string) error {
	if f.powerOffVM != nil {
		return f.powerOffVM(ctx, name)
	}
	return nil
}

func (f *fakeARM) DeallocateVM(ctx context.Context, name string) error {
	if f.deallocateVM != nil {
		return f.deallocateVM(ctx, name)
	}
	return nil
}

func (f *fakeARM) DeleteVM(ctx context.Context, name string) error {
	if f.deleteVM != nil {
		return f.deleteVM(ctx, name)
	}
	return nil
}

func (f *fakeARM) GetVM(ctx context.Context, name string) (*armcompute.VirtualMachine, error) {
	if f.getVM != nil {
		return f.getVM(ctx, name)
	}
	return &armcompute.VirtualMachine{Name: to.Ptr(name)}, nil
}

func (f *fakeARM) InstanceView(ctx context.Context, name string) (*armcompute.VirtualMachineInstanceView, error) {
	if f.instanceView != nil {
		return f.instanceView(ctx, name)
	}
	return &armcompute.VirtualMachineInstanceView{}, nil
}

func (f *fakeARM) ListVMs(ctx context.Context) ([]*armcompute.VirtualMachine, error) {
	if f.listVMs != nil {
		return f.listVMs(ctx)
	}
	return nil, nil
}

func (f *fakeARM) UpdateVM(ctx context.Context, name string, params armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error) {
	if f.updateVM != nil {
		return f.updateVM(ctx, name, params)
	}
	return &armcompute.VirtualMachine{Name: to.Ptr(name)}, nil
}

func (f *fakeARM) CreateSnapshot(ctx context.Context, name string, params armcompute.Snapshot) (*armcompute.Snapshot, error) {
	if f.createSnapshot != nil {
		return f.createSnapshot(ctx, name, params)
	}
	return &armcompute.Snapshot{Name: to.Ptr(name)}, nil
}

func (f *fakeARM) DeleteSnapshot(ctx context.Context, name string) error {
	if f.deleteSnapshot != nil {
		return f.deleteSnapshot(ctx, name)
	}
	return nil
}

func (f *fakeARM) ListSnapshots(ctx context.Context) ([]*armcompute.Snapshot, error) {
	if f.listSnapshots != nil {
		return f.listSnapshots(ctx)
	}
	return nil, nil
}

func (f *fakeARM) CreateDisk(ctx context.Context, name string, params armcompute.Disk) (*armcompute.Disk, error) {
	if f.createDisk != nil {
		return f.createDisk(ctx, name, params)
	}
	return &armcompute.Disk{Name: to.Ptr(name), ID: to.Ptr("/disks/" + name)}, nil
}

func (f *fakeARM) Close() error {
	f.closed = true
	return nil
}

// newTestOrchestrator builds an orchestrator over a fake client with tiny poll
// intervals so waits complete instantly and never touch the network.
func newTestOrchestrator(t *testing.T, client vmAPI) *AzureOrchestrator {
	t.Helper()
	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderAzure,
		WorkDir:      t.TempDir(),
		MaxInstances: 10,
		Azure: &compute.AzureProviderConfig{
			SubscriptionID: "sub-1",
			ResourceGroup:  "rg-1",
			Location:       "eastus",
			VMSize:         "Standard_D2s_v5",
			ImageReference: "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest",
		},
	}
	o := newOrchestrator(cfg, logging.DefaultLogger(), client)
	o.pollInterval = time.Millisecond
	o.pollTimeout = 2 * time.Second
	return o
}

// managedVM returns a fake Azure VM tagged as platform-managed with an OS disk.
func managedVM(name string) *armcompute.VirtualMachine {
	return &armcompute.VirtualMachine{
		Name:     to.Ptr(name),
		Location: to.Ptr("eastus"),
		Tags: map[string]*string{
			managedTagKey: to.Ptr(managedTagValue),
			nameTagKey:    to.Ptr(name),
		},
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_D2s_v5")),
			},
			StorageProfile: &armcompute.StorageProfile{
				OSDisk: &armcompute.OSDisk{
					ManagedDisk: &armcompute.ManagedDiskParameters{
						ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/" + name + "-osdisk"),
					},
				},
			},
		},
	}
}

// powerView returns an InstanceView reporting the given power-state value.
func powerView(state string) *armcompute.VirtualMachineInstanceView {
	return &armcompute.VirtualMachineInstanceView{
		Statuses: []*armcompute.InstanceViewStatus{
			{Code: to.Ptr("ProvisioningState/succeeded")},
			{Code: to.Ptr(powerStatePrefix + state)},
		},
	}
}
