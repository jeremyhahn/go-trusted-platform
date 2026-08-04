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
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

func TestAzureOrchestrator_ImplementsContracts(t *testing.T) {
	var _ compute.Orchestrator = (*AzureOrchestrator)(nil)
	var _ compute.VMSnapshotter = (*AzureOrchestrator)(nil)
	var _ compute.VMAttester = (*AzureOrchestrator)(nil)
}

func TestProviderRegistered_UnderTag(t *testing.T) {
	if !compute.IsProviderCompiled(compute.ProviderAzure) {
		t.Fatal("ProviderAzure must be registered when the azurecompute tag is built")
	}
}

func TestCreate_HappyPath(t *testing.T) {
	client := &fakeARM{
		createVM: func(_ context.Context, name string, params armcompute.VirtualMachine) (*armcompute.VirtualMachine, error) {
			sp := params.Properties.SecurityProfile
			if sp == nil || sp.SecurityType == nil || *sp.SecurityType != armcompute.SecurityTypesTrustedLaunch {
				t.Error("expected SecurityType=TrustedLaunch")
			}
			if sp.UefiSettings == nil || !derefBool(sp.UefiSettings.VTpmEnabled) {
				t.Error("expected vTPM enabled")
			}
			return managedVM(name), nil
		},
	}
	o := newTestOrchestrator(t, client)

	inst, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if inst.ID != "node-01" {
		t.Errorf("ID = %q, want node-01", inst.ID)
	}
	if inst.Type != compute.ComputeTypeVM {
		t.Errorf("Type = %q, want vm", inst.Type)
	}
	if inst.Metadata["provider"] != string(compute.ProviderAzure) {
		t.Errorf("provider metadata = %q", inst.Metadata["provider"])
	}
}

func TestCreate_NilProfile(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.Create(context.Background(), nil)
	if !errors.Is(err, compute.ErrInvalidProfile) {
		t.Fatalf("err = %v, want ErrInvalidProfile", err)
	}
}

func TestCreate_APIError(t *testing.T) {
	client := &fakeARM{
		createVM: func(context.Context, string, armcompute.VirtualMachine) (*armcompute.VirtualMachine, error) {
			return nil, errors.New("quota exceeded")
		},
	}
	o := newTestOrchestrator(t, client)
	_, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "CreateVM" {
		t.Fatalf("err = %v, want APIError{CreateVM}", err)
	}
}

func TestStartStopDelete(t *testing.T) {
	var started, stopped, deleted bool
	client := &fakeARM{
		startVM:    func(context.Context, string) error { started = true; return nil },
		powerOffVM: func(context.Context, string) error { stopped = true; return nil },
		deleteVM:   func(context.Context, string) error { deleted = true; return nil },
	}
	o := newTestOrchestrator(t, client)
	ctx := context.Background()

	if err := o.Start(ctx, "node-01"); err != nil || !started {
		t.Fatalf("Start: %v started=%v", err, started)
	}
	if err := o.Stop(ctx, "node-01"); err != nil || !stopped {
		t.Fatalf("Stop: %v stopped=%v", err, stopped)
	}
	if err := o.Delete(ctx, "node-01"); err != nil || !deleted {
		t.Fatalf("Delete: %v deleted=%v", err, deleted)
	}
}

func TestLifecycle_EmptyInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	ctx := context.Background()
	for name, fn := range map[string]func() error{
		"Start":  func() error { return o.Start(ctx, "") },
		"Stop":   func() error { return o.Stop(ctx, "") },
		"Delete": func() error { return o.Delete(ctx, "") },
		"Wait":   func() error { return o.Wait(ctx, "") },
	} {
		if err := fn(); !errors.Is(err, compute.ErrInvalidInstanceID) {
			t.Errorf("%s: err = %v, want ErrInvalidInstanceID", name, err)
		}
	}
}

func TestStart_APIError(t *testing.T) {
	client := &fakeARM{startVM: func(context.Context, string) error {
		return errors.New("boom")
	}}
	o := newTestOrchestrator(t, client)
	err := o.Start(context.Background(), "node-01")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "StartVM" {
		t.Fatalf("err = %v, want APIError{StartVM}", err)
	}
}

func TestGetState_Mapping(t *testing.T) {
	cases := []struct {
		power string
		want  compute.InstanceState
	}{
		{powerStateStarting, compute.StateStarting},
		{powerStateRunning, compute.StateRunning},
		{powerStateStopping, compute.StateStopping},
		{powerStateDeallocating, compute.StateStopping},
		{powerStateStopped, compute.StateStopped},
		{powerStateDeallocated, compute.StateStopped},
	}
	for _, tc := range cases {
		client := &fakeARM{instanceView: func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error) {
			return powerView(tc.power), nil
		}}
		o := newTestOrchestrator(t, client)
		got, err := o.GetState(context.Background(), "node-01")
		if err != nil {
			t.Fatalf("GetState(%s): %v", tc.power, err)
		}
		if got != tc.want {
			t.Errorf("power %s -> %q, want %q", tc.power, got, tc.want)
		}
	}
}

func TestGet_NotFound(t *testing.T) {
	client := &fakeARM{getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) {
		return nil, &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceNotFound"}
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.Get(context.Background(), "missing")
	if !errors.Is(err, compute.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound", err)
	}
}

func TestList_FiltersByManagedTagAndName(t *testing.T) {
	keep := managedVM("keep")
	drop := managedVM("drop")
	unmanaged := &armcompute.VirtualMachine{Name: to.Ptr("foreign")} // no managed tag
	client := &fakeARM{
		listVMs: func(context.Context) ([]*armcompute.VirtualMachine, error) {
			return []*armcompute.VirtualMachine{keep, drop, unmanaged}, nil
		},
		instanceView: func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error) {
			return powerView(powerStateRunning), nil
		},
	}
	o := newTestOrchestrator(t, client)

	list, err := o.List(context.Background(), &compute.InstanceFilter{Name: "keep"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "keep" {
		t.Fatalf("list = %+v, want single keep", list)
	}
}

func TestList_APIError(t *testing.T) {
	client := &fakeARM{listVMs: func(context.Context) ([]*armcompute.VirtualMachine, error) {
		return nil, errors.New("boom")
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.List(context.Background(), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want APIError", err)
	}
}

func TestWait_ReachesTerminal(t *testing.T) {
	client := &fakeARM{instanceView: func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error) {
		return powerView(powerStateStopped), nil
	}}
	o := newTestOrchestrator(t, client)
	if err := o.Wait(context.Background(), "node-01"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestWait_ContextCancelled(t *testing.T) {
	client := &fakeARM{instanceView: func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error) {
		return powerView(powerStateRunning), nil // never terminal
	}}
	o := newTestOrchestrator(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.Wait(ctx, "node-01"); err == nil {
		t.Fatal("Wait: expected error on cancelled context")
	}
}

func TestAttachNetwork_HappyAndError(t *testing.T) {
	vm := managedVM("node-01")
	var attached bool
	client := &fakeARM{
		getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) { return vm, nil },
		updateVM: func(_ context.Context, _ string, up armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error) {
			nics := up.Properties.NetworkProfile.NetworkInterfaces
			if len(nics) != 1 || derefStr(nics[0].ID) != "/nics/nic-1" {
				t.Errorf("nics = %+v", nics)
			}
			attached = true
			return vm, nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.AttachNetwork(context.Background(), "node-01", "/nics/nic-1"); err != nil || !attached {
		t.Fatalf("AttachNetwork: %v attached=%v", err, attached)
	}

	if err := o.AttachNetwork(context.Background(), "node-01", ""); !errors.Is(err, compute.ErrNetworkAttachmentFailed) {
		t.Fatalf("empty port err = %v, want ErrNetworkAttachmentFailed", err)
	}
}

func TestDetachNetwork_NotAttached(t *testing.T) {
	vm := managedVM("node-01") // no NICs
	client := &fakeARM{getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) {
		return vm, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.DetachNetwork(context.Background(), "node-01", "/nics/nic-x")
	if !errors.Is(err, compute.ErrNetworkDetachmentFailed) {
		t.Fatalf("err = %v, want ErrNetworkDetachmentFailed", err)
	}
}

func TestDetachNetwork_Happy(t *testing.T) {
	vm := managedVM("node-01")
	vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
		NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
			{ID: to.Ptr("/nics/nic-1")},
			{ID: to.Ptr("/nics/nic-2")},
		},
	}
	var detached bool
	client := &fakeARM{
		getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) { return vm, nil },
		updateVM: func(_ context.Context, _ string, up armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error) {
			nics := up.Properties.NetworkProfile.NetworkInterfaces
			if len(nics) != 1 || derefStr(nics[0].ID) != "/nics/nic-2" {
				t.Errorf("remaining nics = %+v", nics)
			}
			detached = true
			return vm, nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.DetachNetwork(context.Background(), "node-01", "/nics/nic-1"); err != nil || !detached {
		t.Fatalf("DetachNetwork: %v detached=%v", err, detached)
	}
}

func TestActivateInstance_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	err := o.ActivateInstance(context.Background(), "node-01", &policy.PortPolicy{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}

func TestClose(t *testing.T) {
	client := &fakeARM{}
	o := newTestOrchestrator(t, client)
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !client.closed {
		t.Error("expected underlying client to be closed")
	}
}

func TestNew_ConfigValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		cfg  *compute.OrchestratorConfig
	}{
		{"nil config", nil},
		{"nil azure block", &compute.OrchestratorConfig{Provider: compute.ProviderAzure}},
		{"missing subscription", &compute.OrchestratorConfig{Provider: compute.ProviderAzure, Azure: &compute.AzureProviderConfig{ResourceGroup: "rg", Location: "l", VMSize: "s", ImageReference: "i"}}},
		{"missing resource group", &compute.OrchestratorConfig{Provider: compute.ProviderAzure, Azure: &compute.AzureProviderConfig{SubscriptionID: "s", Location: "l", VMSize: "s", ImageReference: "i"}}},
		{"missing location", &compute.OrchestratorConfig{Provider: compute.ProviderAzure, Azure: &compute.AzureProviderConfig{SubscriptionID: "s", ResourceGroup: "rg", VMSize: "s", ImageReference: "i"}}},
		{"missing vm size", &compute.OrchestratorConfig{Provider: compute.ProviderAzure, Azure: &compute.AzureProviderConfig{SubscriptionID: "s", ResourceGroup: "rg", Location: "l", ImageReference: "i"}}},
		{"missing image", &compute.OrchestratorConfig{Provider: compute.ProviderAzure, Azure: &compute.AzureProviderConfig{SubscriptionID: "s", ResourceGroup: "rg", Location: "l", VMSize: "s"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(ctx, tc.cfg, nil)
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %v, want ConfigError", err)
			}
		})
	}
}

func TestImageReference_Marketplace(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	ref := o.imageReference()
	if ref.Publisher == nil || *ref.Publisher != "Canonical" {
		t.Errorf("publisher = %v", ref.Publisher)
	}
	if ref.Version == nil || *ref.Version != "latest" {
		t.Errorf("version = %v", ref.Version)
	}
}

func TestImageReference_ResourceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	o.azure.ImageReference = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/images/img"
	ref := o.imageReference()
	if ref.ID == nil || *ref.ID != o.azure.ImageReference {
		t.Errorf("id = %v", ref.ID)
	}
}

// derefBool safely dereferences a *bool for assertions.
func derefBool(b *bool) bool { return b != nil && *b }
