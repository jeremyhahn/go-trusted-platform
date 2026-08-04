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

package gcp

import (
	"context"
	"errors"
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/googleapi"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

func TestGCPOrchestrator_ImplementsContracts(t *testing.T) {
	var _ compute.Orchestrator = (*GCPOrchestrator)(nil)
	var _ compute.VMSnapshotter = (*GCPOrchestrator)(nil)
	var _ compute.VMAttester = (*GCPOrchestrator)(nil)
}

func TestProviderRegistered_UnderTag(t *testing.T) {
	if !compute.IsProviderCompiled(compute.ProviderGCP) {
		t.Fatal("ProviderGCP must be registered when the gcpcompute tag is built")
	}
}

func TestCreate_HappyPath(t *testing.T) {
	client := &fakeGCE{
		insertInstance: func(_ context.Context, in *computepb.Instance) (*computepb.Instance, error) {
			if in.GetShieldedInstanceConfig() == nil || !in.GetShieldedInstanceConfig().GetEnableVtpm() {
				t.Error("expected ShieldedInstanceConfig with vTPM enabled")
			}
			if len(in.GetLabels()) == 0 {
				t.Error("expected labels on launch")
			}
			return runningInstance("node-01"), nil
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
	if inst.Metadata["provider"] != string(compute.ProviderGCP) {
		t.Errorf("provider metadata = %q", inst.Metadata["provider"])
	}
}

func TestCreate_NilProfile(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	_, err := o.Create(context.Background(), nil)
	if !errors.Is(err, compute.ErrInvalidProfile) {
		t.Fatalf("err = %v, want ErrInvalidProfile", err)
	}
}

func TestCreate_InsertError(t *testing.T) {
	client := &fakeGCE{
		insertInstance: func(context.Context, *computepb.Instance) (*computepb.Instance, error) {
			return nil, errors.New("quota exceeded")
		},
	}
	o := newTestOrchestrator(t, client)
	_, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "InsertInstance" {
		t.Fatalf("err = %v, want APIError{InsertInstance}", err)
	}
}

func TestStartStopDelete(t *testing.T) {
	var started, stopped, deleted bool
	client := &fakeGCE{
		startInstance:  func(context.Context, string) error { started = true; return nil },
		stopInstance:   func(context.Context, string) error { stopped = true; return nil },
		deleteInstance: func(context.Context, string) error { deleted = true; return nil },
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
	o := newTestOrchestrator(t, &fakeGCE{})
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
	client := &fakeGCE{startInstance: func(context.Context, string) error {
		return errors.New("boom")
	}}
	o := newTestOrchestrator(t, client)
	err := o.Start(context.Background(), "node-01")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "StartInstance" {
		t.Fatalf("err = %v, want APIError{StartInstance}", err)
	}
}

func TestGetState_Mapping(t *testing.T) {
	cases := []struct {
		gceStatus string
		want      compute.InstanceState
	}{
		{statusProvisioning, compute.StateCreating},
		{statusStaging, compute.StateCreating},
		{statusRunning, compute.StateRunning},
		{statusStopping, compute.StateStopping},
		{statusStopped, compute.StateStopped},
		{statusTerminated, compute.StateStopped},
		{statusRepairing, compute.StateError},
	}
	for _, tc := range cases {
		inst := runningInstance("node-01")
		inst.Status = ptr(tc.gceStatus)
		client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
			return inst, nil
		}}
		o := newTestOrchestrator(t, client)
		got, err := o.GetState(context.Background(), "node-01")
		if err != nil {
			t.Fatalf("GetState(%s): %v", tc.gceStatus, err)
		}
		if got != tc.want {
			t.Errorf("status %s -> %q, want %q", tc.gceStatus, got, tc.want)
		}
	}
}

func TestGet_NotFound(t *testing.T) {
	client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
		return nil, &googleapi.Error{Code: 404, Message: "notFound"}
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.Get(context.Background(), "missing")
	if !errors.Is(err, compute.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound", err)
	}
}

func TestList_FiltersByName(t *testing.T) {
	a := runningInstance("keep")
	b := runningInstance("drop")
	client := &fakeGCE{listInstances: func(context.Context, string) ([]*computepb.Instance, error) {
		return []*computepb.Instance{a, b}, nil
	}}
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
	client := &fakeGCE{listInstances: func(context.Context, string) ([]*computepb.Instance, error) {
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
	inst := runningInstance("node-01")
	inst.Status = ptr(statusTerminated)
	client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
		return inst, nil
	}}
	o := newTestOrchestrator(t, client)
	if err := o.Wait(context.Background(), "node-01"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestWait_ContextCancelled(t *testing.T) {
	inst := runningInstance("node-01") // never terminal
	client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
		return inst, nil
	}}
	o := newTestOrchestrator(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.Wait(ctx, "node-01"); err == nil {
		t.Fatal("Wait: expected error on cancelled context")
	}
}

func TestAttachNetwork_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	if err := o.AttachNetwork(context.Background(), "node-01", "nic-1"); !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("AttachNetwork err = %v, want ErrCapabilityNotSupported", err)
	}
	if err := o.DetachNetwork(context.Background(), "node-01", "nic-1"); !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("DetachNetwork err = %v, want ErrCapabilityNotSupported", err)
	}
}

func TestActivateInstance_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	err := o.ActivateInstance(context.Background(), "node-01", &policy.PortPolicy{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}

func TestClose(t *testing.T) {
	client := &fakeGCE{}
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
		{"nil gcp block", &compute.OrchestratorConfig{Provider: compute.ProviderGCP}},
		{"missing project", &compute.OrchestratorConfig{Provider: compute.ProviderGCP, GCP: &compute.GCPProviderConfig{Zone: "z", MachineType: "m", SourceImage: "i"}}},
		{"missing zone", &compute.OrchestratorConfig{Provider: compute.ProviderGCP, GCP: &compute.GCPProviderConfig{ProjectID: "p", MachineType: "m", SourceImage: "i"}}},
		{"missing machine type", &compute.OrchestratorConfig{Provider: compute.ProviderGCP, GCP: &compute.GCPProviderConfig{ProjectID: "p", Zone: "z", SourceImage: "i"}}},
		{"missing source image", &compute.OrchestratorConfig{Provider: compute.ProviderGCP, GCP: &compute.GCPProviderConfig{ProjectID: "p", Zone: "z", MachineType: "m"}}},
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

func TestSanitizeInstanceName(t *testing.T) {
	cases := map[string]string{
		"Node-01":     "node-01",
		"my_host.dev": "my-host-dev",
		"123abc":      "vm-123abc",
		"":            "vm-",
	}
	for in, want := range cases {
		if got := sanitizeInstanceName(in); got != want {
			t.Errorf("sanitizeInstanceName(%q) = %q, want %q", in, got, want)
		}
	}
}
