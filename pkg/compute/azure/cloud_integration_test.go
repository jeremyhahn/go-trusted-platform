//go:build cloud_integration && azurecompute

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
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestAzureCompute_RealCloud exercises the full Azure orchestrator lifecycle
// against real Azure. It is opt-in: build with `-tags 'cloud_integration
// azurecompute'` and run explicitly (see `make test-cloud-compute-azure`). It
// launches billable resources.
//
// Per the platform testing policy this test never calls t.Skip: when the build
// tag is present but the required configuration is absent, it fails with a
// clear, typed message so a misconfigured CI run is loud rather than silently
// green.
func TestAzureCompute_RealCloud(t *testing.T) {
	sub := os.Getenv("COMPUTE_AZURE_SUBSCRIPTION")
	rg := os.Getenv("COMPUTE_AZURE_RESOURCE_GROUP")
	location := os.Getenv("COMPUTE_AZURE_LOCATION")
	vmSize := os.Getenv("COMPUTE_AZURE_VM_SIZE")
	image := os.Getenv("COMPUTE_AZURE_IMAGE")
	if sub == "" || rg == "" || location == "" || vmSize == "" || image == "" {
		t.Fatalf("cloud_integration requires COMPUTE_AZURE_SUBSCRIPTION, COMPUTE_AZURE_RESOURCE_GROUP, COMPUTE_AZURE_LOCATION, COMPUTE_AZURE_VM_SIZE, COMPUTE_AZURE_IMAGE (got sub=%q rg=%q location=%q size=%q image=%q)", sub, rg, location, vmSize, image)
	}

	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderAzure,
		WorkDir:      t.TempDir(),
		MaxInstances: 4,
		Azure: &compute.AzureProviderConfig{
			SubscriptionID: sub,
			ResourceGroup:  rg,
			Location:       location,
			VMSize:         vmSize,
			ImageReference: image,
			TenantID:       os.Getenv("COMPUTE_AZURE_TENANT"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)

	orch, err := New(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = orch.Close() })

	inst, err := orch.Create(ctx, &entities.DeviceProfile{Name: "gtp-cloud-it"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		if err := orch.Delete(context.Background(), inst.ID); err != nil {
			t.Errorf("cleanup Delete(%s): %v", inst.ID, err)
		}
	})
	t.Logf("launched VM %s", inst.ID)

	// Wait for the VM to reach running before snapshotting.
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		state, err := orch.GetState(ctx, inst.ID)
		if err != nil {
			t.Fatalf("GetState: %v", err)
		}
		if state == compute.StateRunning {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("VM %s did not reach running", inst.ID)
		case <-tick.C:
		}
	}

	// Azure control-plane attestation is honestly rejected: Trusted Launch
	// attestation is guest-driven via Microsoft Azure Attestation.
	attester, ok := orch.(compute.VMAttester)
	if !ok {
		t.Fatal("Azure orchestrator must implement VMAttester")
	}
	if _, err := attester.AttestVM(ctx, inst.ID, nil, nil); !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("AttestVM err = %v, want ErrCapabilityNotSupported (guest-driven attestation)", err)
	}

	snapshotter, ok := orch.(compute.VMSnapshotter)
	if !ok {
		t.Fatal("Azure orchestrator must implement VMSnapshotter")
	}
	snap, err := snapshotter.CreateSnapshot(ctx, inst.ID, "gtp-cloud-it-snap")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		if err := snapshotter.DeleteSnapshot(context.Background(), inst.ID, snap.Name); err != nil {
			t.Errorf("cleanup DeleteSnapshot: %v", err)
		}
	})
	if list, err := snapshotter.ListSnapshots(ctx, inst.ID); err != nil || len(list) == 0 {
		t.Fatalf("ListSnapshots: %v (n=%d)", err, len(list))
	}
}
