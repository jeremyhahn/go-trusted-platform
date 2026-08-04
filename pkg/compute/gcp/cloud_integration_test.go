//go:build cloud_integration && gcpcompute

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
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestGCPCompute_RealCloud exercises the full GCP orchestrator lifecycle
// against real Google Compute Engine. It is opt-in: build with `-tags
// 'cloud_integration gcpcompute'` and run explicitly (see
// `make test-cloud-compute-gcp`). It launches billable resources.
//
// Per the platform testing policy this test never calls t.Skip: when the build
// tag is present but the required configuration is absent, it fails with a
// clear, typed message so a misconfigured CI run is loud rather than silently
// green.
func TestGCPCompute_RealCloud(t *testing.T) {
	project := os.Getenv("COMPUTE_GCP_PROJECT")
	zone := os.Getenv("COMPUTE_GCP_ZONE")
	machineType := os.Getenv("COMPUTE_GCP_MACHINE_TYPE")
	image := os.Getenv("COMPUTE_GCP_IMAGE")
	if project == "" || zone == "" || machineType == "" || image == "" {
		t.Fatalf("cloud_integration requires COMPUTE_GCP_PROJECT, COMPUTE_GCP_ZONE, COMPUTE_GCP_MACHINE_TYPE, COMPUTE_GCP_IMAGE (got project=%q zone=%q type=%q image=%q)", project, zone, machineType, image)
	}

	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderGCP,
		WorkDir:      t.TempDir(),
		MaxInstances: 4,
		GCP: &compute.GCPProviderConfig{
			ProjectID:       project,
			Zone:            zone,
			MachineType:     machineType,
			SourceImage:     image,
			Network:         os.Getenv("COMPUTE_GCP_NETWORK"),
			Subnetwork:      os.Getenv("COMPUTE_GCP_SUBNETWORK"),
			CredentialsFile: os.Getenv("COMPUTE_GCP_CREDENTIALS"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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
	t.Logf("launched instance %s", inst.ID)

	// Wait for the instance to reach running before attesting.
	attester, ok := orch.(compute.VMAttester)
	if !ok {
		t.Fatal("GCP orchestrator must implement VMAttester")
	}
	deadline := time.NewTimer(10 * time.Minute)
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
			t.Fatalf("instance %s did not reach running", inst.ID)
		case <-tick.C:
		}
	}

	report, err := attester.AttestVM(ctx, inst.ID, nil, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if len(report.AKPublicKey) == 0 {
		t.Error("expected Shielded VM EK public key in attestation report")
	}

	snapshotter, ok := orch.(compute.VMSnapshotter)
	if !ok {
		t.Fatal("GCP orchestrator must implement VMSnapshotter")
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
