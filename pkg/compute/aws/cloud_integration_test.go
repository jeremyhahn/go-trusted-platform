//go:build cloud_integration && awscompute

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

package aws

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestAWSCompute_RealCloud exercises the full AWS orchestrator lifecycle
// against real EC2. It is opt-in: build with `-tags 'cloud_integration
// awscompute'` and run explicitly (see `make test-cloud-compute-aws`). It
// launches billable resources.
//
// Per the platform testing policy this test never calls t.Skip: when the
// build tag is present but the required configuration is absent, it fails
// with a clear, typed message so a misconfigured CI run is loud rather than
// silently green.
func TestAWSCompute_RealCloud(t *testing.T) {
	region := os.Getenv("COMPUTE_AWS_REGION")
	ami := os.Getenv("COMPUTE_AWS_AMI")
	instanceType := os.Getenv("COMPUTE_AWS_INSTANCE_TYPE")
	if region == "" || ami == "" || instanceType == "" {
		t.Fatalf("cloud_integration requires COMPUTE_AWS_REGION, COMPUTE_AWS_AMI, COMPUTE_AWS_INSTANCE_TYPE (got region=%q ami=%q type=%q)", region, ami, instanceType)
	}

	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderAWS,
		WorkDir:      t.TempDir(),
		MaxInstances: 4,
		AWS: &compute.AWSProviderConfig{
			Region:       region,
			AMIID:        ami,
			InstanceType: instanceType,
			SubnetID:     os.Getenv("COMPUTE_AWS_SUBNET"),
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
		t.Fatal("AWS orchestrator must implement VMAttester")
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
		t.Error("expected NitroTPM EK public key in attestation report")
	}

	snapshotter, ok := orch.(compute.VMSnapshotter)
	if !ok {
		t.Fatal("AWS orchestrator must implement VMSnapshotter")
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
