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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeGCE implements gceAPI with per-method function seams. A nil seam returns
// a benign empty output so tests set only the calls they exercise.
type fakeGCE struct {
	insertInstance     func(context.Context, *computepb.Instance) (*computepb.Instance, error)
	startInstance      func(context.Context, string) error
	stopInstance       func(context.Context, string) error
	deleteInstance     func(context.Context, string) error
	getInstance        func(context.Context, string) (*computepb.Instance, error)
	listInstances      func(context.Context, string) ([]*computepb.Instance, error)
	shieldedIdentity   func(context.Context, string) (*computepb.ShieldedInstanceIdentity, error)
	createDiskSnapshot func(context.Context, string, *computepb.Snapshot) (*computepb.Snapshot, error)
	deleteSnapshot     func(context.Context, string) error
	listSnapshots      func(context.Context, string) ([]*computepb.Snapshot, error)
	insertDisk         func(context.Context, *computepb.Disk) error
	attachDisk         func(context.Context, string, *computepb.AttachedDisk) error
	detachDisk         func(context.Context, string, string) error
	closed             bool
}

func (f *fakeGCE) InsertInstance(ctx context.Context, inst *computepb.Instance) (*computepb.Instance, error) {
	if f.insertInstance != nil {
		return f.insertInstance(ctx, inst)
	}
	return &computepb.Instance{}, nil
}

func (f *fakeGCE) StartInstance(ctx context.Context, name string) error {
	if f.startInstance != nil {
		return f.startInstance(ctx, name)
	}
	return nil
}

func (f *fakeGCE) StopInstance(ctx context.Context, name string) error {
	if f.stopInstance != nil {
		return f.stopInstance(ctx, name)
	}
	return nil
}

func (f *fakeGCE) DeleteInstance(ctx context.Context, name string) error {
	if f.deleteInstance != nil {
		return f.deleteInstance(ctx, name)
	}
	return nil
}

func (f *fakeGCE) GetInstance(ctx context.Context, name string) (*computepb.Instance, error) {
	if f.getInstance != nil {
		return f.getInstance(ctx, name)
	}
	return &computepb.Instance{}, nil
}

func (f *fakeGCE) ListInstances(ctx context.Context, filter string) ([]*computepb.Instance, error) {
	if f.listInstances != nil {
		return f.listInstances(ctx, filter)
	}
	return nil, nil
}

func (f *fakeGCE) ShieldedIdentity(ctx context.Context, name string) (*computepb.ShieldedInstanceIdentity, error) {
	if f.shieldedIdentity != nil {
		return f.shieldedIdentity(ctx, name)
	}
	return &computepb.ShieldedInstanceIdentity{}, nil
}

func (f *fakeGCE) CreateDiskSnapshot(ctx context.Context, diskName string, snap *computepb.Snapshot) (*computepb.Snapshot, error) {
	if f.createDiskSnapshot != nil {
		return f.createDiskSnapshot(ctx, diskName, snap)
	}
	return &computepb.Snapshot{}, nil
}

func (f *fakeGCE) DeleteSnapshot(ctx context.Context, snapshotName string) error {
	if f.deleteSnapshot != nil {
		return f.deleteSnapshot(ctx, snapshotName)
	}
	return nil
}

func (f *fakeGCE) ListSnapshots(ctx context.Context, filter string) ([]*computepb.Snapshot, error) {
	if f.listSnapshots != nil {
		return f.listSnapshots(ctx, filter)
	}
	return nil, nil
}

func (f *fakeGCE) InsertDisk(ctx context.Context, disk *computepb.Disk) error {
	if f.insertDisk != nil {
		return f.insertDisk(ctx, disk)
	}
	return nil
}

func (f *fakeGCE) AttachDisk(ctx context.Context, instanceName string, disk *computepb.AttachedDisk) error {
	if f.attachDisk != nil {
		return f.attachDisk(ctx, instanceName, disk)
	}
	return nil
}

func (f *fakeGCE) DetachDisk(ctx context.Context, instanceName, deviceName string) error {
	if f.detachDisk != nil {
		return f.detachDisk(ctx, instanceName, deviceName)
	}
	return nil
}

func (f *fakeGCE) Close() error {
	f.closed = true
	return nil
}

// newTestOrchestrator builds an orchestrator over a fake client with tiny poll
// intervals so waits complete instantly and never touch the network.
func newTestOrchestrator(t *testing.T, client gceAPI) *GCPOrchestrator {
	t.Helper()
	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderGCP,
		WorkDir:      t.TempDir(),
		MaxInstances: 10,
		GCP: &compute.GCPProviderConfig{
			ProjectID:   "proj-1",
			Zone:        "us-central1-a",
			MachineType: "n2-standard-2",
			SourceImage: "projects/debian-cloud/global/images/family/debian-12",
		},
	}
	o := newOrchestrator(cfg, logging.DefaultLogger(), client)
	o.pollInterval = time.Millisecond
	o.pollTimeout = 2 * time.Second
	return o
}

// runningInstance returns a fake GCE instance in the RUNNING state with a
// labeled name and a boot disk.
func runningInstance(name string) *computepb.Instance {
	boot := true
	return &computepb.Instance{
		Name:        ptr(name),
		Status:      ptr(statusRunning),
		Zone:        ptr("projects/proj-1/zones/us-central1-a"),
		MachineType: ptr("projects/proj-1/zones/us-central1-a/machineTypes/n2-standard-2"),
		Labels:      map[string]string{managedLabelKey: managedLabelValue, nameLabelKey: name},
		Disks: []*computepb.AttachedDisk{{
			Boot:       &boot,
			DeviceName: ptr("persistent-disk-0"),
			Source:     ptr("projects/proj-1/zones/us-central1-a/disks/" + name),
		}},
		NetworkInterfaces: []*computepb.NetworkInterface{{
			NetworkIP: ptr("10.0.0.5"),
		}},
	}
}

// ekIdentity returns a Shielded VM identity carrying a PEM-encoded RSA EK
// suitable for a fake GetShieldedInstanceIdentity response.
func ekIdentity(t *testing.T) *computepb.ShieldedInstanceIdentity {
	t.Helper()
	return &computepb.ShieldedInstanceIdentity{
		EncryptionKey: &computepb.ShieldedInstanceIdentityEntry{
			EkPub: ptr(rsaEKPEM(t)),
		},
	}
}

// rsaEKPEM returns a PEM-encoded DER PKIX RSA public key.
func rsaEKPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
