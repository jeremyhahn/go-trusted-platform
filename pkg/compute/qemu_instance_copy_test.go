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

package compute

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertCopyTestVM inserts a stopped VM with one tracked disk and one
// metadata key, the fields a shallow copy would share with the live record.
func insertCopyTestVM(t *testing.T, orch *QEMUOrchestrator, running bool) *qemuInstance {
	t.Helper()
	qi := insertVMInstance(t, orch, "vm1", running, &InstanceConfig{WorkDir: t.TempDir(), DiskPath: "/boot.qcow2", DiskSize: "10G"})
	qi.instance.Disks = []DiskInfo{{ID: "d1", SizeGB: 5}}
	qi.instance.Metadata = map[string]string{"k": "v"}
	return qi
}

func mutateInstanceCopy(inst *Instance) {
	inst.Disks[0].SizeGB = 99
	inst.Config.DiskSize = "99G"
	inst.Metadata["k"] = "changed"
}

func assertRecordUnchanged(t *testing.T, inst *Instance) {
	t.Helper()
	require.Len(t, inst.Disks, 1)
	assert.Equal(t, uint64(5), inst.Disks[0].SizeGB, "a caller's copy must not reach the record's disks")
	require.NotNil(t, inst.Config)
	assert.Equal(t, "10G", inst.Config.DiskSize, "a caller's copy must not reach the record's config")
	assert.Equal(t, "v", inst.Metadata["k"], "a caller's copy must not reach the record's metadata")
}

func TestQEMUOrchestrator_GetReturnsADeepCopy(t *testing.T) {
	orch := newOpsOrchestrator(t)
	insertCopyTestVM(t, orch, false)

	got, err := orch.Get(context.Background(), "vm1")
	require.NoError(t, err)
	mutateInstanceCopy(got)

	again, err := orch.Get(context.Background(), "vm1")
	require.NoError(t, err)
	assertRecordUnchanged(t, again)
}

func TestQEMUOrchestrator_ListReturnsDeepCopies(t *testing.T) {
	orch := newOpsOrchestrator(t)
	insertCopyTestVM(t, orch, false)

	list, err := orch.List(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	mutateInstanceCopy(list[0])

	again, err := orch.List(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, again, 1)
	assertRecordUnchanged(t, again[0])
}

// TestQEMUOrchestrator_ReadsRaceWithDiskChanges reads the copies Get and
// List return while ResizeDisk changes the record; under -race a shared
// Disks slice or Config pointer is reported.
func TestQEMUOrchestrator_ReadsRaceWithDiskChanges(t *testing.T) {
	orch := newOpsOrchestrator(t)
	insertCopyTestVM(t, orch, true)
	installDiskSeams(t, &fakeDiskMon{}, nil)

	const rounds = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = orch.ResizeDisk(context.Background(), "vm1", "d1", uint64(6+i))
			_ = orch.ResizeDisk(context.Background(), "vm1", "hd0", uint64(11+i))
		}
	}()
	go func() {
		defer wg.Done()
		var sink uint64
		var size string
		for i := 0; i < rounds; i++ {
			if inst, err := orch.Get(context.Background(), "vm1"); err == nil {
				for _, d := range inst.Disks {
					sink += d.SizeGB
				}
				if inst.Config != nil {
					size = inst.Config.DiskSize
				}
			}
			if list, err := orch.List(context.Background(), nil); err == nil {
				for _, inst := range list {
					for _, d := range inst.Disks {
						sink += d.SizeGB
					}
					if inst.Config != nil {
						size = inst.Config.DiskSize
					}
				}
			}
		}
		_, _ = sink, size
	}()
	wg.Wait()
}
