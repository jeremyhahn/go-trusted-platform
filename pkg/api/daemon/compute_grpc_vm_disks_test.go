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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInstanceToVMProto_Disks checks that the VM projection returns the boot
// disk and every attached disk in config.disks, so the VM detail page's disk
// controls list real disks against the real server.
func TestInstanceToVMProto_Disks(t *testing.T) {
	svc := createTestComputeService(t)

	t.Run("boot disk from config", func(t *testing.T) {
		result := svc.instanceToVMProto(&compute.Instance{
			ID:   "vm-1",
			Name: "vm-1",
			Config: &compute.InstanceConfig{
				DiskPath: "/var/lib/vms/vm-1.qcow2",
				DiskSize: "20G",
			},
		})
		require.NotNil(t, result)
		require.NotNil(t, result.Config)
		require.Len(t, result.Config.Disks, 1)
		d := result.Config.Disks[0]
		assert.Equal(t, "hd0", d.Id)
		assert.Equal(t, "/var/lib/vms/vm-1.qcow2", d.Path)
		assert.Equal(t, uint64(20), d.SizeGb)
		assert.True(t, d.Bootable)
		assert.False(t, d.Readonly)
	})

	t.Run("attached disks keep their ids", func(t *testing.T) {
		result := svc.instanceToVMProto(&compute.Instance{
			ID:   "vm-1",
			Name: "vm-1",
			Config: &compute.InstanceConfig{
				DiskPath: "/var/lib/vms/vm-1.qcow2",
				DiskSize: "20G",
			},
			Disks: []compute.DiskInfo{
				{ID: "d-a", Path: "/var/lib/vms/a.qcow2", Bus: "virtio", SizeGB: 5, Readonly: true},
				{ID: "d-b", Path: "/var/lib/vms/b.raw", Bus: "sata", SizeGB: 7},
			},
		})
		require.NotNil(t, result)
		require.NotNil(t, result.Config)
		require.Len(t, result.Config.Disks, 3)
		assert.Equal(t, "hd0", result.Config.Disks[0].Id)
		a := result.Config.Disks[1]
		assert.Equal(t, "d-a", a.Id)
		assert.Equal(t, "/var/lib/vms/a.qcow2", a.Path)
		assert.Equal(t, uint64(5), a.SizeGb)
		assert.True(t, a.Readonly)
		assert.Equal(t, platformv1.DiskBus_DISK_BUS_VIRTIO, a.Bus)
		assert.False(t, a.Bootable)
		b := result.Config.Disks[2]
		assert.Equal(t, "d-b", b.Id)
		assert.Equal(t, uint64(7), b.SizeGb)
		assert.Equal(t, platformv1.DiskBus_DISK_BUS_SATA, b.Bus)
	})

	t.Run("disk size units", func(t *testing.T) {
		cases := []struct {
			size string
			want uint64
		}{
			{"1T", 1024},
			{"20g", 20},
			{"512M", 1},
			{"20GiB", 20},
			{"", 0},
			{"junk", 0},
		}
		for _, tc := range cases {
			result := svc.instanceToVMProto(&compute.Instance{
				ID:   "vm-1",
				Name: "vm-1",
				Config: &compute.InstanceConfig{
					DiskPath: "/var/lib/vms/vm-1.qcow2",
					DiskSize: tc.size,
				},
			})
			require.NotNil(t, result)
			require.NotNil(t, result.Config)
			require.Len(t, result.Config.Disks, 1, "size %q", tc.size)
			assert.Equal(t, "/var/lib/vms/vm-1.qcow2", result.Config.Disks[0].Path, "size %q", tc.size)
			assert.Equal(t, tc.want, result.Config.Disks[0].SizeGb, "size %q", tc.size)
		}
	})

	t.Run("no disk path and no disks gives no disks", func(t *testing.T) {
		result := svc.instanceToVMProto(&compute.Instance{
			ID:     "vm-1",
			Name:   "vm-1",
			Config: &compute.InstanceConfig{Memory: 2048},
		})
		require.NotNil(t, result)
		require.NotNil(t, result.Config)
		assert.Empty(t, result.Config.Disks)
	})

	t.Run("disks without config", func(t *testing.T) {
		result := svc.instanceToVMProto(&compute.Instance{
			ID:   "vm-2",
			Name: "vm-2",
			Disks: []compute.DiskInfo{
				{ID: "d-c", Path: "/var/lib/vms/c.qcow2", SizeGB: 3},
			},
		})
		require.NotNil(t, result)
		require.NotNil(t, result.Config)
		assert.Equal(t, "vm-2", result.Config.Name)
		require.Len(t, result.Config.Disks, 1)
		assert.Equal(t, "d-c", result.Config.Disks[0].Id)
	})
}

// TestComputeGRPCService_GetVM_ReturnsDisks checks that GetVM carries the
// boot disk and the attached disks through to the response.
func TestComputeGRPCService_GetVM_ReturnsDisks(t *testing.T) {
	orch := newGRPCMockOrchestrator()
	orch.instances["vm-3"] = &compute.Instance{
		ID:    "vm-3",
		Name:  "vm-3",
		Type:  compute.ComputeTypeVM,
		State: compute.StateStopped,
		Config: &compute.InstanceConfig{
			DiskPath: "/var/lib/vms/vm-3.qcow2",
			DiskSize: "10G",
		},
		Disks: []compute.DiskInfo{
			{ID: "d-x", Path: "/var/lib/vms/x.qcow2", Bus: "virtio", SizeGB: 4},
		},
	}
	svc := NewComputeGRPCService(logging.DefaultLogger(), orch)

	resp, err := svc.GetVM(context.Background(), &platformv1.GetVMRequest{Id: "vm-3"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Vm)
	require.NotNil(t, resp.Vm.Config)

	ids := make([]string, 0, len(resp.Vm.Config.Disks))
	sizes := make([]uint64, 0, len(resp.Vm.Config.Disks))
	for _, d := range resp.Vm.Config.Disks {
		ids = append(ids, d.Id)
		sizes = append(sizes, d.SizeGb)
	}
	assert.Equal(t, []string{"hd0", "d-x"}, ids)
	assert.Equal(t, []uint64{10, 4}, sizes)
}
