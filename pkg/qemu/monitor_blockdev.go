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

package qemu

import (
	"context"
	"encoding/json"

	"github.com/digitalocean/go-qemu/qmp"
)

// BlockStat carries the cumulative I/O counters for a single QEMU block
// device as reported by the QMP query-blockstats command.
type BlockStat struct {
	// Device is the legacy block backend name (empty for blockdev nodes).
	Device string `json:"device"`

	// NodeName is the block node name (blockdev-add nodes).
	NodeName string `json:"node-name"`

	// Stats holds the cumulative byte and operation counters.
	Stats BlockStatCounters `json:"stats"`
}

// BlockStatCounters holds the cumulative I/O counters for a block device.
type BlockStatCounters struct {
	// RdBytes is the total number of bytes read since VM start.
	RdBytes int64 `json:"rd_bytes"`

	// WrBytes is the total number of bytes written since VM start.
	WrBytes int64 `json:"wr_bytes"`

	// RdOperations is the total number of read operations.
	RdOperations int64 `json:"rd_operations"`

	// WrOperations is the total number of write operations.
	WrOperations int64 `json:"wr_operations"`

	// FlushOperations is the total number of flush operations.
	FlushOperations int64 `json:"flush_operations"`
}

// BlockStats returns the cumulative I/O counters for every block device
// attached to the VM via the QMP query-blockstats command. It mirrors
// BlockDevices, returning one entry per backend.
func (m *Monitor) BlockStats(ctx context.Context) ([]BlockStat, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	rawResp, err := m.runCommand(qmp.Command{Execute: "query-blockstats"})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Return []BlockStat `json:"return"`
	}
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-blockstats", Cause: err}
	}

	return resp.Return, nil
}

// BlockdevAddQcow2 registers a qcow2-backed block node with the running VM via
// the QMP blockdev-add command. The node can subsequently be surfaced to the
// guest by attaching a virtio-blk device (AddVirtioBlkDevice) that references
// the node by name. This is the first half of an online disk hotplug.
func (m *Monitor) BlockdevAddQcow2(ctx context.Context, nodeName, filename string) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}
	if nodeName == "" || filename == "" {
		return ErrMonitorCommandFailed{Command: "blockdev-add", Cause: &MessageError{Msg: "node name and filename are required"}}
	}

	args := map[string]interface{}{
		"driver":    "qcow2",
		"node-name": nodeName,
		"file": map[string]interface{}{
			"driver":   "file",
			"filename": filename,
		},
	}
	_, err := m.runCommand(qmp.Command{Execute: "blockdev-add", Args: args})
	return err
}

// BlockdevDel removes a block node previously added with BlockdevAddQcow2 via
// the QMP blockdev-del command. The node must not be in use by any device
// (call DeviceDel first). This is the second half of an online disk unplug.
func (m *Monitor) BlockdevDel(ctx context.Context, nodeName string) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}
	if nodeName == "" {
		return ErrMonitorCommandFailed{Command: "blockdev-del", Cause: &MessageError{Msg: "node name is required"}}
	}

	args := map[string]interface{}{"node-name": nodeName}
	_, err := m.runCommand(qmp.Command{Execute: "blockdev-del", Args: args})
	return err
}

// AddVirtioBlkDevice attaches a virtio-blk-pci device to the guest, backed by
// a block node previously registered with BlockdevAddQcow2, via the QMP
// device_add command. The guest sees a hot-plugged virtio disk. This is the
// second half of an online disk hotplug.
func (m *Monitor) AddVirtioBlkDevice(ctx context.Context, deviceID, nodeName string) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}
	if deviceID == "" || nodeName == "" {
		return ErrMonitorCommandFailed{Command: "device_add", Cause: &MessageError{Msg: "device id and node name are required"}}
	}

	args := map[string]interface{}{
		"driver": "virtio-blk-pci",
		"drive":  nodeName,
		"id":     deviceID,
	}
	_, err := m.runCommand(qmp.Command{Execute: "device_add", Args: args})
	return err
}

// DeviceDel removes a hot-plugged guest device via the QMP device_del command.
// QEMU processes the request asynchronously — the guest must cooperate to
// release the device — but the command returns once the request is accepted.
// This is the first half of an online disk unplug.
func (m *Monitor) DeviceDel(ctx context.Context, deviceID string) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}
	if deviceID == "" {
		return ErrMonitorCommandFailed{Command: "device_del", Cause: &MessageError{Msg: "device id is required"}}
	}

	args := map[string]interface{}{"id": deviceID}
	_, err := m.runCommand(qmp.Command{Execute: "device_del", Args: args})
	return err
}

// BlockResize grows (or shrinks) a block device online via the QMP
// block_resize command. The target is addressed by node name when nodeName is
// non-empty, otherwise by the legacy device name. sizeBytes is the new virtual
// size in bytes. The guest observes the new capacity after a device rescan.
func (m *Monitor) BlockResize(ctx context.Context, nodeName, device string, sizeBytes int64) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}
	if sizeBytes <= 0 {
		return ErrMonitorCommandFailed{Command: "block_resize", Cause: &MessageError{Msg: "size must be greater than zero"}}
	}
	if nodeName == "" && device == "" {
		return ErrMonitorCommandFailed{Command: "block_resize", Cause: &MessageError{Msg: "node name or device is required"}}
	}

	args := map[string]interface{}{"size": sizeBytes}
	if nodeName != "" {
		args["node-name"] = nodeName
	} else {
		args["device"] = device
	}
	_, err := m.runCommand(qmp.Command{Execute: "block_resize", Args: args})
	return err
}
