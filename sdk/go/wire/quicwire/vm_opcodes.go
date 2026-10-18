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

package quicwire

// VM operation codes, carried as sub-opcodes in payload[0] under
// OpVMExtendedCategory (0x69).
const (
	// OpVMCreate creates a VM
	OpVMCreate byte = 0x60

	// OpVMDelete deletes a VM
	OpVMDelete byte = 0x61

	// OpVMStart starts a VM
	OpVMStart byte = 0x62

	// OpVMStop stops a VM
	OpVMStop byte = 0x63

	// OpVMGet reads one VM
	OpVMGet byte = 0x64

	// OpVMList lists VMs
	OpVMList byte = 0x65

	// OpVMRestart restarts a VM
	OpVMRestart byte = 0xB6

	// OpVMSuspend suspends a running VM
	OpVMSuspend byte = 0xB7

	// OpVMResume resumes a suspended VM
	OpVMResume byte = 0xB8

	// OpVMAttest generates a vTPM quote for a running VM
	OpVMAttest byte = 0xB9
	// OpVMSnapshotCreate creates a snapshot of a VM
	OpVMSnapshotCreate byte = 0xBB

	// OpVMSnapshotRestore restores a VM from a snapshot
	OpVMSnapshotRestore byte = 0xBC

	// OpVMSnapshotDelete deletes a VM snapshot
	OpVMSnapshotDelete byte = 0xBD

	// OpVMSnapshotList lists a VM's snapshots
	OpVMSnapshotList byte = 0xBE
	// OpVMVerifyAttest verifies VM quote evidence against the VM's vTPM
	OpVMVerifyAttest byte = 0xBF
)
