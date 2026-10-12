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

// VM operation codes use the existing opcodes from protocol.go (0x60-0x6A range)
// Additional VM-specific operations
const (
	// OpVMRestart restarts a VM
	OpVMRestart byte = 0xB6

	// OpVMSuspend suspends a running VM
	OpVMSuspend byte = 0xB7

	// OpVMResume resumes a suspended VM
	OpVMResume byte = 0xB8

	// OpVMAttest performs TPM attestation for a VM
	OpVMAttest byte = 0xB9

	// OpVMConsole retrieves console information for a VM
	OpVMConsole byte = 0xBA

	// OpVMSnapshot creates a snapshot of a VM
	OpVMSnapshot byte = 0xBB

	// OpVMSnapshotRestore restores a VM from a snapshot
	OpVMSnapshotRestore byte = 0xBC

	// OpVMSnapshotDelete deletes a snapshot
	OpVMSnapshotDelete byte = 0xBD

	// OpVMSnapshotList lists snapshots for a VM
	OpVMSnapshotList byte = 0xBE

	// OpVMVerifyAttest verifies VM attestation evidence
	OpVMVerifyAttest byte = 0xBF
)

// NOTE: the extended VM opcodes above (0xB6-0xBF) collide with the IAM
// role/group opcode ranges at the top level of the daemon dispatcher, so
// remote transports reach them as sub-opcodes carried in payload[0] under
// OpVMExtendedCategory (0x69, inside the VM opcode range). The daemon
// VMHandler accepts both framings: direct opcodes (in-process callers, tests)
// and the category framing (wire traffic).
