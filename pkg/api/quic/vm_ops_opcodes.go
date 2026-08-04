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

package quic

// Operational VM opcodes (Metrics, disk hotplug/unplug/resize, Migrate). Like
// the container operational opcodes these are carried ONLY as compute extended
// category (quic.OpVMExtendedCategory, 0x69) sub-opcodes in payload[0], never
// at the top level of the daemon dispatcher, so their byte values live in the
// 0x69 sub-opcode namespace and only need to be unique among the sub-opcodes
// routed under that category.
//
// They therefore reuse byte values (0xCC-0xD0) that are ALSO top-level category
// opcodes (OpSwitchCategory=0xCC, OpKMSExtendedCategory=0xCD,
// OpSecretsCategory=0xCE, OpProvisioningCategory=0xCF) — exactly the same
// overlap the container operational opcodes already rely on (OpContainerExec=
// 0xCA / OpContainerMetrics=0xCB reuse the top-level KMS range). Under 0x69
// they are unambiguous: the daemon dispatcher only ever inspects them after it
// has already matched OpVMExtendedCategory at the top level.
//
// All four disk/metrics operations are unary: they decode the platform.v1 pb
// request and delegate to the shared *ComputeGRPCService (see
// pkg/api/daemon/quic_vm_pb.go::handleVMPB), the same business path the gRPC
// transport uses. MigrateVM is likewise unary — its long-running work happens
// server-side against the QEMU migration manager and it returns a terminal
// status; interactive console and log-follow remain streaming-only and
// daemon-native.
//
// The extended VM lifecycle/snapshot/attestation sub-opcodes (0xB6-0xBF) are
// handled by the flat VMHandler (see vm_handlers.go::handleExtendedCategory);
// these operational sub-opcodes are intercepted ahead of that fallthrough by
// the daemon dispatcher's IsVMSubOpcode check.
const (
	// OpVMMetrics samples a running VM's resource-usage metrics.
	OpVMMetrics byte = 0xCC

	// OpVMAttachDisk hot-plugs a disk onto a running VM.
	OpVMAttachDisk byte = 0xCD

	// OpVMDetachDisk unplugs a disk from a running VM.
	OpVMDetachDisk byte = 0xCE

	// OpVMResizeDisk changes a VM disk's virtual size.
	OpVMResizeDisk byte = 0xCF

	// OpVMMigrate migrates a VM to another host (cold or live).
	OpVMMigrate byte = 0xD0
)

// vmSubOpcodes is the set of operational VM opcodes accepted as compute
// extended category (OpVMExtendedCategory, 0x69) sub-opcodes and routed to the
// shared *ComputeGRPCService by the daemon dispatcher. It is deliberately
// disjoint from containerSubOpcodes (checked first by handleVMServiceOperation)
// and from the extended VM lifecycle sub-opcode range 0xB6-0xBF (handled by the
// flat VMHandler).
var vmSubOpcodes = map[byte]bool{
	OpVMMetrics:    true,
	OpVMAttachDisk: true,
	OpVMDetachDisk: true,
	OpVMResizeDisk: true,
	OpVMMigrate:    true,
}

// IsVMSubOpcode reports whether op is an operational VM sub-opcode that must be
// routed to the converged pb handler under OpVMExtendedCategory rather than to
// the flat VMHandler.
func IsVMSubOpcode(op byte) bool {
	return vmSubOpcodes[op]
}
