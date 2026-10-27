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

// Container operation codes (0xFC-0xFF range)
const (
	// OpContainerCreate creates a new container
	OpContainerCreate byte = 0xFC

	// OpContainerStart starts a stopped container
	OpContainerStart byte = 0xFD

	// OpContainerStop stops a running container
	OpContainerStop byte = 0xFE

	// OpContainerRemove removes a container
	OpContainerRemove byte = 0xFF

	// Using previously unused codes from the reserved space
	// OpContainerGet retrieves a container by ID (reusing reserved 0x6F)
	OpContainerGet byte = 0x6F

	// OpContainerList lists containers
	OpContainerList byte = 0xAE

	// OpContainerAttest performs TPM attestation for a container
	OpContainerAttest byte = 0xEC
)

// NOTE: several container opcodes above collide with other opcode ranges at
// the top level of the daemon dispatcher (0xEC falls in the PXE range,
// 0xFC-0xFF in the PXE extended range), so remote transports reach them as
// sub-opcodes carried in payload[0] under the compute extended category
// opcode (OpVMExtendedCategory, 0x69) — the same category framing the
// extended VM operations use. The daemon ContainerHandler accepts both framings:
// direct opcodes (in-process callers, tests) and the category framing (wire
// traffic, unwrapped by the daemon dispatcher).
