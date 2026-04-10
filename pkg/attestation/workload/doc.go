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

// Package workload provides workload PCR extension capabilities for tracking
// container and VM lifecycle events in the TPM measurement chain.
//
// The workload package implements a chain manager that extends TPM PCRs with
// workload measurements, creating an auditable chain of workload startups.
// This enables attestation of which workloads have run on a system.
//
// Key components:
//   - ChainManager: Manages PCR extensions and maintains measurement history
//   - LifecycleManager: Hooks into container/VM lifecycle events
//
// Extension Formula:
//
//	digest = SHA256(workload_type || "|" || workload_id || "|" || image_digest)
//	new_pcr = SHA256(current_pcr || digest)
//
// Supported workload types:
//   - Container: Docker, containerd, etc.
//   - VM: Virtual machines managed by libvirt, QEMU, etc.
package workload
