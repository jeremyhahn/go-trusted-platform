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

// Package manifest provides Host Manifest capabilities for aggregating
// attestations from physical hosts, VMs, and containers into a single
// signed document with Merkle tree integrity verification.
//
// The manifest package enables comprehensive attestation of a host and all
// its workloads. It supports:
//   - Aggregating physical TPM quotes from the host
//   - Collecting vTPM quotes from VMs
//   - Gathering container attestations from PCR 14 chain
//   - Building Merkle trees for integrity verification
//   - AK (Attestation Key) based signing and verification
//   - Nonce-based freshness verification
//
// Key components:
//   - ManifestBuilder: Collects and builds host manifests
//   - ManifestSigner: Signs manifests with TPM AK
//   - ManifestVerifier: Verifies manifest signatures and integrity
//
// Host Manifest Structure:
//
// A HostManifest contains:
//   - Host attestation from the physical TPM
//   - VM attestations from vTPMs
//   - Container attestations from workload chain
//   - Merkle root for data integrity
//   - AK signature for authenticity
//
// Manifest Generation Process:
//  1. Enumerate all workloads (VMs and containers)
//  2. Collect attestations from each workload
//  3. Build Merkle tree from all attestation data
//  4. Generate manifest with fresh nonce
//  5. Sign manifest with host's AK
//
// Manifest Verification Process:
//  1. Verify AK signature on manifest
//  2. Validate Merkle root against contents
//  3. Check individual VM and container attestations
//  4. Verify nonce matches expected value
//  5. Ensure manifest has not expired
package manifest
