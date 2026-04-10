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

// Package vm provides VM attestation capabilities using vTPM (virtual Trusted
// Platform Module) for quote generation and verification.
//
// The vm package enables attestation of virtual machines running on trusted
// hosts. It supports:
//   - vTPM-based AIK/AK quote generation
//   - Quote signature verification
//   - EK certificate chain validation (signed by Platform CA)
//   - VM-to-host binding verification via EK certificate subject
//   - PCR value matching against expected state
//
// Key components:
//   - VMAttestor: Generates TPM quotes from a VM's vTPM
//   - VMVerifier: Verifies quotes and validates attestation claims
//
// VM Identity Format:
//
// The vTPM EK certificate subject CN contains the VM-to-host binding:
//
//	CN = "vm:<vmID>@host:<hostID>"
//
// This enables verification that a quote came from a specific VM running on
// a specific trusted host.
//
// Quote Generation Process:
//  1. Load AIK/AK from vTPM
//  2. Read specified PCR values
//  3. Generate TPM quote signed by AIK/AK
//  4. Include nonce for freshness
//  5. Return signed quote with PCR values
//
// Quote Verification Process:
//  1. Verify AIK/AK signature on quote
//  2. Validate EK certificate chain (must chain to Platform CA)
//  3. Parse VM identity from EK certificate subject
//  4. Compare PCR values against expected state
//  5. Verify nonce matches expected value
package vm
