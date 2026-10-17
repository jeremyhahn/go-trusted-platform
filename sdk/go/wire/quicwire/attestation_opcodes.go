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

// Attestation operation codes (using reserved space in 0x70-0x7F range)
const (
	// OpAttestGetManifest retrieves an attestation manifest
	OpAttestGetManifest byte = 0x76 // Reusing OpAttestGetReport for manifest get

	// OpAttestBuildManifest builds a new attestation manifest
	OpAttestBuildManifest byte = 0x7C

	// OpAttestVerifyManifest verifies an attestation manifest
	OpAttestVerifyManifest byte = 0x7D

	// OpAttestHost collects host attestation
	OpAttestHost byte = 0x7E

	// OpAttestVM performs VM attestation
	OpAttestVMWorkload byte = 0x7F

	// OpAttestContainerWorkload performs container attestation. It moved off
	// 0xED, which the daemon dispatches to PXE (OpPXEGetDevice), onto the
	// unassigned 0x6A (#949).
	OpAttestContainerWorkload byte = 0x6A

	// Using extended attestation codes (0xEE-0xEF)
	// OpAttestDeviceWorkload performs device attestation
	OpAttestDeviceWorkload byte = 0xEE

	// OpAttestListReports lists attestation reports
	OpAttestListReports byte = 0xEF

	// Using additional codes (0xEB-0xEC)
	// OpAttestGetReportByID retrieves an attestation report by ID
	OpAttestGetReportByID byte = 0x77

	// OpAttestCreatePolicy creates an attestation policy
	OpAttestCreatePolicy byte = 0xAA

	// OpAttestListPolicies lists attestation policies
	OpAttestListPolicies byte = 0xAB
)
