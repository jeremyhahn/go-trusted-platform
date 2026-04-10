// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

// Package dell is a placeholder for the Dell iDRAC9 BMC attestation
// backend. The full implementation will use the documented Redfish
// Oem.Dell.Attestation endpoints and TCG DICE chain retrieval on
// iDRAC9 firmware 4.40.40.00 or newer. This stub currently returns
// [attestation.ErrNotImplemented] for every method and exists only so
// the dispatcher can route Dell hardware to a backend of the correct
// type. See docs/architecture/bmc-attestation.md Phase 2.
package dell
