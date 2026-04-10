// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

// Package hpe is a placeholder for the HPE iLO5/iLO6 BMC attestation
// backend. The full implementation will use Redfish
// Oem.Hpe.SecurityService endpoints to retrieve Silicon Root of Trust
// evidence. This stub currently returns [attestation.ErrNotImplemented]
// for every method. See docs/architecture/bmc-attestation.md Phase 3.
package hpe
