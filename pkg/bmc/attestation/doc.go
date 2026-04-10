// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed under AGPL-3.0 or a commercial
// license. See the LICENSE file at the repository root for details.

// Package attestation provides a vendor-neutral API for BMC remote
// attestation across Supermicro, Dell iDRAC, and HPE iLO.
//
// Higher-level services obtain an [AttestationProvider] via [NewProvider],
// which inspects a [bmc.Client] to detect the vendor and returns the
// appropriate concrete backend. Evidence produced by the provider is
// opaque to callers; parsing and verification are performed through
// [AttestationProvider.GetInfo] and a [Verifier].
//
// See docs/architecture/bmc-attestation.md for the full design.
package attestation
