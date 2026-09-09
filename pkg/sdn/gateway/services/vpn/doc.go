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

// Package vpn is the gateway's attested remote-access service: one admission
// control plane in front of pluggable data planes (docs/vpn/).
//
// An admission is five steps, every one of which fails closed: device
// identity (the mTLS peer against the caller-admission policy), a TPM
// attestation verdict, a posture report evaluated by the platform OPA
// engine, a person factor bound to the session nonce, and an address lease
// from the platform IPAM. What an admitted client holds is a lease with an
// expiry, not a standing entitlement: the peer is installed for the lease's
// lifetime and removed when the lease expires, is revoked, or fails to renew.
//
// Every dependency is an interface in Deps so the pipeline is tested with
// fakes and composed by the daemon with the real seams: the caller-admission
// policy, the attestation service, the OPA engine, the SDK's FIDO2/PIV
// factors, the IPAM allocator and the datapath process that programs peers.
package vpn
