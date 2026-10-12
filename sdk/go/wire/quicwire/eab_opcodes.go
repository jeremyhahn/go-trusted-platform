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

// EAB (External Account Binding) sub-opcodes.
//
// The single-byte QUIC opcode space (0x00-0xFF) is fully allocated, so
// EAB credential management multiplexes under the existing provisioning
// category opcode OpProvisioningCategory (0xCF) — EAB credentials exist
// solely to authenticate the pre-enrollment provisioning flow, making
// 0xCF the semantically correct category. The first byte of the request
// payload selects the sub-operation, exactly like the config delivery
// sub-opcodes that share the category.
//
// Sub-opcode ranges under 0xCF:
//
//	0x01-0x07  config delivery (provisioning_opcodes.go)
//	0x08-0x0F  reserved for config delivery growth
//	0x10-0x1A  EAB credential management (this file)
//
// The daemon dispatcher (pkg/api/daemon/quic_eab.go) routes the EAB
// range before delegating the remainder to the config delivery handler,
// so the two sub-opcode families never collide.
const (
	// EABSubCreateCredential creates a new EAB credential.
	EABSubCreateCredential byte = 0x10
	// EABSubGetCredential retrieves a credential by ID.
	EABSubGetCredential byte = 0x11
	// EABSubGetCredentialByKeyID retrieves a credential by KeyID.
	EABSubGetCredentialByKeyID byte = 0x12
	// EABSubListCredentials lists credentials with optional filtering.
	EABSubListCredentials byte = 0x13
	// EABSubRevokeCredential marks a credential as revoked.
	EABSubRevokeCredential byte = 0x14
	// EABSubValidateCredential checks a (KeyID, HMAC key) pair.
	EABSubValidateCredential byte = 0x15
	// EABSubDeleteCredential permanently removes a credential.
	EABSubDeleteCredential byte = 0x16
	// EABSubGetCredentialQRCode renders a credential as a PNG QR code.
	EABSubGetCredentialQRCode byte = 0x17
	// EABSubGetEnrollmentURL renders an enrollment URL for a credential.
	EABSubGetEnrollmentURL byte = 0x18
	// EABSubMarkCredentialUsed marks a credential as used post-enrollment.
	EABSubMarkCredentialUsed byte = 0x19
	// EABSubCleanupExpiredCredentials removes expired credentials.
	EABSubCleanupExpiredCredentials byte = 0x1A
)
