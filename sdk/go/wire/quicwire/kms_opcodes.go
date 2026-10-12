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

// KMS extended and Secrets category opcodes.
//
// The single-byte opcode space in the 0xC0-0xCF KMS range is exhausted
// (0xCC is OpSwitchCategory), so the key-lifecycle verbs added for REST
// parity (revoke, metadata, policy, algorithms) and the secrets surface
// multiplex sub-operations under category opcodes, following the same
// pattern as the Phase 3.5 ceremony/piv/luks/fido2 categories: the first
// byte of the request payload selects the sub-operation.
const (
	// OpKMSExtendedCategory multiplexes KMS key-lifecycle sub-operations
	// (revoke, metadata get/update, policy get/set, supported algorithms).
	OpKMSExtendedCategory byte = 0xCD
	// OpSecretsCategory multiplexes secrets sub-operations
	// (store, get, list, delete, rotation-policy get/set).
	OpSecretsCategory byte = 0xCE
)

// KMS extended sub-opcodes.
const (
	// KMSSubRevokeKey revokes a key, marking it unusable.
	KMSSubRevokeKey byte = 0x01
	// KMSSubGetKeyMetadata retrieves key metadata without key material.
	KMSSubGetKeyMetadata byte = 0x02
	// KMSSubUpdateKeyMetadata updates mutable key metadata fields.
	KMSSubUpdateKeyMetadata byte = 0x03
	// KMSSubSetKeyPolicy sets the access control policy for a key.
	KMSSubSetKeyPolicy byte = 0x04
	// KMSSubGetKeyPolicy retrieves the access control policy for a key.
	KMSSubGetKeyPolicy byte = 0x05
	// KMSSubGetSupportedAlgorithms lists algorithms supported by the backend.
	KMSSubGetSupportedAlgorithms byte = 0x06
	// KMSSubSignCSR has the CA certify a KMS key for code signing, from a
	// CSR the key signed (CAHandler.SignCSR). It needs CASignCSRPermission,
	// not a kms permission. It lives here because the single-byte CA range
	// is full and the operation certifies a KMS key.
	KMSSubSignCSR byte = 0x07
)

// Secrets sub-opcodes.
const (
	// SecretsSubStore stores a secret.
	SecretsSubStore byte = 0x01
	// SecretsSubGet retrieves a secret.
	SecretsSubGet byte = 0x02
	// SecretsSubList lists secrets.
	SecretsSubList byte = 0x03
	// SecretsSubDelete deletes a secret.
	SecretsSubDelete byte = 0x04
	// SecretsSubSetRotationPolicy sets the automatic rotation policy.
	SecretsSubSetRotationPolicy byte = 0x05
	// SecretsSubGetRotationPolicy retrieves the automatic rotation policy.
	SecretsSubGetRotationPolicy byte = 0x06
)
