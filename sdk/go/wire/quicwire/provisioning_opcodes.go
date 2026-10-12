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

// Provisioning (config delivery) category opcode.
//
// The pre-enrollment config delivery service (nonce issuance, config
// fetch, remote Secure Boot DB digest signing, and provisioning session
// management) multiplexes its sub-operations under a single category
// opcode, following the same pattern as OpSwitchCategory (0xCC),
// OpKMSExtendedCategory (0xCD), and OpSecretsCategory (0xCE): the first
// byte of the request payload selects the sub-operation.
const (
	// OpProvisioningCategory multiplexes config delivery sub-operations
	// (get-nonce, fetch-config, sign-digest, poll/fulfill/list/get session).
	OpProvisioningCategory byte = 0xCF
)

// Provisioning sub-opcodes for the OpProvisioningCategory (0xCF) category
// opcode.
const (
	// ProvisioningSubGetNonce issues a single-use anti-replay nonce.
	ProvisioningSubGetNonce byte = 0x01
	// ProvisioningSubFetchConfig authenticates a device and resolves its
	// platform configuration (delivered config or pending session).
	ProvisioningSubFetchConfig byte = 0x02
	// ProvisioningSubSignDigest signs a UKI or kernel-module digest with
	// the control-plane Secure Boot DB key.
	ProvisioningSubSignDigest byte = 0x03
	// ProvisioningSubPollSession checks whether a pending provisioning
	// session has been fulfilled.
	ProvisioningSubPollSession byte = 0x04
	// ProvisioningSubFulfillSession links a device profile to a pending
	// provisioning session.
	ProvisioningSubFulfillSession byte = 0x05
	// ProvisioningSubListSessions lists all active provisioning sessions.
	ProvisioningSubListSessions byte = 0x06
	// ProvisioningSubGetSession retrieves a provisioning session by ID.
	ProvisioningSubGetSession byte = 0x07
)
