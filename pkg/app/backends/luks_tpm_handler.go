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

package backends

import (
	luks "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/luks"
)

// The TPM LUKS passphrase sealer is owned by go-xkms (the stack's canonical
// home for all TPM 2.0 operations) and reached through the QuicBaaS SDK.
// This file is the thin platform wiring: alias the SDK surface under the
// names the LUKS backend and its callers already use.

// LUKS TPM handler errors, aliased from the canonical go-xkms surface so
// errors.Is works across the SDK boundary.
var (
	// ErrLUKSTPMNoTransport indicates the sealer was given no TPM — the
	// platform TPM is not open.
	ErrLUKSTPMNoTransport = luks.ErrTPMNoTransport

	// ErrLUKSTPMPolicyFailed indicates the PCR policy digest could not be
	// computed. This is typically a bug in the requested PCR selection.
	ErrLUKSTPMPolicyFailed = luks.ErrTPMPolicyFailed

	// ErrLUKSTPMSealFailed indicates the underlying TPM2_Create seal command
	// returned an error.
	ErrLUKSTPMSealFailed = luks.ErrTPMSealFailed

	// ErrLUKSTPMUnsealFailed indicates the TPM2_Unseal command returned an
	// error (most commonly because current PCR state does not match the
	// policy).
	ErrLUKSTPMUnsealFailed = luks.ErrTPMUnsealFailed

	// ErrLUKSTPMInvalidToken indicates the TPM LUKS token JSON could not be
	// parsed.
	ErrLUKSTPMInvalidToken = luks.ErrTPMInvalidToken

	// ErrLUKSTPMPCRSelectionNotSupported indicates PCRs were requested for a
	// Platform SRK seal, which is always bound to the platform PCR policy.
	ErrLUKSTPMPCRSelectionNotSupported = luks.ErrTPMPCRSelectionNotSupported
)

// LUKSTPMTokenType is the LUKS2 token type written for a Shared SRK seal
// (systemd-cryptsetup's "systemd-tpm2"). Matches the value already routed by
// luksKeySlotTypeMap.
const LUKSTPMTokenType = luks.TPMTokenType

// LUKSXKMSTPMTokenType is the LUKS2 token type written for a Platform SRK
// seal.
const LUKSXKMSTPMTokenType = luks.XKMSTPMTokenType

// LUKSTPM is the platform TPM surface the sealer runs on: seal, unseal and
// the Platform / Shared SRK attributes. The platform's open TPM satisfies it.
type LUKSTPM = luks.TPMSealUnsealer

// LUKSTPMSealerConfig selects the seal parent (Platform SRK by default, or
// the Shared SRK for systemd-cryptsetup) and the PCR bank.
type LUKSTPMSealerConfig = luks.TPMSealerConfig

// LUKSTPMSealResult is the richer enrol output: passphrase bytes and the
// token payload to persist in the LUKS2 header.
type LUKSTPMSealResult = luks.TPMSealResult

// Compile-time assertion: the canonical sealer satisfies the platform's
// narrow LUKSTPMHandler interface.
var _ LUKSTPMHandler = (*luks.TPMSealer)(nil)

// NewLUKSTPMHandler constructs the canonical go-xkms TPM-backed LUKS
// passphrase sealer on the platform TPM. A nil tpm returns
// ErrLUKSTPMNoTransport so callers can leave the backend's TPM handler unset
// (ErrLUKSTPMNotWired path).
func NewLUKSTPMHandler(tpm LUKSTPM, cfg LUKSTPMSealerConfig) (*luks.TPMSealer, error) {
	return luks.NewTPMSealer(tpm, cfg)
}
