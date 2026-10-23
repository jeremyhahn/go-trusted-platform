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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The TPM LUKS passphrase sealer is owned by go-xkms (the stack's canonical
// home for all TPM 2.0 operations) and reached through the QuicBaaS SDK.
// This file is the thin platform wiring: alias the SDK surface under the
// names the LUKS backend and its callers already use, and adapt the
// platform logger to the sealer's constructor.

// LUKS TPM handler errors, aliased from the canonical go-xkms surface so
// errors.Is works across the SDK boundary.
var (
	// ErrLUKSTPMNoTransport indicates no TPMOpener could be resolved — the
	// host has no /dev/tpmrm0 and no simulator was injected.
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

	// ErrLUKSTPMInvalidHandle indicates the requested persistent handle
	// string could not be parsed as a uint32.
	ErrLUKSTPMInvalidHandle = luks.ErrTPMInvalidHandle

	// ErrLUKSTPMInvalidToken indicates the TPM LUKS token JSON could not be
	// parsed.
	ErrLUKSTPMInvalidToken = luks.ErrTPMInvalidToken
)

// LUKSTPMTokenType is the LUKS2 token type we write for TPM-sealed slots.
// Matches the value already routed by luksKeySlotTypeMap.
const LUKSTPMTokenType = luks.TPMTokenType

// TPMOpener opens a go-tpm transport for a sealing / unsealing operation.
type TPMOpener = luks.TPMOpener

// TPMOpenerFunc adapts a function to the TPMOpener interface.
type TPMOpenerFunc = luks.TPMOpenerFunc

// LUKSTPMSealResult is the richer enrol output: passphrase bytes and the
// token payload to persist in the LUKS2 header.
type LUKSTPMSealResult = luks.TPMSealResult

// DefaultTPMOpener returns a TPMOpener that opens /dev/tpmrm0 on Linux.
// If the TPM device is missing the opener returns ErrLUKSTPMNoTransport so
// callers can downgrade cleanly to a "not wired" failure mode.
var DefaultTPMOpener = luks.DefaultTPMOpener

// Compile-time assertion: the canonical sealer satisfies the platform's
// narrow LUKSTPMHandler interface.
var _ LUKSTPMHandler = (*luks.TPMSealer)(nil)

// NewLUKSTPMHandler constructs the canonical go-xkms TPM-backed LUKS
// passphrase sealer with the platform logger. Passing a nil opener returns
// ErrLUKSTPMNoTransport so callers can fall back to leaving the backend's
// TPM handler unset (ErrLUKSTPMNotWired path).
func NewLUKSTPMHandler(logger *logging.Logger, opener TPMOpener) (*luks.TPMSealer, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return luks.NewTPMSealer(logger.Slog(), opener)
}
