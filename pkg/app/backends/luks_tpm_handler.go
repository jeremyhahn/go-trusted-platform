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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	luks "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/luks"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The TPM LUKS passphrase sealer is owned by go-xkms (the stack's canonical
// home for all TPM 2.0 operations) and reached through the QuicBaaS SDK.
// This file is the thin platform wiring: alias the SDK surface under the
// names the LUKS backend and its callers already use, and adapt the
// sealer to the backend's narrow LUKSTPMHandler interface.

// LUKS TPM handler errors, aliased from the canonical go-xkms surface so
// errors.Is works across the SDK boundary.
var (
	// ErrLUKSTPMNoTransport indicates no TPM was given to the sealer.
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

	// ErrLUKSTPMPCRSelectionNotSupported indicates a PCR list was given while
	// sealing under the Platform SRK, whose PCR policy is fixed by go-xkms.
	ErrLUKSTPMPCRSelectionNotSupported = luks.ErrTPMPCRSelectionNotSupported
)

// ErrLUKSTPMInvalidHandle indicates the requested persistent handle string
// could not be parsed as a uint32.
var ErrLUKSTPMInvalidHandle = errors.New("luks backend: invalid tpm handle")

// ErrLUKSTPMHandleNotSupported refuses a caller-chosen parent handle: the go-xkms sealer picks its parent (PSRK or SSRK) from TPMSealerConfig.
var ErrLUKSTPMHandleNotSupported = errors.New("luks backend: a tpm parent handle is not supported; the sealer's parent comes from its config")

// LUKSTPMTokenType is the LUKS2 token type we write for TPM-sealed slots.
// Matches the value already routed by luksKeySlotTypeMap.
const LUKSTPMTokenType = luks.TPMTokenType

// TPMSealUnsealer is the TPM surface the sealer seals through; any go-xkms pkg/tpm2.TPM2 satisfies it.
type TPMSealUnsealer = luks.TPMSealUnsealer

// TPMSealerConfig selects the sealer's storage parent and PCR bank.
type TPMSealerConfig = luks.TPMSealerConfig

// LUKSTPMSealResult is the richer enrol output: passphrase bytes and the
// token payload to persist in the LUKS2 header.
type LUKSTPMSealResult = luks.TPMSealResult

// LUKSTPMSealer adapts the go-xkms TPMSealer to LUKSTPMHandler.
type LUKSTPMSealer struct {
	sealer *luks.TPMSealer
}

// Compile-time assertion: the adapter satisfies the platform's narrow
// LUKSTPMHandler interface.
var _ LUKSTPMHandler = (*LUKSTPMSealer)(nil)

// NewLUKSTPMHandler constructs the canonical go-xkms TPM-backed LUKS
// passphrase sealer over tpm. A nil tpm returns ErrLUKSTPMNoTransport so
// callers can leave the backend's TPM handler unset (ErrLUKSTPMNotWired path).
func NewLUKSTPMHandler(logger *logging.Logger, tpm TPMSealUnsealer, cfg TPMSealerConfig) (*LUKSTPMSealer, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if tpm == nil {
		return nil, ErrLUKSTPMNoTransport
	}
	s, err := luks.NewTPMSealer(tpm, cfg)
	if err != nil {
		return nil, err
	}
	logger.Debug("luks tpm sealer ready", "parent", s.Parent().String())
	return &LUKSTPMSealer{sealer: s}, nil
}

// Seal seals a fresh LUKS passphrase and returns it with the LUKS2 token JSON.
// The passphrase is copied out of protected memory; the caller clears it.
func (s *LUKSTPMSealer) Seal(ctx context.Context, handle string, pcrs []int32) ([]byte, []byte, error) {
	if err := checkLUKSTPMHandle(handle); err != nil {
		return nil, nil, err
	}
	res, err := s.sealer.SealPassphrase(ctx, pcrs)
	if err != nil {
		return nil, nil, err
	}
	if res == nil || res.Passphrase == nil || res.Token == nil {
		return nil, nil, fmt.Errorf("%w: empty seal result", ErrLUKSTPMSealFailed)
	}
	defer res.Passphrase.Destroy()
	tokenJSON, err := json.Marshal(res.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrLUKSTPMInvalidToken, err)
	}
	passphrase := append([]byte(nil), res.Passphrase.Bytes()...)
	return passphrase, tokenJSON, nil
}

// UnsealPassphrase decodes tokenJSON and unseals its passphrase.
func (s *LUKSTPMSealer) UnsealPassphrase(ctx context.Context, tokenJSON []byte) ([]byte, error) {
	var tok luks2.Token
	if err := json.Unmarshal(tokenJSON, &tok); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLUKSTPMInvalidToken, err)
	}
	return s.sealer.UnsealPassphrase(ctx, &tok)
}

// checkLUKSTPMHandle accepts only an empty handle; a malformed one is ErrLUKSTPMInvalidHandle.
func checkLUKSTPMHandle(handle string) error {
	if handle == "" {
		return nil
	}
	if _, err := strconv.ParseUint(handle, 0, 32); err != nil {
		return fmt.Errorf("%w: %q", ErrLUKSTPMInvalidHandle, handle)
	}
	return fmt.Errorf("%w: %q", ErrLUKSTPMHandleNotSupported, handle)
}
