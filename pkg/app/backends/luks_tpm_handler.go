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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
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

// PlatformTPMOpener returns a TPMOpener over the platform's selected TPM
// instead of the SDK default device. module is resolved at Open time; a nil
// module answers ErrLUKSTPMNoTransport. Which mode applies depends on the
// module's Device():
//
//   - A kernel resource-manager device (/dev/tpmrm*, such as the default
//     /dev/tpmrm0, resolved through symlinks): every Open opens a new
//     connection to that same device and the closer closes it. The resource
//     manager gives each connection its own context and serializes commands
//     between them, so the sealer never shares a connection with the
//     platform's own TPM work (quotes, NV reads and writes, transient-handle
//     flushes), and an enrolment runs at the same time as that work. An open
//     failure answers ErrLUKSTPMNoTransport wrapping the cause.
//   - Any other device path (an exclusive /dev/tpm0 the platform already
//     holds): a second open would answer EBUSY, so every Open lends the
//     module's own connection under a lock. The lock orders the sealers
//     only; the platform's own users of that connection are not covered.
//     Covering them needs a synchronized transport from go-xkms (upstream
//     gap). A nil transport answers ErrLUKSTPMNoTransport.
//   - An in-process TPM (the simulator: no device path): every Open lends the
//     module's own transport under the same lock, which orders the sealers
//     only, not the platform's own users of that transport. This mode is for
//     single-user test hardware; a nil transport answers
//     ErrLUKSTPMNoTransport.
func PlatformTPMOpener(module func() xkmssdk.TrustedPlatformModule) TPMOpener {
	// lock (capacity 1) is held from Open until the returned closer's
	// Close, so in the lent modes (exclusive device, in-process TPM) one
	// sealer at a time exchanges commands over the platform's transport.
	lock := make(chan struct{}, 1)
	return TPMOpenerFunc(func(ctx context.Context) (transport.TPMCloser, error) {
		if module == nil {
			return nil, ErrLUKSTPMNoTransport
		}
		m := module()
		if m == nil {
			return nil, ErrLUKSTPMNoTransport
		}
		if device := m.Device(); device != "" && isTPMCharDevice(device) && isTPMResourceManager(device) {
			conn, err := openTPMDevice(device)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrLUKSTPMNoTransport, err)
			}
			return conn, nil
		}
		tpm := m.Transport()
		if tpm == nil {
			return nil, ErrLUKSTPMNoTransport
		}
		select {
		case lock <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &sharedTPM{TPM: tpm, release: func() { <-lock }}, nil
	})
}

// openTPMDevice opens a new connection to the TPM character device at path;
// isTPMCharDevice reports whether path is one. Tests replace both.
var (
	openTPMDevice   = linuxtpm.Open
	isTPMCharDevice = func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
)

// isTPMResourceManager reports whether path (resolved through symlinks;
// unresolved on error) names a kernel TPM resource-manager device
// (/dev/tpmrm*), the only kind that takes a second connection while the
// platform holds one. An exclusive /dev/tpm* answers a second open EBUSY.
func isTPMResourceManager(path string) bool {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return strings.HasPrefix(filepath.Base(path), "tpmrm")
}

// sharedTPM lends the platform's transport to the sealer in the in-process
// (simulator) mode of PlatformTPMOpener; the device mode hands the sealer
// its own connection instead. The sealer closes its transport after each
// command batch, but the platform owns and closes its transport, so Close
// only hands the transport to the next sealer.
type sharedTPM struct {
	transport.TPM
	release func()
	once    sync.Once
}

// Close leaves the platform's transport open and releases the opener's
// lock, at most once.
func (s *sharedTPM) Close() error {
	s.once.Do(s.release)
	return nil
}

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
