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

package barrier

import "fmt"

// ---------------------------------------------------------------------------
// Failure error types — wrap the SDK error so callers can match via
// errors.As and reach the underlying cause via errors.Unwrap.
// ---------------------------------------------------------------------------

// ErrBarrierInitFailed is returned when barrier initialization fails.
type ErrBarrierInitFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierInitFailed) Error() string {
	return fmt.Sprintf("barrier initialization failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierInitFailed) Unwrap() error { return e.Err }

// ErrBarrierInitShamirFailed is returned when Shamir initialization fails.
type ErrBarrierInitShamirFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierInitShamirFailed) Error() string {
	return fmt.Sprintf("barrier init-shamir failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierInitShamirFailed) Unwrap() error { return e.Err }

// ErrBarrierStatusFailed is returned when barrier status retrieval fails.
type ErrBarrierStatusFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierStatusFailed) Error() string {
	return fmt.Sprintf("failed to get barrier status: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierStatusFailed) Unwrap() error { return e.Err }

// ErrBarrierUnsealFailed is returned when barrier unseal fails.
type ErrBarrierUnsealFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierUnsealFailed) Error() string {
	return fmt.Sprintf("barrier unseal failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierUnsealFailed) Unwrap() error { return e.Err }

// ErrBarrierUnsealSharesFailed is returned when barrier unseal-shares fails.
type ErrBarrierUnsealSharesFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierUnsealSharesFailed) Error() string {
	return fmt.Sprintf("barrier unseal-shares failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierUnsealSharesFailed) Unwrap() error { return e.Err }

// ErrBarrierSealFailed is returned when barrier seal fails.
type ErrBarrierSealFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierSealFailed) Error() string {
	return fmt.Sprintf("barrier seal failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierSealFailed) Unwrap() error { return e.Err }

// ErrBarrierRekeyFailed is returned when barrier rekey fails.
type ErrBarrierRekeyFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierRekeyFailed) Error() string {
	return fmt.Sprintf("barrier rekey failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierRekeyFailed) Unwrap() error { return e.Err }

// ErrBarrierRecoveryGenerateFailed is returned when recovery key
// generation fails.
type ErrBarrierRecoveryGenerateFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierRecoveryGenerateFailed) Error() string {
	return fmt.Sprintf("barrier recovery generate failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierRecoveryGenerateFailed) Unwrap() error { return e.Err }

// ErrBarrierRecoveryRecoverFailed is returned when recovery-driven
// unseal fails.
type ErrBarrierRecoveryRecoverFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrBarrierRecoveryRecoverFailed) Error() string {
	return fmt.Sprintf("barrier recovery recover failed: %v", e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrBarrierRecoveryRecoverFailed) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// Validation error types — fired before any RPC, so they can carry the
// offending flag set verbatim for operator diagnostics.
// ---------------------------------------------------------------------------

// ErrInvalidBarrierStrategy is returned when --barrier-strategy is not
// in the canonical {none, passphrase, shamir} set.
type ErrInvalidBarrierStrategy struct {
	Strategy string
}

// Error implements the error interface.
func (e ErrInvalidBarrierStrategy) Error() string {
	return fmt.Sprintf("barrier init: invalid --barrier-strategy %q (allowed: none, passphrase, shamir)", e.Strategy)
}

// ErrSecretRequired is returned when --passphrase is required for the
// chosen strategy but absent.
type ErrSecretRequired struct {
	Strategy string
}

// Error implements the error interface.
func (e ErrSecretRequired) Error() string {
	return fmt.Sprintf("barrier init: --passphrase is required when --barrier-strategy=%s", e.Strategy)
}

// ErrSecretNotAllowed is returned when --passphrase is supplied for a
// strategy that does not accept it (currently only --barrier-strategy=none).
type ErrSecretNotAllowed struct {
	Strategy string
}

// Error implements the error interface.
func (e ErrSecretNotAllowed) Error() string {
	return fmt.Sprintf("barrier init: --passphrase is not allowed when --barrier-strategy=%s", e.Strategy)
}

// PINsNotAllowedError is returned when --so-pin or --user-pin is
// supplied for --barrier-strategy=none, which has no key material to
// gate. The Flag field names the offending PIN.
type PINsNotAllowedError struct {
	Flag     string
	Strategy string
}

// Error implements the error interface.
func (e PINsNotAllowedError) Error() string {
	return fmt.Sprintf("barrier init: --%s is not allowed when --barrier-strategy=%s (no key material to gate)",
		e.Flag, e.Strategy)
}

// ErrUserPinRequiresSOPin is returned when --user-pin is supplied
// without --so-pin. The PIN backend requires the SO PIN to be set
// before any user PIN is recorded.
type ErrUserPinRequiresSOPin struct{}

// Error implements the error interface.
func (ErrUserPinRequiresSOPin) Error() string {
	return "--user-pin requires --so-pin (the SO PIN must be set before any user PIN)"
}

// ErrInvalidThreshold is returned when threshold and total are
// inconsistent (e.g. threshold > total).
type ErrInvalidThreshold struct {
	Threshold int
	Total     int
}

// Error implements the error interface.
func (e ErrInvalidThreshold) Error() string {
	return fmt.Sprintf("invalid threshold: threshold (%d) must be >= 2 and <= total (%d)",
		e.Threshold, e.Total)
}

// ErrInvalidTotal is returned when --total is < threshold or < 2.
type ErrInvalidTotal struct {
	Total int
}

// Error implements the error interface.
func (e ErrInvalidTotal) Error() string {
	return fmt.Sprintf("invalid total: must be >= 2, got %d", e.Total)
}

// ErrMissingSecret is returned when --passphrase is required but absent.
type ErrMissingSecret struct{}

// Error implements the error interface.
func (ErrMissingSecret) Error() string {
	return "passphrase is required: provide --passphrase"
}

// ErrMissingShares is returned when neither --share nor --shares-file
// is provided to unseal-shares or recovery recover.
type ErrMissingShares struct{}

// Error implements the error interface.
func (ErrMissingShares) Error() string {
	return "at least one share is required: pass --share <s> (repeatable) or --shares-file <path|->"
}

// ErrShareSourcesConflict is returned when both --share and
// --shares-file are provided to unseal-shares.
type ErrShareSourcesConflict struct{}

// Error implements the error interface.
func (ErrShareSourcesConflict) Error() string {
	return "specify either --share (repeatable) or --shares-file, not both"
}

// ErrSharesFileReadFailed is returned when --shares-file cannot be
// read from disk.
type ErrSharesFileReadFailed struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e ErrSharesFileReadFailed) Error() string {
	return fmt.Sprintf("read shares file %q: %v", e.Path, e.Err)
}

// Unwrap returns the wrapped error for errors.Is/errors.As.
func (e ErrSharesFileReadFailed) Unwrap() error { return e.Err }

// ErrSealCancelled is returned when the operator declines the
// interactive seal confirmation.
type ErrSealCancelled struct{}

// Error implements the error interface.
func (ErrSealCancelled) Error() string {
	return "barrier seal cancelled by user"
}

// ErrRekeyPartialFlags is returned when only one of --threshold /
// --total is supplied to rekey. Either both or neither must be set.
type ErrRekeyPartialFlags struct{}

// Error implements the error interface.
func (ErrRekeyPartialFlags) Error() string {
	return "barrier rekey: --threshold and --total must be set together (or both omitted)"
}
