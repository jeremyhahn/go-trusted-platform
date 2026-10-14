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

package common

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// ErrPCRBoundSealUnavailable refuses a seal request that names PCRs. The
// go-xkms release the platform builds against ignores a PCR selection that
// comes without a policy digest: the object would be protected by its
// password alone and unseal whatever the PCRs hold. Binding the object to the
// PCRs needs the PolicyPCR digest or a named TPMPolicy, which go-quicbaas does
// not re-export yet (go-quicbaas #1171). Until it does, the seal fails closed.
type ErrPCRBoundSealUnavailable struct{}

// Error implements the error interface.
func (ErrPCRBoundSealUnavailable) Error() string {
	return "PCR-bound sealing is unavailable until go-quicbaas re-exports the TPM PolicyPCR primitives (go-quicbaas #1171): " +
		"the seal was refused rather than produce an object that is not bound to the PCRs"
}
