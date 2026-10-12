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

package hostquote

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// ErrCollectFailed reports a quote that could not be produced, or one the
// node refused to emit because its own verifier would reject it.
type ErrCollectFailed struct {
	Reason string
	Cause  error
}

func (e ErrCollectFailed) Error() string {
	msg := "hostquote: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrCollectFailed) Unwrap() error { return e.Cause }

// ErrPCRIndexOutOfRange reports a selected PCR a TPM 2.0 does not have.
type ErrPCRIndexOutOfRange struct{ Index int }

func (e ErrPCRIndexOutOfRange) Error() string {
	return fmt.Sprintf("pcr index %d out of range 0-%d", e.Index, MaxPCRIndex)
}

// ErrPCRIndexDuplicate reports a PCR selected twice.
type ErrPCRIndexDuplicate struct{ Index int }

func (e ErrPCRIndexDuplicate) Error() string {
	return fmt.Sprintf("pcr index %d selected twice", e.Index)
}

// ErrQuotedSelectionMismatch reports a quote over PCRs other than the
// selected ones.
type ErrQuotedSelectionMismatch struct {
	Quoted   []int
	Selected []int
}

func (e ErrQuotedSelectionMismatch) Error() string {
	return fmt.Sprintf("TPM quoted PCRs %v, caller selected %v", e.Quoted, e.Selected)
}

// ErrPCRBankMissing reports a TPM that returned no bank of the requested
// algorithm.
type ErrPCRBankMissing struct{ Algorithm manifest.HashAlgorithm }

func (e ErrPCRBankMissing) Error() string {
	return fmt.Sprintf("TPM returned no %s bank", e.Algorithm)
}

// ErrPCRValueMissing reports a bank with no value for a selected PCR.
type ErrPCRValueMissing struct {
	Algorithm manifest.HashAlgorithm
	Index     int
}

func (e ErrPCRValueMissing) Error() string {
	return fmt.Sprintf("bank %s has no value for pcr %d", e.Algorithm, e.Index)
}
