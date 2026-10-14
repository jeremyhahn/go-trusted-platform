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

import (
	"errors"
	"strings"
	"testing"
)

// Transports match the refusal with errors.As through their own wrapping;
// operators read the missing upstream capability from its message.
func TestErrPCRBoundSealUnavailable_MatchesThroughWrapping(t *testing.T) {
	err := &WrappedError{Msg: "seal", Err: ErrPCRBoundSealUnavailable{}}

	if !errors.As(err, &ErrPCRBoundSealUnavailable{}) {
		t.Fatalf("errors.As does not find the refusal in %v", err)
	}
	if !strings.Contains(err.Error(), "go-quicbaas #1171") {
		t.Errorf("the refusal must name the missing upstream capability, got %q", err.Error())
	}
}

func TestErrPCRBoundSealUnavailable_DoesNotMatchOtherErrors(t *testing.T) {
	err := &WrappedError{Msg: "seal", Err: &MessageError{Msg: "tpm: sealing failed"}}

	if errors.As(err, &ErrPCRBoundSealUnavailable{}) {
		t.Errorf("an unrelated seal failure must not read as a PCR-bound refusal: %v", err)
	}
}
