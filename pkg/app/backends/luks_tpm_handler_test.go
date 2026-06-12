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
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// These tests cover the thin platform wiring around the canonical go-xkms
// TPM LUKS sealer (reached through the QuicBaaS SDK). The sealer's own
// behaviour — handle resolution, token encoding, PCR selection, and the
// simulator-backed seal/unseal round-trips — is tested upstream in
// go-xkms/pkg/luks.

func TestNewLUKSTPMHandler_NilOpener(t *testing.T) {
	_, err := NewLUKSTPMHandler(nil, nil)
	if !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestNewLUKSTPMHandler_SatisfiesLUKSTPMHandler(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	var _ LUKSTPMHandler = h
}

func TestLUKSTPMHandler_OpenFailure_Surfaces(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, _, err = h.Seal(context.Background(), "", []int32{7}); !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestLUKSTPMHandler_Seal_InvalidHandle(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, _, err = h.Seal(context.Background(), "not-a-number", nil); !errors.Is(err, ErrLUKSTPMInvalidHandle) {
		t.Fatalf("expected ErrLUKSTPMInvalidHandle, got %v", err)
	}
}

func TestLUKSTPMHandler_Unseal_InvalidTokenJSON(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, err = h.UnsealPassphrase(context.Background(), []byte("not-json")); !errors.Is(err, ErrLUKSTPMInvalidToken) {
		t.Fatalf("expected ErrLUKSTPMInvalidToken, got %v", err)
	}
}

// erroringOpener is a TPMOpener stub that short-circuits with the configured
// error. It lets us exercise the wiring's error surface without a TPM.
type erroringOpener struct {
	err error
}

// Open satisfies the TPMOpener contract.
func (e erroringOpener) Open(context.Context) (transport.TPMCloser, error) {
	return nil, e.err
}
