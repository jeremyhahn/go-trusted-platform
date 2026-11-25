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
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests cover the thin platform wiring around the canonical go-xkms
// TPM LUKS sealer (reached through the QuicBaaS SDK). The sealer's own
// behaviour — token encoding, PCR selection, and the simulator-backed
// seal/unseal round-trips — is tested upstream in go-xkms/pkg/luks.

func newStubLUKSTPMHandler(t *testing.T) *LUKSTPMSealer {
	t.Helper()
	h, err := NewLUKSTPMHandler(nil, erroringTPM{err: errStubTPM}, TPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	return h
}

func TestNewLUKSTPMHandler_NilTPM(t *testing.T) {
	_, err := NewLUKSTPMHandler(nil, nil, TPMSealerConfig{})
	if !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestNewLUKSTPMHandler_SatisfiesLUKSTPMHandler(t *testing.T) {
	var _ LUKSTPMHandler = newStubLUKSTPMHandler(t)
}

func TestLUKSTPMHandler_SealFailure_Surfaces(t *testing.T) {
	h := newStubLUKSTPMHandler(t)
	if _, _, err := h.Seal(context.Background(), "", nil); err == nil {
		t.Fatal("expected the TPM seal failure to surface, got nil")
	}
}

func TestLUKSTPMHandler_Seal_PCRSelectionUnderPSRK(t *testing.T) {
	h := newStubLUKSTPMHandler(t)
	if _, _, err := h.Seal(context.Background(), "", []int32{7}); !errors.Is(err, ErrLUKSTPMPCRSelectionNotSupported) {
		t.Fatalf("expected ErrLUKSTPMPCRSelectionNotSupported, got %v", err)
	}
}

func TestLUKSTPMHandler_Seal_InvalidHandle(t *testing.T) {
	h := newStubLUKSTPMHandler(t)
	if _, _, err := h.Seal(context.Background(), "not-a-number", nil); !errors.Is(err, ErrLUKSTPMInvalidHandle) {
		t.Fatalf("expected ErrLUKSTPMInvalidHandle, got %v", err)
	}
}

func TestLUKSTPMHandler_Seal_HandleNotSupported(t *testing.T) {
	h := newStubLUKSTPMHandler(t)
	if _, _, err := h.Seal(context.Background(), "0x81000001", nil); !errors.Is(err, ErrLUKSTPMHandleNotSupported) {
		t.Fatalf("expected ErrLUKSTPMHandleNotSupported, got %v", err)
	}
}

func TestLUKSTPMHandler_Unseal_InvalidTokenJSON(t *testing.T) {
	h := newStubLUKSTPMHandler(t)
	if _, err := h.UnsealPassphrase(context.Background(), []byte("not-json")); !errors.Is(err, ErrLUKSTPMInvalidToken) {
		t.Fatalf("expected ErrLUKSTPMInvalidToken, got %v", err)
	}
}

var errStubTPM = errors.New("stub tpm failure")

// erroringTPM is a TPMSealUnsealer stub that fails every call with err.
type erroringTPM struct {
	err error
}

func (e erroringTPM) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return nil, e.err
}

func (e erroringTPM) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, e.err
}

func (e erroringTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) { return nil, e.err }

func (e erroringTPM) SSRKAttributes() (*types.KeyAttributes, error) { return nil, e.err }

func (e erroringTPM) Transport() transport.TPM { return nil }
