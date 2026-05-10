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

//go:build tpm_simulator

package backends

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// simLock serialises access to the go-tpm-tools simulator singleton. The
// library itself blocks on a sync.Mutex; we mirror the invariant so tests
// do not spin waiting for it.
var simLock sync.Mutex

// sharedSimOpener hands out a no-op TPM closer wrapping a shared
// transport.TPM. Used in seal+unseal round-trip tests so both operations
// see the same TPM state.
type sharedSimOpener struct {
	tpm transport.TPM
}

func (s *sharedSimOpener) Open(context.Context) (transport.TPMCloser, error) {
	return nopTPMCloser{tpm: s.tpm}, nil
}

type nopTPMCloser struct{ tpm transport.TPM }

func (n nopTPMCloser) Send(cmd []byte) ([]byte, error) { return n.tpm.Send(cmd) }
func (n nopTPMCloser) Close() error                    { return nil }

// provisionPersistentSRK creates a storage primary under the Owner hierarchy
// and evicts it to the supplied persistent handle on the given simulator.
func provisionPersistentSRK(t *testing.T, tpm transport.TPM, handle libtpm2.TPMHandle) {
	t.Helper()
	primary, err := libtpm2.CreatePrimary{
		PrimaryHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMRHOwner,
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InPublic: libtpm2.New2B(libtpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	defer flushContext(tpm, primary.ObjectHandle)

	if _, err := (libtpm2.EvictControl{
		Auth: libtpm2.AuthHandle{
			Handle: libtpm2.TPMRHOwner,
			Auth:   libtpm2.PasswordAuth(nil),
		},
		ObjectHandle: &libtpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		PersistentHandle: handle,
	}).Execute(tpm); err != nil {
		t.Fatalf("EvictControl: %v", err)
	}
}

// TestLUKSTPMHandler_SealUnsealRoundTrip seals a random passphrase against a
// software TPM with a PCR policy on PCR 7, then unseals it via the same
// policy — the bytes must match exactly.
func TestLUKSTPMHandler_SealUnsealRoundTrip(t *testing.T) {
	simLock.Lock()
	sim, err := simulator.Get()
	if err != nil {
		simLock.Unlock()
		t.Fatalf("simulator.Get: %v", err)
	}
	defer func() {
		sim.Close()
		simLock.Unlock()
	}()

	sharedTPM := transport.FromReadWriter(sim)
	provisionPersistentSRK(t, sharedTPM, libtpm2.TPMHandle(0x81000001))

	h, err := NewLUKSTPMHandler(logging.DefaultLogger(), &sharedSimOpener{tpm: sharedTPM})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	res, err := h.SealPassphrase(context.Background(), "", []int32{7})
	if err != nil {
		t.Fatalf("SealPassphrase: %v", err)
	}
	if len(res.Passphrase) != 32 {
		t.Fatalf("passphrase length = %d, want 32", len(res.Passphrase))
	}
	if len(res.TokenJSON) == 0 {
		t.Fatal("empty token json")
	}
	if len(res.PolicyDigest) == 0 {
		t.Fatal("empty policy digest")
	}

	var tok tpmLUKSToken
	if err := json.Unmarshal(res.TokenJSON, &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	if tok.Type != LUKSTPMTokenType {
		t.Fatalf("token type = %q, want %q", tok.Type, LUKSTPMTokenType)
	}
	if tok.TPM2PCRBank != "sha256" {
		t.Fatalf("pcr bank = %q, want sha256", tok.TPM2PCRBank)
	}
	if tok.TPM2Handle != 0x81000001 {
		t.Fatalf("handle = %#x, want 0x81000001", tok.TPM2Handle)
	}
	if len(tok.TPM2PCRs) != 1 || tok.TPM2PCRs[0] != 7 {
		t.Fatalf("pcrs = %v, want [7]", tok.TPM2PCRs)
	}

	unsealed, err := h.UnsealPassphrase(context.Background(), res.TokenJSON)
	if err != nil {
		t.Fatalf("UnsealPassphrase: %v", err)
	}
	if !bytes.Equal(unsealed, res.Passphrase) {
		t.Fatalf("unseal mismatch:\n  got  %x\n  want %x", unsealed, res.Passphrase)
	}
}

// TestLUKSTPMHandler_Seal_PolicyBindsPCRState proves PCR policy enforcement
// — extending PCR 7 after seal must make the subsequent unseal fail with
// ErrLUKSTPMUnsealFailed.
func TestLUKSTPMHandler_Seal_PolicyBindsPCRState(t *testing.T) {
	simLock.Lock()
	sim, err := simulator.Get()
	if err != nil {
		simLock.Unlock()
		t.Fatalf("simulator.Get: %v", err)
	}
	defer func() {
		sim.Close()
		simLock.Unlock()
	}()

	sharedTPM := transport.FromReadWriter(sim)
	provisionPersistentSRK(t, sharedTPM, libtpm2.TPMHandle(0x81000001))

	h, err := NewLUKSTPMHandler(logging.DefaultLogger(), &sharedSimOpener{tpm: sharedTPM})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	res, err := h.SealPassphrase(context.Background(), "", []int32{7})
	if err != nil {
		t.Fatalf("SealPassphrase: %v", err)
	}

	// Perturb PCR 7 so the policy digest no longer matches.
	if _, err := (libtpm2.PCRExtend{
		PCRHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(7),
			Auth:   libtpm2.PasswordAuth(nil),
		},
		Digests: libtpm2.TPMLDigestValues{
			Digests: []libtpm2.TPMTHA{{
				HashAlg: libtpm2.TPMAlgSHA256,
				Digest:  bytes.Repeat([]byte{0xAB}, 32),
			}},
		},
	}).Execute(sharedTPM); err != nil {
		t.Fatalf("PCRExtend: %v", err)
	}

	if _, err = h.UnsealPassphrase(context.Background(), res.TokenJSON); !errors.Is(err, ErrLUKSTPMUnsealFailed) {
		t.Fatalf("expected ErrLUKSTPMUnsealFailed after PCR extend, got %v", err)
	}
}
