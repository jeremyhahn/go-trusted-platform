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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// stubXKMSFIDO2Handler fakes the go-xkms fido2.Handler interface by computing
// HMAC-SHA256(key=credentialID, data=salt) instead of invoking an actual
// authenticator. The output is deterministic so enroll→unlock round-trips
// can be asserted.
type stubXKMSFIDO2Handler struct {
	seed []byte
	// calls tracks how many UnlockWithKey calls were made. Useful to
	// confirm context cancellation interrupts a slow derivation.
	calls int
	// blockUntil, when non-nil, causes UnlockWithKey to block on the
	// channel before returning. Tests use it to exercise ctx cancellation.
	blockUntil chan struct{}
}

// newStubXKMSFIDO2Handler returns a stub seeded with the supplied bytes.
// The seed is combined with the credential id so tests configured with
// different seeds produce different derived keys.
func newStubXKMSFIDO2Handler(seed []byte) *stubXKMSFIDO2Handler {
	if seed == nil {
		seed = []byte("stub-seed")
	}
	return &stubXKMSFIDO2Handler{seed: seed}
}

func (s *stubXKMSFIDO2Handler) EnrollKey(_ *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	return &fido2.EnrollmentResult{}, nil
}

func (s *stubXKMSFIDO2Handler) UnlockWithKey(cfg *fido2.AuthenticationConfig) ([]byte, error) {
	s.calls++
	if s.blockUntil != nil {
		<-s.blockUntil
	}
	// HMAC(cred||seed, salt) — deterministic, 32 bytes.
	key := append([]byte{}, cfg.CredentialID...)
	key = append(key, s.seed...)
	mac := hmac.New(sha256.New, key)
	mac.Write(cfg.Salt)
	return mac.Sum(nil), nil
}

func (s *stubXKMSFIDO2Handler) ListDevices() ([]fido2.Device, error) { return nil, nil }
func (s *stubXKMSFIDO2Handler) WaitForDevice(ctx context.Context) (*fido2.Device, error) {
	return nil, errors.New("not implemented")
}
func (s *stubXKMSFIDO2Handler) Close() error { return nil }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewLUKSFIDO2Handler_NilXKMSHandler(t *testing.T) {
	_, err := NewLUKSFIDO2Handler(nil, nil, "")
	if !errors.Is(err, ErrLUKSFIDO2NoXKMSHandler) {
		t.Fatalf("expected ErrLUKSFIDO2NoXKMSHandler, got %v", err)
	}
}

func TestNewLUKSFIDO2Handler_DefaultRPID(t *testing.T) {
	stub := newStubXKMSFIDO2Handler(nil)
	h, err := NewLUKSFIDO2Handler(nil, stub, "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if h.rpID == "" {
		t.Fatal("expected default RP ID to be applied")
	}
}

// ---------------------------------------------------------------------------
// Enroll → unlock round-trip
// ---------------------------------------------------------------------------

func TestLUKSFIDO2Handler_EnrollUnlockRoundTrip(t *testing.T) {
	stub := newStubXKMSFIDO2Handler([]byte("trip-seed"))
	h, err := NewLUKSFIDO2Handler(logging.DefaultLogger(), stub, "example.com")
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	credID := hex.EncodeToString([]byte("credential-bytes"))

	res, err := h.DeriveEnroll(context.Background(), credID, false, true)
	if err != nil {
		t.Fatalf("DeriveEnroll: %v", err)
	}
	if len(res.DerivedKey) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(res.DerivedKey))
	}
	if len(res.Salt) != 32 {
		t.Fatalf("salt length = %d, want 32", len(res.Salt))
	}

	// Round-trip the token JSON → unlock and compare derived keys.
	unlockKey, err := h.DeriveUnlock(context.Background(), res.TokenJSON)
	if err != nil {
		t.Fatalf("DeriveUnlock: %v", err)
	}
	if !bytes.Equal(res.DerivedKey, unlockKey) {
		t.Fatalf("enroll key %x != unlock key %x", res.DerivedKey, unlockKey)
	}

	// Sanity-check the emitted token schema.
	var tok fido2LUKSToken
	if err := json.Unmarshal(res.TokenJSON, &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	if tok.Type != LUKSFIDO2TokenType {
		t.Fatalf("token type = %q, want %q", tok.Type, LUKSFIDO2TokenType)
	}
	if tok.CredentialID != credID {
		t.Fatalf("credential id mismatch")
	}
	if tok.Salt == "" {
		t.Fatal("salt empty in token")
	}
	if tok.RPID != "example.com" {
		t.Fatalf("rp id = %q, want example.com", tok.RPID)
	}
}

func TestLUKSFIDO2Handler_EnrollCredential_ReturnsKeyOnly(t *testing.T) {
	stub := newStubXKMSFIDO2Handler(nil)
	h, _ := NewLUKSFIDO2Handler(nil, stub, "example.com")

	credID := hex.EncodeToString([]byte("another-cred"))
	key, err := h.EnrollCredential(context.Background(), credID, false, false)
	if err != nil {
		t.Fatalf("EnrollCredential: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestLUKSFIDO2Handler_InvalidCredentialID(t *testing.T) {
	stub := newStubXKMSFIDO2Handler(nil)
	h, _ := NewLUKSFIDO2Handler(nil, stub, "example.com")

	_, err := h.DeriveEnroll(context.Background(), "", false, false)
	if !errors.Is(err, ErrLUKSFIDO2InvalidCredential) {
		t.Fatalf("expected ErrLUKSFIDO2InvalidCredential, got %v", err)
	}
}

func TestLUKSFIDO2Handler_InvalidToken(t *testing.T) {
	stub := newStubXKMSFIDO2Handler(nil)
	h, _ := NewLUKSFIDO2Handler(nil, stub, "example.com")

	_, err := h.DeriveUnlock(context.Background(), []byte("not-json"))
	if !errors.Is(err, ErrLUKSFIDO2InvalidToken) {
		t.Fatalf("expected ErrLUKSFIDO2InvalidToken, got %v", err)
	}
}

func TestLUKSFIDO2Handler_ContextCancelledDuringDerive(t *testing.T) {
	stub := newStubXKMSFIDO2Handler(nil)
	stub.blockUntil = make(chan struct{})
	defer close(stub.blockUntil) // release the goroutine when test exits
	h, _ := NewLUKSFIDO2Handler(nil, stub, "example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	credID := hex.EncodeToString([]byte("slow-credential"))
	_, err := h.DeriveEnroll(ctx, credID, false, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestDecodeCredentialID_AcceptsMultipleEncodings(t *testing.T) {
	raw := []byte("cred-bytes")
	for _, enc := range []struct {
		name string
		in   string
	}{
		{"hex", hex.EncodeToString(raw)},
		{"stdb64", "Y3JlZC1ieXRlcw=="},
		{"rawb64", "Y3JlZC1ieXRlcw"},
	} {
		got, err := decodeCredentialID(enc.in)
		if err != nil {
			t.Fatalf("decodeCredentialID(%s): %v", enc.name, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("decodeCredentialID(%s) = %x, want %x", enc.name, got, raw)
		}
	}
}

func TestDecodeCredentialID_Empty(t *testing.T) {
	if _, err := decodeCredentialID(""); !errors.Is(err, ErrLUKSFIDO2InvalidCredential) {
		t.Fatalf("expected ErrLUKSFIDO2InvalidCredential, got %v", err)
	}
}
