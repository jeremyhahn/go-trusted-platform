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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestLUKSBackend_NonLUKSDevice(t *testing.T) {
	// Any non-LUKS device (e.g. /dev/null) should surface an error rather
	// than panic or silently succeed. This exercises the go-luks2 header
	// read path without needing a loopback setup.
	b := NewLUKSBackend(logging.DefaultLogger())

	_, err := b.Status(context.Background(), "/dev/null")
	if err == nil {
		t.Fatalf("expected error for non-LUKS device, got nil")
	}
}

func TestLUKSBackend_EnrollFIDO2_NoHandler(t *testing.T) {
	b := NewLUKSBackend(logging.DefaultLogger())
	_, err := b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
		Device:             "/tmp/nonexistent",
		ExistingPassphrase: "old",
		CredentialID:       "cred",
	})
	if !errors.Is(err, ErrLUKSFIDO2NotWired) {
		t.Fatalf("expected ErrLUKSFIDO2NotWired, got %v", err)
	}
}

func TestLUKSBackend_EnrollTPM_NoHandler(t *testing.T) {
	b := NewLUKSBackend(logging.DefaultLogger())
	_, err := b.EnrollTPM(context.Background(), &daemon.LUKSEnrollTPMRequest{
		Device:             "/tmp/nonexistent",
		ExistingPassphrase: "old",
	})
	if !errors.Is(err, ErrLUKSTPMNotWired) {
		t.Fatalf("expected ErrLUKSTPMNotWired, got %v", err)
	}
}

func TestLUKSBackend_EnrollTPM_SealErrorSurfaces(t *testing.T) {
	b := NewLUKSBackend(logging.DefaultLogger(), WithLUKSTPMHandler(failingTPMHandler{err: ErrLUKSTPMPCRSelectionNotSupported}))
	_, err := b.EnrollTPM(context.Background(), &daemon.LUKSEnrollTPMRequest{
		Device:             "/tmp/nonexistent",
		ExistingPassphrase: "old",
		PCRs:               []int32{7},
	})
	if !errors.Is(err, ErrLUKSTPMPCRSelectionNotSupported) {
		t.Fatalf("expected ErrLUKSTPMPCRSelectionNotSupported, got %v", err)
	}
}

func TestLUKSBackend_SetHandlers(t *testing.T) {
	b := NewLUKSBackend(logging.DefaultLogger())
	b.SetFIDO2Handler(fakeFIDO2Handler{})
	b.SetTPMHandler(fakeTPMHandler{})
	if b.fido2 == nil {
		t.Fatal("FIDO2 handler not set")
	}
	if b.tpm == nil {
		t.Fatal("TPM handler not set")
	}
	// Calling SetX(nil) disables the handler again.
	b.SetFIDO2Handler(nil)
	b.SetTPMHandler(nil)
	if b.fido2 != nil || b.tpm != nil {
		t.Fatal("handlers not cleared")
	}
}

func TestLUKSBackend_ImplementsInterface(t *testing.T) {
	var _ daemon.LUKSBackend = (*LUKSBackend)(nil)
}

func TestDefaultRootChecker(t *testing.T) {
	rc := DefaultRootChecker()
	if rc == nil {
		t.Fatal("expected non-nil RootChecker")
	}
	// Just exercising the method to ensure it returns a stable bool without
	// panicking. The actual value depends on test-runner uid.
	_ = rc.IsRoot()
}

func TestClearBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	clearBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, expected 0", i, v)
		}
	}
}

type fakeFIDO2Handler struct{}

func (fakeFIDO2Handler) EnrollCredential(ctx context.Context, credentialID string, requirePIN, requireUV bool) ([]byte, error) {
	return make([]byte, 32), nil
}

type fakeTPMHandler struct{}

func (fakeTPMHandler) SealPassphrase(ctx context.Context, pcrs []int32) (*LUKSTPMSealResult, error) {
	return &LUKSTPMSealResult{}, nil
}

// failingTPMHandler returns err from every seal.
type failingTPMHandler struct{ err error }

func (h failingTPMHandler) SealPassphrase(ctx context.Context, pcrs []int32) (*LUKSTPMSealResult, error) {
	return nil, h.err
}
