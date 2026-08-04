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
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// emptyEnumerator is a stub HID enumerator that reports zero devices. It lets
// the FIDO2 backend run its handler logic without requiring real hardware or
// depending on go-xkms's internal test fixtures.
type emptyEnumerator struct{}

func (emptyEnumerator) Enumerate(vendorID, productID uint16) ([]fido2.HIDDevice, error) {
	return nil, nil
}

func (emptyEnumerator) Open(path string) (fido2.HIDDevice, error) {
	return nil, errors.New("stub enumerator: no devices")
}

func newTestFIDO2Backend(t *testing.T) *FIDO2Backend {
	t.Helper()
	b, err := NewFIDO2Backend(logging.DefaultLogger(), nil, emptyEnumerator{})
	if err != nil {
		t.Fatalf("NewFIDO2Backend: %v", err)
	}
	return b
}

func TestFIDO2Backend_ListDevices_Empty(t *testing.T) {
	b := newTestFIDO2Backend(t)
	defer b.Close()

	devs, err := b.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devs))
	}
}

func TestFIDO2Backend_WaitDevice_TimesOut(t *testing.T) {
	b := newTestFIDO2Backend(t)
	defer b.Close()

	// With no devices present, WaitDevice must respect the timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := b.WaitDevice(ctx, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error from WaitDevice timeout, got nil")
	}
}

func TestFIDO2Backend_Info_NotFound(t *testing.T) {
	b := newTestFIDO2Backend(t)
	defer b.Close()

	_, err := b.Info(context.Background(), "missing-device")
	if !errors.Is(err, ErrFIDO2DeviceNotFound) {
		t.Fatalf("expected ErrFIDO2DeviceNotFound, got %v", err)
	}
}

func TestFIDO2Backend_Authenticate_NoCredStore(t *testing.T) {
	b := newTestFIDO2Backend(t)
	defer b.Close()

	_, err := b.Authenticate(context.Background(), "cred-id")
	if !errors.Is(err, ErrFIDO2AuthenticateNotWired) {
		t.Fatalf("expected ErrFIDO2AuthenticateNotWired, got %v", err)
	}
}

func TestFIDO2Backend_SetCredentialStore(t *testing.T) {
	b := newTestFIDO2Backend(t)
	defer b.Close()

	store := &fakeCredStore{}
	b.SetCredentialStore(store)
	if b.credStore == nil {
		t.Fatal("credential store not set")
	}
}

func TestFIDO2Backend_ImplementsInterface(t *testing.T) {
	var _ daemon.FIDO2Backend = (*FIDO2Backend)(nil)
}

func TestCopyFIDO2Options(t *testing.T) {
	src := map[string]bool{"rk": true, "uv": false}
	out := copyFIDO2Options(src)
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	// Mutation of copy must not affect the source.
	out["rk"] = false
	if !src["rk"] {
		t.Fatal("mutation of copy affected source")
	}
	if copyFIDO2Options(nil) != nil {
		t.Fatal("nil input should produce nil output")
	}
}

type fakeCredStore struct{}

func (fakeCredStore) LookupCredential(ctx context.Context, credentialID string) (*FIDO2CredentialRecord, error) {
	return nil, nil
}
