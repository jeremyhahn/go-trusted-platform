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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// The PIV service-layer requests carry PIN and private-key material in a
// MemoryEnclave. These tests pin the two properties the migration promises:
// the protected field is preferred, and the deprecated plain field still
// works for callers that have not migrated.

func TestPIVGenerateRequest_WithPIN_PrefersEnclave(t *testing.T) {
	req := &PIVGenerateRequest{
		PIN:        "plain-should-lose",
		PINEnclave: memguard.NewMemoryEnclaveFromString("123456"),
	}
	defer req.Destroy()

	var got string
	if err := req.WithPIN(func(pin string) error {
		got = pin
		return nil
	}); err != nil {
		t.Fatalf("WithPIN: %v", err)
	}
	if got != "123456" {
		t.Errorf("WithPIN saw %q, want the enclave value %q", got, "123456")
	}
}

func TestPIVGenerateRequest_WithPIN_FallsBackAndPropagatesError(t *testing.T) {
	req := &PIVGenerateRequest{PIN: "654321"}

	sentinel := errors.New("boom")
	var got string
	err := req.WithPIN(func(pin string) error {
		got = pin
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Errorf("WithPIN err = %v, want %v", err, sentinel)
	}
	if got != "654321" {
		t.Errorf("WithPIN saw %q, want the deprecated plain value %q", got, "654321")
	}
}

func TestPIVSignRequest_WithPIN_PrefersEnclave(t *testing.T) {
	req := &PIVSignRequest{
		PIN:        "plain-should-lose",
		PINEnclave: memguard.NewMemoryEnclaveFromString("sign-pin"),
	}
	defer req.Destroy()

	var got string
	if err := req.WithPIN(func(pin string) error {
		got = pin
		return nil
	}); err != nil {
		t.Fatalf("WithPIN: %v", err)
	}
	if got != "sign-pin" {
		t.Errorf("WithPIN saw %q, want %q", got, "sign-pin")
	}
}

func TestPIVSignRequest_WithPIN_DestroyedEnclaveFallsBack(t *testing.T) {
	// Destroy leaves no live enclave, so the request must fall back to the
	// deprecated plain field rather than silently signing with an empty PIN.
	req := &PIVSignRequest{
		PIN:        "fallback-pin",
		PINEnclave: memguard.NewMemoryEnclaveFromString("sign-pin"),
	}
	req.Destroy()

	var got string
	if err := req.WithPIN(func(pin string) error {
		got = pin
		return nil
	}); err != nil {
		t.Fatalf("WithPIN: %v", err)
	}
	if got != "fallback-pin" {
		t.Errorf("WithPIN saw %q, want %q", got, "fallback-pin")
	}
}

func TestPIVImportRequest_WithPrivateKeyPEM_PrefersEnclave(t *testing.T) {
	req := &PIVImportRequest{
		PrivateKeyPEM: "plain-should-lose",
		PrivateKey:    memguard.NewMemoryEnclaveFromString("-----BEGIN PRIVATE KEY-----"),
		PINEnclave:    memguard.NewMemoryEnclaveFromString("111111"),
	}
	defer req.Destroy()

	if !req.HasPrivateKey() {
		t.Fatal("HasPrivateKey() = false with a populated enclave")
	}
	var got string
	if err := req.WithPrivateKeyPEM(func(pem []byte) error {
		got = string(pem)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKeyPEM: %v", err)
	}
	if got != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("WithPrivateKeyPEM saw %q, want the enclave value", got)
	}
}

func TestPIVImportRequest_WithPrivateKeyPEM_FallsBackAndPropagatesError(t *testing.T) {
	req := &PIVImportRequest{PrivateKeyPEM: "legacy-pem"}

	if !req.HasPrivateKey() {
		t.Fatal("HasPrivateKey() = false with the deprecated field set")
	}
	sentinel := errors.New("boom")
	var got string
	err := req.WithPrivateKeyPEM(func(pem []byte) error {
		got = string(pem)
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Errorf("WithPrivateKeyPEM err = %v, want %v", err, sentinel)
	}
	if got != "legacy-pem" {
		t.Errorf("WithPrivateKeyPEM saw %q, want %q", got, "legacy-pem")
	}
}

func TestPIVImportRequest_HasPrivateKey_EmptyEnclaveIsMissingKey(t *testing.T) {
	// An empty-but-live enclave is how the transports encode "the client
	// sent no key"; the service must still reject it.
	req := &PIVImportRequest{
		Slot:       "9a",
		PrivateKey: memguard.NewMemoryEnclaveFromString(""),
	}
	defer req.Destroy()

	if req.HasPrivateKey() {
		t.Error("HasPrivateKey() = true for an empty enclave")
	}

	svc := NewPIVService(logging.DefaultLogger(), &fakePIVBackend{})
	if err := svc.Import(context.Background(), req); !errors.Is(err, ErrPIVPrivateKeyRequired) {
		t.Errorf("Import err = %v, want ErrPIVPrivateKeyRequired", err)
	}
}

func TestPIVRequests_DestroyIsIdempotentAndNilSafe(t *testing.T) {
	// Handlers defer Destroy on requests that may carry no enclave at all
	// (deprecated plain-field callers); it must not panic, and repeating it
	// on a populated request must not panic either.
	gen := &PIVGenerateRequest{}
	imp := &PIVImportRequest{}
	sign := &PIVSignRequest{}
	gen.Destroy()
	imp.Destroy()
	sign.Destroy()

	populated := &PIVImportRequest{
		PrivateKey: memguard.NewMemoryEnclaveFromString("key"),
		PINEnclave: memguard.NewMemoryEnclaveFromString("pin"),
	}
	populated.Destroy()
	populated.Destroy()

	if populated.PrivateKey.IsAlive() || populated.PINEnclave.IsAlive() {
		t.Error("Destroy left an enclave alive")
	}
}
