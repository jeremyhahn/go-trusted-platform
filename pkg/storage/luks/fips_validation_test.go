// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package luks

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// The FIPS-activated behaviour itself is covered in pkg/fips, which can control
// the kernel indicator. What must be proven HERE is that the keyslot paths
// actually CALL the validator — before this change ValidateKDF/ValidateHash
// existed but had zero callers, so the restriction was unenforced everywhere.
//
// An unrecognised algorithm is refused in EVERY mode, so these assertions hold
// regardless of whether the machine running them is FIPS-activated.

func TestAddKey_ValidatesKeyslotAlgorithms(t *testing.T) {
	h := &CryptsetupHandler{}

	t.Run("unknown KDF refused before touching the device", func(t *testing.T) {
		err := h.AddKey(context.Background(), "/nonexistent-device", []byte("old"), []byte("new"),
			&AddKeyOptions{KDFType: "scrypt"})
		var unknown fips.ErrUnknownKDF
		if !errors.As(err, &unknown) {
			t.Fatalf("expected ErrUnknownKDF from the keyslot path, got %T: %v", err, err)
		}
	})

	t.Run("unknown hash refused before touching the device", func(t *testing.T) {
		err := h.AddKey(context.Background(), "/nonexistent-device", []byte("old"), []byte("new"),
			&AddKeyOptions{Hash: "md5"})
		var unknown fips.ErrUnknownHash
		if !errors.As(err, &unknown) {
			t.Fatalf("expected ErrUnknownHash from the keyslot path, got %T: %v", err, err)
		}
	})
}

func TestFormat_ValidatesKeyslotAlgorithms(t *testing.T) {
	h := &CryptsetupHandler{}

	err := h.Format(context.Background(), "/nonexistent-device", []byte("pw"),
		&FormatOptions{KDFType: "scrypt"})
	var unknown fips.ErrUnknownKDF
	if !errors.As(err, &unknown) {
		t.Fatalf("expected ErrUnknownKDF from the format path, got %T: %v", err, err)
	}
}
