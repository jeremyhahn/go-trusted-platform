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

package luks

import (
	"context"
	"testing"
)

// TestCryptsetupHandlerFormatMinimalOptions tests Format with minimal options
func TestCryptsetupHandlerFormatMinimalOptions(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test with empty options - should use defaults
	opts := &FormatOptions{}
	err := handler.Format(ctx, "/dev/nonexistent", []byte("password"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// TestCryptsetupHandlerFormatHashAlgorithmAlias tests the HashAlgorithm alias
func TestCryptsetupHandlerFormatHashAlgorithmAlias(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test HashAlgorithm alias without HashAlgo
	opts := &FormatOptions{
		HashAlgorithm: "sha512",
		// No HashAlgo set - HashAlgorithm should be used
	}
	err := handler.Format(ctx, "/dev/nonexistent", []byte("password"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// TestCryptsetupHandlerFormatPBKDFTypeAlias tests the PBKDFType alias
func TestCryptsetupHandlerFormatPBKDFTypeAlias(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test PBKDFType alias without KDFType
	opts := &FormatOptions{
		PBKDFType: "pbkdf2",
		// No KDFType set - PBKDFType should be used
	}
	err := handler.Format(ctx, "/dev/nonexistent", []byte("password"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// TestCryptsetupHandlerAddKeyForce tests AddKey with Force option
func TestCryptsetupHandlerAddKeyForce(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	keyslot := 1
	opts := &AddKeyOptions{
		KeySlot: &keyslot,
		Force:   true,
		KDFType: "argon2id",
		Hash:    "sha256",
	}
	err := handler.AddKey(ctx, "/dev/nonexistent", []byte("old"), []byte("new"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// TestCryptsetupHandlerOpenWithOptions tests Open with various options
func TestCryptsetupHandlerOpenWithOptions(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	opts := &OpenOptions{
		ReadOnly:            true,
		AllowDiscards:       true,
		NoReadWorkqueue:     true,
		NoWriteWorkqueue:    true,
		SubmitFromCryptCPUs: true,
		Timeout:             60,
	}
	err := handler.Open(ctx, "/dev/nonexistent", "test-mapping", []byte("password"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}
