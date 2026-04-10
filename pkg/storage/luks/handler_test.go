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

func TestNewCryptsetupHandler(t *testing.T) {
	handler, err := NewCryptsetupHandler(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewCryptsetupHandlerWithConfig(t *testing.T) {
	config := &Config{
		XKMSPath: "/test/path",
		Debug:    true,
	}
	handler, err := NewCryptsetupHandler(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewCryptsetupHandlerImpl(t *testing.T) {
	handler, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	// Verify it implements both interfaces
	var _ Handler = handler
	var _ = handler
}

func TestNewCryptsetupHandlerWithTokens(t *testing.T) {
	handler, err := NewCryptsetupHandlerWithTokens(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	// Verify it implements both interfaces
	var _ Handler = handler
	var _ = handler
	var _ TokenHandler = handler
}

func TestCryptsetupHandlerIsLUKS(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test with non-existent device - should return false, nil error
	isLuks, err := handler.IsLUKS(ctx, "/dev/nonexistent-device-test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if isLuks {
		t.Error("expected false for non-existent device")
	}
}

func TestCryptsetupHandlerFormat(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test with nil options
	err := handler.Format(ctx, "/dev/nonexistent", []byte("password"), nil)
	if err == nil {
		t.Error("expected error for non-existent device")
	}

	// Test with full options
	opts := &FormatOptions{
		Label:          "test-label",
		Subsystem:      "test-subsystem",
		Cipher:         "aes",
		CipherMode:     "xts-plain64",
		KeySize:        512,
		HashAlgo:       "sha256",
		HashAlgorithm:  "sha512", // Test alias
		SectorSize:     512,
		KDFType:        "argon2id",
		PBKDFType:      "pbkdf2", // Test alias
		PBKDFIterTime:  2000,
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	err = handler.Format(ctx, "/dev/nonexistent", []byte("password"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerAddKey(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Test with nil options
	err := handler.AddKey(ctx, "/dev/nonexistent", []byte("old"), []byte("new"), nil)
	if err == nil {
		t.Error("expected error for non-existent device")
	}

	// Test with KeySlot option
	keyslot := 1
	opts := &AddKeyOptions{
		KeySlot: &keyslot,
	}
	err = handler.AddKey(ctx, "/dev/nonexistent", []byte("old"), []byte("new"), opts)
	if err == nil {
		t.Error("expected error for non-existent device")
	}

	// Test with Keyslot alias
	opts2 := &AddKeyOptions{
		Keyslot: &keyslot,
	}
	err = handler.AddKey(ctx, "/dev/nonexistent", []byte("old"), []byte("new"), opts2)
	if err == nil {
		t.Error("expected error for non-existent device")
	}

	// Test with KDF and Hash options
	opts3 := &AddKeyOptions{
		KDFType: "argon2id",
		Hash:    "sha256",
	}
	err = handler.AddKey(ctx, "/dev/nonexistent", []byte("old"), []byte("new"), opts3)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerOpen(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.Open(ctx, "/dev/nonexistent", "test-mapping", []byte("password"), nil)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerClose(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.Close(ctx, "nonexistent-mapping")
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestCryptsetupHandlerStatus(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	status, err := handler.Status(ctx, "/dev/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if status != nil {
		t.Error("expected nil status on error")
	}
}

func TestCryptsetupHandlerVersion(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	version, err := handler.Version(ctx, "/dev/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if version != 0 {
		t.Errorf("expected version 0 on error, got %d", version)
	}
}

func TestCryptsetupHandlerRemoveKey(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.RemoveKey(ctx, "/dev/nonexistent", 0)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerKillSlot(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.KillSlot(ctx, "/dev/nonexistent", 0)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerChangeKey(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.ChangeKey(ctx, "/dev/nonexistent", 0, []byte("old"), []byte("new"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerUUID(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	uuid, err := handler.UUID(ctx, "/dev/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if uuid != "" {
		t.Error("expected empty UUID on error")
	}
}

func TestCryptsetupHandlerDumpHeader(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	header, err := handler.DumpHeader(ctx, "/dev/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if header != nil {
		t.Error("expected nil header on error")
	}
}

func TestCryptsetupHandlerTestKey(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	err := handler.TestKey(ctx, "/dev/nonexistent", []byte("password"), nil)
	if err == nil {
		t.Error("expected error for non-existent device")
	}

	// Test with specific slot
	slot := 0
	err = handler.TestKey(ctx, "/dev/nonexistent", []byte("password"), &slot)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestCryptsetupHandlerResize(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Resize is not yet implemented
	err := handler.Resize(ctx, "test-mapping", nil)
	if err == nil {
		t.Error("expected error for unimplemented feature")
	}
	if err.Error() != "resize not yet implemented in go-luks2" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCryptsetupHandlerSuspend(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Suspend is not yet implemented
	err := handler.Suspend(ctx, "test-mapping")
	if err == nil {
		t.Error("expected error for unimplemented feature")
	}
	if err.Error() != "suspend not yet implemented in go-luks2" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCryptsetupHandlerResume(t *testing.T) {
	handler, _ := NewCryptsetupHandlerImpl(nil, nil)
	ctx := context.Background()

	// Resume is not yet implemented
	err := handler.Resume(ctx, "test-mapping", []byte("password"))
	if err == nil {
		t.Error("expected error for unimplemented feature")
	}
	if err.Error() != "resume not yet implemented in go-luks2" {
		t.Errorf("unexpected error message: %v", err)
	}
}
