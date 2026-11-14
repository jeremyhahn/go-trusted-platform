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

package initrd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewFIDO2Strategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewFIDO2Strategy returned nil")
	}

	if strategy.Name() != "FIDO2" {
		t.Errorf("expected name FIDO2, got %s", strategy.Name())
	}

	if strategy.Priority() != 3 {
		t.Errorf("expected priority 3, got %d", strategy.Priority())
	}
}

func TestFIDO2StrategyUnlockNoFIDO2Slots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error when no FIDO2 slots")
	}
}

func TestFIDO2StrategyUnlockContextCanceled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockFIDO2},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestFIDO2StrategyInstallNoHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.FIDO2 = nil

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockFIDO2},
		},
	}

	err := strategy.Install(ctx, volume, []byte("password"))
	if err == nil {
		t.Error("expected error when FIDO2 handler is nil")
	}
}

func TestFIDO2StrategyInstallNoFIDO2Slot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Install(ctx, volume, []byte("password"))
	if err == nil {
		t.Error("expected error when no FIDO2 key slot configured")
	}
}

func TestFIDO2StrategyLoadAuthConfigNeedsTokens(t *testing.T) {
	strategy := NewFIDO2Strategy(createTestPlatform(), logging.DefaultLogger())

	_, err := strategy.loadAuthConfig(context.Background(), "/dev/sda2", luks.KeySlot{Index: 0, Type: luks.UnlockFIDO2})
	if !errors.Is(err, ErrFIDO2TokensUnsupported) {
		t.Fatalf("loadAuthConfig = %v, want ErrFIDO2TokensUnsupported", err)
	}
}

func TestFIDO2StrategyLoadAuthConfigFromToken(t *testing.T) {
	platform := createTestPlatform()
	tl := newTokenLUKS(platform.LUKS.(*MockLUKSHandler))
	platform.LUKS = tl
	credentialID := []byte{0xde, 0xad, 0xbe, 0xef}
	salt := bytes.Repeat([]byte{0x5a}, 32)
	tl.tokens[0] = &luks.Token{Type: "fido2-manual", Keyslots: []string{"1"}, FIDO2Credential: "ignored-other-slot", FIDO2Salt: "x"}
	tl.tokens[3] = &luks.Token{
		Type:            "fido2-manual",
		Keyslots:        []string{"5"},
		FIDO2Credential: base64.StdEncoding.EncodeToString(credentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(salt),
		FIDO2UPRequired: true,
	}
	strategy := NewFIDO2Strategy(platform, logging.DefaultLogger())

	config, err := strategy.loadAuthConfig(context.Background(), "/dev/sda2", luks.KeySlot{Index: 5, Type: luks.UnlockFIDO2})
	if err != nil {
		t.Fatalf("loadAuthConfig: %v", err)
	}
	if !bytes.Equal(config.CredentialID, credentialID) || !bytes.Equal(config.Salt, salt) {
		t.Errorf("config credential/salt = %x/%x, want %x/%x", config.CredentialID, config.Salt, credentialID, salt)
	}
	if config.RelyingPartyID != "luks-root" || !config.RequireUserVerification || config.Timeout == 0 {
		t.Errorf("config = %+v, want luks-root, user verification and a timeout", config)
	}

	if _, err := strategy.loadAuthConfig(context.Background(), "/dev/sda2", luks.KeySlot{Index: 7, Type: luks.UnlockFIDO2}); !errors.Is(err, ErrFIDO2TokenMissing) {
		t.Errorf("loadAuthConfig(slot 7) = %v, want ErrFIDO2TokenMissing", err)
	}
	tl.tokens[4] = &luks.Token{Type: "fido2-manual", Keyslots: []string{"8"}, FIDO2Credential: "abcd", FIDO2Salt: "!!"}
	if _, err := strategy.loadAuthConfig(context.Background(), "/dev/sda2", luks.KeySlot{Index: 8, Type: luks.UnlockFIDO2}); !errors.Is(err, ErrFIDO2TokenInvalid) {
		t.Errorf("loadAuthConfig(slot 8) = %v, want ErrFIDO2TokenInvalid", err)
	}
}
