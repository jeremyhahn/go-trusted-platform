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
	"errors"
	"testing"
)

func TestTokenConstants(t *testing.T) {
	t.Parallel()

	t.Run("MaxTokenSlots", func(t *testing.T) {
		if MaxTokenSlots != 32 {
			t.Errorf("MaxTokenSlots = %d, want 32", MaxTokenSlots)
		}
	})

	t.Run("TokenTypeConstants", func(t *testing.T) {
		tests := []struct {
			name     string
			constant string
			want     string
		}{
			{"FIDO2", TokenTypeFIDO2, "fido2"},
			{"TPM2", TokenTypeTPM2, "systemd-tpm2"},
			{"Platform", TokenTypePlatform, "platform"},
			{"Keyring", TokenTypeKeyring, "keyring"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.constant != tt.want {
					t.Errorf("TokenType%s = %q, want %q", tt.name, tt.constant, tt.want)
				}
			})
		}
	})
}

func TestTokenConversion(t *testing.T) {
	t.Parallel()

	t.Run("RoundTrip", func(t *testing.T) {
		original := &Token{
			Type:            TokenTypeFIDO2,
			Keyslots:        []string{"0", "2"},
			FIDO2Credential: "cred123",
			FIDO2Salt:       "salt456",
			FIDO2RP:         "test.example.com",
			FIDO2UPRequired: true,
		}

		luksToken := tokenToLUKS(original)
		converted := tokenFromLUKS(luksToken)

		if converted.Type != original.Type {
			t.Errorf("Type = %q, want %q", converted.Type, original.Type)
		}
		if len(converted.Keyslots) != len(original.Keyslots) {
			t.Errorf("Keyslots length = %d, want %d", len(converted.Keyslots), len(original.Keyslots))
		}
		for i, ks := range converted.Keyslots {
			if ks != original.Keyslots[i] {
				t.Errorf("Keyslots[%d] = %q, want %q", i, ks, original.Keyslots[i])
			}
		}
		if converted.FIDO2Credential != original.FIDO2Credential {
			t.Errorf("FIDO2Credential = %q, want %q", converted.FIDO2Credential, original.FIDO2Credential)
		}
		if converted.FIDO2Salt != original.FIDO2Salt {
			t.Errorf("FIDO2Salt = %q, want %q", converted.FIDO2Salt, original.FIDO2Salt)
		}
		if converted.FIDO2RP != original.FIDO2RP {
			t.Errorf("FIDO2RP = %q, want %q", converted.FIDO2RP, original.FIDO2RP)
		}
		if converted.FIDO2UPRequired != original.FIDO2UPRequired {
			t.Errorf("FIDO2UPRequired = %v, want %v", converted.FIDO2UPRequired, original.FIDO2UPRequired)
		}
	})

	t.Run("TPM2RoundTrip", func(t *testing.T) {
		original := &Token{
			Type:           TokenTypeTPM2,
			Keyslots:       []string{"1"},
			TPM2Hash:       "sha256",
			TPM2PolicyHash: "policy",
			TPM2PCRBank:    "sha256",
			TPM2PCRs:       []int{0, 7, 14},
			TPM2Blob:       "blob-data",
			TPM2PublicKey:  "pub-key",
			TPM2SRKNV:      "srk-nv",
			TPM2KeyHandle:  0x81010001,
		}

		luksToken := tokenToLUKS(original)
		converted := tokenFromLUKS(luksToken)

		if converted.TPM2Hash != original.TPM2Hash {
			t.Errorf("TPM2Hash = %q, want %q", converted.TPM2Hash, original.TPM2Hash)
		}
		if converted.TPM2PolicyHash != original.TPM2PolicyHash {
			t.Errorf("TPM2PolicyHash = %q, want %q", converted.TPM2PolicyHash, original.TPM2PolicyHash)
		}
		if converted.TPM2PCRBank != original.TPM2PCRBank {
			t.Errorf("TPM2PCRBank = %q, want %q", converted.TPM2PCRBank, original.TPM2PCRBank)
		}
		if len(converted.TPM2PCRs) != len(original.TPM2PCRs) {
			t.Errorf("TPM2PCRs length = %d, want %d", len(converted.TPM2PCRs), len(original.TPM2PCRs))
		}
		for i, pcr := range converted.TPM2PCRs {
			if pcr != original.TPM2PCRs[i] {
				t.Errorf("TPM2PCRs[%d] = %d, want %d", i, pcr, original.TPM2PCRs[i])
			}
		}
		if converted.TPM2Blob != original.TPM2Blob {
			t.Errorf("TPM2Blob = %q, want %q", converted.TPM2Blob, original.TPM2Blob)
		}
		if converted.TPM2PublicKey != original.TPM2PublicKey {
			t.Errorf("TPM2PublicKey = %q, want %q", converted.TPM2PublicKey, original.TPM2PublicKey)
		}
		if converted.TPM2SRKNV != original.TPM2SRKNV {
			t.Errorf("TPM2SRKNV = %q, want %q", converted.TPM2SRKNV, original.TPM2SRKNV)
		}
		if converted.TPM2KeyHandle != original.TPM2KeyHandle {
			t.Errorf("TPM2KeyHandle = 0x%x, want 0x%x", converted.TPM2KeyHandle, original.TPM2KeyHandle)
		}
	})
}

func TestTokenHandler_ValidationErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	handler, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	t.Run("TokenCreate_NilToken", func(t *testing.T) {
		_, err := handler.TokenCreate(ctx, "/dev/nonexistent", nil)
		if !errors.Is(err, ErrTokenNil) {
			t.Errorf("Expected ErrTokenNil, got: %v", err)
		}
	})

	t.Run("TokenCreate_EmptyType", func(t *testing.T) {
		token := &Token{Keyslots: []string{"0"}}
		_, err := handler.TokenCreate(ctx, "/dev/nonexistent", token)
		if !errors.Is(err, ErrTokenTypeEmpty) {
			t.Errorf("Expected ErrTokenTypeEmpty, got: %v", err)
		}
	})

	t.Run("TokenCreateAt_NilToken", func(t *testing.T) {
		err := handler.TokenCreateAt(ctx, "/dev/nonexistent", 0, nil)
		if !errors.Is(err, ErrTokenNil) {
			t.Errorf("Expected ErrTokenNil, got: %v", err)
		}
	})

	t.Run("TokenCreateAt_EmptyType", func(t *testing.T) {
		token := &Token{Keyslots: []string{"0"}}
		err := handler.TokenCreateAt(ctx, "/dev/nonexistent", 0, token)
		if !errors.Is(err, ErrTokenTypeEmpty) {
			t.Errorf("Expected ErrTokenTypeEmpty, got: %v", err)
		}
	})

	t.Run("TokenCreateAt_InvalidID_Negative", func(t *testing.T) {
		token := &Token{Type: TokenTypePlatform, Keyslots: []string{"0"}}
		err := handler.TokenCreateAt(ctx, "/dev/nonexistent", -1, token)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenCreateAt_InvalidID_TooLarge", func(t *testing.T) {
		token := &Token{Type: TokenTypePlatform, Keyslots: []string{"0"}}
		err := handler.TokenCreateAt(ctx, "/dev/nonexistent", MaxTokenSlots, token)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenRead_InvalidID_Negative", func(t *testing.T) {
		_, err := handler.TokenRead(ctx, "/dev/nonexistent", -1)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenRead_InvalidID_TooLarge", func(t *testing.T) {
		_, err := handler.TokenRead(ctx, "/dev/nonexistent", 100)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenDelete_InvalidID_Negative", func(t *testing.T) {
		err := handler.TokenDelete(ctx, "/dev/nonexistent", -5)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenUpdate_NilToken", func(t *testing.T) {
		err := handler.TokenUpdate(ctx, "/dev/nonexistent", 0, nil)
		if !errors.Is(err, ErrTokenNil) {
			t.Errorf("Expected ErrTokenNil, got: %v", err)
		}
	})

	t.Run("TokenUpdate_EmptyType", func(t *testing.T) {
		token := &Token{Keyslots: []string{"0"}}
		err := handler.TokenUpdate(ctx, "/dev/nonexistent", 0, token)
		if !errors.Is(err, ErrTokenTypeEmpty) {
			t.Errorf("Expected ErrTokenTypeEmpty, got: %v", err)
		}
	})

	t.Run("TokenUpdate_InvalidID", func(t *testing.T) {
		token := &Token{Type: TokenTypePlatform, Keyslots: []string{"0"}}
		err := handler.TokenUpdate(ctx, "/dev/nonexistent", -1, token)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})

	t.Run("TokenExists_InvalidID", func(t *testing.T) {
		_, err := handler.TokenExists(ctx, "/dev/nonexistent", 50)
		var invalidIDErr *TokenInvalidIDError
		if !errors.As(err, &invalidIDErr) {
			t.Errorf("Expected TokenInvalidIDError, got: %v", err)
		}
	})
}

func TestTokenHandler_InterfaceImplementation(t *testing.T) {
	t.Parallel()

	handler, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Verify CryptsetupHandler implements all interfaces
	var _ TokenHandler = handler
	var _ Handler = handler
	var _ HandlerWithTokens = handler
}
