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
	"encoding/json"

	goluks "github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// MaxTokenSlots is the maximum number of token slots in LUKS2
const MaxTokenSlots = 32

// Token type constants for LUKS2 token metadata
const (
	// TokenTypeFIDO2 is a FIDO2 security key token
	TokenTypeFIDO2 = "fido2"

	// TokenTypeTPM2 is a TPM2 sealed key token (systemd-tpm2 format)
	TokenTypeTPM2 = "systemd-tpm2"

	// TokenTypePlatform is a platform-specific token for go-trusted-platform
	TokenTypePlatform = "platform"

	// TokenTypeKeyring is a kernel keyring token
	TokenTypeKeyring = "keyring"
)

// Token represents LUKS2 token metadata for storing unlock information.
// The format is compatible with LUKS2's JSON token metadata structure.
type Token struct {
	// Type identifies the token handler (e.g., "fido2", "systemd-tpm2", "platform")
	Type string `json:"type"`

	// Keyslots contains the list of keyslot IDs this token can unlock
	Keyslots []string `json:"keyslots"`

	// TokenData contains type-specific data as raw JSON
	TokenData json.RawMessage `json:"token_data,omitempty"`

	// FIDO2 fields (for type "fido2")
	FIDO2Credential string `json:"fido2-credential,omitempty"`
	FIDO2Salt       string `json:"fido2-salt,omitempty"`
	FIDO2RP         string `json:"fido2-rp,omitempty"`
	FIDO2UPRequired bool   `json:"fido2-up-required,omitempty"`

	// TPM2 fields (for type "systemd-tpm2")
	TPM2Hash       string `json:"tpm2-hash,omitempty"`
	TPM2PolicyHash string `json:"tpm2-policy-hash,omitempty"`
	TPM2PCRBank    string `json:"tpm2-pcr-bank,omitempty"`
	TPM2PCRs       []int  `json:"tpm2-pcrs,omitempty"`
	TPM2Blob       string `json:"tpm2-blob,omitempty"`
	TPM2PublicKey  string `json:"tpm2-pubkey,omitempty"`
	TPM2SRKNV      string `json:"tpm2-srk-nv,omitempty"`
	TPM2KeyHandle  uint64 `json:"tpm2-key-handle,omitempty"`
}

// TokenHandler defines operations for LUKS2 token metadata management.
// Tokens store information about how to unlock keyslots without storing
// the actual encryption keys.
type TokenHandler interface {
	// TokenCreate creates a new token at the first available slot
	TokenCreate(ctx context.Context, devicePath string, token *Token) (int, error)

	// TokenCreateAt creates a new token at a specific slot ID
	TokenCreateAt(ctx context.Context, devicePath string, tokenID int, token *Token) error

	// TokenRead reads a token by ID
	TokenRead(ctx context.Context, devicePath string, tokenID int) (*Token, error)

	// TokenDelete deletes a token by ID
	TokenDelete(ctx context.Context, devicePath string, tokenID int) error

	// TokenUpdate updates an existing token's data
	TokenUpdate(ctx context.Context, devicePath string, tokenID int, token *Token) error

	// TokenList returns all tokens from the device
	TokenList(ctx context.Context, devicePath string) (map[int]*Token, error)

	// TokenExists checks if a token exists at the specified slot
	TokenExists(ctx context.Context, devicePath string, tokenID int) (bool, error)

	// TokenCount returns the number of tokens in the LUKS2 header
	TokenCount(ctx context.Context, devicePath string) (int, error)
}

// Ensure CryptsetupHandler implements TokenHandler
var _ TokenHandler = (*CryptsetupHandler)(nil)

// TokenCreate creates a new token at the first available slot.
// Returns the token ID of the newly created token.
func (h *CryptsetupHandler) TokenCreate(ctx context.Context, devicePath string, token *Token) (int, error) {
	if token == nil {
		return -1, ErrTokenNil
	}

	if token.Type == "" {
		return -1, ErrTokenTypeEmpty
	}

	// Find first available slot
	slotID, err := goluks.FindFreeTokenSlot(devicePath)
	if err != nil {
		if err == goluks.ErrNoFreeTokenSlot {
			return -1, ErrTokenNoFreeSlot
		}
		return -1, &TokenOperationError{Op: "find_free_slot", Err: err}
	}

	// Convert to go-luks2 token format and import
	luksToken := tokenToLUKS(token)
	if err := goluks.ImportToken(devicePath, slotID, luksToken); err != nil {
		return -1, &TokenOperationError{Op: "create", Err: err}
	}

	return slotID, nil
}

// TokenCreateAt creates a new token at a specific slot ID.
// Returns an error if the slot is already occupied.
func (h *CryptsetupHandler) TokenCreateAt(ctx context.Context, devicePath string, tokenID int, token *Token) error {
	if token == nil {
		return ErrTokenNil
	}

	if token.Type == "" {
		return ErrTokenTypeEmpty
	}

	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return &TokenInvalidIDError{ID: tokenID}
	}

	// Check if slot is already occupied
	exists, err := goluks.TokenExists(devicePath, tokenID)
	if err != nil {
		return &TokenOperationError{Op: "check_exists", Err: err}
	}
	if exists {
		return &TokenSlotOccupiedError{ID: tokenID}
	}

	// Convert to go-luks2 token format and import
	luksToken := tokenToLUKS(token)
	if err := goluks.ImportToken(devicePath, tokenID, luksToken); err != nil {
		return &TokenOperationError{Op: "create_at", Err: err}
	}

	return nil
}

// TokenRead reads a token by ID.
func (h *CryptsetupHandler) TokenRead(ctx context.Context, devicePath string, tokenID int) (*Token, error) {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return nil, &TokenInvalidIDError{ID: tokenID}
	}

	luksToken, err := goluks.GetToken(devicePath, tokenID)
	if err != nil {
		if err == goluks.ErrTokenNotFound {
			return nil, &TokenNotFoundError{ID: tokenID}
		}
		return nil, &TokenOperationError{Op: "read", Err: err}
	}

	return tokenFromLUKS(luksToken), nil
}

// TokenDelete deletes a token by ID.
func (h *CryptsetupHandler) TokenDelete(ctx context.Context, devicePath string, tokenID int) error {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return &TokenInvalidIDError{ID: tokenID}
	}

	if err := goluks.RemoveToken(devicePath, tokenID); err != nil {
		if err == goluks.ErrTokenNotFound {
			return &TokenNotFoundError{ID: tokenID}
		}
		return &TokenOperationError{Op: "delete", Err: err}
	}

	return nil
}

// TokenUpdate updates an existing token's data.
// The token at tokenID must already exist.
func (h *CryptsetupHandler) TokenUpdate(ctx context.Context, devicePath string, tokenID int, token *Token) error {
	if token == nil {
		return ErrTokenNil
	}

	if token.Type == "" {
		return ErrTokenTypeEmpty
	}

	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return &TokenInvalidIDError{ID: tokenID}
	}

	// Verify token exists before updating
	exists, err := goluks.TokenExists(devicePath, tokenID)
	if err != nil {
		return &TokenOperationError{Op: "check_exists", Err: err}
	}
	if !exists {
		return &TokenNotFoundError{ID: tokenID}
	}

	// Convert to go-luks2 token format and import (overwrites existing)
	luksToken := tokenToLUKS(token)
	if err := goluks.ImportToken(devicePath, tokenID, luksToken); err != nil {
		return &TokenOperationError{Op: "update", Err: err}
	}

	return nil
}

// TokenList returns all tokens from the device.
func (h *CryptsetupHandler) TokenList(ctx context.Context, devicePath string) (map[int]*Token, error) {
	luksTokens, err := goluks.ListTokens(devicePath)
	if err != nil {
		return nil, &TokenOperationError{Op: "list", Err: err}
	}

	result := make(map[int]*Token, len(luksTokens))
	for id, luksToken := range luksTokens {
		result[id] = tokenFromLUKS(luksToken)
	}

	return result, nil
}

// TokenExists checks if a token exists at the specified slot.
func (h *CryptsetupHandler) TokenExists(ctx context.Context, devicePath string, tokenID int) (bool, error) {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return false, &TokenInvalidIDError{ID: tokenID}
	}

	exists, err := goluks.TokenExists(devicePath, tokenID)
	if err != nil {
		return false, &TokenOperationError{Op: "exists", Err: err}
	}

	return exists, nil
}

// TokenCount returns the number of tokens in the LUKS2 header.
func (h *CryptsetupHandler) TokenCount(ctx context.Context, devicePath string) (int, error) {
	count, err := goluks.CountTokens(devicePath)
	if err != nil {
		return 0, &TokenOperationError{Op: "count", Err: err}
	}

	return count, nil
}

// tokenToLUKS converts a Token to go-luks2 Token format.
func tokenToLUKS(t *Token) *goluks.Token {
	return &goluks.Token{
		Type:            t.Type,
		Keyslots:        t.Keyslots,
		FIDO2Credential: t.FIDO2Credential,
		FIDO2Salt:       t.FIDO2Salt,
		FIDO2RP:         t.FIDO2RP,
		FIDO2UPRequired: t.FIDO2UPRequired,
		TPM2Hash:        t.TPM2Hash,
		TPM2PolicyHash:  t.TPM2PolicyHash,
		TPM2PCRBank:     t.TPM2PCRBank,
		TPM2PCRs:        t.TPM2PCRs,
		TPM2Blob:        t.TPM2Blob,
		TPM2PublicKey:   t.TPM2PublicKey,
		TPM2SRKNV:       t.TPM2SRKNV,
		TPM2KeyHandle:   t.TPM2KeyHandle,
	}
}

// tokenFromLUKS converts a go-luks2 Token to our Token format.
func tokenFromLUKS(t *goluks.Token) *Token {
	return &Token{
		Type:            t.Type,
		Keyslots:        t.Keyslots,
		FIDO2Credential: t.FIDO2Credential,
		FIDO2Salt:       t.FIDO2Salt,
		FIDO2RP:         t.FIDO2RP,
		FIDO2UPRequired: t.FIDO2UPRequired,
		TPM2Hash:        t.TPM2Hash,
		TPM2PolicyHash:  t.TPM2PolicyHash,
		TPM2PCRBank:     t.TPM2PCRBank,
		TPM2PCRs:        t.TPM2PCRs,
		TPM2Blob:        t.TPM2Blob,
		TPM2PublicKey:   t.TPM2PublicKey,
		TPM2SRKNV:       t.TPM2SRKNV,
		TPM2KeyHandle:   t.TPM2KeyHandle,
	}
}
