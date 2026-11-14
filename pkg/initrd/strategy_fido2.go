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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

const (
	// fido2TokenType is the LUKS2 token type the platformd backend writes for
	// a FIDO2 keyslot; Install writes the same shape.
	fido2TokenType      = "fido2-manual"
	fido2RelyingPartyID = "luks-root"
	fido2SaltSize       = 32
)

var (
	// ErrFIDO2TokensUnsupported: the LUKS handler has no token area, so a
	// FIDO2 enrollment could not be recovered at boot.
	ErrFIDO2TokensUnsupported = errors.New("initrd: fido2: LUKS handler has no token support")
	// ErrFIDO2TokenMissing: no LUKS2 token holds the credential and salt of
	// the keyslot.
	ErrFIDO2TokenMissing = errors.New("initrd: fido2: no token for the keyslot")
	// ErrFIDO2TokenInvalid: a token's credential or salt does not decode.
	ErrFIDO2TokenInvalid = errors.New("initrd: fido2: invalid token")
)

// FIDO2Strategy unlocks using FIDO2 hardware security key
type FIDO2Strategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
}

// NewFIDO2Strategy creates a new FIDO2 unlock strategy
func NewFIDO2Strategy(platform *Platform, logger *logging.Logger) *FIDO2Strategy {
	return &FIDO2Strategy{
		platform: platform,
		logger:   logger,
		priority: 3, // Third priority - requires user presence
	}
}

// Name returns the strategy name
func (s *FIDO2Strategy) Name() string {
	return "FIDO2"
}

// Priority returns the execution priority
func (s *FIDO2Strategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this strategy can unlock the volume
func (s *FIDO2Strategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Check if FIDO2 handler is available
	if s.platform.FIDO2 == nil {
		s.logger.Debug("FIDO2: Handler not available")
		return false
	}

	// Check if volume has a FIDO2 key slot configured
	for _, slot := range volume.KeySlots {
		if slot.Type == luks.UnlockFIDO2 {
			return true
		}
	}

	s.logger.Debug("FIDO2: No FIDO2 key slot configured")
	return false
}

// Unlock attempts to unlock the volume using FIDO2
func (s *FIDO2Strategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting FIDO2 unlock for %s", volume.DevicePath)

	// Find FIDO2 key slots
	for _, slot := range volume.KeySlots {
		if slot.Type != luks.UnlockFIDO2 {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		s.logger.Debugf("Trying FIDO2 slot %d", slot.Index)
		s.logger.Info("Please touch your security key...")

		// Load authentication config from slot metadata
		authConfig, err := s.loadAuthConfig(ctx, volume.DevicePath, slot)
		if err != nil {
			s.logger.Warnf("Failed to load auth config for slot %d: %v", slot.Index, err)
			continue
		}

		// Authenticate with FIDO2 device
		key, err := s.platform.FIDO2.UnlockWithKey(authConfig)
		if err != nil {
			s.logger.Warnf("FIDO2 authentication failed for slot %d: %v", slot.Index, err)
			continue
		}

		// Attempt LUKS unlock
		openOpts := &luks.OpenOptions{
			AllowDiscards: volume.AllowDiscards,
			Timeout:       volume.Timeout,
			KeySlot:       &slot.Index,
		}

		err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts)
		if err == nil {
			s.logger.Infof("Successfully unlocked %s with FIDO2 slot %d",
				volume.DevicePath, slot.Index)
			return nil
		}

		s.logger.Warnf("LUKS open failed with slot %d: %v", slot.Index, err)
	}

	return &MessageError{Msg: "all FIDO2 slots failed"}
}

// Install performs installation-time setup for FIDO2 strategy
func (s *FIDO2Strategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing FIDO2 strategy for %s", volume.DevicePath)

	// Check if FIDO2 handler is available
	if s.platform.FIDO2 == nil {
		return &MessageError{Msg: "FIDO2 handler not available"}
	}

	// Find the first available FIDO2 slot
	var targetSlot *luks.KeySlot
	for i := range volume.KeySlots {
		if volume.KeySlots[i].Type == luks.UnlockFIDO2 {
			targetSlot = &volume.KeySlots[i]
			break
		}
	}

	if targetSlot == nil {
		return &MessageError{Msg: "no FIDO2 key slot configured"}
	}

	// Boot reads the credential and salt back from a LUKS2 token; without a
	// token area the enrolled key could never be derived again.
	tokens, ok := s.platform.LUKS.(luks.HandlerWithTokens)
	if !ok {
		return ErrFIDO2TokensUnsupported
	}

	// Create enrollment config
	enrollConfig := &fido2.EnrollmentConfig{
		RelyingParty: fido2.RelyingParty{
			ID:   fido2RelyingPartyID,
			Name: fmt.Sprintf("LUKS %s", volume.MappingName),
		},
		User: fido2.User{
			ID:          []byte(volume.MappingName),
			Name:        "root",
			DisplayName: "Root Volume",
		},
		Timeout: s.unlockTimeout(),
	}

	s.logger.Info("Please touch your security key to enroll...")

	// Enroll FIDO2 credential
	result, err := s.platform.FIDO2.EnrollKey(enrollConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to enroll FIDO2 key", Err: err}
	}
	if result == nil || len(result.CredentialID) == 0 {
		return &WrappedError{Msg: "FIDO2 enrollment returned no credential", Err: ErrFIDO2TokenInvalid}
	}

	// The keyslot key is the authenticator's hmac-secret over a fresh salt:
	// the credential ID is public metadata and is never the key.
	salt := make([]byte, fido2SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return &WrappedError{Msg: "failed to generate FIDO2 salt", Err: err}
	}
	authConfig := fido2.DefaultAuthenticationConfig(result.CredentialID, salt)
	authConfig.RelyingPartyID = fido2RelyingPartyID
	authConfig.Timeout = s.unlockTimeout()

	s.logger.Info("Please touch your security key again to derive the volume key...")
	key, err := s.platform.FIDO2.UnlockWithKey(authConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to derive the FIDO2 key", Err: err}
	}
	if len(key) == 0 {
		return &WrappedError{Msg: "FIDO2 key derivation returned no key", Err: ErrInstallationFailed}
	}

	// Add the key to the LUKS key slot
	// Use FIPS-appropriate PBKDF (auto-detected from kernel)
	addOpts := &luks.AddKeyOptions{
		KeySlot: &targetSlot.Index,
		KDFType: fips.GetKDF(),
		Hash:    fips.GetHash(),
	}

	s.logger.Info("Adding FIDO2 key to LUKS", "slot", targetSlot.Index, "fips", fips.IsEnabled(), "kdf", addOpts.KDFType)
	err = s.platform.LUKS.AddKey(ctx, volume.DevicePath, password, key, addOpts)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to add key to LUKS slot %d", targetSlot.Index), Err: err}
	}

	// Persist the credential and salt; a keyslot boot cannot open is removed.
	if err := s.storeEnrollmentMetadata(ctx, tokens, volume.DevicePath, targetSlot.Index, result.CredentialID, salt); err != nil {
		if kerr := s.platform.LUKS.KillSlot(ctx, volume.DevicePath, targetSlot.Index); kerr != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to store FIDO2 token for slot %d, and removing the keyslot failed", targetSlot.Index), Err: errors.Join(err, kerr)}
		}
		return &WrappedError{Msg: fmt.Sprintf("failed to store FIDO2 token for slot %d; keyslot removed", targetSlot.Index), Err: err}
	}

	s.logger.Infof("Successfully installed FIDO2 strategy in slot %d", targetSlot.Index)
	return nil
}

// loadAuthConfig reads the credential and salt of a keyslot from the LUKS2
// token that lists it.
func (s *FIDO2Strategy) loadAuthConfig(ctx context.Context, devicePath string, slot luks.KeySlot) (*fido2.AuthenticationConfig, error) {
	tokens, ok := s.platform.LUKS.(luks.HandlerWithTokens)
	if !ok {
		return nil, ErrFIDO2TokensUnsupported
	}
	list, err := tokens.TokenList(ctx, devicePath)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read LUKS2 tokens", Err: err}
	}
	ids := make([]int, 0, len(list))
	for id := range list {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	want := strconv.Itoa(slot.Index)
	for _, id := range ids {
		token := list[id]
		if token == nil || token.FIDO2Credential == "" || !slices.Contains(token.Keyslots, want) {
			continue
		}
		credentialID, err := decodeFIDO2Credential(token.FIDO2Credential)
		if err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("token %d credential", id), Err: err}
		}
		salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt)
		if err != nil || len(salt) == 0 {
			return nil, &WrappedError{Msg: fmt.Sprintf("token %d salt", id), Err: ErrFIDO2TokenInvalid}
		}
		config := fido2.DefaultAuthenticationConfig(credentialID, salt)
		config.RelyingPartyID = fido2RelyingPartyID
		if token.FIDO2RP != "" {
			config.RelyingPartyID = token.FIDO2RP
		}
		config.RequireUserVerification = token.FIDO2UPRequired
		config.Timeout = s.unlockTimeout()
		return config, nil
	}
	return nil, ErrFIDO2TokenMissing
}

func (s *FIDO2Strategy) unlockTimeout() time.Duration {
	if s.platform.Config != nil && s.platform.Config.UnlockTimeout > 0 {
		return time.Duration(s.platform.Config.UnlockTimeout) * time.Second
	}
	return 30 * time.Second
}

// storeEnrollmentMetadata writes the credential and salt of a FIDO2 keyslot
// into a LUKS2 token, where loadAuthConfig finds them at boot.
func (s *FIDO2Strategy) storeEnrollmentMetadata(ctx context.Context, tokens luks.TokenHandler, devicePath string, slot int, credentialID, salt []byte) error {
	token := &luks.Token{
		Type:            fido2TokenType,
		Keyslots:        []string{strconv.Itoa(slot)},
		FIDO2Credential: hex.EncodeToString(credentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(salt),
		FIDO2RP:         fido2RelyingPartyID,
	}
	id, err := tokens.TokenCreate(ctx, devicePath, token)
	if err != nil {
		return err
	}
	s.logger.Debugf("Stored FIDO2 enrollment token %d for slot %d", id, slot)
	return nil
}

// decodeFIDO2Credential accepts the encodings a fido2 token's credential is
// written in: hex (this strategy and the platformd backend) or base64.
func decodeFIDO2Credential(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrFIDO2TokenInvalid
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, ErrFIDO2TokenInvalid
}
