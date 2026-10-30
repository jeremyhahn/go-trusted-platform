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
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

const (
	// fido2RelyingPartyID is the relying party the strategy enrols under,
	// and the default when a token carries none.
	fido2RelyingPartyID = "luks-root"

	// fido2SaltSize is the salt length the CTAP2 hmac-secret extension takes.
	fido2SaltSize = 32
)

// fido2SaltReader is the entropy source for generated hmac-secret salts.
var fido2SaltReader io.Reader = rand.Reader

// FIDO2Strategy unlocks using FIDO2 hardware security key. The LUKS key is
// the authenticator's hmac-secret output; only the credential ID, salt and
// relying party are persisted, in a LUKS2 token bound to the keyslot.
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
		clear(key)
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

	// Without LUKS2 tokens the enrolment cannot be persisted and boot could
	// never open the slot, so refuse before touching the authenticator.
	tokens, err := s.tokenHandler()
	if err != nil {
		return err
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
		Timeout: time.Duration(s.platform.Config.UnlockTimeout) * time.Second,
	}

	s.logger.Info("Please touch your security key to enroll...")

	// Enroll FIDO2 credential
	result, err := s.platform.FIDO2.EnrollKey(enrollConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to enroll FIDO2 key", Err: err}
	}

	salt := result.Salt
	if len(salt) == 0 {
		salt, err = newFIDO2Salt()
		if err != nil {
			return err
		}
	}

	rpID := result.RelyingParty.ID
	if rpID == "" {
		rpID = enrollConfig.RelyingParty.ID
	}

	// The LUKS key is the hmac-secret output the authenticator derives from
	// the new credential and salt (a second touch, as systemd-cryptenroll
	// does). It is never stored; Unlock derives it again at boot.
	authConfig := &fido2.AuthenticationConfig{
		RelyingPartyID: rpID,
		CredentialID:   result.CredentialID,
		Salt:           salt,
		Timeout:        enrollConfig.Timeout,
	}

	s.logger.Info("Please touch your security key again to derive the volume key...")
	key, err := s.platform.FIDO2.UnlockWithKey(authConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to derive the FIDO2 hmac-secret key", Err: err}
	}
	defer clear(key)

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
	clear(key)

	// Persist the enrolment so a fresh boot can derive the key again. A slot
	// boot cannot open is removed rather than reported as installed.
	err = s.storeEnrollmentMetadata(ctx, volume.DevicePath, tokens, targetSlot, authConfig)
	if err != nil {
		killErr := s.platform.LUKS.KillSlot(ctx, volume.DevicePath, targetSlot.Index)
		return &FIDO2TokenStoreError{Slot: targetSlot.Index, Err: err, RollbackErr: killErr}
	}

	s.logger.Infof("Successfully installed FIDO2 strategy in slot %d", targetSlot.Index)
	return nil
}

// newFIDO2Salt generates a fresh hmac-secret salt when the authenticator
// handler did not return one.
func newFIDO2Salt() ([]byte, error) {
	salt := make([]byte, fido2SaltSize)
	if _, err := io.ReadFull(fido2SaltReader, salt); err != nil {
		return nil, &FIDO2SaltError{Err: err}
	}
	return salt, nil
}

// tokenHandler returns the LUKS2 token interface of the platform's LUKS
// handler, or a typed error when the handler has no token support.
func (s *FIDO2Strategy) tokenHandler() (luks.TokenHandler, error) {
	tokens, ok := s.platform.LUKS.(luks.TokenHandler)
	if !ok {
		return nil, &FIDO2TokenUnsupportedError{}
	}
	return tokens, nil
}

// loadAuthConfig reads the FIDO2 enrolment for a slot from the LUKS2 header.
// It uses the first token (lowest ID) bound to the slot that carries a
// credential and a salt, whatever its type, so volumes enrolled by the
// installer (type fido2-manual) unlock as well.
func (s *FIDO2Strategy) loadAuthConfig(ctx context.Context, devicePath string, slot luks.KeySlot) (*fido2.AuthenticationConfig, error) {
	tokens, err := s.tokenHandler()
	if err != nil {
		return nil, err
	}

	all, err := tokens.TokenList(ctx, devicePath)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to list LUKS2 tokens", Err: err}
	}

	ids := make([]int, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	slotID := strconv.Itoa(slot.Index)
	for _, id := range ids {
		token := all[id]
		if token == nil || token.FIDO2Credential == "" || token.FIDO2Salt == "" {
			continue
		}
		if !slices.Contains(token.Keyslots, slotID) {
			continue
		}
		return decodeFIDO2Token(token, slot.Index)
	}

	return nil, &FIDO2TokenNotFoundError{DevicePath: devicePath, Slot: slot.Index}
}

// decodeFIDO2Token turns a LUKS2 FIDO2 token into an authentication config.
func decodeFIDO2Token(token *luks.Token, slot int) (*fido2.AuthenticationConfig, error) {
	credentialID, err := base64.StdEncoding.DecodeString(token.FIDO2Credential)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Slot: slot, Field: "fido2-credential", Err: err}
	}

	salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Slot: slot, Field: "fido2-salt", Err: err}
	}

	rpID := token.FIDO2RP
	if rpID == "" {
		rpID = fido2RelyingPartyID
	}

	return &fido2.AuthenticationConfig{
		RelyingPartyID: rpID,
		CredentialID:   credentialID,
		Salt:           salt,
		Timeout:        30 * time.Second,
	}, nil
}

// storeEnrollmentMetadata writes the credential ID, salt and relying party
// of an enrolment to a LUKS2 token bound to the slot, in the systemd-fido2
// layout the installer also writes.
func (s *FIDO2Strategy) storeEnrollmentMetadata(ctx context.Context, devicePath string, tokens luks.TokenHandler, slot *luks.KeySlot, config *fido2.AuthenticationConfig) error {
	s.logger.Debugf("Storing FIDO2 enrollment metadata for slot %d", slot.Index)

	token := &luks.Token{
		Type:            luks.TokenTypeFIDO2,
		Keyslots:        []string{strconv.Itoa(slot.Index)},
		FIDO2Credential: base64.StdEncoding.EncodeToString(config.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(config.Salt),
		FIDO2RP:         config.RelyingPartyID,
	}

	if _, err := tokens.TokenCreate(ctx, devicePath, token); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create LUKS2 FIDO2 token for slot %d", slot.Index), Err: err}
	}
	return nil
}
