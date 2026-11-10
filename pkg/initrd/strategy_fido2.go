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

	// fido2ManualTokenType is the token type the runtime LUKS service
	// (backends.LUKSFIDO2TokenType) and earlier installers write. It names
	// no key derivation: the runtime keys its slot with the SDK derivation,
	// earlier installers with the raw hmac-secret.
	fido2ManualTokenType = "fido2-manual"

	// fido2UnlockTimeout bounds the wait for the user's touch at boot.
	fido2UnlockTimeout = 30 * time.Second
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

	targets, err := s.headerFIDO2Slots(ctx, volume.DevicePath)
	if err != nil {
		return err
	}

	var slotErrs []error
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := s.unlockSlot(ctx, volume, target); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			s.logger.Warnf("FIDO2 slot %d (token %d) failed: %v", target.slot, target.tokenID, err)
			slotErrs = append(slotErrs, err)
			continue
		}
		s.logger.Infof("Successfully unlocked %s with FIDO2 slot %d", volume.DevicePath, target.slot)
		return nil
	}

	return &WrappedError{Msg: "all FIDO2 slots failed", Err: errors.Join(slotErrs...)}
}

// unlockSlot derives the key a header token describes and opens its keyslot.
// The token type picks the derivation (fido2TokenDecoders); a type with no
// entry keys its slot with the raw hmac-secret and is refused before the
// authenticator is asked. An fido2-manual token names no derivation, so the
// SDK derivation is tried once and a rejection by the keyslot is reported as
// FIDO2RawSecretTokenError, without asking the authenticator again.
func (s *FIDO2Strategy) unlockSlot(ctx context.Context, volume *luks.VolumeConfig, target fido2SlotToken) error {
	decode, ok := fido2TokenDecoders[target.token.Type]
	if !ok {
		return target.rawSecretError(volume.DevicePath, nil)
	}

	authConfig, err := decode(target)
	if err != nil {
		return err
	}

	s.logger.Debugf("Trying FIDO2 slot %d from token %d", target.slot, target.tokenID)
	s.logger.Info("Please touch your security key...")

	key, err := s.awaitKey(ctx, func() ([]byte, error) {
		return s.platform.FIDO2.UnlockWithKey(authConfig)
	})
	if err != nil {
		return err
	}
	// The touch and the cancellation can arrive together, and Open does not
	// watch ctx: a cancelled unlock must not map the volume.
	if err := ctx.Err(); err != nil {
		s.discardLateKey(key)
		return err
	}

	slot := target.slot
	openOpts := &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
		KeySlot:       &slot,
	}
	err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts)
	clear(key)
	if err != nil && target.token.Type == fido2ManualTokenType {
		return target.rawSecretError(volume.DevicePath, err)
	}
	return err
}

// awaitKey returns the key of an authenticator call, or ctx.Err() as soon as
// ctx ends. It holds the process-wide authenticator gate for the call; when
// the gate cannot be taken the call never runs. The SDK cannot stop the HID
// request, so an abandoned call runs on in a drain that zeroes the key a late
// touch yields and only then frees the gate: a retry waits for it and never
// overlaps it on the shared handler. done is buffered, so neither goroutine
// outlives the call.
func (s *FIDO2Strategy) awaitKey(ctx context.Context, call func() ([]byte, error)) ([]byte, error) {
	if err := s.acquireFIDO2Operation(ctx); err != nil {
		return nil, err
	}
	type outcome struct {
		key []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		key, err := call()
		done <- outcome{key: key, err: err}
	}()
	select {
	case result := <-done:
		releaseFIDO2Operation()
		return result.key, result.err
	case <-ctx.Done():
		go func() {
			result := <-done
			s.discardLateKey(result.key)
			releaseFIDO2Operation()
		}()
		return nil, ctx.Err()
	}
}

// fido2Operation admits one authenticator operation at a time in the process.
// It is package-level and not a field of FIDO2Strategy because the SDK handler
// (Platform.FIDO2) is shared by every strategy built on a platform, and a
// retry is a new strategy value over that same handler. The handler's calls
// take no context and write its shared timeout without a lock, so two calls
// at once are a data race and compete for the user's touch. An abandoned call
// therefore keeps the gate after its unlock was cancelled: it still runs on
// the handler until the touch or the SDK timeout ends it.
var fido2Operation = make(chan struct{}, 1)

// acquireFIDO2Operation takes the authenticator gate, or returns ctx.Err()
// when ctx has ended before or while it waits; it then holds nothing.
func (s *FIDO2Strategy) acquireFIDO2Operation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case fido2Operation <- struct{}{}:
	default:
		s.logger.Info("Waiting for the previous security key operation to end (touch or remove the key)...")
		select {
		case fido2Operation <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// The gate and the cancellation can arrive together.
	if err := ctx.Err(); err != nil {
		releaseFIDO2Operation()
		return err
	}
	return nil
}

// releaseFIDO2Operation frees the authenticator gate for the next operation.
func releaseFIDO2Operation() {
	<-fido2Operation
}

// discardLateKey zeroes a key the authenticator returned after the unlock
// was cancelled.
func (s *FIDO2Strategy) discardLateKey(key []byte) {
	if key == nil {
		return
	}
	clear(key)
	s.logger.Debug("Discarded a late FIDO2 key after cancellation")
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

	// The enrolment is one authenticator operation: the gate is held from
	// the credential creation until the key derivation has returned, and
	// nothing is written to the volume when it cannot be taken.
	if err := s.acquireFIDO2Operation(ctx); err != nil {
		return err
	}

	s.logger.Info("Please touch your security key to enroll...")

	// Enroll FIDO2 credential
	result, err := s.platform.FIDO2.EnrollKey(enrollConfig)
	if err != nil {
		releaseFIDO2Operation()
		return &WrappedError{Msg: "failed to enroll FIDO2 key", Err: err}
	}

	salt := result.Salt
	if len(salt) == 0 {
		salt, err = newFIDO2Salt()
		if err != nil {
			releaseFIDO2Operation()
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
	releaseFIDO2Operation()
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

// headerFIDO2Slots lists the keyslots that the header's FIDO2 tokens are bound
// to, in token ID order, from tokens that carry a credential and a salt. The
// slot comes from the token's keyslots and never from the volume
// configuration: buildVolumeConfig numbers slots by FallbackMethods position
// (FIDO2 is 2 by default) while the installer enrols slot 3. A slot named by
// several tokens is taken from the lowest-ID one.
func (s *FIDO2Strategy) headerFIDO2Slots(ctx context.Context, devicePath string) ([]fido2SlotToken, error) {
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

	seen := make(map[int]bool)
	var targets []fido2SlotToken
	for _, id := range ids {
		token := all[id]
		if token == nil || token.FIDO2Credential == "" || token.FIDO2Salt == "" {
			continue
		}
		for _, keyslot := range token.Keyslots {
			slot, err := strconv.Atoi(keyslot)
			if err != nil {
				s.logger.Warnf("LUKS2 token %d names keyslot %q, which is not a number: %v", id, keyslot, err)
				continue
			}
			if seen[slot] {
				continue
			}
			seen[slot] = true
			targets = append(targets, fido2SlotToken{tokenID: id, slot: slot, token: token})
		}
	}

	if len(targets) == 0 {
		return nil, &FIDO2TokenNotFoundError{DevicePath: devicePath}
	}
	return targets, nil
}

// fido2SlotToken is a keyslot named by a FIDO2 token in the LUKS2 header.
type fido2SlotToken struct {
	tokenID int
	slot    int
	token   *luks.Token
}

// rawSecretError reports the slot as keyed with the raw hmac-secret. cause is
// the keyslot's rejection of the SDK derivation, or nil when the slot was not
// tried.
func (t fido2SlotToken) rawSecretError(devicePath string, cause error) error {
	return &FIDO2RawSecretTokenError{
		DevicePath: devicePath,
		Slot:       t.slot,
		TokenID:    t.tokenID,
		Type:       t.token.Type,
		Err:        cause,
	}
}

// fido2TokenDecoders maps a FIDO2 token type to a decoder that rebuilds the
// authentication config its producer derived the slot key with.
var fido2TokenDecoders = map[string]func(target fido2SlotToken) (*fido2.AuthenticationConfig, error){
	luks.TokenTypeFIDO2:  decodeSDKToken,
	fido2ManualTokenType: decodeManualToken,
}

// decodeSDKToken decodes a type fido2 token, written by this strategy and by
// the installer: base64 credential and salt, no user verification.
func decodeSDKToken(target fido2SlotToken) (*fido2.AuthenticationConfig, error) {
	credentialID, err := base64.StdEncoding.DecodeString(target.token.FIDO2Credential)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Slot: target.slot, Field: "fido2-credential", Err: err}
	}

	salt, err := decodeTokenSalt(target)
	if err != nil {
		return nil, err
	}

	rpID := target.token.FIDO2RP
	if rpID == "" {
		rpID = fido2RelyingPartyID
	}

	return &fido2.AuthenticationConfig{
		RelyingPartyID: rpID,
		CredentialID:   credentialID,
		Salt:           salt,
		Timeout:        fido2UnlockTimeout,
	}, nil
}

// decodeManualToken decodes a type fido2-manual token as the runtime LUKS
// service (pkg/app/backends) writes it: the credential ID verbatim in hex or
// any base64 form, the salt in base64, and fido2-up-required carrying the
// user-verification option the slot key was derived with.
func decodeManualToken(target fido2SlotToken) (*fido2.AuthenticationConfig, error) {
	credentialID, err := decodeManualCredential(target.token.FIDO2Credential)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Slot: target.slot, Field: "fido2-credential", Err: err}
	}

	salt, err := decodeTokenSalt(target)
	if err != nil {
		return nil, err
	}

	config := fido2.DefaultAuthenticationConfig(credentialID, salt)
	if target.token.FIDO2RP != "" {
		config.RelyingPartyID = target.token.FIDO2RP
	}
	config.RequireUserVerification = target.token.FIDO2UPRequired
	config.Timeout = fido2UnlockTimeout
	return config, nil
}

// decodeTokenSalt decodes the base64 salt every FIDO2 token type carries.
func decodeTokenSalt(target fido2SlotToken) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(target.token.FIDO2Salt)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Slot: target.slot, Field: "fido2-salt", Err: err}
	}
	return salt, nil
}

// decodeManualCredential accepts the credential encodings the runtime LUKS
// service accepts, in its order: hex, then standard, raw standard and raw URL
// base64.
func decodeManualCredential(encoded string) ([]byte, error) {
	if credentialID, err := hex.DecodeString(encoded); err == nil {
		return credentialID, nil
	}
	if credentialID, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return credentialID, nil
	}
	if credentialID, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return credentialID, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
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
