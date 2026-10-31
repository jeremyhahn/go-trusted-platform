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

package installer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

const (
	// fido2ManualTokenType is the token type the runtime LUKS service
	// (backends.LUKSFIDO2TokenType) and earlier installers write. It names
	// no key derivation: the runtime keys its slot with the SDK derivation,
	// earlier installers with the raw hmac-secret.
	fido2ManualTokenType = "fido2-manual"

	// fido2InstallerRelyingPartyID is the relying party the installer
	// enrols under by default, and the default for a type fido2 token that
	// carries none.
	fido2InstallerRelyingPartyID = "luks-alpine"

	// fido2UnlockTestMapping is the mapping TestUnlock opens and closes.
	fido2UnlockTestMapping = "fido2_unlock_test"
)

// The go-luks2 header read and device mapping of the unlock. Tests replace
// them with an in-memory header.
var (
	luksListTokens = luks2.ListTokens
	luksUnlock     = luks2.Unlock
	luksLock       = luks2.Lock
	luksIsUnlocked = luks2.IsUnlocked
)

// fido2TokenDecoders maps a FIDO2 token type to a decoder that rebuilds the
// authentication config its producer derived the slot key with. A type with
// no entry (systemd-fido2) keys its slot with the raw hmac-secret.
var fido2TokenDecoders = map[string]func(token *FIDO2Token) (*fido2.AuthenticationConfig, error){
	luks.TokenTypeFIDO2:  decodeSDKToken,
	fido2ManualTokenType: decodeManualToken,
}

// FIDO2Unlock opens a LUKS device with the key the SDK FIDO2 handler derives
// (UnlockWithKey) from the credential and salt in the header's FIDO2 token.
type FIDO2Unlock struct {
	luksDevice string
	debug      bool
}

// NewFIDO2Unlock creates a new FIDO2 unlock handler
func NewFIDO2Unlock(luksDevice string, debug bool) *FIDO2Unlock {
	return &FIDO2Unlock{
		luksDevice: luksDevice,
		debug:      debug,
	}
}

// GetTokenInfo returns the lowest-ID FIDO2 token in the LUKS2 header that
// carries a credential, a salt and a keyslot and whose type the SDK can
// derive: fido2 (the installer and the initrd) or fido2-manual (the runtime
// LUKS service). When the header holds only tokens of other types it returns
// FIDO2RawSecretTokenError for the first of them.
func (f *FIDO2Unlock) GetTokenInfo() (*FIDO2Token, error) {
	tokens, err := luksListTokens(f.luksDevice)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read LUKS header", Err: err}
	}

	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var refused *FIDO2Token
	for _, id := range ids {
		luksToken := tokens[id]
		if luksToken == nil || luksToken.FIDO2Credential == "" || luksToken.FIDO2Salt == "" || len(luksToken.Keyslots) == 0 {
			continue
		}
		token := &FIDO2Token{
			Type:            luksToken.Type,
			Keyslots:        luksToken.Keyslots,
			FIDO2Credential: luksToken.FIDO2Credential,
			FIDO2Salt:       luksToken.FIDO2Salt,
			FIDO2RP:         luksToken.FIDO2RP,
			FIDO2UPRequired: luksToken.FIDO2UPRequired,
		}
		if _, ok := fido2TokenDecoders[token.Type]; ok {
			return token, nil
		}
		if refused == nil {
			refused = token
		}
	}

	if refused != nil {
		return nil, f.rawSecretError(refused, nil)
	}
	return nil, &FIDO2TokenNotFoundError{Device: f.luksDevice}
}

// DeriveKey derives the slot key for the token through the SDK FIDO2
// handler. The token type picks the authentication config (relying party,
// user verification) the key was enrolled with.
func (f *FIDO2Unlock) DeriveKey(ctx context.Context, token *FIDO2Token) ([]byte, error) {
	decode, ok := fido2TokenDecoders[token.Type]
	if !ok {
		return nil, f.rawSecretError(token, nil)
	}
	authConfig, err := decode(token)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		authConfig.Timeout = time.Until(deadline)
	}

	cfg := fido2.DefaultConfig
	cfg.RelyingPartyID = authConfig.RelyingPartyID
	cfg.Debug = f.debug
	handler, err := newFIDO2Handler(&cfg)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open the FIDO2 handler", Err: err}
	}
	defer func() {
		if closeErr := handler.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close the FIDO2 handler: %v\n", closeErr)
		}
	}()

	fmt.Println("Touch your security key to unlock...")
	key, err := handler.UnlockWithKey(authConfig)
	if err != nil {
		return nil, &FIDO2DeriveKeyError{Err: err}
	}
	return key, nil
}

// Unlock opens the LUKS device using FIDO2 security key
func (f *FIDO2Unlock) Unlock(ctx context.Context, mappedName string) error {
	token, key, err := f.tokenKey(ctx)
	if err != nil {
		return err
	}
	defer clear(key)

	if err := luksUnlock(f.luksDevice, key, mappedName); err != nil {
		return f.keyRejected(token, err)
	}

	fmt.Printf("LUKS device unlocked successfully as /dev/mapper/%s\n", mappedName)
	return nil
}

// TestUnlock tests if the FIDO2 key can unlock the device without actually opening it
func (f *FIDO2Unlock) TestUnlock(ctx context.Context) error {
	token, key, err := f.tokenKey(ctx)
	if err != nil {
		return err
	}
	defer clear(key)

	if luksIsUnlocked(fido2UnlockTestMapping) {
		if err := luksLock(fido2UnlockTestMapping); err != nil {
			return &WrappedError{Msg: "failed to close a stale FIDO2 test mapping", Err: err}
		}
	}

	if err := luksUnlock(f.luksDevice, key, fido2UnlockTestMapping); err != nil {
		return f.keyRejected(token, err)
	}

	if err := luksLock(fido2UnlockTestMapping); err != nil {
		fmt.Printf("Warning: failed to close test mapping: %v\n", err)
	}

	fmt.Println("FIDO2 unlock test passed successfully!")
	return nil
}

// tokenKey reads the header's FIDO2 token and derives its slot key.
func (f *FIDO2Unlock) tokenKey(ctx context.Context) (*FIDO2Token, []byte, error) {
	token, err := f.GetTokenInfo()
	if err != nil {
		return nil, nil, err
	}

	if f.debug {
		fmt.Printf("Found FIDO2 token: type=%s, RP=%s, keyslots=%v\n", token.Type, token.FIDO2RP, token.Keyslots)
	}

	key, err := f.DeriveKey(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	return token, key, nil
}

// keyRejected reports that the device did not open with the derived key. An
// fido2-manual token names no derivation, so a rejected key means the slot
// holds the raw hmac-secret of an earlier installer; the authenticator is not
// asked again.
func (f *FIDO2Unlock) keyRejected(token *FIDO2Token, err error) error {
	if token.Type == fido2ManualTokenType {
		return f.rawSecretError(token, err)
	}
	return &FIDO2KeyRejectedError{Device: f.luksDevice, Keyslots: token.Keyslots, Err: err}
}

// rawSecretError reports the token's slot as keyed with the raw hmac-secret.
func (f *FIDO2Unlock) rawSecretError(token *FIDO2Token, cause error) error {
	return &FIDO2RawSecretTokenError{Device: f.luksDevice, Type: token.Type, Keyslots: token.Keyslots, Err: cause}
}

// decodeSDKToken decodes a type fido2 token, written by the installer and by
// the initrd: base64 credential and salt, no user verification.
func decodeSDKToken(token *FIDO2Token) (*fido2.AuthenticationConfig, error) {
	credentialID, err := base64.StdEncoding.DecodeString(token.FIDO2Credential)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Field: "fido2-credential", Err: err}
	}
	salt, err := decodeTokenSalt(token)
	if err != nil {
		return nil, err
	}

	config := fido2.DefaultAuthenticationConfig(credentialID, salt)
	config.RelyingPartyID = token.FIDO2RP
	if config.RelyingPartyID == "" {
		config.RelyingPartyID = fido2InstallerRelyingPartyID
	}
	return config, nil
}

// decodeManualToken decodes a type fido2-manual token as the runtime LUKS
// service (pkg/app/backends) writes it: the credential ID verbatim in hex or
// any base64 form, the salt in base64, and fido2-up-required carrying the
// user-verification option the slot key was derived with.
func decodeManualToken(token *FIDO2Token) (*fido2.AuthenticationConfig, error) {
	credentialID, err := decodeManualCredential(token.FIDO2Credential)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Field: "fido2-credential", Err: err}
	}
	salt, err := decodeTokenSalt(token)
	if err != nil {
		return nil, err
	}

	config := fido2.DefaultAuthenticationConfig(credentialID, salt)
	if token.FIDO2RP != "" {
		config.RelyingPartyID = token.FIDO2RP
	}
	config.RequireUserVerification = token.FIDO2UPRequired
	return config, nil
}

// decodeTokenSalt decodes the base64 salt every FIDO2 token type carries.
func decodeTokenSalt(token *FIDO2Token) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt)
	if err != nil {
		return nil, &FIDO2TokenDecodeError{Field: "fido2-salt", Err: err}
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

// FIDO2TokenNotFoundError reports that the LUKS2 header holds no FIDO2 token
// that carries a credential, a salt and a keyslot.
type FIDO2TokenNotFoundError struct {
	Device string
}

// Error implements the error interface.
func (e *FIDO2TokenNotFoundError) Error() string {
	return fmt.Sprintf("fido2: no LUKS2 FIDO2 token bound to a keyslot on %s", e.Device)
}

// FIDO2RawSecretTokenError reports a FIDO2 slot keyed with the raw
// hmac-secret, which the SDK cannot return (go-xkms #1769). A systemd-fido2
// token is refused before the authenticator is asked, so Err is nil. An
// fido2-manual token names no derivation: the SDK derivation was tried once,
// the device rejected it, and Err is that rejection.
type FIDO2RawSecretTokenError struct {
	Device   string
	Type     string
	Keyslots []string
	Err      error
}

// Error implements the error interface.
func (e *FIDO2RawSecretTokenError) Error() string {
	return fmt.Sprintf("fido2: LUKS2 token (type %q) for keyslots %s on %s keys the slot with the raw hmac-secret, "+
		"which the SDK cannot derive (go-xkms #1769); re-enrol the slot", e.Type, strings.Join(e.Keyslots, ","), e.Device)
}

// Unwrap returns the device's rejection, if the slot was tried.
func (e *FIDO2RawSecretTokenError) Unwrap() error {
	return e.Err
}

// FIDO2KeyRejectedError reports that the device did not open with the key
// derived for a type fido2 token.
type FIDO2KeyRejectedError struct {
	Device   string
	Keyslots []string
	Err      error
}

// Error implements the error interface.
func (e *FIDO2KeyRejectedError) Error() string {
	return fmt.Sprintf("fido2: the derived key did not open %s (keyslots %s): %v", e.Device, strings.Join(e.Keyslots, ","), e.Err)
}

// Unwrap returns the go-luks2 error.
func (e *FIDO2KeyRejectedError) Unwrap() error {
	return e.Err
}

// FIDO2TokenDecodeError reports a FIDO2 token field in no accepted encoding.
type FIDO2TokenDecodeError struct {
	Field string
	Err   error
}

// Error implements the error interface.
func (e *FIDO2TokenDecodeError) Error() string {
	return fmt.Sprintf("fido2: LUKS2 token has an invalid %s: %v", e.Field, e.Err)
}

// Unwrap returns the decode error.
func (e *FIDO2TokenDecodeError) Unwrap() error {
	return e.Err
}
