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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
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

	// fido2RawSecretChallenge is the string whose SHA-256 digest earlier
	// installers passed to fido2-assert as the client data hash.
	fido2RawSecretChallenge = "luks-enrollment-challenge"

	// fido2RawSecretLength is the length of the hmac-secret output, the key
	// earlier installers wrote to a fido2-manual slot.
	fido2RawSecretLength = 32
	// fido2DeriveStep names the SDK key derivation in a cancellation error.
	fido2DeriveStep = "derive the LUKS key"
)

// The go-luks2 header read and device mapping of the unlock. Tests replace
// them with an in-memory header.
var (
	luksListTokens = luks2.ListTokens
	luksUnlock     = luks2.Unlock
	luksLock       = luks2.Lock
	luksIsUnlocked = luks2.IsUnlocked
)

// fido2Command runs a libfido2 tool with stdin and returns its stdout. The
// context ends the tool. Tests replace it with a fake authenticator.
var fido2Command = func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.Output()
}

// fido2TokenDecoders maps a FIDO2 token type to a decoder that rebuilds the
// authentication config its producer derived the slot key with. A type with
// no entry (systemd-fido2) keys its slot with the raw hmac-secret.
var fido2TokenDecoders = map[string]func(token *FIDO2Token) (*fido2.AuthenticationConfig, error){
	luks.TokenTypeFIDO2:  decodeSDKToken,
	fido2ManualTokenType: decodeManualToken,
}

// FIDO2Unlock opens a LUKS device with the key the SDK FIDO2 handler derives
// (UnlockWithKey) from the credential and salt in the header's FIDO2 token.
// A fido2-manual slot the SDK key does not open is tried with the raw
// hmac-secret earlier installers keyed it with.
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
	if err := ctx.Err(); err != nil {
		return nil, &FIDO2CanceledError{Step: fido2DeriveStep, Err: err}
	}
	decode, ok := fido2TokenDecoders[token.Type]
	if !ok {
		return nil, f.rawSecretError(token, nil)
	}
	authConfig, err := decode(token)
	if err != nil {
		return nil, err
	}
	// The deadline also bounds the SDK's own wait for the touch. One that
	// has already passed is a cancellation: the SDK ignores a negative
	// Timeout and would wait for its default.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, &FIDO2CanceledError{Step: fido2DeriveStep, Err: context.DeadlineExceeded}
		}
		authConfig.Timeout = remaining
	}

	cfg := fido2.DefaultConfig
	cfg.RelyingPartyID = authConfig.RelyingPartyID
	cfg.Debug = f.debug
	handler, err := newFIDO2Handler(&cfg)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open the FIDO2 handler", Err: err}
	}
	session := &fido2Session{handler: handler}
	defer session.close()

	fmt.Println("Touch your security key to unlock...")
	key, err := awaitAuthenticator(ctx, session, fido2DeriveStep, func(handler fido2.Handler) ([]byte, error) {
		return handler.UnlockWithKey(authConfig)
	}, clearKey)
	if errors.As(err, new(*FIDO2CanceledError)) {
		return nil, err
	}
	if err != nil {
		return nil, &FIDO2DeriveKeyError{Err: err}
	}
	return key, nil
}

// Unlock opens the LUKS device using FIDO2 security key
func (f *FIDO2Unlock) Unlock(ctx context.Context, mappedName string) error {
	token, err := f.token()
	if err != nil {
		return err
	}

	if err := f.open(ctx, token, mappedName); err != nil {
		return err
	}

	fmt.Printf("LUKS device unlocked successfully as /dev/mapper/%s\n", mappedName)
	return nil
}

// TestUnlock tests if the FIDO2 key can unlock the device without actually opening it
func (f *FIDO2Unlock) TestUnlock(ctx context.Context) error {
	token, err := f.token()
	if err != nil {
		return err
	}

	if luksIsUnlocked(fido2UnlockTestMapping) {
		if err := luksLock(fido2UnlockTestMapping); err != nil {
			return &WrappedError{Msg: "failed to close a stale FIDO2 test mapping", Err: err}
		}
	}

	if err := f.open(ctx, token, fido2UnlockTestMapping); err != nil {
		return err
	}

	if err := luksLock(fido2UnlockTestMapping); err != nil {
		fmt.Printf("Warning: failed to close test mapping: %v\n", err)
	}

	fmt.Println("FIDO2 unlock test passed successfully!")
	return nil
}

// token reads the header's FIDO2 token and checks that it decodes, so a
// corrupt token is refused before the authenticator is asked.
func (f *FIDO2Unlock) token() (*FIDO2Token, error) {
	token, err := f.GetTokenInfo()
	if err != nil {
		return nil, err
	}

	if f.debug {
		fmt.Printf("Found FIDO2 token: type=%s, RP=%s, keyslots=%v\n", token.Type, token.FIDO2RP, token.Keyslots)
	}

	if _, err := fido2TokenDecoders[token.Type](token); err != nil {
		return nil, err
	}
	return token, nil
}

// open maps the device with the key of the token's slot. The type fido2
// token is the SDK-derivation marker: its slot opens with the SDK key alone.
// A fido2-manual token carries no marker. Earlier installers keyed its slot
// with the raw hmac-secret, asked through fido2-assert with user presence
// only, so their fido2-up-required meant presence. The runtime LUKS service
// keys it with the SDK derivation, its fido2-up-required meaning user
// verification. The raw hmac-secret is tried first, so an earlier
// installer's slot never waits on an SDK assertion that asks for a user
// verification the authenticator may not support; the SDK key is tried
// only when the raw hmac-secret does not open the slot.
func (f *FIDO2Unlock) open(ctx context.Context, token *FIDO2Token, mappedName string) error {
	if token.Type != fido2ManualTokenType {
		return f.openDerived(ctx, token, mappedName)
	}

	rawErr := f.openRawSecret(ctx, token, mappedName)
	if rawErr == nil || ctx.Err() != nil {
		return rawErr
	}
	fmt.Println("The raw hmac-secret of an earlier installer did not open the slot; trying the SDK key of the runtime LUKS service...")
	if err := f.openDerived(ctx, token, mappedName); err != nil {
		return errors.Join(rawErr, err)
	}
	return nil
}

// openDerived maps the device with the key the SDK derives for the token.
func (f *FIDO2Unlock) openDerived(ctx context.Context, token *FIDO2Token, mappedName string) error {
	key, err := f.DeriveKey(ctx, token)
	if err != nil {
		return err
	}
	defer clear(key)
	return f.openWith(ctx, token, key, mappedName)
}

// openRawSecret maps the device with the raw hmac-secret an earlier
// installer keyed a fido2-manual slot with.
func (f *FIDO2Unlock) openRawSecret(ctx context.Context, token *FIDO2Token, mappedName string) error {
	secret, err := f.rawSecretKey(ctx, token)
	if err != nil {
		return err
	}
	defer clear(secret)
	return f.openWith(ctx, token, secret, mappedName)
}

// openWith maps the device with key, reporting a rejected key as typed.
func (f *FIDO2Unlock) openWith(ctx context.Context, token *FIDO2Token, key []byte, mappedName string) error {
	// The key may arrive after the caller gave up; a cancelled unlock never
	// maps the volume.
	if err := ctx.Err(); err != nil {
		return &FIDO2CanceledError{Step: "open the volume", Err: err}
	}
	if err := luksUnlock(f.luksDevice, key, mappedName); err != nil {
		return &FIDO2KeyRejectedError{Device: f.luksDevice, Keyslots: token.Keyslots, Err: err}
	}
	return nil
}

// rawSecretKey returns the raw 32-byte hmac-secret an earlier installer keyed
// a fido2-manual slot with. Like that installer it lists the authenticators
// with fido2-token and asks the first one through fido2-assert, passing the
// token's relying party, credential and salt verbatim.
func (f *FIDO2Unlock) rawSecretKey(ctx context.Context, token *FIDO2Token) ([]byte, error) {
	output, err := fido2Command(ctx, "", "fido2-token", "-L")
	if err != nil {
		return nil, &FIDO2AssertError{Step: "list the FIDO2 devices", Err: err}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	devicePath := strings.TrimSuffix(strings.Split(lines[0], " ")[0], ":")
	if devicePath == "" {
		return nil, &FIDO2AssertError{Step: "list the FIDO2 devices", Err: &FIDO2NoDeviceError{}}
	}
	if f.debug {
		fmt.Printf("Using FIDO2 device: %s\n", devicePath)
	}

	challenge := sha256.Sum256([]byte(fido2RawSecretChallenge))
	params := fmt.Sprintf("%s\n%s\n%s\n%s\n",
		base64.StdEncoding.EncodeToString(challenge[:]),
		token.FIDO2RP,
		token.FIDO2Credential,
		token.FIDO2Salt,
	)

	// fido2-assert shares the authenticator with the SDK operations: it waits
	// for an abandoned one to end, and holds the slot until the tool exits
	// (the context kills it, and Output waits for it).
	if err := acquireFIDO2Operation(ctx, "get the hmac-secret"); err != nil {
		return nil, err
	}
	fmt.Println("Touch your security key to unlock...")
	output, err = fido2Command(ctx, params, "fido2-assert", "-G", "-h", devicePath)
	<-fido2Operation
	if err != nil {
		return nil, &FIDO2AssertError{Step: "get the hmac-secret", Err: err}
	}
	assertLines := strings.Split(strings.TrimSpace(string(output)), "\n")
	secret, err := base64.StdEncoding.DecodeString(assertLines[len(assertLines)-1])
	if err != nil {
		return nil, &FIDO2AssertError{Step: "decode the hmac-secret", Err: err}
	}
	if len(secret) != fido2RawSecretLength {
		clear(secret)
		return nil, &FIDO2AssertError{Step: "decode the hmac-secret", Err: &FIDO2SecretLengthError{Length: len(secret)}}
	}
	return secret, nil
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
// user-verification option the slot key was derived with. The SDK key is
// asked for only after the raw hmac-secret of an earlier installer, whose
// fido2-up-required meant user presence, did not open the slot (open), so
// reading the flag as user verification here never stands between a legacy
// slot and its raw-secret unlock. The runtime needs the flag: the
// authenticator's hmac-secret differs with and without user verification.
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

// FIDO2RawSecretTokenError reports a systemd-fido2 slot, keyed with the raw
// hmac-secret, which the SDK cannot return (go-xkms #1769). The token is
// refused before the authenticator is asked, so Err is nil.
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

// FIDO2NoDeviceError reports that fido2-token listed no authenticator.
type FIDO2NoDeviceError struct{}

// Error implements the error interface.
func (e *FIDO2NoDeviceError) Error() string {
	return "no FIDO2 devices detected"
}

// FIDO2AssertError reports a failed step of the raw hmac-secret unlock of a
// fido2-manual token written by an earlier installer.
type FIDO2AssertError struct {
	Step string
	Err  error
}

// Error implements the error interface.
func (e *FIDO2AssertError) Error() string {
	return fmt.Sprintf("fido2: failed to %s for the raw hmac-secret unlock: %v", e.Step, e.Err)
}

// Unwrap returns the cause.
func (e *FIDO2AssertError) Unwrap() error {
	return e.Err
}

// FIDO2SecretLengthError reports an hmac-secret of the wrong length.
type FIDO2SecretLengthError struct {
	Length int
}

// Error implements the error interface.
func (e *FIDO2SecretLengthError) Error() string {
	return fmt.Sprintf("invalid hmac-secret length: expected %d, got %d", fido2RawSecretLength, e.Length)
}
