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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// fakeError is the typed error the fakes in this file return.
type fakeError string

func (e fakeError) Error() string { return string(e) }

const (
	errFakeUnknownCredential fakeError = "fake fido2: unknown credential"
	errFakeWrongKey          fakeError = "fake luks: wrong key for slot"
	errFakeNoToken           fakeError = "fake luks: no such token"
	errFakeTokenExists       fakeError = "fake luks: token already exists"
	errFakeTokenCreate       fakeError = "fake luks: token create failed"
	errFakeTokenList         fakeError = "fake luks: token list failed"
	errFakeKillSlot          fakeError = "fake luks: kill slot failed"
	errFakeUnlock            fakeError = "fake fido2: authenticator removed"
	errFakeEntropy           fakeError = "fake entropy: exhausted"
)

// fakeFIDO2 is an authenticator with a fixed device secret. Its hmac-secret
// output is HMAC-SHA-256(secret, credential ID || salt).
type fakeFIDO2 struct {
	secret      [32]byte
	credentials map[string]bool
	enrolled    int
	noSalt      bool
	unlockErr   error
	unlocks     int
	configs     []*fido2.AuthenticationConfig
}

func newFakeFIDO2() *fakeFIDO2 {
	f := &fakeFIDO2{credentials: map[string]bool{}}
	for i := range f.secret {
		f.secret[i] = byte(0xA0 + i)
	}
	return f
}

// hmacSecret models the authenticator's 32-byte hmac-secret output for a
// credential and salt.
func (f *fakeFIDO2) hmacSecret(credentialID, salt []byte) []byte {
	mac := hmac.New(sha256.New, f.secret[:])
	mac.Write(credentialID)
	mac.Write(salt)
	return mac.Sum(nil)
}

// derive models what the SDK's UnlockWithKey returns: not the hmac-secret
// itself but its 64-byte GenerateDerivedKey expansion, two SHA-256 digests
// over the secret and a versioned label.
func (f *fakeFIDO2) derive(credentialID, salt []byte) []byte {
	secret := f.hmacSecret(credentialID, salt)
	key1 := sha256.Sum256(append(slices.Clone(secret), "go-xkms-key-derivation-v1"...))
	key2 := sha256.Sum256(append(slices.Clone(secret), "go-xkms-key-derivation-v2"...))
	return append(key1[:], key2[:]...)
}

func (f *fakeFIDO2) EnrollKey(config *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	f.enrolled++
	seed := sha256.Sum256([]byte(fmt.Sprintf("credential-%d", f.enrolled)))
	tail := sha256.Sum256(seed[:])
	credentialID := append(seed[:], tail[:]...)
	f.credentials[string(credentialID)] = true

	result := &fido2.EnrollmentResult{
		CredentialID: credentialID,
		RelyingParty: config.RelyingParty,
		User:         config.User,
	}
	if !f.noSalt {
		salt := sha256.Sum256([]byte(fmt.Sprintf("salt-%d", f.enrolled)))
		result.Salt = salt[:]
	}
	return result, nil
}

func (f *fakeFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	f.unlocks++
	f.configs = append(f.configs, config)
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	if !f.credentials[string(config.CredentialID)] {
		return nil, errFakeUnknownCredential
	}
	return f.derive(config.CredentialID, config.Salt), nil
}

func (f *fakeFIDO2) ListDevices() ([]fido2.Device, error) { return nil, nil }

func (f *fakeFIDO2) WaitForDevice(ctx context.Context) (*fido2.Device, error) { return nil, nil }

func (f *fakeFIDO2) Close() error { return nil }

// tokenLUKS is a LUKS2 volume in memory: a key per slot and a token map.
// Open succeeds only with the exact key added to the requested slot.
type tokenLUKS struct {
	*MockLUKSHandler
	keys           map[int][]byte
	tokens         map[int]*luks.Token
	opened         [][]byte
	killed         []int
	tokenCreateErr error
	tokenListErr   error
	killErr        error
}

func newTokenLUKS() *tokenLUKS {
	return &tokenLUKS{
		MockLUKSHandler: &MockLUKSHandler{},
		keys:            map[int][]byte{},
		tokens:          map[int]*luks.Token{},
	}
}

func (l *tokenLUKS) AddKey(ctx context.Context, devicePath string, existingPassword, newPassword []byte, opts *luks.AddKeyOptions) error {
	l.keys[*opts.KeySlot] = bytes.Clone(newPassword)
	return nil
}

func (l *tokenLUKS) Open(ctx context.Context, devicePath, mappingName string, password []byte, opts *luks.OpenOptions) error {
	l.opened = append(l.opened, bytes.Clone(password))
	key, ok := l.keys[*opts.KeySlot]
	if !ok || !bytes.Equal(key, password) {
		return errFakeWrongKey
	}
	return nil
}

func (l *tokenLUKS) KillSlot(ctx context.Context, devicePath string, slot int) error {
	l.killed = append(l.killed, slot)
	if l.killErr != nil {
		return l.killErr
	}
	delete(l.keys, slot)
	return nil
}

func (l *tokenLUKS) TokenCreate(ctx context.Context, devicePath string, token *luks.Token) (int, error) {
	if l.tokenCreateErr != nil {
		return 0, l.tokenCreateErr
	}
	id := 0
	for l.tokens[id] != nil {
		id++
	}
	l.tokens[id] = token
	return id, nil
}

func (l *tokenLUKS) TokenCreateAt(ctx context.Context, devicePath string, tokenID int, token *luks.Token) error {
	if l.tokens[tokenID] != nil {
		return errFakeTokenExists
	}
	l.tokens[tokenID] = token
	return nil
}

func (l *tokenLUKS) TokenRead(ctx context.Context, devicePath string, tokenID int) (*luks.Token, error) {
	token, ok := l.tokens[tokenID]
	if !ok {
		return nil, errFakeNoToken
	}
	return token, nil
}

func (l *tokenLUKS) TokenDelete(ctx context.Context, devicePath string, tokenID int) error {
	if _, ok := l.tokens[tokenID]; !ok {
		return errFakeNoToken
	}
	delete(l.tokens, tokenID)
	return nil
}

func (l *tokenLUKS) TokenUpdate(ctx context.Context, devicePath string, tokenID int, token *luks.Token) error {
	if _, ok := l.tokens[tokenID]; !ok {
		return errFakeNoToken
	}
	l.tokens[tokenID] = token
	return nil
}

func (l *tokenLUKS) TokenList(ctx context.Context, devicePath string) (map[int]*luks.Token, error) {
	if l.tokenListErr != nil {
		return nil, l.tokenListErr
	}
	return l.tokens, nil
}

func (l *tokenLUKS) TokenExists(ctx context.Context, devicePath string, tokenID int) (bool, error) {
	_, ok := l.tokens[tokenID]
	return ok, nil
}

func (l *tokenLUKS) TokenCount(ctx context.Context, devicePath string) (int, error) {
	return len(l.tokens), nil
}

const fido2TestSlot = 1

func fido2TestVolume() *luks.VolumeConfig {
	return &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
			{Index: fido2TestSlot, Type: luks.UnlockFIDO2},
		},
	}
}

func newFIDO2TestPlatform(device *fakeFIDO2, volume luks.Handler) *Platform {
	platform := createTestPlatform()
	platform.FIDO2 = device
	platform.LUKS = volume
	return platform
}

// enrolledToken returns the only token Install wrote.
func enrolledToken(t *testing.T, volume *tokenLUKS) *luks.Token {
	t.Helper()
	if len(volume.tokens) != 1 {
		t.Fatalf("expected exactly one token, got %d", len(volume.tokens))
	}
	for _, token := range volume.tokens {
		return token
	}
	return nil
}

func decodeTestField(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("token field is not base64: %v", err)
	}
	return decoded
}

func TestFIDO2StrategyRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		noSalt bool
	}{
		{name: "authenticator salt"},
		{name: "generated salt", noSalt: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			device := newFakeFIDO2()
			device.noSalt = tt.noSalt
			volume := newTokenLUKS()
			logger := logging.DefaultLogger()

			installer := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logger)
			if err := installer.Install(ctx, fido2TestVolume(), []byte("password")); err != nil {
				t.Fatalf("Install failed: %v", err)
			}

			token := enrolledToken(t, volume)
			if token.Type != luks.TokenTypeFIDO2 {
				t.Errorf("token type = %q, want %q", token.Type, luks.TokenTypeFIDO2)
			}
			if len(token.Keyslots) != 1 || token.Keyslots[0] != "1" {
				t.Errorf("token keyslots = %v, want [1]", token.Keyslots)
			}
			if token.FIDO2RP != fido2RelyingPartyID {
				t.Errorf("token rp = %q, want %q", token.FIDO2RP, fido2RelyingPartyID)
			}
			credentialID := decodeTestField(t, token.FIDO2Credential)
			salt := decodeTestField(t, token.FIDO2Salt)
			if len(salt) != fido2SaltSize {
				t.Errorf("salt length = %d, want %d", len(salt), fido2SaltSize)
			}

			enrolledKey := volume.keys[fido2TestSlot]
			if !bytes.Equal(enrolledKey, device.derive(credentialID, salt)) {
				t.Fatal("the slot key is not the hmac-secret output for the stored credential and salt")
			}

			// A fresh strategy holds no state from Install: everything it
			// needs comes from the LUKS2 token.
			booter := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logger)
			if err := booter.Unlock(ctx, fido2TestVolume()); err != nil {
				t.Fatalf("Unlock on a fresh strategy failed: %v", err)
			}
			if len(volume.opened) != 1 || !bytes.Equal(volume.opened[0], enrolledKey) {
				t.Errorf("Open received %x, want exactly the enrolled key %x", volume.opened, enrolledKey)
			}
		})
	}
}

func TestFIDO2StrategyCredentialIDDoesNotOpen(t *testing.T) {
	ctx := context.Background()
	device := newFakeFIDO2()
	volume := newTokenLUKS()
	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())

	if err := strategy.Install(ctx, fido2TestVolume(), []byte("password")); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	credentialID := decodeTestField(t, enrolledToken(t, volume).FIDO2Credential)
	enrolledKey := volume.keys[fido2TestSlot]

	slot := fido2TestSlot
	for name, candidate := range map[string][]byte{
		"credential ID":        credentialID,
		"credential ID prefix": credentialID[:32],
	} {
		if bytes.Equal(enrolledKey, candidate) {
			t.Errorf("the slot key equals the %s", name)
		}
		err := volume.Open(ctx, "/dev/sda2", "cryptroot", candidate, &luks.OpenOptions{KeySlot: &slot})
		if !errors.Is(err, errFakeWrongKey) {
			t.Errorf("Open with the %s: got %v, want %v", name, err, errFakeWrongKey)
		}
	}
}

func TestFIDO2StrategyUnlockInstallerLayout(t *testing.T) {
	ctx := context.Background()
	device := newFakeFIDO2()
	enrollment, err := device.EnrollKey(&fido2.EnrollmentConfig{})
	if err != nil {
		t.Fatalf("EnrollKey failed: %v", err)
	}

	volume := newTokenLUKS()
	volume.keys[fido2TestSlot] = device.derive(enrollment.CredentialID, enrollment.Salt)
	// Lower token IDs that must not stop the unlock: one for another slot
	// whose credential the authenticator does not hold, one carrying no
	// FIDO2 credential or salt.
	volume.tokens[0] = &luks.Token{
		Type:            "fido2-manual",
		Keyslots:        []string{"0"},
		FIDO2Credential: base64.StdEncoding.EncodeToString([]byte("other-slot")),
		FIDO2Salt:       base64.StdEncoding.EncodeToString([]byte("other-salt")),
	}
	volume.tokens[1] = &luks.Token{Type: "systemd-tpm2", Keyslots: []string{"1"}}
	// The token exactly as pkg/installer writes it: the SDK-derivation type
	// and the slot keyed with what UnlockWithKey returns.
	volume.tokens[2] = &luks.Token{
		Type:            luks.TokenTypeFIDO2,
		Keyslots:        []string{fmt.Sprintf("%d", fido2TestSlot)},
		FIDO2Credential: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
		FIDO2RP:         fido2RelyingPartyID,
		FIDO2UPRequired: true,
	}

	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())
	if err := strategy.Unlock(ctx, fido2TestVolume()); err != nil {
		t.Fatalf("Unlock with the installer's token failed: %v", err)
	}
	// fido2-up-required is user presence on a type fido2 token; the
	// installer derives the key without user verification.
	last := device.configs[len(device.configs)-1]
	if last.RequireUserVerification {
		t.Error("type fido2 token was unlocked with user verification")
	}
}

// TestFIDO2StrategyRawSecretTokenRefused checks that a token whose type does
// not mark the SDK derivation (the installer's former fido2-manual layout,
// whose slot holds the raw hmac-secret) is refused with the typed error
// before the authenticator or the slot is tried.
// enrolledDevice returns a fake authenticator holding one credential.
func enrolledDevice(t *testing.T) (*fakeFIDO2, *fido2.EnrollmentResult) {
	t.Helper()
	device := newFakeFIDO2()
	enrollment, err := device.EnrollKey(&fido2.EnrollmentConfig{})
	if err != nil {
		t.Fatalf("EnrollKey failed: %v", err)
	}
	return device, enrollment
}

func TestFIDO2StrategySystemdTokenRefused(t *testing.T) {
	device, enrollment := enrolledDevice(t)
	volume := newTokenLUKS()
	volume.keys[fido2TestSlot] = device.hmacSecret(enrollment.CredentialID, enrollment.Salt)
	volume.tokens[0] = &luks.Token{
		Type:            "systemd-fido2",
		Keyslots:        []string{fmt.Sprintf("%d", fido2TestSlot)},
		FIDO2Credential: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
		FIDO2RP:         fido2RelyingPartyID,
	}

	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())
	err := strategy.Unlock(context.Background(), fido2TestVolume())
	var rawErr *FIDO2RawSecretTokenError
	if !errors.As(err, &rawErr) {
		t.Fatalf("Unlock error = %v, want FIDO2RawSecretTokenError", err)
	}
	if rawErr.Type != "systemd-fido2" || rawErr.Slot != fido2TestSlot || rawErr.TokenID != 0 || rawErr.Err != nil {
		t.Errorf("error fields = %+v, want systemd-fido2 slot %d token 0 and no cause", rawErr, fido2TestSlot)
	}
	if !strings.Contains(err.Error(), "go-xkms #1769") {
		t.Errorf("error %q does not name go-xkms #1769", err)
	}
	if device.unlocks != 0 {
		t.Errorf("UnlockWithKey called %d times, want 0", device.unlocks)
	}
	if len(volume.opened) != 0 {
		t.Errorf("slot tried %d times, want 0", len(volume.opened))
	}
}

// An fido2-manual token from an earlier installer keys its slot with the raw
// hmac-secret. The token does not say so, so the SDK derivation is tried
// once; the keyslot rejects it and the error names go-xkms #1769.
func TestFIDO2StrategyManualRawSecretToken(t *testing.T) {
	device, enrollment := enrolledDevice(t)
	volume := newTokenLUKS()
	volume.keys[fido2TestSlot] = device.hmacSecret(enrollment.CredentialID, enrollment.Salt)
	volume.tokens[0] = &luks.Token{
		Type:            fido2ManualTokenType,
		Keyslots:        []string{fmt.Sprintf("%d", fido2TestSlot)},
		FIDO2Credential: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
		FIDO2RP:         "luks-alpine",
	}

	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())
	err := strategy.Unlock(context.Background(), fido2TestVolume())
	var rawErr *FIDO2RawSecretTokenError
	if !errors.As(err, &rawErr) {
		t.Fatalf("Unlock error = %v, want FIDO2RawSecretTokenError", err)
	}
	if rawErr.Type != fido2ManualTokenType || rawErr.Slot != fido2TestSlot || rawErr.TokenID != 0 {
		t.Errorf("error fields = %+v, want fido2-manual slot %d token 0", rawErr, fido2TestSlot)
	}
	if !errors.Is(err, errFakeWrongKey) {
		t.Errorf("error %v does not carry the keyslot rejection", err)
	}
	if !strings.Contains(err.Error(), "go-xkms #1769") {
		t.Errorf("error %q does not name go-xkms #1769", err)
	}
	if device.unlocks != 1 {
		t.Errorf("UnlockWithKey called %d times, want 1", device.unlocks)
	}
	if len(volume.opened) != 1 {
		t.Errorf("slot tried %d times, want 1", len(volume.opened))
	}
}

// The runtime LUKS service (pkg/app/backends) writes fido2-manual tokens
// keyed with the SDK derivation: the credential ID as the caller gave it, the
// user-verification option in fido2-up-required, and its relying party.
func TestFIDO2StrategyRuntimeTokens(t *testing.T) {
	encodings := map[string]func([]byte) string{
		"hex":            hex.EncodeToString,
		"base64":         base64.StdEncoding.EncodeToString,
		"raw base64":     base64.RawStdEncoding.EncodeToString,
		"raw URL base64": base64.RawURLEncoding.EncodeToString,
	}
	tests := []struct {
		name       string
		encoding   string
		rpID       string
		upRequired bool
		wantRP     string
	}{
		{name: "hex credential, verification required", encoding: "hex", rpID: "go-xkms", upRequired: true, wantRP: "go-xkms"},
		{name: "base64 credential", encoding: "base64", rpID: "platform", wantRP: "platform"},
		{name: "raw base64 credential", encoding: "raw base64", rpID: "go-xkms", upRequired: true, wantRP: "go-xkms"},
		{name: "raw URL base64 credential, no relying party", encoding: "raw URL base64", wantRP: fido2.DefaultConfig.RelyingPartyID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, enrollment := enrolledDevice(t)
			volume := newTokenLUKS()
			volume.keys[fido2TestSlot] = device.derive(enrollment.CredentialID, enrollment.Salt)
			volume.tokens[0] = &luks.Token{
				Type:            fido2ManualTokenType,
				Keyslots:        []string{fmt.Sprintf("%d", fido2TestSlot)},
				FIDO2Credential: encodings[tt.encoding](enrollment.CredentialID),
				FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
				FIDO2RP:         tt.rpID,
				FIDO2UPRequired: tt.upRequired,
			}

			strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())
			if err := strategy.Unlock(context.Background(), fido2TestVolume()); err != nil {
				t.Fatalf("Unlock failed: %v", err)
			}
			if len(device.configs) != 1 {
				t.Fatalf("UnlockWithKey called %d times, want 1", len(device.configs))
			}
			config := device.configs[0]
			if config.RelyingPartyID != tt.wantRP {
				t.Errorf("relying party = %q, want %q", config.RelyingPartyID, tt.wantRP)
			}
			if config.RequireUserVerification != tt.upRequired {
				t.Errorf("user verification = %v, want %v", config.RequireUserVerification, tt.upRequired)
			}
		})
	}
}

func TestFIDO2StrategyHeaderTokenErrors(t *testing.T) {
	validCredential := base64.StdEncoding.EncodeToString([]byte("credential"))
	validSalt := base64.StdEncoding.EncodeToString([]byte("salt"))

	tests := []struct {
		name      string
		tokens    map[int]*luks.Token
		listErr   error
		wantField string
		check     func(t *testing.T, err error)
	}{
		{
			name: "no FIDO2 token in the header",
			tokens: map[int]*luks.Token{
				0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"1"}, FIDO2Credential: validCredential},
				1: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"slot"}, FIDO2Credential: validCredential, FIDO2Salt: validSalt},
			},
			check: func(t *testing.T, err error) {
				var notFound *FIDO2TokenNotFoundError
				if !errors.As(err, &notFound) || notFound.DevicePath != "/dev/sda2" {
					t.Fatalf("expected FIDO2TokenNotFoundError for /dev/sda2, got %v", err)
				}
				if !strings.Contains(err.Error(), "/dev/sda2") {
					t.Errorf("error %q does not name the device", err)
				}
			},
		},
		{
			name: "bad base64 credential",
			tokens: map[int]*luks.Token{
				0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"1"}, FIDO2Credential: "not*base64", FIDO2Salt: validSalt},
			},
			wantField: "fido2-credential",
		},
		{
			name: "fido2-manual credential in no runtime encoding",
			tokens: map[int]*luks.Token{
				0: {Type: fido2ManualTokenType, Keyslots: []string{"1"}, FIDO2Credential: "not*base64", FIDO2Salt: validSalt},
			},
			wantField: "fido2-credential",
		},
		{
			name: "bad base64 salt",
			tokens: map[int]*luks.Token{
				0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"1"}, FIDO2Credential: validCredential, FIDO2Salt: "not*base64"},
			},
			wantField: "fido2-salt",
		},
		{
			name: "fido2-manual bad base64 salt",
			tokens: map[int]*luks.Token{
				0: {Type: fido2ManualTokenType, Keyslots: []string{"1"}, FIDO2Credential: validCredential, FIDO2Salt: "not*base64"},
			},
			wantField: "fido2-salt",
		},
		{
			name:    "token list fails",
			listErr: errFakeTokenList,
			check: func(t *testing.T, err error) {
				var wrapped *WrappedError
				if !errors.As(err, &wrapped) || !errors.Is(err, errFakeTokenList) {
					t.Fatalf("expected WrappedError around %v, got %v", errFakeTokenList, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			volume := newTokenLUKS()
			volume.tokenListErr = tt.listErr
			for id, token := range tt.tokens {
				volume.tokens[id] = token
			}
			device := newFakeFIDO2()
			strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())

			err := strategy.Unlock(context.Background(), fido2TestVolume())
			if tt.wantField != "" {
				var decodeErr *FIDO2TokenDecodeError
				if !errors.As(err, &decodeErr) || decodeErr.Field != tt.wantField || decodeErr.Slot != fido2TestSlot {
					t.Fatalf("expected FIDO2TokenDecodeError on %s for slot %d, got %v", tt.wantField, fido2TestSlot, err)
				}
				if errors.Unwrap(decodeErr) == nil || !strings.Contains(err.Error(), tt.wantField) {
					t.Errorf("decode error %q does not carry its cause and field", err)
				}
			} else {
				tt.check(t, err)
			}

			if device.unlocks != 0 {
				t.Errorf("UnlockWithKey called %d times", device.unlocks)
			}
			if len(volume.opened) != 0 {
				t.Errorf("Open was called %d times", len(volume.opened))
			}
		})
	}
}

// The slot comes from the header token, not from the configured volume: a
// token bound to slot 2 opens slot 2 although the volume configures FIDO2 at
// slot 1, and a slot named by two tokens is taken from the lower ID.
func TestFIDO2StrategySlotFromHeader(t *testing.T) {
	device, enrollment := enrolledDevice(t)
	volume := newTokenLUKS()
	volume.keys[2] = device.derive(enrollment.CredentialID, enrollment.Salt)
	token := &luks.Token{
		Type:            luks.TokenTypeFIDO2,
		Keyslots:        []string{"2"},
		FIDO2Credential: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
	}
	volume.tokens[4] = token
	volume.tokens[7] = &luks.Token{Type: "systemd-fido2", Keyslots: []string{"2"}, FIDO2Credential: token.FIDO2Credential, FIDO2Salt: token.FIDO2Salt}

	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())
	if err := strategy.Unlock(context.Background(), fido2TestVolume()); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if device.unlocks != 1 || len(volume.opened) != 1 {
		t.Errorf("unlocks = %d, opens = %d, want 1 and 1", device.unlocks, len(volume.opened))
	}
	if device.configs[0].RelyingPartyID != fido2RelyingPartyID || device.configs[0].RequireUserVerification {
		t.Errorf("config = %+v, want relying party %q without user verification", device.configs[0], fido2RelyingPartyID)
	}
}

// The default path: the installer's default configuration enrols FIDO2 in
// its default keyslot, and the initrd's default configuration, through
// buildVolumeConfig with no overrides, unlocks that slot. The two defaults
// number the FIDO2 slot differently (3 and the FallbackMethods position 2).
func TestFIDO2StrategyDefaultPath(t *testing.T) {
	installerConfig := installer.DefaultConfig()
	enrollConfig := &installer.FIDO2EnrollmentConfig{LUKSDevice: "/dev/sda2"}
	if installerConfig.FIDO2 != nil && installerConfig.FIDO2.Keyslot != 0 {
		enrollConfig.TargetKeyslot = installerConfig.FIDO2.Keyslot
	}
	if _, err := installer.NewFIDO2Enrollment(enrollConfig); err != nil {
		t.Fatalf("NewFIDO2Enrollment failed: %v", err)
	}

	// The slot and token exactly as pkg/installer enrols them.
	device, enrollment := enrolledDevice(t)
	volume := newTokenLUKS()
	volume.keys[enrollConfig.TargetKeyslot] = device.derive(enrollment.CredentialID, enrollment.Salt)
	volume.tokens[0] = &luks.Token{
		Type:            luks.TokenTypeFIDO2,
		Keyslots:        []string{fmt.Sprintf("%d", enrollConfig.TargetKeyslot)},
		FIDO2Credential: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(enrollment.Salt),
		FIDO2RP:         enrollConfig.RelyingPartyID,
		FIDO2UPRequired: true,
	}

	// The default fallback methods, through the chain NewManager registers.
	platform := newFIDO2TestPlatform(device, volume)
	platform.Config = DefaultConfig()
	platform.Config.PCRSelection = []uint{7}
	built, err := NewManager(platform, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	manager := built.(*initrdManager)
	marker := filepath.Join(t.TempDir(), "unlock-strategy")
	manager.chain.SetMarkerPath(marker)

	if err := manager.UnlockVolumes(context.Background()); err != nil {
		t.Fatalf("UnlockVolumes on the default path failed: %v", err)
	}
	if len(volume.opened) != 1 {
		t.Errorf("slot tried %d times, want 1", len(volume.opened))
	}
	winner, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("reading the unlock-strategy marker: %v", err)
	}
	if got := strings.TrimSpace(string(winner)); got != "FIDO2" {
		t.Errorf("volume unlocked by %q, want FIDO2", got)
	}
}

func TestFIDO2StrategyNoTokenSupport(t *testing.T) {
	ctx := context.Background()
	device := newFakeFIDO2()
	// MockLUKSHandler has no token methods; any LUKS call on it would fail
	// the test, since none is mocked.
	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, &MockLUKSHandler{}), logging.DefaultLogger())

	err := strategy.Install(ctx, fido2TestVolume(), []byte("password"))
	var unsupported *FIDO2TokenUnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Error() == "" {
		t.Fatalf("Install: expected FIDO2TokenUnsupportedError, got %v", err)
	}
	if device.enrolled != 0 {
		t.Errorf("Install enrolled %d credentials before refusing", device.enrolled)
	}

	if err := strategy.Unlock(ctx, fido2TestVolume()); err == nil {
		t.Error("Unlock succeeded without token support")
	}
}

func TestFIDO2StrategyInstallFailuresWriteNothing(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(device *fakeFIDO2, volume *tokenLUKS)
		check   func(t *testing.T, err error)
	}{
		{
			name:    "hmac-secret derivation fails",
			prepare: func(device *fakeFIDO2, volume *tokenLUKS) { device.unlockErr = errFakeUnlock },
			check: func(t *testing.T, err error) {
				var wrapped *WrappedError
				if !errors.As(err, &wrapped) || !errors.Is(err, errFakeUnlock) {
					t.Fatalf("expected WrappedError around %v, got %v", errFakeUnlock, err)
				}
			},
		},
		{
			name: "salt generation fails",
			prepare: func(device *fakeFIDO2, volume *tokenLUKS) {
				device.noSalt = true
				fido2SaltReader = failingReader{}
			},
			check: func(t *testing.T, err error) {
				var saltErr *FIDO2SaltError
				if !errors.As(err, &saltErr) || !errors.Is(err, errFakeEntropy) || saltErr.Error() == "" {
					t.Fatalf("expected FIDO2SaltError around %v, got %v", errFakeEntropy, err)
				}
			},
		},
		{
			name:    "token create fails and the slot is killed",
			prepare: func(device *fakeFIDO2, volume *tokenLUKS) { volume.tokenCreateErr = errFakeTokenCreate },
			check: func(t *testing.T, err error) {
				var storeErr *FIDO2TokenStoreError
				if !errors.As(err, &storeErr) || storeErr.Slot != fido2TestSlot || storeErr.RollbackErr != nil {
					t.Fatalf("expected FIDO2TokenStoreError for slot %d without a rollback error, got %v", fido2TestSlot, err)
				}
				if !errors.Is(err, errFakeTokenCreate) || !strings.Contains(err.Error(), "was killed") {
					t.Errorf("error %q does not wrap %v", err, errFakeTokenCreate)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saltReader := fido2SaltReader
			t.Cleanup(func() { fido2SaltReader = saltReader })

			device := newFakeFIDO2()
			volume := newTokenLUKS()
			tt.prepare(device, volume)
			strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())

			err := strategy.Install(context.Background(), fido2TestVolume(), []byte("password"))
			tt.check(t, err)
			if len(volume.keys) != 0 {
				t.Errorf("a key was left in slot(s) %v", volume.keys)
			}
			if len(volume.tokens) != 0 {
				t.Errorf("%d token(s) were written", len(volume.tokens))
			}
		})
	}
}

func TestFIDO2StrategyInstallRollbackFails(t *testing.T) {
	device := newFakeFIDO2()
	volume := newTokenLUKS()
	volume.tokenCreateErr = errFakeTokenCreate
	volume.killErr = errFakeKillSlot
	strategy := NewFIDO2Strategy(newFIDO2TestPlatform(device, volume), logging.DefaultLogger())

	err := strategy.Install(context.Background(), fido2TestVolume(), []byte("password"))
	var storeErr *FIDO2TokenStoreError
	if !errors.As(err, &storeErr) {
		t.Fatalf("expected FIDO2TokenStoreError, got %v", err)
	}
	if !errors.Is(err, errFakeTokenCreate) || !errors.Is(err, errFakeKillSlot) {
		t.Errorf("error %q does not wrap both %v and %v", err, errFakeTokenCreate, errFakeKillSlot)
	}
	if len(volume.killed) != 1 || volume.killed[0] != fido2TestSlot {
		t.Errorf("KillSlot calls = %v, want [%d]", volume.killed, fido2TestSlot)
	}
	if !strings.Contains(err.Error(), "also failed") {
		t.Errorf("error %q does not report the failed rollback", err)
	}
}

// failingReader is an entropy source that always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errFakeEntropy }
