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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewFIDO2Unlock(t *testing.T) {
	t.Run("create unlock handler", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/vda2", true)
		assert.NotNil(t, unlock)
		assert.Equal(t, "/dev/vda2", unlock.luksDevice)
		assert.True(t, unlock.debug)
	})

	t.Run("create without debug", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/sda2", false)
		assert.NotNil(t, unlock)
		assert.Equal(t, "/dev/sda2", unlock.luksDevice)
		assert.False(t, unlock.debug)
	})
}

func TestFIDO2Unlock_GetTokenInfo(t *testing.T) {
	t.Run("no FIDO2 token in device", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/null", false)
		token, err := unlock.GetTokenInfo()
		// Should fail because /dev/null is not a LUKS device
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("invalid LUKS device", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/nonexistent/device", false)
		token, err := unlock.GetTokenInfo()
		// Should fail because device doesn't exist
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "failed to read LUKS header")
	})
}

var (
	errFakeWrongKey    = &fakeHandlerError{op: "no keyslot opens with the key"}
	errFakeListTokens  = &fakeHandlerError{op: "list tokens"}
	errFakeOpenHandler = &fakeHandlerError{op: "open handler"}
	errFakeLock        = &fakeHandlerError{op: "lock"}
)

// fakeUnlockDevice serves the unlock's go-luks2 calls from a fakeLUKSHeader
// and its FIDO2 handler from a fake authenticator.
type fakeUnlockDevice struct {
	header   *fakeLUKSHeader
	listErr  error
	lockErr  error
	mapped   map[string]bool
	handlers []*fido2.Config
	openErr  error
}

func useFakeUnlockDevice(t *testing.T, header *fakeLUKSHeader, device fido2.Handler) *fakeUnlockDevice {
	t.Helper()
	fake := &fakeUnlockDevice{header: header, mapped: map[string]bool{}}
	oldList, oldUnlock, oldLock, oldIsUnlocked, oldHandler := luksListTokens, luksUnlock, luksLock, luksIsUnlocked, newFIDO2Handler
	t.Cleanup(func() {
		luksListTokens, luksUnlock, luksLock, luksIsUnlocked, newFIDO2Handler = oldList, oldUnlock, oldLock, oldIsUnlocked, oldHandler
	})
	luksListTokens = func(string) (map[int]*luks2.Token, error) {
		if fake.listErr != nil {
			return nil, fake.listErr
		}
		return header.tokens, nil
	}
	luksUnlock = func(_ string, passphrase []byte, name string) error {
		for _, key := range header.slots {
			if bytes.Equal(key, passphrase) {
				fake.mapped[name] = true
				return nil
			}
		}
		return errFakeWrongKey
	}
	luksLock = func(name string) error {
		if fake.lockErr != nil {
			return fake.lockErr
		}
		delete(fake.mapped, name)
		return nil
	}
	luksIsUnlocked = func(name string) bool { return fake.mapped[name] }
	newFIDO2Handler = func(cfg *fido2.Config) (fido2.Handler, error) {
		fake.handlers = append(fake.handlers, cfg)
		if fake.openErr != nil {
			return nil, fake.openErr
		}
		return device, nil
	}
	return fake
}

// enrolledFakeDevice enrols the fake authenticator through the installer and
// returns the header it wrote.
func enrolledFakeDevice(t *testing.T) (*fakeLUKSHeader, *sdkFakeFIDO2) {
	t.Helper()
	header := useFakeLUKSHeader(t)
	device := newSDKFakeFIDO2()
	require.NoError(t, newTestFIDO2Enrollment(t).enrollWithHandler(device))
	return header, device
}

// Codex review 8605 P1: what the installer enrols, FIDO2Unlock opens; a
// different derived key is refused with a typed error.
func TestFIDO2UnlockAfterEnrollment(t *testing.T) {
	ctx := context.Background()
	header, device := enrolledFakeDevice(t)
	fake := useFakeUnlockDevice(t, header, device)
	unlock := NewFIDO2Unlock("/dev/fake-luks", false)

	require.NoError(t, unlock.Unlock(ctx, "cryptroot"))
	assert.True(t, fake.mapped["cryptroot"], "the device was not mapped")

	require.NoError(t, unlock.TestUnlock(ctx))
	assert.False(t, fake.mapped[fido2UnlockTestMapping], "the test mapping was left open")

	require.Len(t, device.unlocks, 3, "one derivation at enrolment, one per unlock")
	for _, config := range device.unlocks[1:] {
		assert.Equal(t, "luks-alpine", config.RelyingPartyID)
		assert.False(t, config.RequireUserVerification)
	}
	require.Len(t, fake.handlers, 2)
	assert.Equal(t, "luks-alpine", fake.handlers[0].RelyingPartyID)

	// A different authenticator secret derives a different key.
	device.secret[0] ^= 0xff
	for name, run := range map[string]func() error{
		"Unlock":     func() error { return unlock.Unlock(ctx, "cryptroot2") },
		"TestUnlock": func() error { return unlock.TestUnlock(ctx) },
	} {
		err := run()
		var rejected *FIDO2KeyRejectedError
		require.ErrorAs(t, err, &rejected, name)
		assert.ErrorIs(t, err, errFakeWrongKey, name)
		assert.Equal(t, []string{"3"}, rejected.Keyslots, name)
	}
	assert.False(t, fake.mapped["cryptroot2"])
}

// The runtime LUKS service (pkg/app/backends) writes fido2-manual tokens
// keyed with the SDK derivation, the credential ID as the caller gave it and
// the user-verification option in fido2-up-required.
func TestFIDO2UnlockRuntimeTokens(t *testing.T) {
	tests := []struct {
		name       string
		encode     func([]byte) string
		rpID       string
		upRequired bool
		wantRP     string
	}{
		{name: "hex credential, verification required", encode: hex.EncodeToString, rpID: "go-xkms", upRequired: true, wantRP: "go-xkms"},
		{name: "base64 credential", encode: base64.StdEncoding.EncodeToString, rpID: "platform", wantRP: "platform"},
		{name: "raw base64 credential", encode: base64.RawStdEncoding.EncodeToString, rpID: "go-xkms", upRequired: true, wantRP: "go-xkms"},
		{name: "raw URL base64 credential, no relying party", encode: base64.RawURLEncoding.EncodeToString, wantRP: fido2.DefaultConfig.RelyingPartyID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := useFakeLUKSHeader(t)
			device := newSDKFakeFIDO2()
			header.slots[1] = device.derive(device.credential, device.salt)
			header.tokens[0] = &luks2.Token{
				Type:            fido2ManualTokenType,
				Keyslots:        []string{"1"},
				FIDO2Credential: tt.encode(device.credential),
				FIDO2Salt:       base64.StdEncoding.EncodeToString(device.salt),
				FIDO2RP:         tt.rpID,
				FIDO2UPRequired: tt.upRequired,
			}
			useFakeUnlockDevice(t, header, device)

			require.NoError(t, NewFIDO2Unlock("/dev/fake-luks", false).Unlock(context.Background(), "cryptroot"))
			require.Len(t, device.unlocks, 1)
			assert.Equal(t, tt.wantRP, device.unlocks[0].RelyingPartyID)
			assert.Equal(t, tt.upRequired, device.unlocks[0].RequireUserVerification)
		})
	}
}

// An fido2-manual token from an earlier installer keys its slot with the raw
// hmac-secret. The SDK derivation is tried once, the device rejects it and
// the error names go-xkms #1769.
func TestFIDO2UnlockManualRawSecretToken(t *testing.T) {
	header := useFakeLUKSHeader(t)
	device := newSDKFakeFIDO2()
	header.slots[3] = device.hmacSecret(device.credential, device.salt)
	header.tokens[0] = &luks2.Token{
		Type:            fido2ManualTokenType,
		Keyslots:        []string{"3"},
		FIDO2Credential: base64.StdEncoding.EncodeToString(device.credential),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(device.salt),
		FIDO2RP:         "luks-alpine",
		FIDO2UPRequired: true,
	}
	useFakeUnlockDevice(t, header, device)

	err := NewFIDO2Unlock("/dev/fake-luks", false).Unlock(context.Background(), "cryptroot")
	var rawErr *FIDO2RawSecretTokenError
	require.ErrorAs(t, err, &rawErr)
	assert.ErrorIs(t, err, errFakeWrongKey)
	assert.Equal(t, fido2ManualTokenType, rawErr.Type)
	assert.Contains(t, err.Error(), "go-xkms #1769")
	assert.Len(t, device.unlocks, 1, "the authenticator was asked more than once")
}

func TestFIDO2UnlockSystemdToken(t *testing.T) {
	systemdToken := func() *luks2.Token {
		return &luks2.Token{
			Type:            "systemd-fido2",
			Keyslots:        []string{"1"},
			FIDO2Credential: base64.StdEncoding.EncodeToString([]byte("systemd-credential")),
			FIDO2Salt:       base64.StdEncoding.EncodeToString([]byte("systemd-salt")),
		}
	}

	t.Run("refused without asking the authenticator", func(t *testing.T) {
		header := useFakeLUKSHeader(t)
		device := newSDKFakeFIDO2()
		header.tokens[0] = systemdToken()
		fake := useFakeUnlockDevice(t, header, device)

		err := NewFIDO2Unlock("/dev/fake-luks", false).TestUnlock(context.Background())
		var rawErr *FIDO2RawSecretTokenError
		require.ErrorAs(t, err, &rawErr)
		assert.Nil(t, rawErr.Err)
		assert.Equal(t, []string{"1"}, rawErr.Keyslots)
		assert.Contains(t, err.Error(), "go-xkms #1769")
		assert.Empty(t, device.unlocks)
		assert.Empty(t, fake.handlers)

		_, err = NewFIDO2Unlock("/dev/fake-luks", false).DeriveKey(context.Background(), &FIDO2Token{Type: "systemd-fido2"})
		require.ErrorAs(t, err, &rawErr)
	})

	t.Run("passed over for an SDK token", func(t *testing.T) {
		header, device := enrolledFakeDevice(t)
		header.tokens[0], header.tokens[1] = systemdToken(), header.tokens[0]
		useFakeUnlockDevice(t, header, device)

		token, err := NewFIDO2Unlock("/dev/fake-luks", false).GetTokenInfo()
		require.NoError(t, err)
		assert.Equal(t, luks.TokenTypeFIDO2, token.Type)
		require.NoError(t, NewFIDO2Unlock("/dev/fake-luks", false).Unlock(context.Background(), "cryptroot"))
	})
}

func TestFIDO2UnlockFailures(t *testing.T) {
	validCredential := base64.StdEncoding.EncodeToString([]byte("installer-credential-id"))
	validSalt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

	tests := []struct {
		name   string
		tokens map[int]*luks2.Token
		setup  func(fake *fakeUnlockDevice, device *sdkFakeFIDO2)
		check  func(t *testing.T, err error)
	}{
		{
			name: "no usable FIDO2 token",
			tokens: map[int]*luks2.Token{
				0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"3"}, FIDO2Credential: validCredential},
				1: {Type: luks.TokenTypeFIDO2, FIDO2Credential: validCredential, FIDO2Salt: validSalt},
			},
			check: func(t *testing.T, err error) {
				var notFound *FIDO2TokenNotFoundError
				require.ErrorAs(t, err, &notFound)
				assert.Equal(t, "/dev/fake-luks", notFound.Device)
			},
		},
		{
			name:  "token list fails",
			setup: func(fake *fakeUnlockDevice, _ *sdkFakeFIDO2) { fake.listErr = errFakeListTokens },
			check: func(t *testing.T, err error) {
				var wrapped *WrappedError
				require.ErrorAs(t, err, &wrapped)
				assert.ErrorIs(t, err, errFakeListTokens)
			},
		},
		{
			name:   "bad credential",
			tokens: map[int]*luks2.Token{0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"3"}, FIDO2Credential: "not*base64", FIDO2Salt: validSalt}},
			check:  decodeFailure("fido2-credential"),
		},
		{
			name:   "fido2-manual credential in no runtime encoding",
			tokens: map[int]*luks2.Token{0: {Type: fido2ManualTokenType, Keyslots: []string{"3"}, FIDO2Credential: "not*base64", FIDO2Salt: validSalt}},
			check:  decodeFailure("fido2-credential"),
		},
		{
			name:   "bad salt",
			tokens: map[int]*luks2.Token{0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"3"}, FIDO2Credential: validCredential, FIDO2Salt: "not*base64"}},
			check:  decodeFailure("fido2-salt"),
		},
		{
			name:   "fido2-manual bad salt",
			tokens: map[int]*luks2.Token{0: {Type: fido2ManualTokenType, Keyslots: []string{"3"}, FIDO2Credential: validCredential, FIDO2Salt: "not*base64"}},
			check:  decodeFailure("fido2-salt"),
		},
		{
			name:   "handler does not open",
			tokens: map[int]*luks2.Token{0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"3"}, FIDO2Credential: validCredential, FIDO2Salt: validSalt}},
			setup:  func(fake *fakeUnlockDevice, _ *sdkFakeFIDO2) { fake.openErr = errFakeOpenHandler },
			check: func(t *testing.T, err error) {
				var wrapped *WrappedError
				require.ErrorAs(t, err, &wrapped)
				assert.ErrorIs(t, err, errFakeOpenHandler)
			},
		},
		{
			name:   "derivation fails",
			tokens: map[int]*luks2.Token{0: {Type: luks.TokenTypeFIDO2, Keyslots: []string{"3"}, FIDO2Credential: validCredential, FIDO2Salt: validSalt}},
			setup:  func(_ *fakeUnlockDevice, device *sdkFakeFIDO2) { device.unlockErr = errFakeUnlock },
			check: func(t *testing.T, err error) {
				var deriveErr *FIDO2DeriveKeyError
				require.ErrorAs(t, err, &deriveErr)
				assert.ErrorIs(t, err, errFakeUnlock)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := useFakeLUKSHeader(t)
			for id, token := range tt.tokens {
				header.tokens[id] = token
			}
			device := newSDKFakeFIDO2()
			fake := useFakeUnlockDevice(t, header, device)
			if tt.setup != nil {
				tt.setup(fake, device)
			}
			unlock := NewFIDO2Unlock("/dev/fake-luks", false)

			tt.check(t, unlock.Unlock(context.Background(), "cryptroot"))
			tt.check(t, unlock.TestUnlock(context.Background()))
			assert.Empty(t, fake.mapped)
		})
	}
}

func decodeFailure(field string) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		var decodeErr *FIDO2TokenDecodeError
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, field, decodeErr.Field)
		assert.NotNil(t, errors.Unwrap(decodeErr))
		assert.Contains(t, err.Error(), field)
	}
}

// A stale test mapping that cannot be closed stops TestUnlock before the
// device is tried.
func TestFIDO2UnlockStaleTestMapping(t *testing.T) {
	header, device := enrolledFakeDevice(t)
	fake := useFakeUnlockDevice(t, header, device)
	fake.mapped[fido2UnlockTestMapping] = true
	fake.lockErr = errFakeLock

	err := NewFIDO2Unlock("/dev/fake-luks", false).TestUnlock(context.Background())
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, errFakeLock)
	assert.Equal(t, fmt.Sprint(map[string]bool{fido2UnlockTestMapping: true}), fmt.Sprint(fake.mapped))
}
