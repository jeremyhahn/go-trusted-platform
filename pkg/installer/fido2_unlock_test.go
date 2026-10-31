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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
	tools    *fakeFIDO2Tools
}

// fakeFIDO2Tools stands in for the libfido2 tools (fido2-token, fido2-assert)
// of the raw hmac-secret unlock. fido2-assert answers with the raw
// hmac-secret of device for the credential and salt on its stdin.
type fakeFIDO2Tools struct {
	device       *sdkFakeFIDO2
	listOutput   string
	listErr      error
	assertErr    error
	assertOutput string
	calls        [][]string
	stdins       []string
}

func (f *fakeFIDO2Tools) run(_ context.Context, stdin string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	f.stdins = append(f.stdins, stdin)
	if name == "fido2-token" {
		return []byte(f.listOutput), f.listErr
	}
	if f.assertErr != nil {
		return nil, f.assertErr
	}
	if f.assertOutput != "" {
		return []byte(f.assertOutput), nil
	}
	params := strings.Split(stdin, "\n")
	credential, err := base64.StdEncoding.DecodeString(params[2])
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(params[3])
	if err != nil {
		return nil, err
	}
	secret := f.device.hmacSecret(credential, salt)
	return []byte("assertion-header\n" + base64.StdEncoding.EncodeToString(secret) + "\n"), nil
}

func useFakeUnlockDevice(t *testing.T, header *fakeLUKSHeader, device fido2.Handler) *fakeUnlockDevice {
	t.Helper()
	tools := &fakeFIDO2Tools{listOutput: "/dev/hidraw0: vendor=0x1050, product=0x0407 (Yubico YubiKey)\n"}
	if sdkDevice, ok := device.(*sdkFakeFIDO2); ok {
		tools.device = sdkDevice
	}
	fake := &fakeUnlockDevice{header: header, mapped: map[string]bool{}, tools: tools}
	oldList, oldUnlock, oldLock, oldIsUnlocked, oldHandler, oldCommand := luksListTokens, luksUnlock, luksLock, luksIsUnlocked, newFIDO2Handler, fido2Command
	t.Cleanup(func() {
		luksListTokens, luksUnlock, luksLock, luksIsUnlocked, newFIDO2Handler, fido2Command = oldList, oldUnlock, oldLock, oldIsUnlocked, oldHandler, oldCommand
	})
	fido2Command = tools.run
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
	require.NoError(t, newTestFIDO2Enrollment(t).enrollWithHandler(context.Background(), device))
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
	assert.Empty(t, fake.tools.calls, "a token marked with the SDK derivation ran a libfido2 tool")
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
// rawSecretVolume returns a header as an earlier installer left it: a
// fido2-manual token whose slot 3 is keyed with the raw hmac-secret.
func rawSecretVolume(t *testing.T) (*fakeLUKSHeader, *sdkFakeFIDO2) {
	t.Helper()
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
	return header, device
}

// TestFIDO2UnlockManualRawSecretToken opens a volume an earlier installer
// enrolled: the SDK key is rejected once, then the raw hmac-secret from
// fido2-assert opens the slot.
func TestFIDO2UnlockManualRawSecretToken(t *testing.T) {
	ctx := context.Background()
	header, device := rawSecretVolume(t)
	fake := useFakeUnlockDevice(t, header, device)
	unlock := NewFIDO2Unlock("/dev/fake-luks", false)

	require.NoError(t, unlock.Unlock(ctx, "cryptroot"))
	assert.True(t, fake.mapped["cryptroot"], "the device was not mapped")
	require.NoError(t, unlock.TestUnlock(ctx))
	assert.False(t, fake.mapped[fido2UnlockTestMapping], "the test mapping was left open")

	assert.Len(t, device.unlocks, 2, "the SDK derivation is tried once per unlock")
	require.Len(t, fake.tools.calls, 4)
	assert.Equal(t, []string{"fido2-token", "-L"}, fake.tools.calls[0])
	assert.Equal(t, []string{"fido2-assert", "-G", "-h", "/dev/hidraw0"}, fake.tools.calls[1])
	challenge := sha256.Sum256([]byte("luks-enrollment-challenge"))
	assert.Equal(t, base64.StdEncoding.EncodeToString(challenge[:])+"\n"+
		"luks-alpine\n"+
		base64.StdEncoding.EncodeToString(device.credential)+"\n"+
		base64.StdEncoding.EncodeToString(device.salt)+"\n", fake.tools.stdins[1])
}

// TestFIDO2UnlockRawSecretFailures covers each failure of the raw
// hmac-secret unlock of an fido2-manual token.
func TestFIDO2UnlockRawSecretFailures(t *testing.T) {
	errFakeList := &fakeHandlerError{op: "fido2-token -L"}
	errFakeAssert := &fakeHandlerError{op: "fido2-assert"}
	tests := []struct {
		name  string
		setup func(tools *fakeFIDO2Tools, device *sdkFakeFIDO2)
		check func(t *testing.T, err error)
	}{
		{
			name:  "device list fails",
			setup: func(tools *fakeFIDO2Tools, _ *sdkFakeFIDO2) { tools.listErr = errFakeList },
			check: func(t *testing.T, err error) { assertAssertStep(t, err, "list the FIDO2 devices", errFakeList) },
		},
		{
			name:  "no device listed",
			setup: func(tools *fakeFIDO2Tools, _ *sdkFakeFIDO2) { tools.listOutput = "" },
			check: func(t *testing.T, err error) {
				var noDevice *FIDO2NoDeviceError
				assert.ErrorAs(t, err, &noDevice)
			},
		},
		{
			name:  "assertion fails",
			setup: func(tools *fakeFIDO2Tools, _ *sdkFakeFIDO2) { tools.assertErr = errFakeAssert },
			check: func(t *testing.T, err error) { assertAssertStep(t, err, "get the hmac-secret", errFakeAssert) },
		},
		{
			name:  "secret not base64",
			setup: func(tools *fakeFIDO2Tools, _ *sdkFakeFIDO2) { tools.assertOutput = "not*base64" },
			check: func(t *testing.T, err error) {
				var corrupt base64.CorruptInputError
				assert.ErrorAs(t, err, &corrupt)
			},
		},
		{
			name: "secret of the wrong length",
			setup: func(tools *fakeFIDO2Tools, _ *sdkFakeFIDO2) {
				tools.assertOutput = base64.StdEncoding.EncodeToString(make([]byte, 16))
			},
			check: func(t *testing.T, err error) {
				var length *FIDO2SecretLengthError
				require.ErrorAs(t, err, &length)
				assert.Equal(t, 16, length.Length)
			},
		},
		{
			name:  "raw secret rejected",
			setup: func(_ *fakeFIDO2Tools, device *sdkFakeFIDO2) { device.secret[0] ^= 0xff },
			check: func(t *testing.T, err error) {
				var rejected *FIDO2KeyRejectedError
				require.ErrorAs(t, err, &rejected)
				assert.ErrorIs(t, err, errFakeWrongKey)
				assert.Equal(t, []string{"3"}, rejected.Keyslots)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, device := rawSecretVolume(t)
			fake := useFakeUnlockDevice(t, header, device)
			tt.setup(fake.tools, device)

			err := NewFIDO2Unlock("/dev/fake-luks", false).Unlock(context.Background(), "cryptroot")
			require.Error(t, err)
			tt.check(t, err)
			assert.False(t, fake.mapped["cryptroot"])
		})
	}
}

func assertAssertStep(t *testing.T, err error, step string, cause error) {
	t.Helper()
	var assertErr *FIDO2AssertError
	require.ErrorAs(t, err, &assertErr)
	assert.Equal(t, step, assertErr.Step)
	assert.ErrorIs(t, err, cause)
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
