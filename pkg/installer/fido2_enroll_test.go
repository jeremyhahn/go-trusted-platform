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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewFIDO2Enrollment(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := NewFIDO2Enrollment(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config is required")
	})

	t.Run("valid config with defaults", func(t *testing.T) {
		config := &FIDO2EnrollmentConfig{
			LUKSDevice:     "/dev/vda2",
			LUKSPassphrase: "test-password",
		}

		enrollment, err := NewFIDO2Enrollment(config)
		require.NoError(t, err)
		assert.NotNil(t, enrollment)

		// Check defaults were applied
		assert.Equal(t, 3, config.TargetKeyslot)
		assert.Equal(t, "luks-alpine", config.RelyingPartyID)
		assert.Equal(t, "luks-user", config.UserName)
	})

	t.Run("valid config with custom values", func(t *testing.T) {
		config := &FIDO2EnrollmentConfig{
			LUKSDevice:     "/dev/sda2",
			LUKSPassphrase: "my-password",
			TargetKeyslot:  4,
			RelyingPartyID: "custom-rp",
			UserName:       "custom-user",
		}

		enrollment, err := NewFIDO2Enrollment(config)
		require.NoError(t, err)
		assert.NotNil(t, enrollment)

		// Custom values should be preserved
		assert.Equal(t, 4, config.TargetKeyslot)
		assert.Equal(t, "custom-rp", config.RelyingPartyID)
		assert.Equal(t, "custom-user", config.UserName)
	})
}

func TestFIDO2Token(t *testing.T) {
	t.Run("valid token structure", func(t *testing.T) {
		token := FIDO2Token{
			Type:            "fido2-manual",
			Keyslots:        []string{"3"},
			FIDO2Credential: "Y3JlZGVudGlhbC1pZC1iYXNlNjQ=",
			FIDO2Salt:       "c2FsdC1iYXNlNjQ=",
			FIDO2RP:         "luks-alpine",
			FIDO2UPRequired: true,
		}

		assert.Equal(t, "fido2-manual", token.Type)
		assert.Len(t, token.Keyslots, 1)
		assert.Equal(t, "3", token.Keyslots[0])
		assert.NotEmpty(t, token.FIDO2Credential)
		assert.NotEmpty(t, token.FIDO2Salt)
		assert.Equal(t, "luks-alpine", token.FIDO2RP)
		assert.True(t, token.FIDO2UPRequired)
	})
}

// fakeHandlerError is the typed error the fake authenticator and header
// return for an injected failure.
type fakeHandlerError struct {
	op string
}

func (e *fakeHandlerError) Error() string {
	return "fake " + e.op + " failure"
}

var (
	errFakeEnroll      = &fakeHandlerError{op: "enroll"}
	errFakeUnlock      = &fakeHandlerError{op: "unlock"}
	errFakeAddKey      = &fakeHandlerError{op: "add key"}
	errFakeCredential  = &fakeHandlerError{op: "unknown credential"}
	errFakeNoTokenSlot = &fakeHandlerError{op: "no free token slot"}
	errFakeKillSlot    = &fakeHandlerError{op: "kill slot"}
	errFakeNoUV        = &fakeHandlerError{op: "user verification unsupported"}
)

// sdkFakeFIDO2 models the SDK FIDO2 handler. The authenticator's hmac-secret
// is HMAC-SHA-256 over the credential and salt under a fixed device secret,
// and UnlockWithKey returns what the SDK returns: not that secret but its
// 64-byte GenerateDerivedKey expansion. Enrolment and unlock both go
// through the same derivation, as with the real handler.
type sdkFakeFIDO2 struct {
	secret     [32]byte
	credential []byte
	salt       []byte
	enrollErr  error
	unlockErr  error
	unlocks    []*fido2.AuthenticationConfig
	// noUV models an authenticator without built-in user verification: it
	// rejects every assertion that asks for it.
	noUV bool
	// touch, when set, runs first in each authenticator call with the
	// call's name ("enroll" or "unlock"); a test blocks in it.
	touch func(op string)
	// returned holds every key UnlockWithKey returned, so a test can check
	// that an abandoned operation's key was cleared.
	returned [][]byte
	// closed, when set, receives once per Close.
	closed chan struct{}
}

func newSDKFakeFIDO2() *sdkFakeFIDO2 {
	f := &sdkFakeFIDO2{
		credential: []byte("installer-credential-id"),
		salt:       bytes.Repeat([]byte{0x5a}, 32),
	}
	copy(f.secret[:], "fixed-authenticator-device-secret")
	return f
}

func (f *sdkFakeFIDO2) hmacSecret(credentialID, salt []byte) []byte {
	mac := hmac.New(sha256.New, f.secret[:])
	mac.Write(credentialID)
	mac.Write(salt)
	return mac.Sum(nil)
}

func (f *sdkFakeFIDO2) derive(credentialID, salt []byte) []byte {
	secret := f.hmacSecret(credentialID, salt)
	key1 := sha256.Sum256(append(slices.Clone(secret), "go-xkms-key-derivation-v1"...))
	key2 := sha256.Sum256(append(slices.Clone(secret), "go-xkms-key-derivation-v2"...))
	return append(key1[:], key2[:]...)
}

func (f *sdkFakeFIDO2) Close() error {
	if f.closed != nil {
		f.closed <- struct{}{}
	}
	return nil
}

func (f *sdkFakeFIDO2) ListDevices() ([]fido2.Device, error) {
	return []fido2.Device{{}}, nil
}

func (f *sdkFakeFIDO2) WaitForDevice(context.Context) (*fido2.Device, error) {
	return &fido2.Device{}, nil
}

func (f *sdkFakeFIDO2) EnrollKey(config *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	if f.touch != nil {
		f.touch("enroll")
	}
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	return &fido2.EnrollmentResult{
		CredentialID: slices.Clone(f.credential),
		Salt:         slices.Clone(f.salt),
		RelyingParty: config.RelyingParty,
	}, nil
}

func (f *sdkFakeFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	if f.touch != nil {
		f.touch("unlock")
	}
	f.unlocks = append(f.unlocks, config)
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	if f.noUV && config.RequireUserVerification {
		return nil, errFakeNoUV
	}
	if !bytes.Equal(config.CredentialID, f.credential) {
		return nil, errFakeCredential
	}
	key := f.derive(config.CredentialID, config.Salt)
	f.returned = append(f.returned, key)
	return key, nil
}

// blockFakeFIDO2 makes the device's op call ("enroll" or "unlock") block
// until finish. waiting is closed when the call starts. finish releases the
// call and waits until its operation slot is free again, that is, until an
// abandoned call's drain has cleared its result and closed the handler; it
// also runs at cleanup, so a failed test never leaves the slot held.
func blockFakeFIDO2(t *testing.T, device *sdkFakeFIDO2, op string) (waiting chan struct{}, finish func()) {
	t.Helper()
	device.closed = make(chan struct{}, 4)
	waiting = make(chan struct{})
	release := make(chan struct{})
	var started sync.Once
	device.touch = func(called string) {
		if called == op {
			started.Do(func() { close(waiting) })
			<-release
		}
	}
	finish = sync.OnceFunc(func() {
		close(release)
		fido2Operation <- struct{}{}
		<-fido2Operation
	})
	t.Cleanup(finish)
	return waiting, finish
}

// useFIDO2OperationBusy replaces the busy notice with one that signals the
// returned channel.
func useFIDO2OperationBusy(t *testing.T) chan struct{} {
	t.Helper()
	busy := make(chan struct{}, 4)
	old := fido2OperationBusy
	t.Cleanup(func() { fido2OperationBusy = old })
	fido2OperationBusy = func() { busy <- struct{}{} }
	return busy
}

// abandonFIDO2Enrollment starts an enrolment, cancels it while its
// credential is being created and returns once it has returned, leaving the
// abandoned authenticator call blocked until finish.
func abandonFIDO2Enrollment(t *testing.T) (device *sdkFakeFIDO2, finish func()) {
	t.Helper()
	device = newSDKFakeFIDO2()
	waiting, finish := blockFakeFIDO2(t, device, "enroll")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	enrollment := newTestFIDO2Enrollment(t)
	go func() { done <- enrollment.enrollWithHandler(ctx, device) }()
	<-waiting
	cancel()
	require.ErrorAs(t, <-done, new(*FIDO2CanceledError))
	return device, finish
}

// fakeLUKSHeader replaces the go-luks2 header writes of the enrolment.
type fakeLUKSHeader struct {
	addErr     error
	tokenErr   error
	killErr    error
	slots      map[int][]byte
	passedKeys [][]byte
	tokens     map[int]*luks2.Token
}

func useFakeLUKSHeader(t *testing.T) *fakeLUKSHeader {
	t.Helper()
	header := &fakeLUKSHeader{slots: map[int][]byte{}, tokens: map[int]*luks2.Token{}}
	oldAddKey, oldFind, oldImport, oldKill := luksAddKey, luksFindFreeTokenSlot, luksImportToken, luksKillSlot
	t.Cleanup(func() {
		luksAddKey, luksFindFreeTokenSlot, luksImportToken, luksKillSlot = oldAddKey, oldFind, oldImport, oldKill
	})
	luksKillSlot = func(device string, authPassphrase []byte, targetSlot int) error {
		if header.killErr != nil {
			return header.killErr
		}
		delete(header.slots, targetSlot)
		return nil
	}
	luksAddKey = func(device string, passphrase, newPassphrase []byte, opts *luks2.AddKeyOptions) error {
		header.passedKeys = append(header.passedKeys, newPassphrase)
		if header.addErr != nil {
			return header.addErr
		}
		header.slots[*opts.Keyslot] = bytes.Clone(newPassphrase)
		return nil
	}
	luksFindFreeTokenSlot = func(device string) (int, error) {
		if header.tokenErr != nil {
			return -1, header.tokenErr
		}
		return len(header.tokens), nil
	}
	luksImportToken = func(device string, tokenID int, token *luks2.Token) error {
		header.tokens[tokenID] = token
		return nil
	}
	return header
}

func newTestFIDO2Enrollment(t *testing.T) *FIDO2Enrollment {
	t.Helper()
	enrollment, err := NewFIDO2Enrollment(&FIDO2EnrollmentConfig{
		LUKSDevice:     "/dev/fake-luks",
		LUKSPassphrase: "existing-passphrase",
	})
	require.NoError(t, err)
	return enrollment
}

// initrdKeyFor derives the slot key the way the initrd FIDO2 strategy does
// at boot: it reads the token, refuses any type but luks.TokenTypeFIDO2,
// decodes the credential and salt and asks the handler for the key.
func initrdKeyFor(t *testing.T, handler fido2.Handler, token *luks2.Token) []byte {
	t.Helper()
	require.Equal(t, luks.TokenTypeFIDO2, token.Type, "the initrd only unlocks tokens marked with the SDK derivation")
	credential, err := base64.StdEncoding.DecodeString(token.FIDO2Credential)
	require.NoError(t, err)
	salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt)
	require.NoError(t, err)
	key, err := handler.UnlockWithKey(&fido2.AuthenticationConfig{
		RelyingPartyID: token.FIDO2RP,
		CredentialID:   credential,
		Salt:           salt,
	})
	require.NoError(t, err)
	return key
}

// TestFIDO2EnrollmentSlotKeyMatchesInitrd is the compatibility test for
// Codex review 8581 P1: the key the installer stores in the slot must be the
// key the initrd derives from the stored token. A slot keyed with the raw
// hmac-secret fails it.
func TestFIDO2EnrollmentSlotKeyMatchesInitrd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		noSalt bool
	}{
		{name: "salt from the handler"},
		{name: "salt generated by the installer", noSalt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := useFakeLUKSHeader(t)
			device := newSDKFakeFIDO2()
			if tc.noSalt {
				device.salt = nil
			}
			enrollment := newTestFIDO2Enrollment(t)

			require.NoError(t, enrollment.enrollWithHandler(context.Background(), device))

			stored, ok := header.slots[enrollment.config.TargetKeyslot]
			require.True(t, ok, "no key added to slot %d", enrollment.config.TargetKeyslot)
			require.Len(t, header.tokens, 1)
			token := header.tokens[0]
			assert.Equal(t, []string{fmt.Sprintf("%d", enrollment.config.TargetKeyslot)}, token.Keyslots)
			assert.Equal(t, enrollment.config.RelyingPartyID, token.FIDO2RP)

			atBoot := initrdKeyFor(t, device, token)
			assert.Len(t, stored, 64, "the slot key is the SDK's 64-byte derived key")
			assert.Equal(t, atBoot, stored, "the installer's slot key differs from the initrd's")

			salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt)
			require.NoError(t, err)
			assert.Len(t, salt, 32)
			assert.NotEqual(t, device.hmacSecret(device.credential, salt), stored, "the slot holds the raw hmac-secret")

			// The key buffer handed to AddKey is zeroed once the slot is written.
			require.Len(t, header.passedKeys, 1)
			assert.Equal(t, make([]byte, 64), header.passedKeys[0])
		})
	}
}

// TestFIDO2EnrollmentFailures checks each enrolment failure is typed, wraps
// its cause and leaves the header unchanged from that step on.
func TestFIDO2EnrollmentFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setup    func(*sdkFakeFIDO2, *fakeLUKSHeader)
		cause    error
		target   any
		addCalls int
	}{
		{
			name:   "enroll fails",
			setup:  func(d *sdkFakeFIDO2, _ *fakeLUKSHeader) { d.enrollErr = errFakeEnroll },
			cause:  errFakeEnroll,
			target: new(*FIDO2EnrollKeyError),
		},
		{
			name:   "unlock fails",
			setup:  func(d *sdkFakeFIDO2, _ *fakeLUKSHeader) { d.unlockErr = errFakeUnlock },
			cause:  errFakeUnlock,
			target: new(*FIDO2DeriveKeyError),
		},
		{
			name:     "add key fails",
			setup:    func(_ *sdkFakeFIDO2, h *fakeLUKSHeader) { h.addErr = errFakeAddKey },
			cause:    errFakeAddKey,
			target:   new(*FIDO2AddKeyError),
			addCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := useFakeLUKSHeader(t)
			device := newSDKFakeFIDO2()
			tc.setup(device, header)

			err := newTestFIDO2Enrollment(t).enrollWithHandler(context.Background(), device)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.cause), "error %v does not wrap %v", err, tc.cause)
			assert.True(t, errors.As(err, tc.target), "error %T is not %T", err, tc.target)
			assert.Len(t, header.passedKeys, tc.addCalls)
			assert.Empty(t, header.slots)
			assert.Empty(t, header.tokens)
		})
	}
}

// TestFIDO2EnrollmentCancellation cancels the enrolment while each
// authenticator call waits for a touch: the enrolment returns at once and
// writes neither the keyslot nor the token.
func TestFIDO2EnrollmentCancellation(t *testing.T) {
	for _, op := range []string{"enroll", "unlock"} {
		t.Run(op, func(t *testing.T) {
			header := useFakeLUKSHeader(t)
			device := newSDKFakeFIDO2()
			waiting, finish := blockFakeFIDO2(t, device, op)
			enrollment := newTestFIDO2Enrollment(t)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- enrollment.enrollWithHandler(ctx, device) }()

			<-waiting
			cancel()
			err := <-done

			var canceled *FIDO2CanceledError
			require.ErrorAs(t, err, &canceled)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Empty(t, header.passedKeys, "a cancelled enrolment added a keyslot")
			assert.Empty(t, header.tokens, "a cancelled enrolment wrote a token")

			// The abandoned call completes late. Its drain receives the
			// result, clears any key and only then closes the handler.
			finish()
			select {
			case <-device.closed:
			default:
				t.Fatal("the drain did not receive the late result and close the handler")
			}
			if op == "unlock" {
				require.Len(t, device.returned, 1)
				late := device.returned[0]
				assert.Equal(t, make([]byte, len(late)), late, "the late key was not cleared")
			}
		})
	}
}

func TestFIDO2EnrollmentRetryWaitsForAbandonedOperation(t *testing.T) {
	useFakeLUKSHeader(t)
	busy := useFIDO2OperationBusy(t)
	_, finish := abandonFIDO2Enrollment(t)

	retry := newSDKFakeFIDO2()
	var abandonedEnded atomic.Bool
	retry.touch = func(string) {
		assert.True(t, abandonedEnded.Load(), "the retry reached the authenticator while the abandoned operation ran")
	}
	retried := make(chan error, 1)
	enrollment := newTestFIDO2Enrollment(t)
	go func() { retried <- enrollment.enrollWithHandler(context.Background(), retry) }()

	<-busy
	abandonedEnded.Store(true)
	finish()
	require.NoError(t, <-retried)
	assert.Len(t, retry.unlocks, 1, "the retry did not derive its key")
}

func TestFIDO2EnrollmentRetryCanceledWhileWaiting(t *testing.T) {
	header := useFakeLUKSHeader(t)
	busy := useFIDO2OperationBusy(t)
	_, finish := abandonFIDO2Enrollment(t)

	retry := newSDKFakeFIDO2()
	retry.touch = func(string) { t.Error("a retry cancelled while waiting reached the authenticator") }
	ctx, cancel := context.WithCancel(context.Background())
	retried := make(chan error, 1)
	enrollment := newTestFIDO2Enrollment(t)
	go func() { retried <- enrollment.enrollWithHandler(ctx, retry) }()

	<-busy
	cancel()
	err := <-retried

	var canceled *FIDO2CanceledError
	require.ErrorAs(t, err, &canceled)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, "create the credential", canceled.Step)
	assert.Empty(t, header.passedKeys)
	finish()
}

// TestFIDO2EnrollmentCanceledBeforeWrites checks the context before the
// first authenticator call and before the token write.
func TestFIDO2EnrollmentCanceledBeforeWrites(t *testing.T) {
	t.Run("before the credential", func(t *testing.T) {
		header := useFakeLUKSHeader(t)
		device := newSDKFakeFIDO2()
		var calls []string
		device.touch = func(op string) { calls = append(calls, op) }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := newTestFIDO2Enrollment(t).enrollWithHandler(ctx, device)
		var canceled *FIDO2CanceledError
		require.ErrorAs(t, err, &canceled)
		assert.Equal(t, "create the credential", canceled.Step)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, calls, "the authenticator was asked after cancellation")
		assert.Empty(t, header.passedKeys)
	})
	// Codex review 8643: a cancellation after the keyslot write removes the
	// slot again, so boot is not left with a slot it cannot unlock and a
	// retry can reuse the target slot.
	cancelAfterAddKey := func(t *testing.T, header *fakeLUKSHeader) error {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		addKey := luksAddKey
		luksAddKey = func(device string, passphrase, newPassphrase []byte, opts *luks2.AddKeyOptions) error {
			cancel()
			return addKey(device, passphrase, newPassphrase, opts)
		}
		return newTestFIDO2Enrollment(t).enrollWithHandler(ctx, newSDKFakeFIDO2())
	}
	t.Run("before the token", func(t *testing.T) {
		header := useFakeLUKSHeader(t)

		err := cancelAfterAddKey(t, header)
		var canceled *FIDO2CanceledError
		require.ErrorAs(t, err, &canceled)
		assert.Equal(t, "store the token", canceled.Step)
		assert.ErrorIs(t, err, context.Canceled)
		require.Len(t, header.passedKeys, 1, "the keyslot was not written before the cancellation")
		assert.Empty(t, header.slots, "a cancelled enrolment left its keyslot")
		assert.Empty(t, header.tokens, "a cancelled enrolment wrote a token")
	})
	// Codex review 8667: the token-slot lookup reads the header without a
	// context; a cancellation during it rolls the keyslot back and imports
	// no token.
	t.Run("during the token-slot lookup", func(t *testing.T) {
		header := useFakeLUKSHeader(t)
		ctx, cancel := context.WithCancel(context.Background())
		find := luksFindFreeTokenSlot
		luksFindFreeTokenSlot = func(device string) (int, error) {
			cancel()
			<-ctx.Done()
			return find(device)
		}
		var imports int
		luksImportToken = func(device string, tokenID int, token *luks2.Token) error {
			imports++
			return nil
		}

		err := newTestFIDO2Enrollment(t).enrollWithHandler(ctx, newSDKFakeFIDO2())
		var canceled *FIDO2CanceledError
		require.ErrorAs(t, err, &canceled)
		assert.Equal(t, "import the token", canceled.Step)
		assert.ErrorIs(t, err, context.Canceled)
		require.Len(t, header.passedKeys, 1, "the keyslot was not written before the lookup")
		assert.Empty(t, header.slots, "a cancelled enrolment left its keyslot")
		assert.Zero(t, imports, "a cancelled enrolment imported a token")
	})
	t.Run("before the token, rollback fails", func(t *testing.T) {
		header := useFakeLUKSHeader(t)
		header.killErr = errFakeKillSlot

		err := cancelAfterAddKey(t, header)
		var canceled *FIDO2CanceledError
		require.ErrorAs(t, err, &canceled)
		assert.ErrorIs(t, err, context.Canceled)
		var rollback *FIDO2RollbackError
		require.ErrorAs(t, err, &rollback)
		assert.Equal(t, 3, rollback.Slot)
		assert.ErrorIs(t, err, errFakeKillSlot)
		assert.Empty(t, header.tokens, "a cancelled enrolment wrote a token")
	})
}

// TestFIDO2EnrollmentTokenSlotUnavailable checks that a header with no free
// token slot keeps the enrolled key and reports success, as before.
func TestFIDO2EnrollmentTokenSlotUnavailable(t *testing.T) {
	header := useFakeLUKSHeader(t)
	header.tokenErr = errFakeNoTokenSlot
	enrollment := newTestFIDO2Enrollment(t)

	require.NoError(t, enrollment.enrollWithHandler(context.Background(), newSDKFakeFIDO2()))
	assert.Len(t, header.slots, 1)
	assert.Empty(t, header.tokens)
}

func TestFIDO2EnrollmentHandlerConfig(t *testing.T) {
	enrollment := newTestFIDO2Enrollment(t)
	enrollment.config.Debug = true

	cfg := enrollment.handlerConfig("/dev/hidraw3")
	assert.Equal(t, "/dev/hidraw3", cfg.DevicePath)
	assert.Equal(t, enrollment.config.RelyingPartyID, cfg.RelyingPartyID)
	assert.True(t, cfg.Debug)
	assert.Equal(t, fido2.DefaultConfig.Timeout, cfg.Timeout)
	assert.Empty(t, fido2.DefaultConfig.DevicePath, "handlerConfig must not modify the SDK default")
}

func TestRandomRead(t *testing.T) {
	t.Run("read random bytes", func(t *testing.T) {
		buf := make([]byte, 32)
		n, err := randomRead(buf)
		require.NoError(t, err)
		assert.Equal(t, 32, n)

		// Check that buffer was filled (not all zeros)
		allZeros := true
		for _, b := range buf {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "buffer should contain non-zero bytes")
	})

	t.Run("different reads produce different results", func(t *testing.T) {
		buf1 := make([]byte, 32)
		buf2 := make([]byte, 32)

		_, err := randomRead(buf1)
		require.NoError(t, err)

		_, err = randomRead(buf2)
		require.NoError(t, err)

		// Buffers should be different (extremely unlikely to be same)
		assert.NotEqual(t, buf1, buf2)
	})
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 50, 50},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

func TestDetectFIDO2Device(t *testing.T) {
	t.Run("no fido2 tools available", func(t *testing.T) {
		// This test will pass on systems without fido2-token
		// The function should gracefully return empty string
		device, err := DetectFIDO2Device()
		require.NoError(t, err)
		// Either empty (no tools) or actual device path
		_ = device // Just check no panic/error
	})
}

func TestIsFIDO2Available(t *testing.T) {
	t.Run("check availability", func(t *testing.T) {
		// This should not panic or error
		available := IsFIDO2Available()
		// Result depends on system configuration
		_ = available
	})
}
