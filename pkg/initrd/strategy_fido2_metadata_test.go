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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	"github.com/stretchr/testify/mock"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// The boot handler (pkg/boot/commands) is a CryptsetupHandler; FIDO2 Install
// and Unlock need its token area.
var _ luks.HandlerWithTokens = (*luks.CryptsetupHandler)(nil)

// tokenLUKS adds an in-memory LUKS2 token area to MockLUKSHandler.
type tokenLUKS struct {
	*MockLUKSHandler
	tokens    map[int]*luks.Token
	createErr error
}

func newTokenLUKS(m *MockLUKSHandler) *tokenLUKS {
	return &tokenLUKS{MockLUKSHandler: m, tokens: map[int]*luks.Token{}}
}

// withFIDO2Tokens gives p a token area holding one fido2 token per slot.
func withFIDO2Tokens(p *Platform, m *MockLUKSHandler, slots ...int) *tokenLUKS {
	tl := newTokenLUKS(m)
	for i, slot := range slots {
		tl.tokens[i] = &luks.Token{
			Type:            "fido2-manual",
			Keyslots:        []string{strconv.Itoa(slot)},
			FIDO2Credential: hex.EncodeToString([]byte{0x11, byte(slot)}),
			FIDO2Salt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(slot)}, 32)),
			FIDO2RP:         "luks-root",
		}
	}
	p.LUKS = tl
	return tl
}

func (l *tokenLUKS) TokenCreate(_ context.Context, _ string, token *luks.Token) (int, error) {
	if l.createErr != nil {
		return -1, l.createErr
	}
	for id := 0; id < luks.MaxTokenSlots; id++ {
		if _, used := l.tokens[id]; !used {
			cp := *token
			l.tokens[id] = &cp
			return id, nil
		}
	}
	return -1, &MessageError{Msg: "token area full"}
}

func (l *tokenLUKS) TokenCreateAt(_ context.Context, _ string, id int, token *luks.Token) error {
	cp := *token
	l.tokens[id] = &cp
	return nil
}

func (l *tokenLUKS) TokenRead(_ context.Context, _ string, id int) (*luks.Token, error) {
	t, ok := l.tokens[id]
	if !ok {
		return nil, &MessageError{Msg: "no token"}
	}
	cp := *t
	return &cp, nil
}

func (l *tokenLUKS) TokenDelete(_ context.Context, _ string, id int) error {
	delete(l.tokens, id)
	return nil
}

func (l *tokenLUKS) TokenUpdate(ctx context.Context, dev string, id int, token *luks.Token) error {
	return l.TokenCreateAt(ctx, dev, id, token)
}

func (l *tokenLUKS) TokenList(_ context.Context, _ string) (map[int]*luks.Token, error) {
	out := make(map[int]*luks.Token, len(l.tokens))
	for id, t := range l.tokens {
		cp := *t
		out[id] = &cp
	}
	return out, nil
}

func (l *tokenLUKS) TokenExists(_ context.Context, _ string, id int) (bool, error) {
	_, ok := l.tokens[id]
	return ok, nil
}

func (l *tokenLUKS) TokenCount(_ context.Context, _ string) (int, error) {
	return len(l.tokens), nil
}

// hmacFIDO2 models an hmac-secret authenticator: the key depends on the
// credential and the salt, so a boot without both cannot recover it.
type hmacFIDO2 struct {
	fido2.Handler

	credentialID  []byte
	seed          []byte
	enrollCalls   int
	unlockConfigs []*fido2.AuthenticationConfig
}

func (f *hmacFIDO2) EnrollKey(*fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	f.enrollCalls++
	return &fido2.EnrollmentResult{CredentialID: f.credentialID}, nil
}

func (f *hmacFIDO2) UnlockWithKey(cfg *fido2.AuthenticationConfig) ([]byte, error) {
	f.unlockConfigs = append(f.unlockConfigs, cfg)
	if !bytes.Equal(cfg.CredentialID, f.credentialID) || len(cfg.Salt) == 0 {
		return nil, &MessageError{Msg: "authenticator: unknown credential or no salt"}
	}
	h := sha256.New()
	h.Write(f.seed)
	h.Write(cfg.CredentialID)
	h.Write(cfg.Salt)
	return h.Sum(nil), nil
}

func newHMACFIDO2() *hmacFIDO2 {
	return &hmacFIDO2{
		credentialID: bytes.Repeat([]byte{0x11, 0x22}, 24),
		seed:         []byte("authenticator-secret"),
	}
}

// TestFIDO2Install_KeyRecoverableAtBoot is the #1365 round trip: the key
// Install writes into the keyslot is the key a later boot derives from the
// header token alone.
func TestFIDO2Install_KeyRecoverableAtBoot(t *testing.T) {
	ctx := context.Background()
	password := []byte("install-password")
	fido := newHMACFIDO2()
	p, m := cov964aPlatform(t, nil, nil)
	p.FIDO2 = fido
	tl := newTokenLUKS(m)
	p.LUKS = tl

	var enrolled []byte
	m.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { enrolled = append([]byte(nil), args.Get(3).([]byte)...) }).
		Return(nil)

	if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p, cov964aFIDO2Slot), password); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if bytes.Equal(enrolled, fido.credentialID[:32]) {
		t.Fatal("Install enrolled the credential ID as the key; the credential ID is public metadata")
	}
	if len(tl.tokens) != 1 {
		t.Fatalf("tokens after Install = %d, want 1", len(tl.tokens))
	}
	var token *luks.Token
	for _, tok := range tl.tokens {
		token = tok
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != "2" {
		t.Errorf("token keyslots = %v, want [2]", token.Keyslots)
	}
	if token.FIDO2RP != "luks-root" {
		t.Errorf("token RP = %q, want luks-root", token.FIDO2RP)
	}
	if cred, err := hex.DecodeString(token.FIDO2Credential); err != nil || !bytes.Equal(cred, fido.credentialID) {
		t.Errorf("token credential = %q, want the hex of the enrolled credential", token.FIDO2Credential)
	}
	if salt, err := base64.StdEncoding.DecodeString(token.FIDO2Salt); err != nil || len(salt) != 32 {
		t.Errorf("token salt = %q, want 32 base64 bytes", token.FIDO2Salt)
	}

	var opened []byte
	m.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { opened = append([]byte(nil), args.Get(3).([]byte)...) }).
		Return(nil)
	boot := cov964aVolume(p, luks.KeySlot{Index: 0, Type: luks.UnlockPassword}, cov964aFIDO2Slot)
	if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(ctx, boot); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !bytes.Equal(opened, enrolled) {
		t.Fatal("boot derived a different key from the one Install enrolled")
	}
}

// TestFIDO2Unlock_SkipsSlotWithoutToken: a FIDO2 slot with no token has no
// credential or salt to ask the authenticator for, so boot does not ask.
func TestFIDO2Unlock_SkipsSlotWithoutToken(t *testing.T) {
	fido := newHMACFIDO2()
	p, m := cov964aPlatform(t, nil, nil)
	p.FIDO2 = fido
	p.LUKS = newTokenLUKS(m)

	err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(context.Background(), cov964aVolume(p, cov964aFIDO2Slot))
	if err == nil {
		t.Fatal("Unlock succeeded with no FIDO2 token")
	}
	if len(fido.unlockConfigs) != 0 {
		t.Errorf("UnlockWithKey called %d times with no token to read", len(fido.unlockConfigs))
	}
}

// TestFIDO2Install_RefusesHandlerWithoutTokens: without a token area the
// enrollment could not be recovered at boot, so Install refuses before the
// authenticator is touched or a keyslot is written.
func TestFIDO2Install_RefusesHandlerWithoutTokens(t *testing.T) {
	fido := newHMACFIDO2()
	p, m := cov964aPlatform(t, nil, nil)
	p.FIDO2 = fido

	err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(context.Background(), cov964aVolume(p, cov964aFIDO2Slot), []byte("pw"))
	if !errors.Is(err, ErrFIDO2TokensUnsupported) {
		t.Fatalf("Install = %v, want ErrFIDO2TokensUnsupported", err)
	}
	if fido.enrollCalls != 0 {
		t.Error("EnrollKey called with no way to persist the enrollment")
	}
	m.AssertNotCalled(t, "AddKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestFIDO2Install_TokenWriteFailureRemovesKeyslot: a keyslot whose token
// could not be written cannot be opened at boot, so Install removes it.
func TestFIDO2Install_TokenWriteFailureRemovesKeyslot(t *testing.T) {
	password := []byte("install-password")
	p, m := cov964aPlatform(t, nil, nil)
	p.FIDO2 = newHMACFIDO2()
	tl := newTokenLUKS(m)
	tl.createErr = &cov964aError{op: "token write"}
	p.LUKS = tl

	m.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).Return(nil)
	m.On("KillSlot", mock.Anything, p.Config.RootDevice, cov964aFIDO2Slot.Index).Return(nil)

	err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(context.Background(), cov964aVolume(p, cov964aFIDO2Slot), password)
	if !errors.Is(err, tl.createErr) {
		t.Fatalf("Install = %v, want the token write error", err)
	}
	m.AssertExpectations(t)
}
