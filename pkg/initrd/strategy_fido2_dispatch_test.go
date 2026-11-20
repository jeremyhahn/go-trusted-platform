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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// dispatchToken builds a FIDO2 token of the given type for one keyslot,
// carrying the test authenticator's credential, a 32-byte salt and the
// luks-root RP.
func dispatchToken(fido *hmacFIDO2, tokenType string, slot int) *luks.Token {
	return &luks.Token{
		Type:            tokenType,
		Keyslots:        []string{strconv.Itoa(slot)},
		FIDO2Credential: hex.EncodeToString(fido.credentialID),
		FIDO2Salt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(slot)}, 32)),
		FIDO2RP:         "luks-root",
	}
}

// TestFIDO2Unlock_DispatchesByTokenType pins that boot opens only the
// daemon/Install-written "gtp-fido2-derived" token through UnlockWithKey,
// and refuses a raw hmac-secret token ("fido2-manual", written by the
// installer) without asking the authenticator.
func TestFIDO2Unlock_DispatchesByTokenType(t *testing.T) {
	ctx := context.Background()

	t.Run("derived token unlocks with UnlockWithKey", func(t *testing.T) {
		fido := newHMACFIDO2()
		p, m := cov964aPlatform(t, nil, nil)
		p.FIDO2 = fido
		tl := newTokenLUKS(m)
		tl.tokens[0] = dispatchToken(fido, "gtp-fido2-derived", 2)
		p.LUKS = tl
		m.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", mock.Anything, mock.Anything).Return(nil)

		if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p, cov964aFIDO2Slot)); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		if len(fido.unlockConfigs) != 1 {
			t.Fatalf("UnlockWithKey calls = %d, want 1", len(fido.unlockConfigs))
		}
		if !bytes.Equal(fido.unlockConfigs[0].CredentialID, fido.credentialID) {
			t.Error("UnlockWithKey was not asked for the token's credential")
		}
	})

	t.Run("installer fido2-manual token is refused without asking the authenticator", func(t *testing.T) {
		fido := newHMACFIDO2()
		p, m := cov964aPlatform(t, nil, nil)
		p.FIDO2 = fido
		tl := newTokenLUKS(m)
		tl.tokens[0] = dispatchToken(fido, "fido2-manual", 2)
		p.LUKS = tl
		m.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", mock.Anything, mock.Anything).Return(errors.New("wrong key"))

		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p, cov964aFIDO2Slot))
		if err == nil {
			t.Fatal("Unlock of a raw hmac-secret token succeeded")
		}
		if !strings.Contains(err.Error(), "raw hmac-secret") {
			t.Errorf("error %q does not name the raw hmac-secret token", err)
		}
		if len(fido.unlockConfigs) != 0 {
			t.Errorf("UnlockWithKey calls = %d, want 0: a raw token must not cost a touch", len(fido.unlockConfigs))
		}
		m.AssertNotCalled(t, "Open", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("derived slot still opens when a raw slot comes first", func(t *testing.T) {
		fido := newHMACFIDO2()
		p, m := cov964aPlatform(t, nil, nil)
		p.FIDO2 = fido
		tl := newTokenLUKS(m)
		tl.tokens[0] = dispatchToken(fido, "fido2-manual", 4)
		tl.tokens[1] = dispatchToken(fido, "gtp-fido2-derived", 2)
		p.LUKS = tl
		opened := -1
		m.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { opened = *args.Get(4).(*luks.OpenOptions).KeySlot }).
			Return(nil)

		raw := luks.KeySlot{Index: 4, Type: luks.UnlockFIDO2}
		if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p, raw, cov964aFIDO2Slot)); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		if opened != 2 {
			t.Errorf("opened slot = %d, want 2 (the derived slot)", opened)
		}
		if len(fido.unlockConfigs) != 1 {
			t.Errorf("UnlockWithKey calls = %d, want 1", len(fido.unlockConfigs))
		}
	})

	t.Run("Install writes the derived type", func(t *testing.T) {
		password := []byte("install-password")
		fido := newHMACFIDO2()
		p, m := cov964aPlatform(t, nil, nil)
		p.FIDO2 = fido
		tl := newTokenLUKS(m)
		p.LUKS = tl
		m.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).Return(nil)

		if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p, cov964aFIDO2Slot), password); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if len(tl.tokens) != 1 {
			t.Fatalf("tokens after Install = %d, want 1", len(tl.tokens))
		}
		for _, tok := range tl.tokens {
			if tok.Type != "gtp-fido2-derived" {
				t.Errorf("token type = %q, want gtp-fido2-derived", tok.Type)
			}
		}
	})
}
