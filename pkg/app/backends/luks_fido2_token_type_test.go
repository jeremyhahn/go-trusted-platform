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

package backends

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

// TestLUKSFIDO2Enroll_WritesTheDerivedTokenType pins that every token the
// daemon writes for a FIDO2 slot names the derivation its keyslot key went
// through: "gtp-fido2-derived" (go-xkms UnlockWithKey output), never the
// installer's raw hmac-secret "fido2-manual".
func TestLUKSFIDO2Enroll_WritesTheDerivedTokenType(t *testing.T) {
	t.Run("rich handler", func(t *testing.T) {
		auth := &hmacSecretAuthenticator{
			credentialID: []byte("platformd-enrolled-credential-01"),
			seed:         []byte("authenticator-secret"),
		}
		handler, err := NewLUKSFIDO2Handler(nil, auth, "")
		if err != nil {
			t.Fatalf("NewLUKSFIDO2Handler: %v", err)
		}
		res, err := handler.DeriveEnroll(context.Background(), hex.EncodeToString(auth.credentialID), false, true)
		if err != nil {
			t.Fatalf("DeriveEnroll: %v", err)
		}
		var tok map[string]any
		if err := json.Unmarshal(res.TokenJSON, &tok); err != nil {
			t.Fatalf("token JSON: %v", err)
		}
		if tok["type"] != "gtp-fido2-derived" {
			t.Fatalf("token type = %v, want gtp-fido2-derived", tok["type"])
		}
	})

	t.Run("minimal handler fallback", func(t *testing.T) {
		device := newLUKSImage(t)
		key := []byte("fido2-hmac-secret-derived-key-32")
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(&stubFIDO2Key{key: append([]byte(nil), key...)}))

		res, err := b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
			Device:             device,
			ExistingPassphrase: testLUKSPassphrase,
			CredentialID:       "Y3JlZGVudGlhbA",
			RequireUV:          true,
		})
		if err != nil {
			t.Fatalf("EnrollFIDO2: %v", err)
		}
		tok := tokenByID(t, device, res.TokenID)
		if tok["type"] != "gtp-fido2-derived" {
			t.Fatalf("token type = %v, want gtp-fido2-derived", tok["type"])
		}
	})

	t.Run("listed as fido2", func(t *testing.T) {
		got, ok := luksKeySlotTypeMap["gtp-fido2-derived"]
		if !ok {
			t.Fatal("luksKeySlotTypeMap has no gtp-fido2-derived entry")
		}
		if got != daemon.LUKSKeyTypeFIDO2 {
			t.Fatalf("gtp-fido2-derived lists as %v, want %v", got, daemon.LUKSKeyTypeFIDO2)
		}
	})
}
