// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package kms

import (
	"context"
	"net/http"
	"strings"
	"testing"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
)

// fakeDecryptCrypto records the decrypt request that reaches the crypto
// service and answers it with fixed plaintext.
type fakeDecryptCrypto struct {
	cryptoclient.Client
	decryptReq *cryptoclient.DecryptRequest
}

func (f *fakeDecryptCrypto) Decrypt(_ context.Context, req *cryptoclient.DecryptRequest) (*cryptoclient.DecryptResponse, error) {
	f.decryptReq = req
	return &cryptoclient.DecryptResponse{Plaintext: []byte("opened")}, nil
}

func TestDecrypt_WithoutVersionReachesTheService(t *testing.T) {
	crypto := &fakeDecryptCrypto{}
	h := newSignTestHandlers(crypto)

	w := serveDataKey(h.Decrypt, "/api/v1/kms/decrypt/kek", `{"ciphertext":"`+b64("sealed")+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if crypto.decryptReq == nil || string(crypto.decryptReq.Ciphertext) != "sealed" {
		t.Fatalf("decrypt request = %+v, want the ciphertext forwarded", crypto.decryptReq)
	}
}

// TestDecrypt_NamedVersionIsRefused pins the refusal: the SDK decrypt call
// has no version field, so a named version must not be silently dropped.
func TestDecrypt_NamedVersionIsRefused(t *testing.T) {
	for _, version := range []string{"3", "-1"} {
		t.Run(version, func(t *testing.T) {
			crypto := &fakeDecryptCrypto{}
			h := newSignTestHandlers(crypto)

			body := `{"ciphertext":"` + b64("sealed") + `","version":` + version + `}`
			w := serveDataKey(h.Decrypt, "/api/v1/kms/decrypt/kek", body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "version") {
				t.Errorf("body %s does not name the version field", w.Body.String())
			}
			if crypto.decryptReq != nil {
				t.Fatal("a versioned decrypt reached the crypto service")
			}
		})
	}
}
