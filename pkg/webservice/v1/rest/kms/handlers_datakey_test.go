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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"

	kmssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// fakeDataKeyCrypto records the data-key requests that reach the crypto
// service and answers them with fixed key material, or with err.
type fakeDataKeyCrypto struct {
	cryptoclient.Client
	dataKeyReq *cryptoclient.GenerateDataKeyRequest
	wrappedReq *cryptoclient.GenerateWrappedDataKeyRequest
	err        error
}

func (f *fakeDataKeyCrypto) GenerateDataKey(_ context.Context, req *cryptoclient.GenerateDataKeyRequest) (*cryptoclient.GenerateDataKeyResponse, error) {
	f.dataKeyReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.GenerateDataKeyResponse{
		KeyID:          req.KeyID,
		Plaintext:      []byte("plaintext-dek"),
		CiphertextBlob: []byte("wrapped-dek"),
	}, nil
}

func (f *fakeDataKeyCrypto) GenerateWrappedDataKey(_ context.Context, req *cryptoclient.GenerateWrappedDataKeyRequest) (*cryptoclient.GenerateWrappedDataKeyResponse, error) {
	f.wrappedReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.GenerateWrappedDataKeyResponse{
		KeyID:          req.KeyID,
		CiphertextBlob: []byte("wrapped-dek"),
	}, nil
}

// dataKeyRoutes lists both data-key routes with the name each gives the KEK.
var dataKeyRoutes = []struct {
	name     string
	target   string
	keyField string
	handler  func(*Handlers) http.HandlerFunc
}{
	{"GenerateDataKey", "/api/v1/kms/data-keys", "key_id",
		func(h *Handlers) http.HandlerFunc { return h.GenerateDataKey }},
	{"GenerateWrappedDataKey", "/api/v1/kms/data-keys/wrapped", "wrapping_key_id",
		func(h *Handlers) http.HandlerFunc { return h.GenerateWrappedDataKey }},
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// serveDataKey sends body to one data-key route and returns the recorder.
func serveDataKey(handler http.HandlerFunc, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func TestGenerateDataKey_ReturnsTheMintedKeyAndForwardsTheRequest(t *testing.T) {
	crypto := &fakeDataKeyCrypto{}
	h := newSignTestHandlers(crypto)

	w := serveDataKey(h.GenerateDataKey, "/api/v1/kms/data-keys",
		`{"key_id":"kek","key_size":256,"context":"`+b64("aad")+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if crypto.dataKeyReq.KeyID != "kek" || crypto.dataKeyReq.KeySize != 256 || string(crypto.dataKeyReq.Context) != "aad" {
		t.Fatalf("service request = %+v", crypto.dataKeyReq)
	}
	var got GenerateDataKeyResponse
	decodeEnvelope(t, w, &got)
	if got.KeyID != "kek" || string(got.PlaintextKey) != "plaintext-dek" || string(got.EncryptedKey) != "wrapped-dek" {
		t.Fatalf("reply = %+v", got)
	}
}

// TestGenerateWrappedDataKey_ReturnsNoPlaintext: the wrapped route exists so
// the caller never holds the plaintext key; the reply must not carry one.
func TestGenerateWrappedDataKey_ReturnsNoPlaintext(t *testing.T) {
	crypto := &fakeDataKeyCrypto{}
	h := newSignTestHandlers(crypto)

	w := serveDataKey(h.GenerateWrappedDataKey, "/api/v1/kms/data-keys/wrapped",
		`{"wrapping_key_id":"kek","key_size":256}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if crypto.wrappedReq.KeyID != "kek" || crypto.wrappedReq.KeySize != 256 {
		t.Fatalf("service request = %+v", crypto.wrappedReq)
	}
	var got map[string]interface{}
	decodeEnvelope(t, w, &got)
	if got["wrapping_key_id"] != "kek" || got["wrapped_key"] != b64("wrapped-dek") {
		t.Fatalf("reply = %v", got)
	}
	if _, has := got["plaintext_key"]; has {
		t.Fatalf("wrapped reply carries plaintext: %v", got)
	}
}

func TestDataKeyRoutes_UnknownKeyIsNotFound(t *testing.T) {
	for _, route := range dataKeyRoutes {
		t.Run(route.name, func(t *testing.T) {
			h := newSignTestHandlers(&fakeDataKeyCrypto{err: errors.New("kek: key not found")})
			w := serveDataKey(route.handler(h), route.target, `{"`+route.keyField+`":"kek"}`)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// TestDataKeyRoutes_BadBodyNeverReachesTheService: each malformed request is
// refused with 400 before the crypto service mints anything.
func TestDataKeyRoutes_BadBodyNeverReachesTheService(t *testing.T) {
	for _, route := range dataKeyRoutes {
		bodies := map[string]string{
			"malformed JSON":    `{"` + route.keyField,
			"missing key":       `{"key_size":256}`,
			"negative key size": `{"` + route.keyField + `":"kek","key_size":-1}`,
		}
		for name, body := range bodies {
			t.Run(route.name+"/"+name, func(t *testing.T) {
				crypto := &fakeDataKeyCrypto{}
				w := serveDataKey(route.handler(newSignTestHandlers(crypto)), route.target, body)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
				}
				if crypto.dataKeyReq != nil || crypto.wrappedReq != nil {
					t.Fatal("bad request reached the crypto service")
				}
			})
		}
	}
}

func TestDataKeyRoutes_NoCryptoServiceIsUnavailable(t *testing.T) {
	for _, route := range dataKeyRoutes {
		t.Run(route.name, func(t *testing.T) {
			w := serveDataKey(route.handler(newSignTestHandlers(nil)), route.target, `{"`+route.keyField+`":"kek"}`)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// TestValidateDataKeyRequest_NamesTheOffendingField: the two routes call the
// KEK by different names, and the 400 must name the one the caller sent.
func TestValidateDataKeyRequest_NamesTheOffendingField(t *testing.T) {
	cases := []struct {
		keyField, keyID string
		keySize         int32
		wantField       string
	}{
		{"key_id", "", 0, "key_id"},
		{"wrapping_key_id", "", 256, "wrapping_key_id"},
	}
	for _, tc := range cases {
		var invalid *ErrInvalidRequest
		err := validateDataKeyRequest(tc.keyField, tc.keyID, "", tc.keySize)
		if !errors.As(err, &invalid) || invalid.Field != tc.wantField {
			t.Errorf("validateDataKeyRequest(%q, %q, %d) = %v, want field %q",
				tc.keyField, tc.keyID, tc.keySize, err, tc.wantField)
		}
	}
	var sizeErr *kmssdk.ErrInvalidDataKeySize
	if err := validateDataKeyRequest("key_id", "kek", "", -8); !errors.As(err, &sizeErr) {
		t.Errorf("negative key size = %v, want *kms.ErrInvalidDataKeySize", err)
	}
	if err := validateDataKeyRequest("key_id", "kek", "", 0); err != nil {
		t.Errorf("zero key size (service default) refused: %v", err)
	}
}
