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

package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// getSecretsClient answers Get with a fixed secret, the shape the quicbaas
// Secrets client returns after its JSON round-trip of the data map.
type getSecretsClient struct {
	secretsclient.Client

	secret *secretsclient.Secret
}

func (f *getSecretsClient) Get(_ context.Context, _ string, _ ...secretsclient.GetOption) (*secretsclient.Secret, error) {
	return f.secret, nil
}

func TestGetSecret_ReturnsStoredBytes(t *testing.T) {
	stored := []byte{0, 1, 2, 255}
	fake := &getSecretsClient{secret: &secretsclient.Secret{
		Path:    "db/password",
		Version: 3,
		Data:    map[string]interface{}{"value": base64.StdEncoding.EncodeToString(stored)},
	}}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.GetSecret(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets/db/password", "db/password", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var got SecretResponse
	decodeEnvelope(t, w, &got)
	if string(got.Value) != string(stored) {
		t.Fatalf("value = %q, want the stored bytes %q", got.Value, stored)
	}
	if got.Version != 3 {
		t.Fatalf("version = %d, want 3", got.Version)
	}
}

func TestGetSecret_MalformedStoredValue(t *testing.T) {
	fake := &getSecretsClient{secret: &secretsclient.Secret{
		Path: "db/password",
		Data: map[string]interface{}{"value": "not base64!"},
	}}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.GetSecret(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets/db/password", "db/password", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
}

// rotateSecretsClient records the rotation it is asked for.
type rotateSecretsClient struct {
	secretsclient.Client

	rotateReq *secretsclient.RotateSecretRequest
}

func (f *rotateSecretsClient) Rotate(_ context.Context, req *secretsclient.RotateSecretRequest) (*secretsclient.RotateSecretResponse, error) {
	f.rotateReq = req
	return &secretsclient.RotateSecretResponse{SecretID: req.SecretID, OldVersion: 1, NewVersion: 2}, nil
}

// TestRotateSecret_SendsTheStoredDataMap checks a rotation sends the value in
// the same encoded data map StoreSecret writes, so GetSecret reads it back.
func TestRotateSecret_SendsTheStoredDataMap(t *testing.T) {
	rotated := []byte{9, 8, 7, 'n', 'e', 'w'}
	fake := &rotateSecretsClient{}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.RotateSecret(w, parityRequest(t, http.MethodPost, "/api/v1/kms/secrets/db/password/rotate", "db/password", RotateSecretRequest{Value: rotated}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var data map[string]interface{}
	if err := json.Unmarshal(fake.rotateReq.NewData, &data); err != nil {
		t.Fatalf("rotation data is not the encoded data map: %v", err)
	}
	if data["value"] != base64.StdEncoding.EncodeToString(rotated) {
		t.Fatalf("rotation value = %v, want the base64 of %q", data["value"], rotated)
	}
}

func TestRotateSecret_MalformedBodyIsRefused(t *testing.T) {
	fake := &rotateSecretsClient{}
	h := newParityTestHandlers(nil, fake)

	r := parityRequest(t, http.MethodPost, "/api/v1/kms/secrets/db/password/rotate", "db/password", nil)
	r.Body = io.NopCloser(strings.NewReader("{not json"))
	w := httptest.NewRecorder()
	h.RotateSecret(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if fake.rotateReq != nil {
		t.Fatal("a malformed body reached Rotate")
	}
}
