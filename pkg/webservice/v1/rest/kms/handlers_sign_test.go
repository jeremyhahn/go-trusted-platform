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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// fakeCryptoClient captures the Sign request forwarded to the QuicBaaS crypto
// client. Unused Client methods are inherited from the embedded interface and
// panic if called, which is intentional for a handler-scoped test.
type fakeCryptoClient struct {
	cryptoclient.Client
	signReq *cryptoclient.SignRequest
	signErr error
}

func (f *fakeCryptoClient) Sign(_ context.Context, req *cryptoclient.SignRequest) (*cryptoclient.SignResponse, error) {
	f.signReq = req
	if f.signErr != nil {
		return nil, f.signErr
	}
	return &cryptoclient.SignResponse{Signature: []byte("sig"), KeyVersion: 1}, nil
}

func newSignTestHandlers(crypto cryptoclient.Client) *Handlers {
	logger := logging.DefaultLogger()
	return NewHandlers(logger, nil, crypto, nil, nil, response.NewResponseWriter(logger, nil))
}

func signRequest(t *testing.T, body interface{}) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign/db-key", bytes.NewReader(data))
	return mux.SetURLVars(req, map[string]string{"name": "db-key"})
}

// TestSign_PreHashedPassthrough verifies the pre_hashed request field reaches
// the QuicBaaS crypto client so an already-computed digest is signed directly
// instead of being hashed a second time.
func TestSign_PreHashedPassthrough(t *testing.T) {
	fake := &fakeCryptoClient{}
	h := newSignTestHandlers(fake)

	w := httptest.NewRecorder()
	h.Sign(w, signRequest(t, &SignRequest{
		Data:      []byte{0xde, 0xad, 0xbe, 0xef},
		Hash:      "SHA256",
		PreHashed: true,
	}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.signReq == nil {
		t.Fatal("crypto client Sign was not called")
	}
	if !fake.signReq.PreHashed {
		t.Error("PreHashed = false on the crypto client request, want true")
	}
	if fake.signReq.KeyID != "db-key" {
		t.Errorf("KeyID = %q, want db-key", fake.signReq.KeyID)
	}
}

// TestSign_NotPreHashedByDefault verifies a request without pre_hashed keeps
// the hash-then-sign behavior.
func TestSign_NotPreHashedByDefault(t *testing.T) {
	fake := &fakeCryptoClient{}
	h := newSignTestHandlers(fake)

	w := httptest.NewRecorder()
	h.Sign(w, signRequest(t, &SignRequest{Data: []byte("raw message"), Hash: "SHA256"}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.signReq == nil {
		t.Fatal("crypto client Sign was not called")
	}
	if fake.signReq.PreHashed {
		t.Error("PreHashed = true on the crypto client request, want false")
	}
}
