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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// batchCrypto records the batch requests the KMS handlers hand to the
// crypto service and answers each with one success and one failure.
type batchCrypto struct {
	cryptoclient.Client
	encReq *cryptoclient.EncryptBatchRequest
	decReq *cryptoclient.DecryptBatchRequest
}

func (f *batchCrypto) EncryptBatch(_ context.Context, req *cryptoclient.EncryptBatchRequest) (*cryptoclient.EncryptBatchResponse, error) {
	f.encReq = req
	return &cryptoclient.EncryptBatchResponse{
		KeyID:      req.KeyID,
		KeyVersion: 4,
		Results: []cryptoclient.BatchEncryptResult{
			{Ciphertext: []byte("ct"), Nonce: []byte("nn")},
			{Error: "plaintext too large"},
		},
	}, nil
}

func (f *batchCrypto) DecryptBatch(_ context.Context, req *cryptoclient.DecryptBatchRequest) (*cryptoclient.DecryptBatchResponse, error) {
	f.decReq = req
	return &cryptoclient.DecryptBatchResponse{
		KeyID: req.KeyID,
		Results: []cryptoclient.BatchDecryptResult{
			{Plaintext: []byte("one")},
			{Error: "bad tag"},
		},
	}, nil
}

// TestSDKRoundTrip_BatchEncrypt drives the platform SDK's REST BatchEncrypt
// against the webservice KMS router and checks the items reach the crypto
// service in order and the per-item results come back by item id.
func TestSDKRoundTrip_BatchEncrypt(t *testing.T) {
	fake := &batchCrypto{}
	client := kmsOverSDK(t, nil, fake)

	resp, err := client.BatchEncrypt(context.Background(), &platformv1.BatchEncryptRequest{
		KeyId: "kek",
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "a", Plaintext: []byte("one")},
			{ItemId: "b", Plaintext: []byte("two")},
		},
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}
	if fake.encReq == nil {
		t.Fatal("crypto EncryptBatch was not called")
	}
	if fake.encReq.KeyID != "kek" {
		t.Errorf("KeyID = %q, want kek", fake.encReq.KeyID)
	}
	if len(fake.encReq.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(fake.encReq.Items))
	}
	if got := fake.encReq.Items[0]; string(got.Plaintext) != "one" || len(got.Context) != 0 {
		t.Errorf("item 0 = %q/%q, want one and no context", got.Plaintext, got.Context)
	}
	if got := fake.encReq.Items[1]; string(got.Plaintext) != "two" || len(got.Context) != 0 {
		t.Errorf("item 1 = %q/%q, want two/empty", got.Plaintext, got.Context)
	}

	if resp.GetKeyId() != "kek" {
		t.Errorf("reply KeyId = %q, want kek", resp.GetKeyId())
	}
	if len(resp.GetResults()) != 2 {
		t.Fatalf("results = %d, want 2", len(resp.GetResults()))
	}
	a, b := resp.GetResults()[0], resp.GetResults()[1]
	if a.GetItemId() != "a" || string(a.GetCiphertext()) != "ct" || string(a.GetNonce()) != "nn" ||
		a.GetKeyVersion() != 0 || !a.GetStatus().GetSuccess() {
		t.Errorf("item a = %+v, want ct/nn, no version, success", a)
	}
	if b.GetItemId() != "b" || b.GetStatus().GetSuccess() || b.GetStatus().GetMessage() != "plaintext too large" {
		t.Errorf("item b = %+v, want failed with plaintext too large", b)
	}
	if resp.GetSuccessCount() != 1 || resp.GetFailureCount() != 1 {
		t.Errorf("counts = %d/%d, want 1/1", resp.GetSuccessCount(), resp.GetFailureCount())
	}
}

// TestSDKRoundTrip_BatchDecrypt drives the platform SDK's REST BatchDecrypt
// against the webservice KMS router.
func TestSDKRoundTrip_BatchDecrypt(t *testing.T) {
	fake := &batchCrypto{}
	client := kmsOverSDK(t, nil, fake)

	resp, err := client.BatchDecrypt(context.Background(), &platformv1.BatchDecryptRequest{
		KeyId: "kek",
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "a", Ciphertext: []byte("ct"), Nonce: []byte("nn")},
			{ItemId: "b", Ciphertext: []byte("xx")},
		},
	})
	if err != nil {
		t.Fatalf("BatchDecrypt: %v", err)
	}
	if fake.decReq == nil {
		t.Fatal("crypto DecryptBatch was not called")
	}
	if fake.decReq.KeyID != "kek" {
		t.Errorf("KeyID = %q, want kek", fake.decReq.KeyID)
	}
	if len(fake.decReq.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(fake.decReq.Items))
	}
	if got := fake.decReq.Items[0]; string(got.Ciphertext) != "ct" || string(got.Nonce) != "nn" {
		t.Errorf("item 0 = %q/%q, want ct/nn", got.Ciphertext, got.Nonce)
	}
	if got := fake.decReq.Items[1]; string(got.Ciphertext) != "xx" || len(got.Nonce) != 0 {
		t.Errorf("item 1 = %q/%q, want xx/empty", got.Ciphertext, got.Nonce)
	}

	if resp.GetKeyId() != "kek" {
		t.Errorf("reply KeyId = %q, want kek", resp.GetKeyId())
	}
	if len(resp.GetResults()) != 2 {
		t.Fatalf("results = %d, want 2", len(resp.GetResults()))
	}
	a, b := resp.GetResults()[0], resp.GetResults()[1]
	if a.GetItemId() != "a" || string(a.GetPlaintext()) != "one" || !a.GetStatus().GetSuccess() {
		t.Errorf("item a = %+v, want plaintext one success", a)
	}
	if b.GetItemId() != "b" || b.GetStatus().GetSuccess() || b.GetStatus().GetMessage() != "bad tag" {
		t.Errorf("item b = %+v, want failed with bad tag", b)
	}
	if resp.GetSuccessCount() != 1 || resp.GetFailureCount() != 1 {
		t.Errorf("counts = %d/%d, want 1/1", resp.GetSuccessCount(), resp.GetFailureCount())
	}
}

func batchRouter(fake *batchCrypto) *mux.Router {
	logger := logging.DefaultLogger()
	root := mux.NewRouter()
	NewKMSRouter(logger, nil, fake, nil, nil, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func postBatch(root http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	root.ServeHTTP(w, req)
	return w
}

// TestBatchRoutes_EmptyItemsNeverReachTheService checks a batch with no
// items is refused before the crypto service is called.
func TestBatchRoutes_EmptyItemsNeverReachTheService(t *testing.T) {
	for _, path := range []string{"/api/v1/kms/batch-encrypt", "/api/v1/kms/batch-decrypt"} {
		fake := &batchCrypto{}
		w := postBatch(batchRouter(fake), path, `{"key_id":"kek","items":[]}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body: %s)", path, w.Code, w.Body.String())
		}
		if fake.encReq != nil || fake.decReq != nil {
			t.Errorf("%s: the crypto service saw a request", path)
		}
	}
}

// TestBatchDecryptRoute_RefusesAnItemKeyVersion checks a decrypt item that
// names a key version is refused: the crypto service carries none.
func TestBatchDecryptRoute_RefusesAnItemKeyVersion(t *testing.T) {
	fake := &batchCrypto{}
	w := postBatch(batchRouter(fake), "/api/v1/kms/batch-decrypt",
		`{"key_id":"kek","items":[{"item_id":"a","ciphertext":"Y3Q=","key_version":3}]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if fake.decReq != nil {
		t.Error("the crypto service saw a request")
	}
}
