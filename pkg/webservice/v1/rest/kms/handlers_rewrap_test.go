package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
)

// fakeRewrapCrypto records the Rewrap request the REST handler forwards.
type fakeRewrapCrypto struct {
	cryptoclient.Client
	rewrapReq *cryptoclient.RewrapRequest
}

func (f *fakeRewrapCrypto) Rewrap(_ context.Context, req *cryptoclient.RewrapRequest) (*cryptoclient.RewrapResponse, error) {
	f.rewrapReq = req
	return &cryptoclient.RewrapResponse{
		KeyID:         req.KeyID,
		OldKeyVersion: 1,
		NewKeyVersion: 3,
		Ciphertext:    []byte("resealed"),
	}, nil
}

// POST /rewrap/{name} re-encrypts a ciphertext under the newest version of
// the named key and returns both versions and the new ciphertext (#2057).
func TestRewrap_ForwardsKeyCiphertextAndContext(t *testing.T) {
	crypto := &fakeRewrapCrypto{}
	h := newSignTestHandlers(crypto)

	w := serveDataKey(h.Rewrap, "/api/v1/kms/rewrap/old",
		`{"ciphertext":"`+b64("sealed")+`","context":"`+b64("aad")+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	req := crypto.rewrapReq
	if req == nil {
		t.Fatal("Rewrap was not called")
	}
	if req.KeyID != "old" || string(req.Ciphertext) != "sealed" || string(req.Context) != "aad" {
		t.Fatalf("rewrap request = %+v, want key old with the ciphertext and context", req)
	}

	var env struct {
		Payload RewrapResponse `json:"payload"`
	}
	body := w.Body.Bytes()
	if err := json.Unmarshal(body, &env); err != nil || env.Payload.KeyID == "" {
		var flat RewrapResponse
		if err := json.Unmarshal(body, &flat); err != nil {
			t.Fatalf("decode response: %v (body: %s)", err, body)
		}
		env.Payload = flat
	}
	got := env.Payload
	if got.KeyID != "old" || got.OldVersion != 1 || got.NewVersion != 3 || string(got.Ciphertext) != "resealed" {
		t.Fatalf("response = %+v, want old v1 -> v3 resealed", got)
	}
}

func TestRewrap_RequiresCiphertext(t *testing.T) {
	crypto := &fakeRewrapCrypto{}
	h := newSignTestHandlers(crypto)

	w := serveDataKey(h.Rewrap, "/api/v1/kms/rewrap/old", `{}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if crypto.rewrapReq != nil {
		t.Fatal("Rewrap reached the service without a ciphertext")
	}
}
