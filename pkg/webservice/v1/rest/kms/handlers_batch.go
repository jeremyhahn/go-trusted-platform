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
	"fmt"
	"net/http"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
)

// BatchEncryptItem is one item of a batch encrypt request.
type BatchEncryptItem struct {
	ItemID    string `json:"item_id"`
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
	// Nonce is accepted in the body only to refuse it: the crypto service
	// always generates the nonce.
	Nonce []byte `json:"nonce,omitempty"`
}

// BatchEncryptRequest is the body of POST /api/v1/kms/batch-encrypt.
type BatchEncryptRequest struct {
	KeyID string             `json:"key_id"`
	Items []BatchEncryptItem `json:"items"`
}

// BatchDecryptItem is one item of a batch decrypt request.
type BatchDecryptItem struct {
	ItemID     string `json:"item_id"`
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	// KeyVersion is accepted in the body only to refuse a non-zero value:
	// the crypto service decrypts with the version the ciphertext names.
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// BatchDecryptRequest is the body of POST /api/v1/kms/batch-decrypt.
type BatchDecryptRequest struct {
	KeyID string             `json:"key_id"`
	Items []BatchDecryptItem `json:"items"`
}

// BatchItemResult is one item of a batch reply. Error is set exactly when
// the item failed.
type BatchItemResult struct {
	ItemID     string `json:"item_id"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Plaintext  []byte `json:"plaintext,omitempty"`
	Error      string `json:"error,omitempty"`
}

// BatchResponse is the reply of both batch routes, in the shape the
// platform SDK's REST transport decodes.
type BatchResponse struct {
	KeyID        string            `json:"key_id"`
	KeyVersion   uint64            `json:"key_version,omitempty"`
	Results      []BatchItemResult `json:"results"`
	SuccessCount int32             `json:"success_count"`
	FailureCount int32             `json:"failure_count"`
}

// tally counts the successes and failures of a batch reply.
func (b *BatchResponse) tally() {
	for _, res := range b.Results {
		if res.Error != "" {
			b.FailureCount++
		} else {
			b.SuccessCount++
		}
	}
}

// BatchEncrypt handles POST /api/v1/kms/batch-encrypt.
func (h *Handlers) BatchEncrypt(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req BatchEncryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.KeyID == "" {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "key_id", Reason: "is required"})
		return
	}
	if len(req.Items) == 0 {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "items", Reason: "at least one item is required"})
		return
	}
	items := make([]cryptoclient.BatchEncryptItem, len(req.Items))
	for i, item := range req.Items {
		if len(item.Nonce) != 0 {
			h.respWriter.Error400(w, r, &ErrInvalidRequest{
				Field:  fmt.Sprintf("items[%d].nonce", i),
				Reason: "the crypto service generates the nonce",
			})
			return
		}
		items[i] = cryptoclient.BatchEncryptItem{Plaintext: item.Plaintext, Context: item.Context}
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.EncryptBatch(ctx, &cryptoclient.EncryptBatchRequest{KeyID: req.KeyID, Items: items})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if len(resp.Results) != len(req.Items) {
		h.respWriter.Error500(w, r, fmt.Errorf("kms: batch encrypt returned %d results for %d items",
			len(resp.Results), len(req.Items)))
		return
	}
	out := &BatchResponse{KeyID: resp.KeyID, Results: make([]BatchItemResult, len(resp.Results))}
	if resp.KeyVersion > 0 {
		out.KeyVersion = uint64(resp.KeyVersion)
	}
	for i, res := range resp.Results {
		out.Results[i] = BatchItemResult{
			ItemID:     req.Items[i].ItemID,
			Ciphertext: res.Ciphertext,
			Nonce:      res.Nonce,
			Error:      res.Error,
		}
	}
	out.tally()
	h.success200(w, r, out)
}

// BatchDecrypt handles POST /api/v1/kms/batch-decrypt.
func (h *Handlers) BatchDecrypt(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req BatchDecryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.KeyID == "" {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "key_id", Reason: "is required"})
		return
	}
	if len(req.Items) == 0 {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "items", Reason: "at least one item is required"})
		return
	}
	items := make([]cryptoclient.BatchDecryptItem, len(req.Items))
	for i, item := range req.Items {
		if item.KeyVersion != 0 {
			h.respWriter.Error400(w, r, &ErrInvalidRequest{
				Field:  fmt.Sprintf("items[%d].key_version", i),
				Reason: "the crypto service does not take a key version",
			})
			return
		}
		items[i] = cryptoclient.BatchDecryptItem{Ciphertext: item.Ciphertext, Context: item.Context, Nonce: item.Nonce}
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.DecryptBatch(ctx, &cryptoclient.DecryptBatchRequest{KeyID: req.KeyID, Items: items})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if len(resp.Results) != len(req.Items) {
		h.respWriter.Error500(w, r, fmt.Errorf("kms: batch decrypt returned %d results for %d items",
			len(resp.Results), len(req.Items)))
		return
	}
	out := &BatchResponse{KeyID: resp.KeyID, Results: make([]BatchItemResult, len(resp.Results))}
	for i, res := range resp.Results {
		out.Results[i] = BatchItemResult{
			ItemID:    req.Items[i].ItemID,
			Plaintext: res.Plaintext,
			Error:     res.Error,
		}
	}
	out.tally()
	h.success200(w, r, out)
}
