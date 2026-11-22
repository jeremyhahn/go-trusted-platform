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
	"net/http"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
)

// RewrapRequest is the body of POST /api/v1/kms/rewrap, in the daemon REST
// server's shape. The crypto service rewraps under one key's latest version,
// so the destination key, when named, must be the source key, and neither a
// destination context nor a source key version can be honoured.
type RewrapRequest struct {
	SourceKeyID      string `json:"source_key_id"`
	DestinationKeyID string `json:"destination_key_id,omitempty"`
	Ciphertext       []byte `json:"ciphertext"`
	SourceContext    []byte `json:"source_context,omitempty"`
	DestContext      []byte `json:"dest_context,omitempty"`
	SourceNonce      []byte `json:"source_nonce,omitempty"`
	SourceKeyVersion uint64 `json:"source_key_version,omitempty"`
}

// RewrapResponse is the reply of POST /api/v1/kms/rewrap.
type RewrapResponse struct {
	SourceKeyID      string `json:"source_key_id"`
	DestinationKeyID string `json:"destination_key_id"`
	SourceKeyVersion uint64 `json:"source_key_version"`
	DestKeyVersion   uint64 `json:"dest_key_version"`
	Ciphertext       []byte `json:"ciphertext"`
	Nonce            []byte `json:"nonce,omitempty"`
}

// Rewrap re-encrypts a ciphertext under the latest version of its key.
func (h *Handlers) Rewrap(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req RewrapRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.Rewrap(ctx, &cryptoclient.RewrapRequest{
		KeyID:      req.SourceKeyID,
		Ciphertext: req.Ciphertext,
		Context:    req.SourceContext,
		Nonce:      req.SourceNonce,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	keyID := resp.KeyID
	if keyID == "" {
		keyID = req.SourceKeyID
	}
	h.success200(w, r, &RewrapResponse{
		SourceKeyID:      keyID,
		DestinationKeyID: keyID,
		SourceKeyVersion: nonNegative(resp.OldKeyVersion),
		DestKeyVersion:   nonNegative(resp.NewKeyVersion),
		Ciphertext:       resp.Ciphertext,
		Nonce:            resp.Nonce,
	})
}

// validate refuses what the one-key crypto rewrap cannot honour.
func (req *RewrapRequest) validate() error {
	switch {
	case req.SourceKeyID == "":
		return &ErrInvalidRequest{Field: "source_key_id", Reason: "is required"}
	case len(req.Ciphertext) == 0:
		return &ErrInvalidRequest{Field: "ciphertext", Reason: "is required"}
	case req.DestinationKeyID != "" && req.DestinationKeyID != req.SourceKeyID:
		return &ErrInvalidRequest{Field: "destination_key_id", Reason: "must be the source key: rewrap stays under one key"}
	case len(req.DestContext) != 0:
		return &ErrInvalidRequest{Field: "dest_context", Reason: "is not supported: the source context is kept"}
	case req.SourceKeyVersion != 0:
		return &ErrInvalidRequest{Field: "source_key_version", Reason: "is not supported: the ciphertext names its version"}
	}
	return nil
}

// nonNegative converts a key version to the wire's unsigned form.
func nonNegative(v int) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
