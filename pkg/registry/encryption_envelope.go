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

package registry

import (
	"encoding/json"
	"fmt"
)

// On-disk envelope wrapping an EncryptedLayer. The envelope is JSON
// so the storage layer (which is content-byte agnostic) can persist
// it in the same blob slot a plaintext layer would occupy. The
// envelope contains:
//
//   - keyID:       the KMS key used to wrap the per-layer DEK
//   - wrappedDEK:  the KMS-wrapped DEK (binary, base64-emitted by JSON)
//   - nonce:       the GCM nonce used to encrypt the layer content
//   - ciphertext:  the AES-256-GCM ciphertext of the layer content
//   - originalSize: pre-encryption size; used by Pull to populate
//     Layer.Size after decryption
//
// Versioning is via the "v" field — a future hardening pass (e.g.
// switching DEK wrap to AEAD-with-AAD-binding or upgrading to AES
// key-wrap) bumps v so Pull can route to the right decoder.
type encryptedLayerEnvelope struct {
	Version      int    `json:"v"`
	KeyID        string `json:"key_id"`
	WrappedDEK   []byte `json:"wrapped_dek"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
	OriginalSize int64  `json:"original_size"`
	MediaType    string `json:"media_type"`
	Digest       string `json:"digest"`
}

func encodeEncryptedLayer(l *EncryptedLayer) ([]byte, error) {
	if l == nil {
		return nil, &MessageError{Msg: "registry: encodeEncryptedLayer: nil layer"}
	}
	env := encryptedLayerEnvelope{
		Version:      1,
		KeyID:        l.KeyID,
		WrappedDEK:   l.WrappedDEK,
		Nonce:        l.Nonce,
		Ciphertext:   l.Encrypted,
		OriginalSize: l.OriginalSize,
		MediaType:    l.MediaType,
		Digest:       l.Digest,
	}
	return json.Marshal(env)
}

func decodeEncryptedLayer(data []byte) (*EncryptedLayer, error) {
	var env encryptedLayerEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, &WrappedError{Msg: "registry: decode encrypted layer", Err: err}
	}
	if env.Version != 1 {
		return nil, &MessageError{Msg: fmt.Sprintf("registry: unsupported encrypted-layer envelope version %d", env.Version)}
	}
	return &EncryptedLayer{
		Digest:       env.Digest,
		MediaType:    env.MediaType,
		Size:         int64(len(env.Ciphertext)),
		Encrypted:    env.Ciphertext,
		WrappedDEK:   env.WrappedDEK,
		KeyID:        env.KeyID,
		Nonce:        env.Nonce,
		OriginalSize: env.OriginalSize,
	}, nil
}
