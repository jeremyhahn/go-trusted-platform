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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

// digestAlgorithms maps an OCI digest algorithm to its hash constructor.
var digestAlgorithms = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// verifyBlobDigest checks that content hashes to digest ("<algorithm>:<hex>").
// Blobs are content addressed, so a manifest that names a blob by digest
// (and a signature over that manifest) vouches for these bytes and no others.
func verifyBlobDigest(digest string, content []byte) error {
	algorithm, encoded, found := strings.Cut(digest, ":")
	if !found || encoded == "" {
		return ErrInvalidDigest{Digest: digest, Reason: "missing algorithm prefix"}
	}
	newHash, ok := digestAlgorithms[algorithm]
	if !ok {
		return ErrInvalidDigest{Digest: digest, Reason: "unsupported algorithm: " + algorithm}
	}
	h := newHash()
	h.Write(content)
	actual := algorithm + ":" + hex.EncodeToString(h.Sum(nil))
	if actual != digest {
		return ErrDigestMismatch{Expected: digest, Actual: actual}
	}
	return nil
}

// verifyImageBlobs checks, before anything is stored, that every layer and
// the config hash to the digests the push declares for them.
func verifyImageBlobs(ref string, image *Image) error {
	for i := range image.Layers {
		l := &image.Layers[i]
		if l.Digest == "" {
			return ErrInvalidManifest{Reference: ref, Reason: "layer with empty digest"}
		}
		if err := verifyBlobDigest(l.Digest, l.Content); err != nil {
			return err
		}
	}
	if len(image.Config) > 0 && image.Manifest.Config.Digest != "" {
		return verifyBlobDigest(image.Manifest.Config.Digest, image.Config)
	}
	return nil
}

// storeBlob writes blob at digest unless the digest already holds it. A
// digest that holds other bytes is refused with ErrBlobConflict, never
// overwritten: the image already stored there would otherwise lose its
// content. sameContent, when set, accepts stored bytes that are a different
// encoding of the same content (an encrypted layer sealed under another
// data key) and returns why it does not when they are not.
func (r *Registry) storeBlob(ctx context.Context, digest string, blob []byte, sameContent func(stored []byte) error) error {
	stored, err := r.storage.GetBlob(ctx, digest)
	var notFound ErrBlobNotFound
	switch {
	case errors.As(err, &notFound):
		return r.storage.StoreBlob(ctx, digest, blob)
	case err != nil:
		return err
	case bytes.Equal(stored, blob):
		return nil
	case sameContent == nil:
		return ErrBlobConflict{Digest: digest}
	}
	if err := sameContent(stored); err != nil {
		return ErrBlobConflict{Digest: digest, Cause: err}
	}
	return nil
}

// openSealedLayer decrypts an encrypted layer blob and checks that the
// plaintext hashes to digest, the digest the manifest names it by.
func (r *Registry) openSealedLayer(ctx context.Context, digest string, blob []byte) (*Layer, error) {
	encLayer, err := decodeEncryptedLayer(blob)
	if err != nil {
		return nil, err
	}
	layer, err := r.encryptor.decryptLayer(ctx, encLayer)
	if err != nil {
		return nil, err
	}
	if err := verifyBlobDigest(digest, layer.Content); err != nil {
		return nil, err
	}
	return layer, nil
}

// sealedCopyOf returns the storeBlob sameContent check for an encrypted
// layer: the stored envelope is kept when it opens to the same plaintext.
func (r *Registry) sealedCopyOf(ctx context.Context, digest string) func(stored []byte) error {
	return func(stored []byte) error {
		_, err := r.openSealedLayer(ctx, digest, stored)
		return err
	}
}
