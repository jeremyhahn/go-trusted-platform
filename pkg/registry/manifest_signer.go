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
	"context"
	"encoding/json"
	"time"
)

// defaultSigningKeyID is the signing key a push uses when it names none,
// the same default the encryption path uses for its key. The registry does
// not create it: until an operator creates an ECDSA P-256 or P-384 key of
// this ID in the KMS, such a push is refused with ErrSigningKeyUnavailable.
const defaultSigningKeyID = "registry-default"

// SigningKMSClient is the signing half of the registry's KMS seam, beside
// KMSClient: Sign signs a SHA-256 digest with keyID's asymmetric key and
// names the signature algorithm. The private key never leaves the KMS, and
// a missing key is an error: the signer never creates one. SDKSigner
// implements it on the SDK KMS (Security().KMS() plus Security().Crypto()).
type SigningKMSClient interface {
	Sign(ctx context.Context, keyID string, digest []byte) (signature []byte, algorithm string, err error)
}

// manifestSigningPayload is the byte string a manifest signature covers:
// the manifest JSON bound to ref, without the signature annotations and
// without the storage timestamps, so a verifier can rebuild it from the
// stored manifest.
func manifestSigningPayload(ref string, m *ImageManifest) ([]byte, error) {
	unsigned := *m
	unsigned.Reference = ref
	unsigned.Annotations = withoutSignatureAnnotations(m.Annotations)
	unsigned.CreatedAt = time.Time{}
	unsigned.UpdatedAt = time.Time{}
	return json.Marshal(&unsigned)
}

// withoutSignatureAnnotations returns a copy of annotations with every
// signature annotation removed; nil when nothing remains.
func withoutSignatureAnnotations(annotations map[string]string) map[string]string {
	out := make(map[string]string, len(annotations))
	for k, v := range annotations {
		if _, isSignature := signatureAnnotations[k]; !isSignature {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
