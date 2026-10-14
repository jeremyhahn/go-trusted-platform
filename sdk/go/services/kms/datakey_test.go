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
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestResolveDataKey_KeySizeIsInBits(t *testing.T) {
	cases := []struct {
		name          string
		algorithm     platformv1.KMSKeyAlgorithm
		keySize       int32
		wantAlgorithm platformv1.KMSKeyAlgorithm
		wantBits      int32
	}{
		{"default", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 0, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, 256},
		{"size picks AES-128", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 128, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 128},
		{"size picks AES-192", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 192, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192, 192},
		{"AES-128 own size", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 0, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 128},
		{"AES-256 matching size", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, 256, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, 256},
		{"ChaCha20", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305, 0, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algorithm, bits, err := ResolveDataKey(tc.algorithm, tc.keySize)
			if err != nil {
				t.Fatalf("ResolveDataKey(%s, %d): %v", tc.algorithm, tc.keySize, err)
			}
			if algorithm != tc.wantAlgorithm || bits != tc.wantBits {
				t.Fatalf("ResolveDataKey(%s, %d) = %s, %d; want %s, %d",
					tc.algorithm, tc.keySize, algorithm, bits, tc.wantAlgorithm, tc.wantBits)
			}
		})
	}
}

func TestResolveDataKey_RefusesSizesTheAlgorithmDoesNotMint(t *testing.T) {
	cases := []struct {
		name      string
		algorithm platformv1.KMSKeyAlgorithm
		keySize   int32
	}{
		{"byte count", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 32},
		{"negative", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, -256},
		{"AES-128 with 256", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ResolveDataKey(tc.algorithm, tc.keySize)
			var sizeErr *ErrInvalidDataKeySize
			if !errors.As(err, &sizeErr) {
				t.Fatalf("ResolveDataKey(%s, %d) error = %v, want *ErrInvalidDataKeySize", tc.algorithm, tc.keySize, err)
			}
		})
	}
}

func TestResolveDataKey_RefusesNonDataKeyAlgorithms(t *testing.T) {
	for _, algorithm := range []platformv1.KMSKeyAlgorithm{
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256,
		platformv1.KMSKeyAlgorithm(999),
	} {
		_, _, err := ResolveDataKey(algorithm, 0)
		var algErr *ErrUnsupportedDataKeyAlgorithm
		if !errors.As(err, &algErr) {
			t.Fatalf("ResolveDataKey(%s) error = %v, want *ErrUnsupportedDataKeyAlgorithm", algorithm, err)
		}
	}
}
