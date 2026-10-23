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
	"context"
	"fmt"
	"net/http"
	"testing"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// randomKMS backs the gRPC data-key path: it mints exactly the number of
// bytes gRPC asks for and wraps by echoing.
type randomKMS struct {
	grpcapi.KMSService
}

func (randomKMS) GenerateRandom(_ context.Context, req *grpcapi.KMSGenerateRandomRequest) (*grpcapi.KMSGenerateRandomResponse, error) {
	return &grpcapi.KMSGenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
}

func (randomKMS) Encrypt(_ context.Context, req *grpcapi.KMSEncryptRequest) (*grpcapi.KMSEncryptResponse, error) {
	return &grpcapi.KMSEncryptResponse{Ciphertext: req.Plaintext}, nil
}

// serviceDefaultCrypto mints what the quicbaas crypto service mints for the
// request the SDK client sends, which carries no key attributes: 32 bytes.
type serviceDefaultCrypto struct {
	cryptoclient.Client
	calls int
}

func (c *serviceDefaultCrypto) GenerateDataKey(_ context.Context, req *cryptoclient.GenerateDataKeyRequest) (*cryptoclient.GenerateDataKeyResponse, error) {
	c.calls++
	return &cryptoclient.GenerateDataKeyResponse{KeyID: req.KeyID, Plaintext: make([]byte, 32), CiphertextBlob: []byte("wrapped")}, nil
}

func grpcDataKeyLength(t *testing.T, algorithm platformv1.KMSKeyAlgorithm, keySize int32) int {
	t.Helper()
	svc := grpcapi.NewKMSGRPCService(logging.DefaultLogger(), randomKMS{})
	resp, err := svc.GenerateDataKey(context.Background(), &platformv1.GenerateDataKeyRequest{
		KeyId: "kek", Algorithm: algorithm, KeySize: keySize,
	})
	if err != nil {
		t.Fatalf("gRPC GenerateDataKey(%s, %d): %v", algorithm, keySize, err)
	}
	return len(resp.GetPlaintextKey())
}

// TestDataKeySize_SameKeySizeSameLengthOverGRPCAndREST pins key_size as
// bits on both transports: before, gRPC read 256 as bytes.
func TestDataKeySize_SameKeySizeSameLengthOverGRPCAndREST(t *testing.T) {
	for _, keySize := range []int32{0, 256} {
		t.Run(fmt.Sprint(keySize), func(t *testing.T) {
			h := newSignTestHandlers(&serviceDefaultCrypto{})
			w := serveDataKey(h.GenerateDataKey, "/api/v1/kms/data-keys", fmt.Sprintf(`{"key_id":"kek","key_size":%d}`, keySize))
			if w.Code != http.StatusOK {
				t.Fatalf("REST status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			var got GenerateDataKeyResponse
			decodeEnvelope(t, w, &got)

			grpcLen := grpcDataKeyLength(t, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, keySize)
			if grpcLen != 32 || len(got.PlaintextKey) != grpcLen {
				t.Fatalf("key_size %d: gRPC minted %d bytes, REST %d; want 32 from both", keySize, grpcLen, len(got.PlaintextKey))
			}
		})
	}
}

// TestDataKeySize_RESTRefusesASizeTheSDKCannotCarry: gRPC mints a 128-bit
// key, and REST, whose SDK call drops the size, refuses instead of
// returning a 256-bit one.
func TestDataKeySize_RESTRefusesASizeTheSDKCannotCarry(t *testing.T) {
	if got := grpcDataKeyLength(t, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 128); got != 16 {
		t.Fatalf("gRPC key_size 128 minted %d bytes, want 16", got)
	}

	crypto := &serviceDefaultCrypto{}
	h := newSignTestHandlers(crypto)
	w := serveDataKey(h.GenerateDataKey, "/api/v1/kms/data-keys", `{"key_id":"kek","key_size":128}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("REST status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if crypto.calls != 0 {
		t.Fatal("a size the SDK cannot carry reached the crypto service")
	}
}

func TestGenerateDataKey_NamedAlgorithmIsAccepted(t *testing.T) {
	for _, algorithm := range []string{"KMS_KEY_ALGORITHM_AES_256", "aes-256", "CHACHA20_POLY1305"} {
		t.Run(algorithm, func(t *testing.T) {
			crypto := &serviceDefaultCrypto{}
			h := newSignTestHandlers(crypto)
			w := serveDataKey(h.GenerateDataKey, "/api/v1/kms/data-keys", `{"key_id":"kek","algorithm":"`+algorithm+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			if crypto.calls != 1 {
				t.Fatalf("crypto calls = %d, want 1", crypto.calls)
			}
		})
	}
}

// TestGenerateDataKey_UnsupportedAlgorithmIsRefused covers an unknown
// name, a non-data-key algorithm, and AES-128, which the SDK call cannot
// carry; before, REST ignored the field and minted AES-256 for each.
func TestGenerateDataKey_UnsupportedAlgorithmIsRefused(t *testing.T) {
	routes := map[string]string{
		"/api/v1/kms/data-keys":         `{"key_id":"kek","algorithm":"%s"}`,
		"/api/v1/kms/data-keys/wrapped": `{"wrapping_key_id":"kek","key_algorithm":"%s"}`,
	}
	for _, algorithm := range []string{"AES_512", "RSA_2048", "KMS_KEY_ALGORITHM_AES_128"} {
		for target, body := range routes {
			t.Run(target+" "+algorithm, func(t *testing.T) {
				crypto := &fakeDataKeyCrypto{}
				h := newSignTestHandlers(crypto)
				handler := h.GenerateDataKey
				if target == "/api/v1/kms/data-keys/wrapped" {
					handler = h.GenerateWrappedDataKey
				}
				w := serveDataKey(handler, target, fmt.Sprintf(body, algorithm))
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
				}
				if crypto.dataKeyReq != nil || crypto.wrappedReq != nil {
					t.Fatal("an unsupported algorithm reached the crypto service")
				}
			})
		}
	}
}
