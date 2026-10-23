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

package grpc

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sizedRandomKMS mints exactly the number of random bytes requested, so a
// test reads the data key length gRPC chose off the plaintext key.
type sizedRandomKMS struct {
	*mockKMSService
	randomCalls int
}

func (m *sizedRandomKMS) GenerateRandom(_ context.Context, req *KMSGenerateRandomRequest) (*KMSGenerateRandomResponse, error) {
	m.randomCalls++
	return &KMSGenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
}

func newSizedDataKeyService() (*KMSGRPCService, *sizedRandomKMS) {
	kms := &sizedRandomKMS{mockKMSService: newMockKMSService()}
	return NewKMSGRPCService(logging.NewLogger(slog.LevelError, io.Discard), kms), kms
}

// TestGenerateDataKey_KeySizeIsBitsAndAlgorithmIsHonoured: before, gRPC
// read key_size as bytes (256 minted 256 bytes) and ignored the algorithm.
func TestGenerateDataKey_KeySizeIsBitsAndAlgorithmIsHonoured(t *testing.T) {
	cases := []struct {
		name      string
		algorithm platformv1.KMSKeyAlgorithm
		keySize   int32
		wantBytes int
	}{
		{"default", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 0, 32},
		{"256 bits", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 256, 32},
		{"128 bits", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 128, 16},
		{"AES-128", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 0, 16},
		{"AES-192", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192, 192, 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newSizedDataKeyService()
			resp, err := svc.GenerateDataKey(context.Background(), &platformv1.GenerateDataKeyRequest{
				KeyId: "kek", Algorithm: tc.algorithm, KeySize: tc.keySize,
			})
			if err != nil {
				t.Fatalf("GenerateDataKey: %v", err)
			}
			if got := len(resp.GetPlaintextKey()); got != tc.wantBytes {
				t.Fatalf("plaintext key = %d bytes, want %d", got, tc.wantBytes)
			}
		})
	}
}

func TestGenerateWrappedDataKey_KeyAlgorithmIsHonoured(t *testing.T) {
	var minted []byte
	kms := &recordingEncryptKMS{
		sizedRandomKMS: &sizedRandomKMS{mockKMSService: newMockKMSService()},
		plaintext:      &minted,
	}
	svc := NewKMSGRPCService(logging.NewLogger(slog.LevelError, io.Discard), kms)

	_, err := svc.GenerateWrappedDataKey(context.Background(), &platformv1.GenerateWrappedDataKeyRequest{
		WrappingKeyId: "kek", KeyAlgorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
	})
	if err != nil {
		t.Fatalf("GenerateWrappedDataKey: %v", err)
	}
	if len(minted) != 16 {
		t.Fatalf("wrapped a %d-byte key, want 16 for AES-128", len(minted))
	}
}

// recordingEncryptKMS records the plaintext handed to Encrypt: the
// wrapped route returns no plaintext, so this is where its length shows.
type recordingEncryptKMS struct {
	*sizedRandomKMS
	plaintext *[]byte
}

func (m *recordingEncryptKMS) Encrypt(_ context.Context, req *KMSEncryptRequest) (*KMSEncryptResponse, error) {
	*m.plaintext = req.Plaintext
	return &KMSEncryptResponse{Ciphertext: []byte("wrapped")}, nil
}

func TestGenerateDataKey_InvalidSizeOrAlgorithmIsRefused(t *testing.T) {
	cases := []struct {
		name      string
		algorithm platformv1.KMSKeyAlgorithm
		keySize   int32
	}{
		{"bytes, not bits", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, 32},
		{"negative", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, -256},
		{"size contradicts algorithm", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, 256},
		{"not a data-key algorithm", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, kms := newSizedDataKeyService()
			_, err := svc.GenerateDataKey(context.Background(), &platformv1.GenerateDataKeyRequest{
				KeyId: "kek", Algorithm: tc.algorithm, KeySize: tc.keySize,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err: %v)", status.Code(err), err)
			}
			if kms.randomCalls != 0 {
				t.Fatal("a refused request still minted key material")
			}
		})
	}

	svc, _ := newSizedDataKeyService()
	_, err := svc.GenerateWrappedDataKey(context.Background(), &platformv1.GenerateWrappedDataKeyRequest{
		WrappingKeyId: "kek", KeyAlgorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrapped ED25519: code = %v, want InvalidArgument", status.Code(err))
	}
}
