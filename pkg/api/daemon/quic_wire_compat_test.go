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

package daemon

import (
	"bytes"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The tests in this file guard the QUIC wire contract between the platform
// SDK client and the daemon: the SDK QUIC transport adapter encodes the
// platformv1 proto request structs directly (go-codec falls back to the
// proto json tags, so enum fields travel as int32 values), and decodes
// daemon replies directly into the platformv1 proto response structs. Every
// daemon wire struct must therefore round-trip against its platformv1
// counterpart — requests decode from the proto encoding, and responses
// decode back into the proto struct.

// encodeAs encodes src and decodes it into dst, failing the test on error.
func encodeAs(t *testing.T, src, dst interface{}) {
	t.Helper()
	payload, err := quicwire.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quicwire.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
}

// TestQUICWireCompatPlatformProtoSignRequest guards the QUIC wire contract
// for the enum-typed hash_algorithm field and the pre_hashed flag of the
// platformv1 SignRequest.
func TestQUICWireCompatPlatformProtoSignRequest(t *testing.T) {
	var out KMSSignRequest
	encodeAs(t, &platformv1.SignRequest{
		KeyId:         "k1",
		Message:       []byte{1, 2, 3},
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		PreHashed:     true,
	}, &out)

	if out.KeyId != "k1" {
		t.Errorf("KeyId = %q, want k1", out.KeyId)
	}
	if !bytes.Equal(out.Message, []byte{1, 2, 3}) {
		t.Errorf("Message = %v, want [1 2 3]", out.Message)
	}
	if platformv1.HashAlgorithm(out.HashAlgorithm) != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("HashAlgorithm = %d, want %d", out.HashAlgorithm, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256)
	}
	if !out.PreHashed {
		t.Error("PreHashed = false, want true")
	}
}

func TestQUICWireCompatSignResponse(t *testing.T) {
	var out platformv1.SignResponse
	encodeAs(t, &KMSSignResponse{
		KeyId:         "k1",
		KeyVersion:    3,
		Signature:     []byte{9, 8, 7},
		HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384),
		Timestamp:     1234,
	}, &out)

	if out.GetKeyId() != "k1" {
		t.Errorf("KeyId = %q, want k1", out.GetKeyId())
	}
	if out.GetKeyVersion() != 3 {
		t.Errorf("KeyVersion = %d, want 3", out.GetKeyVersion())
	}
	if !bytes.Equal(out.GetSignature(), []byte{9, 8, 7}) {
		t.Errorf("Signature = %v, want [9 8 7]", out.GetSignature())
	}
	if out.GetHashAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384 {
		t.Errorf("HashAlgorithm = %v, want SHA384", out.GetHashAlgorithm())
	}
	if out.GetTimestamp() != 1234 {
		t.Errorf("Timestamp = %d, want 1234", out.GetTimestamp())
	}
}

func TestQUICWireCompatVerify(t *testing.T) {
	var req KMSVerifyRequest
	encodeAs(t, &platformv1.VerifyRequest{
		KeyId:         "vk",
		Message:       []byte("msg"),
		Signature:     []byte("sig"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
		KeyVersion:    7,
	}, &req)

	if req.KeyId != "vk" || string(req.Message) != "msg" || string(req.Signature) != "sig" {
		t.Errorf("request fields = %q/%q/%q, want vk/msg/sig", req.KeyId, req.Message, req.Signature)
	}
	if platformv1.HashAlgorithm(req.HashAlgorithm) != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512 {
		t.Errorf("HashAlgorithm = %d, want SHA512", req.HashAlgorithm)
	}
	if req.KeyVersion != 7 {
		t.Errorf("KeyVersion = %d, want 7", req.KeyVersion)
	}

	var resp platformv1.VerifyResponse
	encodeAs(t, &KMSVerifyResponse{
		KeyId:      "vk",
		KeyVersion: 7,
		Valid:      true,
		Timestamp:  99,
	}, &resp)

	if resp.GetKeyId() != "vk" || resp.GetKeyVersion() != 7 || !resp.GetValid() || resp.GetTimestamp() != 99 {
		t.Errorf("response = %q/%d/%v/%d, want vk/7/true/99",
			resp.GetKeyId(), resp.GetKeyVersion(), resp.GetValid(), resp.GetTimestamp())
	}
}

func TestQUICWireCompatHash(t *testing.T) {
	var req KMSHashRequest
	encodeAs(t, &platformv1.HashRequest{
		Data:      []byte("payload"),
		Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	}, &req)

	if string(req.Data) != "payload" {
		t.Errorf("Data = %q, want payload", req.Data)
	}
	if platformv1.HashAlgorithm(req.Algorithm) != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384 {
		t.Errorf("Algorithm = %d, want SHA384", req.Algorithm)
	}

	var resp platformv1.HashResponse
	encodeAs(t, &KMSHashResponse{
		Algorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384),
		Hash:      []byte("digest"),
		Timestamp: 42,
	}, &resp)

	if resp.GetAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384 {
		t.Errorf("Algorithm = %v, want SHA384", resp.GetAlgorithm())
	}
	if string(resp.GetHash()) != "digest" || resp.GetTimestamp() != 42 {
		t.Errorf("Hash/Timestamp = %q/%d, want digest/42", resp.GetHash(), resp.GetTimestamp())
	}
}

func TestQUICWireCompatHMAC(t *testing.T) {
	var req KMSHMACRequest
	encodeAs(t, &platformv1.HMACRequest{
		KeyId:         "hk",
		Message:       []byte("data"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}, &req)

	if req.KeyId != "hk" || string(req.Message) != "data" {
		t.Errorf("request = %q/%q, want hk/data", req.KeyId, req.Message)
	}
	if platformv1.HashAlgorithm(req.HashAlgorithm) != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("HashAlgorithm = %d, want SHA256", req.HashAlgorithm)
	}

	var resp platformv1.HMACResponse
	encodeAs(t, &KMSHMACResponse{
		KeyId:         "hk",
		KeyVersion:    2,
		Hmac:          []byte("mac"),
		HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
		Timestamp:     5,
	}, &resp)

	if resp.GetKeyId() != "hk" || resp.GetKeyVersion() != 2 || string(resp.GetHmac()) != "mac" {
		t.Errorf("response = %q/%d/%q, want hk/2/mac", resp.GetKeyId(), resp.GetKeyVersion(), resp.GetHmac())
	}
	if resp.GetHashAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("HashAlgorithm = %v, want SHA256", resp.GetHashAlgorithm())
	}
}

func TestQUICWireCompatVerifyHMAC(t *testing.T) {
	var req KMSVerifyHMACRequest
	encodeAs(t, &platformv1.VerifyHMACRequest{
		KeyId:         "hk",
		Message:       []byte("data"),
		Hmac:          []byte("mac"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
		KeyVersion:    4,
	}, &req)

	if req.KeyId != "hk" || string(req.Message) != "data" || string(req.Hmac) != "mac" {
		t.Errorf("request = %q/%q/%q, want hk/data/mac", req.KeyId, req.Message, req.Hmac)
	}
	if platformv1.HashAlgorithm(req.HashAlgorithm) != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512 {
		t.Errorf("HashAlgorithm = %d, want SHA512", req.HashAlgorithm)
	}
	if req.KeyVersion != 4 {
		t.Errorf("KeyVersion = %d, want 4", req.KeyVersion)
	}

	var resp platformv1.VerifyHMACResponse
	encodeAs(t, &KMSVerifyHMACResponse{
		KeyId:      "hk",
		KeyVersion: 4,
		Valid:      true,
		Timestamp:  6,
	}, &resp)

	if resp.GetKeyId() != "hk" || resp.GetKeyVersion() != 4 || !resp.GetValid() {
		t.Errorf("response = %q/%d/%v, want hk/4/true", resp.GetKeyId(), resp.GetKeyVersion(), resp.GetValid())
	}
}

func TestQUICWireCompatRewrap(t *testing.T) {
	var req KMSRewrapRequest
	encodeAs(t, &platformv1.RewrapRequest{
		KeyId:         "rk",
		Ciphertext:    []byte("ct"),
		Context:       []byte("aad"),
		Nonce:         []byte("n"),
		SourceVersion: 0,
	}, &req)

	if req.KeyId != "rk" || string(req.Ciphertext) != "ct" || string(req.Context) != "aad" || string(req.Nonce) != "n" {
		t.Errorf("request = %q/%q/%q/%q, want rk/ct/aad/n", req.KeyId, req.Ciphertext, req.Context, req.Nonce)
	}
	if req.SourceVersion != 0 {
		t.Errorf("SourceVersion = %d, want 0", req.SourceVersion)
	}

	var resp platformv1.RewrapResponse
	encodeAs(t, &KMSRewrapResponse{
		KeyId:         "rk",
		SourceVersion: 1,
		TargetVersion: 2,
		Ciphertext:    []byte("ct2"),
		Nonce:         []byte("n2"),
		Timestamp:     8,
	}, &resp)

	if resp.GetKeyId() != "rk" || resp.GetSourceVersion() != 1 || resp.GetTargetVersion() != 2 {
		t.Errorf("response = %q/%d/%d, want rk/1/2",
			resp.GetKeyId(), resp.GetSourceVersion(), resp.GetTargetVersion())
	}
	if string(resp.GetCiphertext()) != "ct2" || string(resp.GetNonce()) != "n2" {
		t.Errorf("Ciphertext/Nonce = %q/%q, want ct2/n2", resp.GetCiphertext(), resp.GetNonce())
	}
}

func TestQUICWireCompatUpdateKeyStatus(t *testing.T) {
	var req KMSUpdateKeyStatusRequest
	encodeAs(t, &platformv1.UpdateKeyStatusRequest{
		KeyId:   "sk",
		Version: 2,
		Status:  platformv1.KeyStatus_KEY_STATUS_DISABLED,
	}, &req)

	if req.KeyId != "sk" || req.Version != 2 {
		t.Errorf("request = %q/%d, want sk/2", req.KeyId, req.Version)
	}
	if platformv1.KeyStatus(req.Status) != platformv1.KeyStatus_KEY_STATUS_DISABLED {
		t.Errorf("Status = %d, want DISABLED", req.Status)
	}

	var resp platformv1.UpdateKeyStatusResponse
	encodeAs(t, &KMSUpdateKeyStatusResponse{
		KeyId:     "sk",
		Version:   2,
		KeyStatus: int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
		Timestamp: 11,
	}, &resp)

	if resp.GetKeyId() != "sk" || resp.GetVersion() != 2 {
		t.Errorf("response = %q/%d, want sk/2", resp.GetKeyId(), resp.GetVersion())
	}
	if resp.GetKeyStatus() != platformv1.KeyStatus_KEY_STATUS_DISABLED {
		t.Errorf("KeyStatus = %v, want DISABLED", resp.GetKeyStatus())
	}
}

func TestQUICWireCompatExportKey(t *testing.T) {
	var req KMSExportKeyRequest
	encodeAs(t, &platformv1.ExportKeyRequest{
		KeyId:             "ek",
		WrappingKeyId:     "wk",
		WrappingAlgorithm: platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM,
		Format:            platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM,
		Version:           3,
	}, &req)

	if req.KeyId != "ek" || req.WrappingKeyId != "wk" || req.Version != 3 {
		t.Errorf("request = %q/%q/%d, want ek/wk/3", req.KeyId, req.WrappingKeyId, req.Version)
	}
	if platformv1.WrappingAlgorithm(req.WrappingAlgorithm) != platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM {
		t.Errorf("WrappingAlgorithm = %d, want AES_GCM", req.WrappingAlgorithm)
	}
	if platformv1.KeyExportFormat(req.Format) != platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM {
		t.Errorf("Format = %d, want PEM", req.Format)
	}

	var resp platformv1.ExportKeyResponse
	encodeAs(t, &KMSExportKeyResponse{
		KeyId:             "ek",
		Format:            int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM),
		WrappingKeyId:     "wk",
		WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM),
		WrappedMaterial:   []byte("wrapped"),
		Version:           3,
		Timestamp:         13,
	}, &resp)

	if resp.GetKeyId() != "ek" || resp.GetWrappingKeyId() != "wk" || resp.GetVersion() != 3 {
		t.Errorf("response = %q/%q/%d, want ek/wk/3",
			resp.GetKeyId(), resp.GetWrappingKeyId(), resp.GetVersion())
	}
	if resp.GetFormat() != platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM {
		t.Errorf("Format = %v, want PEM", resp.GetFormat())
	}
	if resp.GetWrappingAlgorithm() != platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM {
		t.Errorf("WrappingAlgorithm = %v, want AES_GCM", resp.GetWrappingAlgorithm())
	}
	if string(resp.GetWrappedMaterial()) != "wrapped" {
		t.Errorf("WrappedMaterial = %q, want wrapped", resp.GetWrappedMaterial())
	}
}

func TestQUICWireCompatGenerateKey(t *testing.T) {
	var req KMSGenerateKeyRequest
	encodeAs(t, &platformv1.GenerateKeyRequest{
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
			KeySize:   256,
			Usage: []platformv1.KeyUsage{
				platformv1.KeyUsage_KEY_USAGE_ENCRYPT,
				platformv1.KeyUsage_KEY_USAGE_DECRYPT,
			},
			Exportable:         true,
			DeletionProtection: true,
		},
		Name:        "gen-key",
		Description: "compat",
		Tags:        map[string]string{"env": "test"},
		Owner:       "alice",
	}, &req)

	if req.Name != "gen-key" || req.Description != "compat" || req.Owner != "alice" {
		t.Errorf("request = %q/%q/%q, want gen-key/compat/alice", req.Name, req.Description, req.Owner)
	}
	if req.Tags["env"] != "test" {
		t.Errorf("Tags = %v, want env=test", req.Tags)
	}
	if req.KeySpec == nil {
		t.Fatal("KeySpec = nil, want populated")
	}
	if platformv1.KMSKeyAlgorithm(req.KeySpec.Algorithm) != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256 {
		t.Errorf("KeySpec.Algorithm = %d, want AES_256", req.KeySpec.Algorithm)
	}
	if req.KeySpec.KeySize != 256 || !req.KeySpec.Exportable || !req.KeySpec.DeletionProtection {
		t.Errorf("KeySpec = %+v, want key_size 256, exportable, deletion_protection", req.KeySpec)
	}
	if len(req.KeySpec.Usage) != 2 ||
		platformv1.KeyUsage(req.KeySpec.Usage[0]) != platformv1.KeyUsage_KEY_USAGE_ENCRYPT ||
		platformv1.KeyUsage(req.KeySpec.Usage[1]) != platformv1.KeyUsage_KEY_USAGE_DECRYPT {
		t.Errorf("KeySpec.Usage = %v, want [ENCRYPT DECRYPT]", req.KeySpec.Usage)
	}

	var resp platformv1.GenerateKeyResponse
	encodeAs(t, &KMSGenerateKeyResponse{
		Key: &KMSKeyHandleResponse{
			KeyId:     "gk1",
			Version:   1,
			Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			Status:    int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			CreatedAt: 100,
		},
		Metadata: &KMSKeyMetadataResponse{
			KeyId:     "gk1",
			Name:      "gen-key",
			Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			Status:    int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			Usage:     []int32{int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT)},
			Version:   1,
		},
		Timestamp: 100,
	}, &resp)

	if resp.GetKey().GetKeyId() != "gk1" || resp.GetKey().GetVersion() != 1 {
		t.Errorf("Key = %q/%d, want gk1/1", resp.GetKey().GetKeyId(), resp.GetKey().GetVersion())
	}
	if resp.GetKey().GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256 {
		t.Errorf("Key.Algorithm = %v, want AES_256", resp.GetKey().GetAlgorithm())
	}
	if resp.GetKey().GetStatus() != platformv1.KeyStatus_KEY_STATUS_ENABLED {
		t.Errorf("Key.Status = %v, want ENABLED", resp.GetKey().GetStatus())
	}
	if resp.GetMetadata().GetName() != "gen-key" {
		t.Errorf("Metadata.Name = %q, want gen-key", resp.GetMetadata().GetName())
	}
	if len(resp.GetMetadata().GetUsage()) != 1 ||
		resp.GetMetadata().GetUsage()[0] != platformv1.KeyUsage_KEY_USAGE_ENCRYPT {
		t.Errorf("Metadata.Usage = %v, want [ENCRYPT]", resp.GetMetadata().GetUsage())
	}
}

func TestQUICWireCompatBatchEncrypt(t *testing.T) {
	var req KMSBatchEncryptRequest
	encodeAs(t, &platformv1.BatchEncryptRequest{
		KeyId: "bk",
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "i1", Plaintext: []byte("p1"), Context: []byte("c1")},
			{ItemId: "i2", Plaintext: []byte("p2")},
		},
	}, &req)

	if req.KeyId != "bk" {
		t.Errorf("KeyId = %q, want bk", req.KeyId)
	}
	if len(req.Items) != 2 {
		t.Fatalf("Items = %d, want 2", len(req.Items))
	}
	if req.Items[0].ItemId != "i1" || string(req.Items[0].Plaintext) != "p1" || string(req.Items[0].Context) != "c1" {
		t.Errorf("Items[0] = %+v, want i1/p1/c1", req.Items[0])
	}
	if req.Items[1].ItemId != "i2" || string(req.Items[1].Plaintext) != "p2" {
		t.Errorf("Items[1] = %+v, want i2/p2", req.Items[1])
	}

	var resp platformv1.BatchEncryptResponse
	encodeAs(t, &KMSBatchEncryptResponse{
		KeyId: "bk",
		Results: []*KMSBatchEncryptResultItem{
			{
				ItemId:     "i1",
				Status:     &KMSStatusResponse{Success: true},
				Ciphertext: []byte("e1"),
				Nonce:      []byte("n1"),
				KeyVersion: 5,
			},
			{
				ItemId: "i2",
				Status: &KMSStatusResponse{Success: false, Message: "boom"},
			},
		},
		SuccessCount: 1,
		FailureCount: 1,
		Timestamp:    77,
	}, &resp)

	if resp.GetKeyId() != "bk" || resp.GetSuccessCount() != 1 || resp.GetFailureCount() != 1 {
		t.Errorf("response = %q/%d/%d, want bk/1/1",
			resp.GetKeyId(), resp.GetSuccessCount(), resp.GetFailureCount())
	}
	if len(resp.GetResults()) != 2 {
		t.Fatalf("Results = %d, want 2", len(resp.GetResults()))
	}
	ok := resp.GetResults()[0]
	if ok.GetItemId() != "i1" || !ok.GetStatus().GetSuccess() ||
		string(ok.GetCiphertext()) != "e1" || string(ok.GetNonce()) != "n1" || ok.GetKeyVersion() != 5 {
		t.Errorf("Results[0] = %+v, want i1/success/e1/n1/5", ok)
	}
	failed := resp.GetResults()[1]
	if failed.GetItemId() != "i2" || failed.GetStatus().GetSuccess() || failed.GetStatus().GetMessage() != "boom" {
		t.Errorf("Results[1] = %+v, want i2/failed/boom", failed)
	}
}

func TestQUICWireCompatBatchDecrypt(t *testing.T) {
	var req KMSBatchDecryptRequest
	encodeAs(t, &platformv1.BatchDecryptRequest{
		KeyId: "bk",
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "i1", Ciphertext: []byte("e1"), Context: []byte("c1"), Nonce: []byte("n1")},
		},
	}, &req)

	if req.KeyId != "bk" {
		t.Errorf("KeyId = %q, want bk", req.KeyId)
	}
	if len(req.Items) != 1 {
		t.Fatalf("Items = %d, want 1", len(req.Items))
	}
	item := req.Items[0]
	if item.ItemId != "i1" || string(item.Ciphertext) != "e1" ||
		string(item.Context) != "c1" || string(item.Nonce) != "n1" {
		t.Errorf("Items[0] = %+v, want i1/e1/c1/n1", item)
	}
	if item.KeyVersion != 0 {
		t.Errorf("KeyVersion = %d, want 0", item.KeyVersion)
	}

	var resp platformv1.BatchDecryptResponse
	encodeAs(t, &KMSBatchDecryptResponse{
		KeyId: "bk",
		Results: []*KMSBatchDecryptResultItem{
			{
				ItemId:    "i1",
				Status:    &KMSStatusResponse{Success: true},
				Plaintext: []byte("p1"),
			},
		},
		SuccessCount: 1,
		Timestamp:    88,
	}, &resp)

	if resp.GetKeyId() != "bk" || resp.GetSuccessCount() != 1 || resp.GetFailureCount() != 0 {
		t.Errorf("response = %q/%d/%d, want bk/1/0",
			resp.GetKeyId(), resp.GetSuccessCount(), resp.GetFailureCount())
	}
	if len(resp.GetResults()) != 1 {
		t.Fatalf("Results = %d, want 1", len(resp.GetResults()))
	}
	result := resp.GetResults()[0]
	if result.GetItemId() != "i1" || !result.GetStatus().GetSuccess() || string(result.GetPlaintext()) != "p1" {
		t.Errorf("Results[0] = %+v, want i1/success/p1", result)
	}
}
