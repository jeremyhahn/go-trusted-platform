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
package rest

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestKMSKeyGeneration_EnumsTravelAsNames pins the three key-generation claims
// to their routes and to bodies that carry algorithms and usages as the names
// the routes decode, never as proto enum numbers (docs/kms/api.md §2, §4).
func TestKMSKeyGeneration_EnumsTravelAsNames(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantPath   string
		wantBody   map[string]interface{}
	}{
		{
			name:       "GenerateKey",
			grpcMethod: platformv1.KeyManagementService_GenerateKey_FullMethodName,
			req: &platformv1.GenerateKeyRequest{
				Name:        "kek",
				Description: "wraps tenant keys",
				Owner:       "ops",
				Tags:        map[string]string{"env": "prod"},
				KeySpec: &platformv1.KMSKeySpec{
					Algorithm:          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
					Usage:              []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, platformv1.KeyUsage_KEY_USAGE_DECRYPT},
					Exportable:         true,
					DeletionProtection: true,
				},
			},
			resp:     &platformv1.GenerateKeyResponse{},
			wantPath: "/api/v1/kms/keys",
			wantBody: map[string]interface{}{
				"name": "kek", "algorithm": "AES-256-GCM", "usage": []interface{}{"ENCRYPT", "DECRYPT"},
				"description": "wraps tenant keys", "owner": "ops", "tags": map[string]interface{}{"env": "prod"},
				"exportable": true, "deletion_protection": true,
			},
		},
		{
			name:       "GenerateKeyWithoutSpec",
			grpcMethod: platformv1.KeyManagementService_GenerateKey_FullMethodName,
			req:        &platformv1.GenerateKeyRequest{Name: "kek"},
			resp:       &platformv1.GenerateKeyResponse{},
			wantPath:   "/api/v1/kms/keys",
			wantBody:   map[string]interface{}{"name": "kek"},
		},
		{
			name:       "GenerateDataKeyCLIDefault",
			grpcMethod: platformv1.KeyManagementService_GenerateDataKey_FullMethodName,
			req: &platformv1.GenerateDataKeyRequest{KeyId: "kek", KeySize: 256, Context: []byte("aad"),
				Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
			resp:     &platformv1.GenerateDataKeyResponse{},
			wantPath: "/api/v1/kms/data-keys",
			wantBody: map[string]interface{}{"key_id": "kek", "algorithm": "KMS_KEY_ALGORITHM_AES_256",
				"key_size": float64(256), "context": b64("aad")},
		},
		{
			name:       "GenerateDataKeyWithoutAlgorithm",
			grpcMethod: platformv1.KeyManagementService_GenerateDataKey_FullMethodName,
			req:        &platformv1.GenerateDataKeyRequest{KeyId: "kek"},
			resp:       &platformv1.GenerateDataKeyResponse{},
			wantPath:   "/api/v1/kms/data-keys",
			wantBody:   map[string]interface{}{"key_id": "kek"},
		},
		{
			name:       "GenerateWrappedDataKey",
			grpcMethod: platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName,
			req: &platformv1.GenerateWrappedDataKeyRequest{WrappingKeyId: "kek", KeySize: 256,
				KeyAlgorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305},
			resp:     &platformv1.GenerateWrappedDataKeyResponse{},
			wantPath: "/api/v1/kms/data-keys/wrapped",
			wantBody: map[string]interface{}{"wrapping_key_id": "kek",
				"key_algorithm": "KMS_KEY_ALGORITHM_CHACHA20_POLY1305", "key_size": float64(256)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != http.MethodPost || captured.path != tc.wantPath {
				t.Fatalf("route = %s %s, want POST %s", captured.method, captured.path, tc.wantPath)
			}
			if !reflect.DeepEqual(captured.body, tc.wantBody) {
				t.Fatalf("body = %v, want %v", captured.body, tc.wantBody)
			}
		})
	}
}

// TestKMSKeyGeneration_UnsendableEnumsRejectedBeforeTheWire: an enum the route
// cannot carry is refused as InvalidArgument with a typed cause, and nothing
// is sent.
func TestKMSKeyGeneration_UnsendableEnumsRejectedBeforeTheWire(t *testing.T) {
	outOfEnum := platformv1.KMSKeyAlgorithm(99)
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantErr    interface{}
	}{
		{
			name:       "GenerateKeyAlgorithmTheRouteDoesNotMint",
			grpcMethod: platformv1.KeyManagementService_GenerateKey_FullMethodName,
			req: &platformv1.GenerateKeyRequest{Name: "k",
				KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072}},
			resp:    &platformv1.GenerateKeyResponse{},
			wantErr: new(ErrKeyAlgorithmNotSupported),
		},
		{
			name:       "GenerateKeyUsageTheRouteDoesNotTake",
			grpcMethod: platformv1.KeyManagementService_GenerateKey_FullMethodName,
			req: &platformv1.GenerateKeyRequest{Name: "k",
				KeySpec: &platformv1.KMSKeySpec{Usage: []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_DERIVE}}},
			resp:    &platformv1.GenerateKeyResponse{},
			wantErr: new(ErrKeyUsageNotSupported),
		},
		{
			name:       "GenerateDataKeyAlgorithmOutsideTheEnum",
			grpcMethod: platformv1.KeyManagementService_GenerateDataKey_FullMethodName,
			req:        &platformv1.GenerateDataKeyRequest{KeyId: "kek", Algorithm: outOfEnum},
			resp:       &platformv1.GenerateDataKeyResponse{},
			wantErr:    new(ErrKeyAlgorithmNotSupported),
		},
		{
			name:       "GenerateWrappedDataKeyAlgorithmOutsideTheEnum",
			grpcMethod: platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName,
			req:        &platformv1.GenerateWrappedDataKeyRequest{WrappingKeyId: "kek", KeyAlgorithm: outOfEnum},
			resp:       &platformv1.GenerateWrappedDataKeyResponse{},
			wantErr:    new(ErrKeyAlgorithmNotSupported),
		},
		{
			name:       "GenerateWrappedDataKeyWrappingAlgorithm",
			grpcMethod: platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName,
			req: &platformv1.GenerateWrappedDataKeyRequest{WrappingKeyId: "kek",
				WrappingAlgorithm: platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM},
			resp:    &platformv1.GenerateWrappedDataKeyResponse{},
			wantErr: new(ErrWrappingAlgorithmNotSupported),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
			}
			if captured.method != "" {
				t.Fatalf("request reached the server: %s %s", captured.method, captured.path)
			}
			_, encodeErr := restRequestEncoders[tc.grpcMethod](tc.req)
			if !errors.As(encodeErr, tc.wantErr) {
				t.Fatalf("encoder error = %T (%v), want %T", encodeErr, encodeErr, tc.wantErr)
			}
		})
	}
}

// TestKMSGenerateKey_ReplyFillsHandleAndMetadata: the route's flat reply,
// algorithm named, decodes into the key handle and metadata.
func TestKMSGenerateKey_ReplyFillsHandleAndMetadata(t *testing.T) {
	a, _ := kmsAdapter(t, `{"key_id":"k1","version":3,"algorithm":"ECDSA-P256","exportable":true,"deletion_protection":true}`)
	resp := &platformv1.GenerateKeyResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_GenerateKey_FullMethodName,
		&platformv1.GenerateKeyRequest{Name: "k1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	key := resp.GetKey()
	if key.GetKeyId() != "k1" || key.GetVersion() != 3 ||
		key.GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256 {
		t.Fatalf("key = %v", key)
	}
	meta := resp.GetMetadata()
	if !meta.GetExportable() || !meta.GetDeletionProtection() || meta.GetKeyId() != "k1" {
		t.Fatalf("metadata = %v", meta)
	}
}

// TestKMSGetKey_FlatReplyFillsKey pins Codex round 2 P1 on #2151:
// GET /api/v1/kms/keys/{name} answers the flat KeyInfoResponse, so the
// adapter decodes it into Key and Metadata instead of returning a nil Key.
func TestKMSGetKey_FlatReplyFillsKey(t *testing.T) {
	a, _ := kmsAdapter(t, `{"key_id":"k1","name":"k1","algorithm":"AES-256-GCM","version":1}`)
	resp := &platformv1.GetKeyResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_GetKey_FullMethodName,
		&platformv1.GetKeyRequest{KeyId: "k1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	key := resp.GetKey()
	if key == nil || key.GetKeyId() != "k1" || key.GetVersion() != 1 {
		t.Fatalf("key = %v", key)
	}
	meta := resp.GetMetadata()
	if meta.GetKeyId() != "k1" || meta.GetName() != "k1" || meta.GetVersion() != 1 {
		t.Fatalf("metadata = %v", meta)
	}
}

// TestKMSListKeys_NonEmptyReplyDecodes pins Codex round 1 P1 on #2151: the
// webservice KMS router answers ListKeys with {"keys":[...]}, RFC3339
// created_at and algorithm names such as AES-256-GCM, which protojson cannot
// decode into KMSKeyHandle.
func TestKMSListKeys_NonEmptyReplyDecodes(t *testing.T) {
	a, _ := kmsAdapter(t, `{"keys":[{"key_id":"k1","name":"k1","algorithm":"AES-256-GCM","version":1,"created_at":"2026-01-02T03:04:05Z"},{"key_id":"k2","name":"k2","algorithm":"ECDSA-P256","version":2,"created_at":"2026-01-03T03:04:05Z"}]}`)
	resp := &platformv1.ListKeysResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ListKeys_FullMethodName,
		&platformv1.ListKeysRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	want := []struct {
		id        string
		version   uint64
		algorithm string
		created   string
	}{
		{"k1", 1, "AES-256-GCM", "2026-01-02T03:04:05Z"},
		{"k2", 2, "ECDSA-P256", "2026-01-03T03:04:05Z"},
	}
	keys := resp.GetKeys()
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %d", keys, len(want))
	}
	for i, w := range want {
		created, _ := time.Parse(time.RFC3339, w.created)
		k := keys[i]
		if k.GetKeyId() != w.id || k.GetVersion() != w.version || k.GetAlgorithm() != kmsKeyAlgorithmsByName[w.algorithm] || k.GetCreatedAt() != created.Unix() {
			t.Fatalf("keys[%d] = %v, want %s v%d %s %d", i, k, w.id, w.version, w.algorithm, created.Unix())
		}
		if k.GetAlgorithm() == 0 {
			t.Fatalf("keys[%d] algorithm %q has no platform value", i, w.algorithm)
		}
	}
}

// TestKMSListKeys_EmptyReplyDecodes checks an empty key list.
func TestKMSListKeys_EmptyReplyDecodes(t *testing.T) {
	a, _ := kmsAdapter(t, `{"keys":[]}`)
	resp := &platformv1.ListKeysResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ListKeys_FullMethodName,
		&platformv1.ListKeysRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(resp.GetKeys()) != 0 {
		t.Fatalf("keys = %v, want none", resp.GetKeys())
	}
}

// TestKMSGenerateKey_UnknownAlgorithmNameAndMalformedReply: an algorithm name
// the SDK does not know decodes as UNSPECIFIED; a reply that is not JSON is an
// error, not an empty key.
func TestKMSGenerateKey_UnknownAlgorithmNameAndMalformedReply(t *testing.T) {
	resp, err := decodeKMSGenerateKey([]byte(`{"key_id":"k1","algorithm":"UNKNOWN"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.GetKey().GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED {
		t.Fatalf("algorithm = %v, want UNSPECIFIED", resp.GetKey().GetAlgorithm())
	}

	_, err = decodeKMSGenerateKey([]byte(`not json`))
	var unmarshal ErrUnmarshalFailed
	if !errors.As(err, &unmarshal) {
		t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
	}
}
