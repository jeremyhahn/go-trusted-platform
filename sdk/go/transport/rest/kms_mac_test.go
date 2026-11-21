// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial

package rest

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestKMSMAC_RoutesAndBodies: HMAC and VerifyHMAC carry the key in the path,
// Hash has none, and every body uses the webservice wire names with the
// hash spelled the way the server parses it.
func TestKMSMAC_RoutesAndBodies(t *testing.T) {
	sha384 := platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384
	cases := []struct {
		name     string
		method   string
		req      proto.Message
		resp     proto.Message
		payload  string
		wantPath string
		wantBody map[string]interface{}
	}{
		{
			name:     "HMAC",
			method:   platformv1.KeyManagementService_HMAC_FullMethodName,
			req:      &platformv1.HMACRequest{KeyId: "mac", Message: []byte("m"), HashAlgorithm: sha384},
			resp:     &platformv1.HMACResponse{},
			payload:  `{"key_id":"mac","hmac":"` + b64("t") + `"}`,
			wantPath: "/api/v1/kms/hmac/mac",
			wantBody: map[string]interface{}{"data": b64("m"), "hash": "SHA-384"},
		},
		{
			name:   "VerifyHMAC",
			method: platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
			req: &platformv1.VerifyHMACRequest{KeyId: "mac", Message: []byte("m"), Hmac: []byte("t"),
				HashAlgorithm: sha384},
			resp:     &platformv1.VerifyHMACResponse{},
			payload:  `{"valid":true}`,
			wantPath: "/api/v1/kms/hmac/mac/verify",
			wantBody: map[string]interface{}{"data": b64("m"), "hmac": b64("t"), "hash": "SHA-384"},
		},
		{
			name:     "Hash",
			method:   platformv1.KeyManagementService_Hash_FullMethodName,
			req:      &platformv1.HashRequest{Data: []byte("d"), Algorithm: sha384},
			resp:     &platformv1.HashResponse{},
			payload:  `{"hash":"SHA-384","digest":"` + b64("h") + `"}`,
			wantPath: "/api/v1/kms/hash",
			wantBody: map[string]interface{}{"data": b64("d"), "hash": "SHA-384", "algorithm": float64(3)},
		},
		{
			name:     "HashUnspecifiedLeavesServerDefault",
			method:   platformv1.KeyManagementService_Hash_FullMethodName,
			req:      &platformv1.HashRequest{Data: []byte("d")},
			resp:     &platformv1.HashResponse{},
			payload:  `{"hash":"SHA-256","digest":"` + b64("h") + `"}`,
			wantPath: "/api/v1/kms/hash",
			wantBody: map[string]interface{}{"data": b64("d")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, tc.payload)
			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != "POST" || captured.path != tc.wantPath {
				t.Fatalf("request = %s %s, want POST %s", captured.method, captured.path, tc.wantPath)
			}
			if len(captured.body) != len(tc.wantBody) {
				t.Fatalf("body = %v, want %v", captured.body, tc.wantBody)
			}
			for k, v := range tc.wantBody {
				if captured.body[k] != v {
					t.Fatalf("body[%s] = %v, want %v (body %v)", k, captured.body[k], v, captured.body)
				}
			}
		})
	}
}

// TestKMSMAC_RefusedBeforeTheWire: a hash the routes cannot carry, an empty
// key and a VerifyHMAC key version are InvalidArgument and nothing is sent.
func TestKMSMAC_RefusedBeforeTheWire(t *testing.T) {
	unsupported := platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256
	cases := []struct {
		name   string
		method string
		req    proto.Message
		resp   proto.Message
	}{
		{"HMACUnsupportedHash", platformv1.KeyManagementService_HMAC_FullMethodName,
			&platformv1.HMACRequest{KeyId: "mac", Message: []byte("m"), HashAlgorithm: unsupported},
			&platformv1.HMACResponse{}},
		{"VerifyHMACUnsupportedHash", platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
			&platformv1.VerifyHMACRequest{KeyId: "mac", Message: []byte("m"), HashAlgorithm: unsupported},
			&platformv1.VerifyHMACResponse{}},
		{"HashUnsupportedHash", platformv1.KeyManagementService_Hash_FullMethodName,
			&platformv1.HashRequest{Data: []byte("d"), Algorithm: unsupported},
			&platformv1.HashResponse{}},
		{"HMACEmptyKey", platformv1.KeyManagementService_HMAC_FullMethodName,
			&platformv1.HMACRequest{Message: []byte("m")}, &platformv1.HMACResponse{}},
		{"VerifyHMACEmptyKey", platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
			&platformv1.VerifyHMACRequest{Message: []byte("m")}, &platformv1.VerifyHMACResponse{}},
		{"VerifyHMACKeyVersion", platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
			&platformv1.VerifyHMACRequest{KeyId: "mac", Message: []byte("m"), Hmac: []byte("t"), KeyVersion: 2},
			&platformv1.VerifyHMACResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
			}
			if captured.path != "" {
				t.Fatalf("request sent to %s, want none", captured.path)
			}
		})
	}
}

// TestKMSMAC_RepliesDecode: the HMAC tag, a false verdict and the Hash digest
// with its algorithm decode into the proto replies; a hash name the routes
// do not know is an unmarshal failure, never a silent default.
func TestKMSMAC_RepliesDecode(t *testing.T) {
	ctx := context.Background()
	t.Run("HMAC", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"key_id":"mac","hmac":"`+b64("tag")+`"}`)
		resp := &platformv1.HMACResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.KeyManagementService_HMAC_FullMethodName,
			&platformv1.HMACRequest{KeyId: "mac", Message: []byte("m")}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetKeyId() != "mac" || string(resp.GetHmac()) != "tag" || !resp.GetStatus().GetSuccess() {
			t.Fatalf("reply = %v", resp)
		}
	})
	t.Run("VerifyHMACFalse", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"valid":false}`)
		resp := &platformv1.VerifyHMACResponse{Valid: true}
		if err := a.Connection().Invoke(ctx, platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
			&platformv1.VerifyHMACRequest{KeyId: "mac", Message: []byte("m"), Hmac: []byte("t")}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetValid() || !resp.GetStatus().GetSuccess() {
			t.Fatalf("reply = %v, want valid=false", resp)
		}
	})
	t.Run("Hash", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"hash":"SHA-512","digest":"`+b64("dg")+`"}`)
		resp := &platformv1.HashResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.KeyManagementService_Hash_FullMethodName,
			&platformv1.HashRequest{Data: []byte("d")}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if string(resp.GetHash()) != "dg" || resp.GetAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512 {
			t.Fatalf("reply = %v", resp)
		}
	})
	t.Run("HashUnknownName", func(t *testing.T) {
		_, err := decodeKMSHash([]byte(`{"hash":"MD5","digest":"` + b64("dg") + `"}`))
		var unmarshal ErrUnmarshalFailed
		if !errors.As(err, &unmarshal) {
			t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
		}
	})
}

// TestKMSMAC_RepliesCarryTheRequest: the routes do not echo the HMAC hash or
// the verified key, so the replies take them from the request: HMAC
// hash_algorithm is the requested one (SHA-256, the server default, when
// unspecified) and VerifyHMAC key_id is the requested key for either verdict.
func TestKMSMAC_RepliesCarryTheRequest(t *testing.T) {
	ctx := context.Background()
	hmacCases := []struct {
		name string
		req  platformv1.HashAlgorithm
		want platformv1.HashAlgorithm
	}{
		{"HMACSHA384", platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384},
		{"HMACUnspecified", platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256},
	}
	for _, tc := range hmacCases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := kmsAdapter(t, `{"key_id":"mac","hmac":"`+b64("tag")+`"}`)
			resp := &platformv1.HMACResponse{}
			if err := a.Connection().Invoke(ctx, platformv1.KeyManagementService_HMAC_FullMethodName,
				&platformv1.HMACRequest{KeyId: "mac", Message: []byte("m"), HashAlgorithm: tc.req}, resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if resp.GetHashAlgorithm() != tc.want {
				t.Fatalf("hash_algorithm = %v, want %v (reply %v)", resp.GetHashAlgorithm(), tc.want, resp)
			}
		})
	}
	for _, valid := range []bool{true, false} {
		payload := `{"valid":false}`
		if valid {
			payload = `{"valid":true}`
		}
		t.Run(payload, func(t *testing.T) {
			a, _ := kmsAdapter(t, payload)
			resp := &platformv1.VerifyHMACResponse{}
			if err := a.Connection().Invoke(ctx, platformv1.KeyManagementService_VerifyHMAC_FullMethodName,
				&platformv1.VerifyHMACRequest{KeyId: "mac", Message: []byte("m"), Hmac: []byte("t")}, resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if resp.GetKeyId() != "mac" || resp.GetValid() != valid {
				t.Fatalf("reply = %v, want key_id mac valid %v", resp, valid)
			}
		})
	}
}

// TestKMSMAC_HashDaemonShape: the daemon reads a numeric algorithm and
// replies {algorithm, hash (base64 digest), timestamp}; the SDK sends the
// number and decodes that reply.
func TestKMSMAC_HashDaemonShape(t *testing.T) {
	a, captured := kmsAdapter(t, `{"algorithm":3,"hash":"`+b64("dg")+`","timestamp":1}`)
	resp := &platformv1.HashResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Hash_FullMethodName,
		&platformv1.HashRequest{Data: []byte("d"), Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(resp.GetHash()) != "dg" || resp.GetAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384 {
		t.Fatalf("reply = %v", resp)
	}
	if captured.body["algorithm"] != float64(3) {
		t.Fatalf("body = %v, want algorithm 3", captured.body)
	}
}
