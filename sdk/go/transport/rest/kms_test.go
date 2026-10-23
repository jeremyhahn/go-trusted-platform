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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// kmsCapture records what one KMS call put on the wire.
type kmsCapture struct {
	method string
	path   string
	query  url.Values
	body   map[string]interface{}
}

// kmsAdapter answers every request with payload and records the request.
func kmsAdapter(t *testing.T, payload string) (*Adapter, *kmsCapture) {
	t.Helper()
	captured := &kmsCapture{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			// Connect's health probe is not a KMS call.
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":` + payload + `}`))
	})
	return a, captured
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestKMSItemRoutes_KeyTravelsInThePathAndBodyUsesServerNames pins each of the
// six keyed KMS claims to its served route (docs/kms/api.md §2, §3) and the body
// to the route's own field names.
func TestKMSItemRoutes_KeyTravelsInThePathAndBodyUsesServerNames(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantMethod string
		wantPath   string
		wantBody   map[string]interface{}
	}{
		{
			name:       "DeleteKey",
			grpcMethod: platformv1.KeyManagementService_DeleteKey_FullMethodName,
			req:        &platformv1.DeleteKeyRequest{KeyId: "kek"},
			resp:       &platformv1.DeleteKeyResponse{},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/kms/keys/kek",
			wantBody:   map[string]interface{}{},
		},
		{
			name:       "RotateKey",
			grpcMethod: platformv1.KeyManagementService_RotateKey_FullMethodName,
			req:        &platformv1.RotateKeyRequest{KeyId: "kek"},
			resp:       &platformv1.RotateKeyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/keys/kek/rotate",
			wantBody:   map[string]interface{}{},
		},
		{
			name:       "Encrypt",
			grpcMethod: platformv1.KeyManagementService_Encrypt_FullMethodName,
			req:        &platformv1.EncryptRequest{KeyId: "kek", Plaintext: []byte("p"), Context: []byte("aad")},
			resp:       &platformv1.EncryptResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/encrypt/kek",
			wantBody:   map[string]interface{}{"plaintext": b64("p"), "context": b64("aad")},
		},
		{
			name:       "Decrypt",
			grpcMethod: platformv1.KeyManagementService_Decrypt_FullMethodName,
			req:        &platformv1.DecryptRequest{KeyId: "kek", Ciphertext: []byte("c"), Context: []byte("aad"), KeyVersion: 2},
			resp:       &platformv1.DecryptResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/decrypt/kek",
			wantBody:   map[string]interface{}{"ciphertext": b64("c"), "context": b64("aad"), "version": float64(2)},
		},
		{
			name:       "Sign",
			grpcMethod: platformv1.KeyManagementService_Sign_FullMethodName,
			req: &platformv1.SignRequest{KeyId: "kek", Message: []byte("m"),
				HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, PreHashed: true},
			resp:       &platformv1.SignResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/sign/kek",
			wantBody:   map[string]interface{}{"data": b64("m"), "hash": "SHA-384", "pre_hashed": true},
		},
		{
			name:       "Verify",
			grpcMethod: platformv1.KeyManagementService_Verify_FullMethodName,
			req: &platformv1.VerifyRequest{KeyId: "kek", Message: []byte("m"), Signature: []byte("s"),
				HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512, KeyVersion: 4},
			resp:       &platformv1.VerifyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/verify/kek",
			wantBody: map[string]interface{}{"data": b64("m"), "signature": b64("s"),
				"hash": "SHA-512", "version": float64(4)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod || captured.path != tc.wantPath {
				t.Fatalf("route = %s %s, want %s %s", captured.method, captured.path, tc.wantMethod, tc.wantPath)
			}
			if !reflect.DeepEqual(captured.body, tc.wantBody) {
				t.Fatalf("body = %v, want %v", captured.body, tc.wantBody)
			}
		})
	}
}

// TestKMSItemRoutes_EmptyKeyRejectedBeforeTheWire: without a key name there is
// no route to call, so the adapter refuses instead of hitting a different one.
func TestKMSItemRoutes_EmptyKeyRejectedBeforeTheWire(t *testing.T) {
	cases := []struct {
		method    string
		req, resp proto.Message
	}{
		{platformv1.KeyManagementService_DeleteKey_FullMethodName, &platformv1.DeleteKeyRequest{}, &platformv1.DeleteKeyResponse{}},
		{platformv1.KeyManagementService_Encrypt_FullMethodName, &platformv1.EncryptRequest{}, &platformv1.EncryptResponse{}},
	}
	for _, tc := range cases {
		a, captured := kmsAdapter(t, `{}`)
		err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: code = %v, want InvalidArgument (err %v)", tc.method, status.Code(err), err)
		}
		if captured.method != "" {
			t.Fatalf("%s: request reached the server: %s %s", tc.method, captured.method, captured.path)
		}
	}
}

// TestKMSSign_UnsupportedHashRejectedBeforeTheWire: the route reads an unknown
// hash name as SHA-256, so a SHA3 request must not be sent at all.
func TestKMSSign_UnsupportedHashRejectedBeforeTheWire(t *testing.T) {
	a, captured := kmsAdapter(t, `{}`)
	req := &platformv1.SignRequest{KeyId: "kek", Message: []byte("m"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Sign_FullMethodName,
		req, &platformv1.SignResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
	}
	if captured.method != "" {
		t.Fatalf("request reached the server: %s %s", captured.method, captured.path)
	}
}

// TestKMSSign_UnspecifiedHashLeavesServerDefault: no hash means no "hash" key,
// so the server's SHA-256 default applies.
func TestKMSSign_UnspecifiedHashLeavesServerDefault(t *testing.T) {
	body, err := encodeKMSSign(&platformv1.SignRequest{Message: []byte("m")})
	if err != nil {
		t.Fatalf("encodeKMSSign: %v", err)
	}
	if _, has := body["hash"]; has {
		t.Fatalf("body carries a hash: %v", body)
	}
}

func TestPutKMSHash_RefusesEveryUnmappedAlgorithm(t *testing.T) {
	for value := range platformv1.HashAlgorithm_name {
		alg := platformv1.HashAlgorithm(value)
		err := putKMSHash(map[string]interface{}{}, alg)
		_, mapped := kmsHashNames[alg]
		var unsupported ErrHashAlgorithmNotSupported
		switch {
		case alg == platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED || mapped:
			if err != nil {
				t.Errorf("%s: unexpected error %v", alg, err)
			}
		case !errors.As(err, &unsupported):
			t.Errorf("%s: err = %v, want ErrHashAlgorithmNotSupported", alg, err)
		}
	}
}

// TestKMSReplies_VersionLandsInKeyVersion: Encrypt and Sign replies name the
// key version "version"; the proto calls it key_version.
func TestKMSReplies_VersionLandsInKeyVersion(t *testing.T) {
	t.Run("Encrypt", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"key_id":"kek","version":7,"ciphertext":"`+b64("c")+`"}`)
		resp := &platformv1.EncryptResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Encrypt_FullMethodName,
			&platformv1.EncryptRequest{KeyId: "kek", Plaintext: []byte("p")}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetKeyId() != "kek" || resp.GetKeyVersion() != 7 || string(resp.GetCiphertext()) != "c" {
			t.Fatalf("reply = %v", resp)
		}
	})
	t.Run("Sign", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"key_id":"kek","version":3,"signature":"`+b64("s")+`"}`)
		resp := &platformv1.SignResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Sign_FullMethodName,
			&platformv1.SignRequest{KeyId: "kek", Message: []byte("m")}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetKeyId() != "kek" || resp.GetKeyVersion() != 3 || string(resp.GetSignature()) != "s" {
			t.Fatalf("reply = %v", resp)
		}
	})
}

func TestKMSReplies_MalformedPayloadRejected(t *testing.T) {
	for _, decode := range []func([]byte) error{
		func(raw []byte) error { _, err := decodeKMSEncrypt(raw); return err },
		func(raw []byte) error { _, err := decodeKMSSign(raw); return err },
	} {
		var unmarshal ErrUnmarshalFailed
		if err := decode([]byte(`{"version":"seven"}`)); !errors.As(err, &unmarshal) {
			t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
		}
	}
}
