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
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// roundTripCrypto answers the crypto calls the round trip makes: Sign through
// fakeCryptoClient, data keys through fakeDataKeyCrypto, Encrypt here.
type roundTripCrypto struct {
	fakeCryptoClient
	dataKeys   fakeDataKeyCrypto
	encryptReq *cryptoclient.EncryptRequest
}

func (f *roundTripCrypto) Encrypt(_ context.Context, req *cryptoclient.EncryptRequest) (*cryptoclient.EncryptResponse, error) {
	f.encryptReq = req
	return &cryptoclient.EncryptResponse{Ciphertext: []byte("sealed"), KeyVersion: 5}, nil
}

func (f *roundTripCrypto) GenerateDataKey(ctx context.Context, req *cryptoclient.GenerateDataKeyRequest) (*cryptoclient.GenerateDataKeyResponse, error) {
	return f.dataKeys.GenerateDataKey(ctx, req)
}

func (f *roundTripCrypto) GenerateWrappedDataKey(ctx context.Context, req *cryptoclient.GenerateWrappedDataKeyRequest) (*cryptoclient.GenerateWrappedDataKeyResponse, error) {
	return f.dataKeys.GenerateWrappedDataKey(ctx, req)
}

// generatingKMS records the key it is asked to generate.
type generatingKMS struct {
	kmsclient.Client
	req *kmsclient.GenerateKeyRequest
}

func (f *generatingKMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.req = req
	return &kmsclient.GenerateKeyResponse{KeyID: req.Name, Version: 1, Algorithm: req.Algorithm,
		Exportable: req.Exportable, DeletionProtection: req.DeletionProtection}, nil
}

// rotatingKMS rotates the one key it knows and reports every other as missing.
type rotatingKMS struct {
	kmsclient.Client
}

func (rotatingKMS) RotateKey(_ context.Context, keyID string) (*kmsclient.RotateKeyResponse, error) {
	if keyID != "kek" {
		return nil, errKeyNotFound
	}
	return &kmsclient.RotateKeyResponse{KeyID: keyID, NewVersion: 2}, nil
}

var errKeyNotFound = errors.New("key not found")

// kmsOverSDK serves the real KMS router under /api/v1 and returns an SDK KMS
// client connected to it over the REST transport.
func kmsOverSDK(t *testing.T, kms kmsclient.Client, crypto cryptoclient.Client) platformv1.KeyManagementServiceClient {
	t.Helper()
	logger := logging.DefaultLogger()
	root := mux.NewRouter()
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewKMSRouter(logger, kms, crypto, nil, nil, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(trust)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return platformv1.NewKeyManagementServiceClient(adapter.Connection())
}

func TestSDKRoundTrip_Encrypt(t *testing.T) {
	crypto := &roundTripCrypto{}
	client := kmsOverSDK(t, nil, crypto)

	resp, err := client.Encrypt(context.Background(),
		&platformv1.EncryptRequest{KeyId: "kek", Plaintext: []byte("secret"), Context: []byte("aad")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if crypto.encryptReq.KeyID != "kek" || string(crypto.encryptReq.Plaintext) != "secret" || string(crypto.encryptReq.Context) != "aad" {
		t.Fatalf("service request = %+v", crypto.encryptReq)
	}
	if resp.GetKeyId() != "kek" || resp.GetKeyVersion() != 5 || string(resp.GetCiphertext()) != "sealed" {
		t.Fatalf("reply = %v", resp)
	}
}

func TestSDKRoundTrip_Sign(t *testing.T) {
	crypto := &roundTripCrypto{}
	client := kmsOverSDK(t, nil, crypto)

	resp, err := client.Sign(context.Background(), &platformv1.SignRequest{KeyId: "kek", Message: []byte("msg"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, PreHashed: true})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got := crypto.signReq
	if got.KeyID != "kek" || string(got.Data) != "msg" || got.HashAlg != cryptoclient.HashSHA384 || !got.PreHashed {
		t.Fatalf("service request = %+v", got)
	}
	if resp.GetKeyId() != "kek" || resp.GetKeyVersion() != 1 || string(resp.GetSignature()) != "sig" {
		t.Fatalf("reply = %v", resp)
	}
}

func TestSDKRoundTrip_RotateKey(t *testing.T) {
	client := kmsOverSDK(t, rotatingKMS{}, nil)

	resp, err := client.RotateKey(context.Background(), &platformv1.RotateKeyRequest{KeyId: "kek"})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if resp.GetKeyId() != "kek" || resp.GetNewVersion() != 2 {
		t.Fatalf("reply = %v", resp)
	}
}

// TestSDKRoundTrip_RotateUnknownKeyIsNotFound: the route's 404 reaches the
// SDK caller as NotFound, not as a transport failure.
func TestSDKRoundTrip_RotateUnknownKeyIsNotFound(t *testing.T) {
	client := kmsOverSDK(t, rotatingKMS{}, nil)

	_, err := client.RotateKey(context.Background(), &platformv1.RotateKeyRequest{KeyId: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err %v)", status.Code(err), err)
	}
}

func TestSDKRoundTrip_GenerateDataKey(t *testing.T) {
	crypto := &roundTripCrypto{}
	client := kmsOverSDK(t, nil, crypto)

	resp, err := client.GenerateDataKey(context.Background(),
		&platformv1.GenerateDataKeyRequest{KeyId: "kek", KeySize: 256, Context: []byte("aad")})
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	got := crypto.dataKeys.dataKeyReq
	if got.KeyID != "kek" || got.KeySize != 256 || string(got.Context) != "aad" {
		t.Fatalf("service request = %+v", got)
	}
	if resp.GetKeyId() != "kek" || string(resp.GetPlaintextKey()) != "plaintext-dek" || string(resp.GetEncryptedKey()) != "wrapped-dek" {
		t.Fatalf("reply = %v", resp)
	}
}

// TestSDKRoundTrip_GenerateDataKeyWithoutKeyIsRefused: the route's 400 reaches
// the SDK caller as InvalidArgument and nothing is minted.
func TestSDKRoundTrip_GenerateDataKeyWithoutKeyIsRefused(t *testing.T) {
	crypto := &roundTripCrypto{}
	client := kmsOverSDK(t, nil, crypto)

	_, err := client.GenerateDataKey(context.Background(), &platformv1.GenerateDataKeyRequest{KeySize: 256})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
	}
	if crypto.dataKeys.dataKeyReq != nil {
		t.Fatal("request without a key reached the crypto service")
	}
}

// TestSDKRoundTrip_DataKeyAlgorithm: the SDK sends the data-key algorithm as a
// name the route decodes. Named and absent algorithms mint a key — the CLI
// default (AES-256, 256 bits) among them — and an algorithm that is not a
// data-key cipher is refused as InvalidArgument with nothing minted.
func TestSDKRoundTrip_DataKeyAlgorithm(t *testing.T) {
	aes256 := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256
	chacha := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305
	rsa := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048
	cases := []struct {
		name      string
		algorithm platformv1.KMSKeyAlgorithm
		keySize   int32
		wantCode  codes.Code
	}{
		{name: "CLIDefault", algorithm: aes256, keySize: 256, wantCode: codes.OK},
		{name: "NamedWithoutSize", algorithm: chacha, wantCode: codes.OK},
		{name: "None", wantCode: codes.OK},
		{name: "NotADataKeyCipher", algorithm: rsa, wantCode: codes.InvalidArgument},
	}

	for _, tc := range cases {
		t.Run("Plain/"+tc.name, func(t *testing.T) {
			crypto := &roundTripCrypto{}
			client := kmsOverSDK(t, nil, crypto)
			resp, err := client.GenerateDataKey(context.Background(), &platformv1.GenerateDataKeyRequest{
				KeyId: "kek", Algorithm: tc.algorithm, KeySize: tc.keySize})
			assertDataKeyOutcome(t, err, tc.wantCode, crypto.dataKeys.dataKeyReq != nil)
			if tc.wantCode == codes.OK && string(resp.GetEncryptedKey()) != "wrapped-dek" {
				t.Fatalf("reply = %v", resp)
			}
		})
		t.Run("Wrapped/"+tc.name, func(t *testing.T) {
			crypto := &roundTripCrypto{}
			client := kmsOverSDK(t, nil, crypto)
			resp, err := client.GenerateWrappedDataKey(context.Background(), &platformv1.GenerateWrappedDataKeyRequest{
				WrappingKeyId: "kek", KeyAlgorithm: tc.algorithm, KeySize: tc.keySize})
			assertDataKeyOutcome(t, err, tc.wantCode, crypto.dataKeys.wrappedReq != nil)
			if tc.wantCode == codes.OK && (resp.GetWrappingKeyId() != "kek" || string(resp.GetWrappedKey()) != "wrapped-dek") {
				t.Fatalf("reply = %v", resp)
			}
		})
	}
}

// assertDataKeyOutcome checks the call's status code and that a key was
// minted exactly when the call succeeded.
func assertDataKeyOutcome(t *testing.T, err error, wantCode codes.Code, minted bool) {
	t.Helper()
	if status.Code(err) != wantCode {
		t.Fatalf("code = %v, want %v (err %v)", status.Code(err), wantCode, err)
	}
	if minted != (wantCode == codes.OK) {
		t.Fatalf("minted = %v with code %v", minted, wantCode)
	}
}

// TestSDKRoundTrip_GenerateKey: the key spec's algorithm and usages reach the
// KMS service, and the reply's key handle reaches the SDK caller.
func TestSDKRoundTrip_GenerateKey(t *testing.T) {
	kms := &generatingKMS{}
	client := kmsOverSDK(t, kms, nil)

	resp, err := client.GenerateKey(context.Background(), &platformv1.GenerateKeyRequest{
		Name: "kek",
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm:  platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
			Usage:      []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_SIGN, platformv1.KeyUsage_KEY_USAGE_VERIFY},
			Exportable: true,
		},
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	got := kms.req
	wantUsage := []kmsclient.KeyUsage{kmsclient.KeyUsageSign, kmsclient.KeyUsageVerify}
	if got.Name != "kek" || got.Algorithm != kmsclient.AlgorithmECDSAP384 || !got.Exportable ||
		!reflect.DeepEqual(got.Usage, wantUsage) {
		t.Fatalf("service request = %+v", got)
	}
	key := resp.GetKey()
	if key.GetKeyId() != "kek" || key.GetVersion() != 1 ||
		key.GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384 || !resp.GetMetadata().GetExportable() {
		t.Fatalf("reply = %v", resp)
	}
}

// TestSDKRoundTrip_GenerateKeyAlgorithmTheRouteDoesNotMint: the SDK refuses an
// algorithm the route cannot generate before anything reaches the service.
func TestSDKRoundTrip_GenerateKeyAlgorithmTheRouteDoesNotMint(t *testing.T) {
	kms := &generatingKMS{}
	client := kmsOverSDK(t, kms, nil)

	_, err := client.GenerateKey(context.Background(), &platformv1.GenerateKeyRequest{
		Name:    "kek",
		KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM3},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
	}
	if kms.req != nil {
		t.Fatal("refused request reached the KMS service")
	}
}
