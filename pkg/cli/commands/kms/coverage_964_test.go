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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// errBackend964 is the failure the in-process KMS answers with when told to fail.
var errBackend964 = status.Error(codes.Unavailable, "kms backend down")

// errFactory964 is the error a test client factory returns.
var errFactory964 = errors.New("no kms client")

// fakeKMSServer964 is platformd's KeyManagementService in process: each RPC
// answers with its canned response, or with fail when fail is set.
type fakeKMSServer964 struct {
	platformv1.UnimplementedKeyManagementServiceServer

	fail   error
	signer *secureboottest.KMS

	encrypt      *platformv1.EncryptResponse
	decrypt      *platformv1.DecryptResponse
	sign         *platformv1.SignResponse
	verify       *platformv1.VerifyResponse
	hash         *platformv1.HashResponse
	hmac         *platformv1.HMACResponse
	verifyHMAC   *platformv1.VerifyHMACResponse
	random       *platformv1.GenerateRandomResponse
	dataKey      *platformv1.GenerateDataKeyResponse
	wrappedKey   *platformv1.GenerateWrappedDataKeyResponse
	rewrap       *platformv1.RewrapResponse
	batchEncrypt *platformv1.BatchEncryptResponse
	batchDecrypt *platformv1.BatchDecryptResponse
	generateKey  *platformv1.GenerateKeyResponse
	getKey       *platformv1.GetKeyResponse
	listKeys     *platformv1.ListKeysResponse
	deleteKey    *platformv1.DeleteKeyResponse
	rotateKey    *platformv1.RotateKeyResponse
	keyVersions  *platformv1.GetKeyVersionsResponse

	gotBatchEncrypt atomic.Pointer[platformv1.BatchEncryptRequest]
	gotBatchDecrypt atomic.Pointer[platformv1.BatchDecryptRequest]
	gotDecrypt      atomic.Pointer[platformv1.DecryptRequest]
}

// answer964 returns resp, or fail when it is set.
func answer964[T any](fail error, resp T) (T, error) {
	if fail != nil {
		var zero T
		return zero, fail
	}
	return resp, nil
}

func (s *fakeKMSServer964) Encrypt(_ context.Context, _ *platformv1.EncryptRequest) (*platformv1.EncryptResponse, error) {
	return answer964(s.fail, s.encrypt)
}

func (s *fakeKMSServer964) Decrypt(_ context.Context, req *platformv1.DecryptRequest) (*platformv1.DecryptResponse, error) {
	s.gotDecrypt.Store(req)
	return answer964(s.fail, s.decrypt)
}

func (s *fakeKMSServer964) Sign(ctx context.Context, req *platformv1.SignRequest) (*platformv1.SignResponse, error) {
	if s.signer != nil {
		return s.signer.Sign(ctx, req)
	}
	return answer964(s.fail, s.sign)
}

func (s *fakeKMSServer964) Verify(_ context.Context, _ *platformv1.VerifyRequest) (*platformv1.VerifyResponse, error) {
	return answer964(s.fail, s.verify)
}

func (s *fakeKMSServer964) Hash(_ context.Context, _ *platformv1.HashRequest) (*platformv1.HashResponse, error) {
	return answer964(s.fail, s.hash)
}

func (s *fakeKMSServer964) HMAC(_ context.Context, _ *platformv1.HMACRequest) (*platformv1.HMACResponse, error) {
	return answer964(s.fail, s.hmac)
}

func (s *fakeKMSServer964) VerifyHMAC(_ context.Context, _ *platformv1.VerifyHMACRequest) (*platformv1.VerifyHMACResponse, error) {
	return answer964(s.fail, s.verifyHMAC)
}

func (s *fakeKMSServer964) GenerateRandom(_ context.Context, _ *platformv1.GenerateRandomRequest) (*platformv1.GenerateRandomResponse, error) {
	return answer964(s.fail, s.random)
}

func (s *fakeKMSServer964) GenerateDataKey(_ context.Context, _ *platformv1.GenerateDataKeyRequest) (*platformv1.GenerateDataKeyResponse, error) {
	return answer964(s.fail, s.dataKey)
}

func (s *fakeKMSServer964) GenerateWrappedDataKey(_ context.Context, _ *platformv1.GenerateWrappedDataKeyRequest) (*platformv1.GenerateWrappedDataKeyResponse, error) {
	return answer964(s.fail, s.wrappedKey)
}

func (s *fakeKMSServer964) Rewrap(_ context.Context, _ *platformv1.RewrapRequest) (*platformv1.RewrapResponse, error) {
	return answer964(s.fail, s.rewrap)
}

func (s *fakeKMSServer964) BatchEncrypt(_ context.Context, req *platformv1.BatchEncryptRequest) (*platformv1.BatchEncryptResponse, error) {
	s.gotBatchEncrypt.Store(req)
	return answer964(s.fail, s.batchEncrypt)
}

func (s *fakeKMSServer964) BatchDecrypt(_ context.Context, req *platformv1.BatchDecryptRequest) (*platformv1.BatchDecryptResponse, error) {
	s.gotBatchDecrypt.Store(req)
	return answer964(s.fail, s.batchDecrypt)
}

func (s *fakeKMSServer964) GenerateKey(_ context.Context, _ *platformv1.GenerateKeyRequest) (*platformv1.GenerateKeyResponse, error) {
	return answer964(s.fail, s.generateKey)
}

func (s *fakeKMSServer964) GetKey(_ context.Context, _ *platformv1.GetKeyRequest) (*platformv1.GetKeyResponse, error) {
	return answer964(s.fail, s.getKey)
}

func (s *fakeKMSServer964) ListKeys(_ context.Context, _ *platformv1.ListKeysRequest) (*platformv1.ListKeysResponse, error) {
	return answer964(s.fail, s.listKeys)
}

func (s *fakeKMSServer964) DeleteKey(_ context.Context, _ *platformv1.DeleteKeyRequest) (*platformv1.DeleteKeyResponse, error) {
	return answer964(s.fail, s.deleteKey)
}

func (s *fakeKMSServer964) RotateKey(_ context.Context, _ *platformv1.RotateKeyRequest) (*platformv1.RotateKeyResponse, error) {
	return answer964(s.fail, s.rotateKey)
}

func (s *fakeKMSServer964) GetKeyVersions(_ context.Context, _ *platformv1.GetKeyVersionsRequest) (*platformv1.GetKeyVersionsResponse, error) {
	return answer964(s.fail, s.keyVersions)
}

// newFakeKMSServer964 returns a server whose every RPC has a full answer.
func newFakeKMSServer964() *fakeKMSServer964 {
	handle := &platformv1.KMSKeyHandle{
		KeyId:     "tenant-kek",
		Version:   3,
		Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		Status:    platformv1.KeyStatus_KEY_STATUS_ENABLED,
		CreatedAt: 1700000000,
	}
	metadata := &platformv1.KMSKeyMetadata{
		KeyId:              "tenant-kek",
		Name:               "Tenant KEK",
		Description:        "wraps tenant DEKs",
		Algorithm:          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		Status:             platformv1.KeyStatus_KEY_STATUS_ENABLED,
		Usage:              []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT},
		Version:            3,
		Exportable:         true,
		DeletionProtection: true,
		CreatedAt:          1700000000,
		UpdatedAt:          1700000100,
	}
	return &fakeKMSServer964{
		encrypt:    &platformv1.EncryptResponse{KeyId: "tenant-kek", KeyVersion: 3, Ciphertext: []byte("sealed"), Nonce: []byte("nonce-123456")},
		decrypt:    &platformv1.DecryptResponse{KeyId: "tenant-kek", KeyVersion: 3, Plaintext: []byte("opened")},
		sign:       &platformv1.SignResponse{KeyId: "signing-key", KeyVersion: 1, Signature: []byte("sig-bytes"), HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256},
		verify:     &platformv1.VerifyResponse{KeyId: "signing-key", KeyVersion: 1, Valid: true},
		hash:       &platformv1.HashResponse{Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256, Hash: []byte{0xde, 0xad, 0xbe, 0xef}},
		hmac:       &platformv1.HMACResponse{KeyId: "mac-key", KeyVersion: 2, Hmac: []byte("mac-bytes"), HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256},
		verifyHMAC: &platformv1.VerifyHMACResponse{KeyId: "mac-key", KeyVersion: 2, Valid: true},
		random:     &platformv1.GenerateRandomResponse{RandomBytes: []byte{0x01, 0x02, 0x03, 0x04}},
		dataKey:    &platformv1.GenerateDataKeyResponse{KeyId: "tenant-kek", PlaintextKey: []byte("plain-dek"), EncryptedKey: []byte("wrapped-dek")},
		wrappedKey: &platformv1.GenerateWrappedDataKeyResponse{WrappingKeyId: "tenant-kek", WrappedKey: []byte("wrapped-only")},
		rewrap:     &platformv1.RewrapResponse{KeyId: "tenant-kek", SourceVersion: 2, TargetVersion: 3, Ciphertext: []byte("resealed"), Nonce: []byte("nonce-2")},
		batchEncrypt: &platformv1.BatchEncryptResponse{
			KeyId: "tenant-kek",
			Results: []*platformv1.BatchEncryptResultItem{
				{ItemId: "item-0", Status: &platformv1.Status{Success: true}, Ciphertext: bytes.Repeat([]byte("c"), 40), Nonce: bytes.Repeat([]byte("n"), 30), KeyVersion: 3},
				{ItemId: "second", Status: &platformv1.Status{Success: false, Message: "quota exceeded"}},
			},
			SuccessCount: 1,
			FailureCount: 1,
		},
		batchDecrypt: &platformv1.BatchDecryptResponse{
			KeyId: "tenant-kek",
			Results: []*platformv1.BatchDecryptResultItem{
				{ItemId: "item-0", Status: &platformv1.Status{Success: true}, Plaintext: []byte("hello"), KeyVersion: 3},
				{ItemId: "second", Status: &platformv1.Status{Success: false, Message: "bad tag"}},
			},
			SuccessCount: 1,
			FailureCount: 1,
		},
		generateKey: &platformv1.GenerateKeyResponse{Key: handle, Metadata: metadata},
		getKey:      &platformv1.GetKeyResponse{Key: handle, Metadata: metadata},
		listKeys:    &platformv1.ListKeysResponse{Keys: []*platformv1.KMSKeyHandle{handle}, NextCursor: "page-2", HasMore: true, TotalCount: 7},
		deleteKey:   &platformv1.DeleteKeyResponse{KeyId: "tenant-kek", KeyStatus: platformv1.KeyStatus_KEY_STATUS_ENABLED, DeletionDate: 1700086400},
		rotateKey:   &platformv1.RotateKeyResponse{KeyId: "tenant-kek", OldVersion: 3, NewVersion: 4},
		keyVersions: &platformv1.GetKeyVersionsResponse{
			KeyId:    "tenant-kek",
			Versions: []*platformv1.KMSKeyVersionInfo{{Version: 3, Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, Status: platformv1.KeyStatus_KEY_STATUS_ENABLED}},
		},
	}
}

// startKMSServer964 serves srv on a unix socket in a temp dir and returns the
// CLI flags that reach it in format.
func startKMSServer964(t *testing.T, srv *fakeKMSServer964) func(cli.OutputFormat) *cli.CommonFlags {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterKeyManagementServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped.
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})

	return func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
}

// capture964 runs fn with os.Stdout redirected and returns what it wrote.
func capture964(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w

	var buf bytes.Buffer
	copied := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(&buf, r)
		copied <- copyErr
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	require.NoError(t, <-copied)
	require.NoError(t, r.Close())
	return buf.String(), runErr
}

// json964 decodes the JSON the CLI printed.
func json964(t *testing.T, out string) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &v), "output: %q", out)
	return v
}

// inputFile964 writes data to a temp file and returns its path.
func inputFile964(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	return path
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// requireCryptoFailed964 asserts err is the typed failure of operation and
// carries the backend's gRPC status.
func requireCryptoFailed964(t *testing.T, err error, operation string) {
	t.Helper()
	var opErr ErrCryptoOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, operation, opErr.Operation)
	assert.Equal(t, codes.Unavailable, status.Code(opErr.Err))
}

func TestCryptoRun964_JSONCarriesTheBackendAnswer(t *testing.T) {
	srv := newFakeKMSServer964()
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, "payload")

	cases := []struct {
		name string
		run  func(*cli.CommonFlags) error
		want map[string]any
	}{
		{"encrypt", func(f *cli.CommonFlags) error {
			return runCryptoEncrypt(f, &encryptFlags{keyID: "tenant-kek", inputPath: in, context: "aad", nonce: b64("nonce")})
		}, map[string]any{"key_id": "tenant-kek", "key_version": float64(3), "ciphertext": b64("sealed"), "nonce": b64("nonce-123456")}},
		{"decrypt", func(f *cli.CommonFlags) error {
			return runCryptoDecrypt(f, &decryptFlags{keyID: "tenant-kek", inputPath: in, context: "aad", nonce: b64("nonce"), keyVersion: 3})
		}, map[string]any{"key_id": "tenant-kek", "plaintext": "opened"}},
		{"sign", func(f *cli.CommonFlags) error {
			return runCryptoSign(f, &signFlags{keyID: "signing-key", inputPath: in, hashAlgorithm: "sha256"})
		}, map[string]any{"key_id": "signing-key", "signature": b64("sig-bytes")}},
		{"hash", func(f *cli.CommonFlags) error {
			return runCryptoHash(f, &hashFlags{inputPath: in, algorithm: "sha256", format: "hex"})
		}, map[string]any{"algorithm": "SHA-256", "hash": "deadbeef", "format": "hex", "size_bytes": float64(4)}},
		{"hmac", func(f *cli.CommonFlags) error {
			return runHMACGenerate(f, &hmacGenerateFlags{keyID: "mac-key", inputPath: in, hashAlgorithm: "sha256"})
		}, map[string]any{"key_id": "mac-key", "hmac": b64("mac-bytes")}},
		{"random", func(f *cli.CommonFlags) error {
			return runCryptoRandom(f, &randomFlags{numBytes: 4, format: "hex"})
		}, map[string]any{"random_bytes": "01020304", "num_bytes": float64(4), "format": "hex"}},
		{"data key", func(f *cli.CommonFlags) error {
			return runGenerateDataKey(f, &dataKeyFlags{keyID: "tenant-kek", algorithm: "aes-256", keySize: 32, context: "aad"})
		}, map[string]any{"key_id": "tenant-kek", "plaintext_key": b64("plain-dek"), "encrypted_key": b64("wrapped-dek")}},
		{"wrapped data key", func(f *cli.CommonFlags) error {
			return runGenerateWrappedDataKey(f, &dataKeyFlags{keyID: "tenant-kek", algorithm: "aes-256", keySize: 32, context: "aad"})
		}, map[string]any{"wrapping_key_id": "tenant-kek", "wrapped_key": b64("wrapped-only")}},
		{"rewrap", func(f *cli.CommonFlags) error {
			return runCryptoRewrap(f, &rewrapFlags{keyID: "tenant-kek", inputPath: in, context: "aad", nonce: b64("nonce"), sourceVersion: 2})
		}, map[string]any{"source_version": float64(2), "target_version": float64(3), "ciphertext": b64("resealed"), "nonce": b64("nonce-2")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := capture964(t, func() error { return tc.run(flags(cli.OutputFormatJSON)) })
			require.NoError(t, err)
			got := json964(t, out)
			for k, v := range tc.want {
				assert.Equal(t, v, got[k], "field %s", k)
			}
		})
	}
}

func TestCryptoRun964_BackendFailureIsTyped(t *testing.T) {
	srv := newFakeKMSServer964()
	srv.fail = errBackend964
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, "payload")
	f := flags(cli.OutputFormatJSON)

	cases := []struct {
		operation string
		run       func() error
	}{
		{"encrypt", func() error { return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: in}) }},
		{"decrypt", func() error { return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: in}) }},
		{"sign", func() error { return runCryptoSign(f, &signFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"}) }},
		{"verify", func() error {
			return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, signature: b64("sig"), hashAlgorithm: "sha256"})
		}},
		{"hash", func() error { return runCryptoHash(f, &hashFlags{inputPath: in, algorithm: "sha256"}) }},
		{"generate HMAC", func() error {
			return runHMACGenerate(f, &hmacGenerateFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"})
		}},
		{"verify HMAC", func() error {
			return runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: in, hmac: b64("mac"), hashAlgorithm: "sha256"})
		}},
		{"generate random", func() error { return runCryptoRandom(f, &randomFlags{numBytes: 8}) }},
		{"generate data key", func() error { return runGenerateDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"}) }},
		{"generate wrapped data key", func() error {
			return runGenerateWrappedDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"})
		}},
		{"rewrap", func() error { return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: in}) }},
	}
	for _, tc := range cases {
		t.Run(tc.operation, func(t *testing.T) {
			_, err := capture964(t, tc.run)
			requireCryptoFailed964(t, err, tc.operation)
		})
	}
}

func TestCryptoRun964_RejectsBadInputBeforeTheRPC(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	in := inputFile964(t, "payload")
	notBase64 := inputFile964(t, "%%%not base64%%%")
	missing := filepath.Join(t.TempDir(), "missing")
	f := flags(cli.OutputFormatJSON)

	t.Run("bad base64 fields", func(t *testing.T) {
		cases := []struct {
			field string
			run   func() error
		}{
			{"nonce", func() error { return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: in, nonce: "%%"}) }},
			{"nonce", func() error { return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: in, nonce: "%%"}) }},
			{"input", func() error {
				return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: notBase64, base64In: true})
			}},
			{"nonce", func() error { return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: in, nonce: "%%"}) }},
			{"input", func() error {
				return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: notBase64, base64In: true})
			}},
			{"signature", func() error {
				return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, signature: "%%", hashAlgorithm: "sha256"})
			}},
			{"hmac", func() error {
				return runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: in, hmac: "%%", hashAlgorithm: "sha256"})
			}},
		}
		for _, tc := range cases {
			err := tc.run()
			var b64Err ErrInvalidBase64
			require.ErrorAs(t, err, &b64Err)
			assert.Equal(t, tc.field, b64Err.Field)
		}
	})

	t.Run("unreadable input file", func(t *testing.T) {
		runs := []func() error{
			func() error { return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: missing}) },
			func() error { return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: missing}) },
			func() error { return runCryptoSign(f, &signFlags{keyID: "k", inputPath: missing}) },
			func() error { return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: missing}) },
			func() error { return runCryptoHash(f, &hashFlags{inputPath: missing}) },
			func() error { return runHMACGenerate(f, &hmacGenerateFlags{keyID: "k", inputPath: missing}) },
			func() error { return runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: missing}) },
			func() error { return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: missing}) },
		}
		for _, run := range runs {
			var inErr ErrInvalidInputFile
			require.ErrorAs(t, run(), &inErr)
			assert.Equal(t, missing, inErr.Path)
		}
	})

	t.Run("bad hash algorithm", func(t *testing.T) {
		runs := []func() error{
			func() error { return runCryptoSign(f, &signFlags{keyID: "k", inputPath: in, hashAlgorithm: "md5"}) },
			func() error {
				return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, signature: b64("s"), hashAlgorithm: "md5"})
			},
			func() error { return runCryptoHash(f, &hashFlags{inputPath: in, algorithm: "md5"}) },
			func() error {
				return runHMACGenerate(f, &hmacGenerateFlags{keyID: "k", inputPath: in, hashAlgorithm: "md5"})
			},
			func() error {
				return runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: in, hmac: b64("m"), hashAlgorithm: "md5"})
			},
		}
		for _, run := range runs {
			var algErr ErrInvalidHashAlgorithm
			require.ErrorAs(t, run(), &algErr)
		}
	})

	t.Run("bad data key algorithm", func(t *testing.T) {
		for _, run := range []func(*cli.CommonFlags, *dataKeyFlags) error{runGenerateDataKey, runGenerateWrappedDataKey} {
			var algErr ErrInvalidAlgorithm
			require.ErrorAs(t, run(f, &dataKeyFlags{keyID: "k", algorithm: "rot13"}), &algErr)
			assert.Equal(t, "rot13", algErr.Algorithm)
		}
	})

	t.Run("no signature or hmac", func(t *testing.T) {
		require.ErrorAs(t, runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"}), new(ErrSignatureRequired))
		require.ErrorAs(t, runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"}), new(ErrHMACRequired))
	})

	t.Run("signature and hmac read from files", func(t *testing.T) {
		sigPath := inputFile964(t, "sig")
		_, err := capture964(t, func() error {
			return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, signaturePath: sigPath, hashAlgorithm: "sha256"})
		})
		require.NoError(t, err)
		_, err = capture964(t, func() error {
			return runHMACVerify(f, &hmacVerifyFlags{keyID: "k", inputPath: in, hmacPath: sigPath, hashAlgorithm: "sha256"})
		})
		require.NoError(t, err)
	})

	t.Run("non-positive random byte count", func(t *testing.T) {
		var countErr ErrInvalidByteCount
		require.ErrorAs(t, runCryptoRandom(f, &randomFlags{numBytes: 0}), &countErr)
		assert.Equal(t, int32(0), countErr.Count)
	})
}

func TestCryptoRun964_VerifyReportsAnInvalidVerdict(t *testing.T) {
	srv := newFakeKMSServer964()
	srv.verify = &platformv1.VerifyResponse{KeyId: "signing-key", KeyVersion: 1, Valid: false}
	srv.verifyHMAC = &platformv1.VerifyHMACResponse{KeyId: "mac-key", KeyVersion: 2, Valid: false}
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, "payload")
	f := flags(cli.OutputFormatJSON)

	out, err := capture964(t, func() error {
		return runCryptoVerify(f, &verifyFlags{keyID: "signing-key", inputPath: in, signature: b64("sig"), hashAlgorithm: "sha256", keyVersion: 1})
	})
	var failed ErrVerificationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, ErrVerificationFailed{Operation: "Signature", KeyID: "signing-key", KeyVersion: 1}, failed)
	assert.Equal(t, false, json964(t, out)["valid"])

	_, err = capture964(t, func() error {
		return runHMACVerify(f, &hmacVerifyFlags{keyID: "mac-key", inputPath: in, hmac: b64("mac"), hashAlgorithm: "sha256", keyVersion: 2})
	})
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, ErrVerificationFailed{Operation: "HMAC", KeyID: "mac-key", KeyVersion: 2}, failed)
}

func TestCryptoRun964_TableWritesTheOutputFile(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	in := inputFile964(t, "payload")
	f := flags(cli.OutputFormatTable)
	dir := t.TempDir()

	cases := []struct {
		name   string
		run    func(out string) error
		want   string
		banner string
	}{
		{"encrypt base64", func(out string) error {
			return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: in, outputPath: out, base64Out: true})
		}, b64("sealed"), "Data encrypted successfully"},
		{"decrypt", func(out string) error {
			return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: in, outputPath: out})
		}, "opened", "Data decrypted successfully"},
		{"sign", func(out string) error {
			return runCryptoSign(f, &signFlags{keyID: "k", inputPath: in, outputPath: out, hashAlgorithm: "sha256"})
		}, "sig-bytes", "Message signed successfully"},
		{"hash base64", func(out string) error {
			return runCryptoHash(f, &hashFlags{inputPath: in, outputPath: out, algorithm: "sha256", format: "base64"})
		}, base64.StdEncoding.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef}), "Hash computed"},
		{"hmac", func(out string) error {
			return runHMACGenerate(f, &hmacGenerateFlags{keyID: "k", inputPath: in, outputPath: out, hashAlgorithm: "sha256"})
		}, "mac-bytes", "HMAC"},
		{"random raw", func(out string) error {
			return runCryptoRandom(f, &randomFlags{numBytes: 4, outputPath: out, format: "raw"})
		}, "\x01\x02\x03\x04", "random"},
		{"data key", func(out string) error {
			return runGenerateDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256", outputPath: out})
		}, b64("wrapped-dek"), "Encrypted Key File"},
		{"wrapped data key", func(out string) error {
			return runGenerateWrappedDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256", outputPath: out})
		}, b64("wrapped-only"), "Wrapped data encryption key generated"},
		{"rewrap", func(out string) error {
			return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: in, outputPath: out})
		}, "resealed", "rewrapped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(dir, tc.name)
			stdout, err := capture964(t, func() error { return tc.run(outPath) })
			require.NoError(t, err)
			written, err := os.ReadFile(outPath)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(written))
			assert.Contains(t, stdout, tc.banner)
		})
	}
}

func TestCryptoRun964_TableWritesToStdout(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	in := inputFile964(t, "payload")
	f := flags(cli.OutputFormatTable)

	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{"encrypt raw", func() error { return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: in}) }, "sealed"},
		{"decrypt raw", func() error { return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: in}) }, "opened"},
		{"hash hex", func() error { return runCryptoHash(f, &hashFlags{inputPath: in, algorithm: "sha256", format: "hex"}) }, "deadbeef\n"},
		{"random hex", func() error { return runCryptoRandom(f, &randomFlags{numBytes: 4, format: "hex"}) }, "01020304\n"},
		{"random base64", func() error { return runCryptoRandom(f, &randomFlags{numBytes: 4, format: "base64"}) }, base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})},
		{"wrapped data key", func() error {
			return runGenerateWrappedDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"})
		}, b64("wrapped-only")},
		{"data key", func() error {
			return runGenerateDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"})
		}, "Data encryption key generated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := capture964(t, tc.run)
			require.NoError(t, err)
			assert.Contains(t, out, tc.want)
		})
	}
}

func TestCryptoRun964_DecryptSendsTheDecodedCiphertext(t *testing.T) {
	srv := newFakeKMSServer964()
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, b64("ciphertext"))

	_, err := capture964(t, func() error {
		return runCryptoDecrypt(flags(cli.OutputFormatJSON), &decryptFlags{keyID: "tenant-kek", inputPath: in, base64In: true, keyVersion: 3})
	})
	require.NoError(t, err)
	got := srv.gotDecrypt.Load()
	require.NotNil(t, got)
	assert.Equal(t, []byte("ciphertext"), got.GetCiphertext())
	assert.Equal(t, uint64(3), got.GetKeyVersion())
}

func TestCryptoRun964_RejectsAnUnknownOutputFormat(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	in := inputFile964(t, "payload")
	batchIn := inputFile964(t, `[{"plaintext":"a","ciphertext":"`+b64("c")+`"}]`)
	f := flags(cli.OutputFormat("xml"))

	runs := map[string]func() error{
		"encrypt": func() error { return runCryptoEncrypt(f, &encryptFlags{keyID: "k", inputPath: in}) },
		"decrypt": func() error { return runCryptoDecrypt(f, &decryptFlags{keyID: "k", inputPath: in}) },
		"sign":    func() error { return runCryptoSign(f, &signFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"}) },
		"verify": func() error {
			return runCryptoVerify(f, &verifyFlags{keyID: "k", inputPath: in, signature: b64("s"), hashAlgorithm: "sha256"})
		},
		"hash": func() error { return runCryptoHash(f, &hashFlags{inputPath: in, algorithm: "sha256"}) },
		"hmac": func() error {
			return runHMACGenerate(f, &hmacGenerateFlags{keyID: "k", inputPath: in, hashAlgorithm: "sha256"})
		},
		"random":      func() error { return runCryptoRandom(f, &randomFlags{numBytes: 4}) },
		"data key":    func() error { return runGenerateDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"}) },
		"wrapped key": func() error { return runGenerateWrappedDataKey(f, &dataKeyFlags{keyID: "k", algorithm: "aes-256"}) },
		"rewrap":      func() error { return runCryptoRewrap(f, &rewrapFlags{keyID: "k", inputPath: in}) },
		"batch encrypt": func() error {
			return runBatchEncrypt(f, &batchEncryptFlags{keyID: "k", inputPath: batchIn})
		},
		"batch decrypt": func() error {
			return runBatchDecrypt(f, &batchDecryptFlags{keyID: "k", inputPath: batchIn})
		},
		"key get":    func() error { return runKeyGet(f, "k", 0) },
		"key list":   func() error { return runKeyList(f, 10, "") },
		"key delete": func() error { return runKeyDelete(f, "k", 7, false) },
		"key rotate": func() error { return runKeyRotate(f, "k", true) },
		"key generate": func() error {
			return runKeyGenerate(f, "k", "aes-256", "encrypt", false, false, "", "", "")
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			var formatErr cli.ErrInvalidOutputFormat
			require.ErrorAs(t, run(), &formatErr)
			assert.Equal(t, "xml", formatErr.Format)
		})
	}
}

func TestBatchRun964_EncryptMapsItemsAndResults(t *testing.T) {
	srv := newFakeKMSServer964()
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, `[{"plaintext":"first","context":"aad","nonce":"`+b64("n0")+`"},{"item_id":"second","plaintext":"two"}]`)

	out, err := capture964(t, func() error {
		return runBatchEncrypt(flags(cli.OutputFormatJSON), &batchEncryptFlags{keyID: "tenant-kek", inputPath: in})
	})
	require.NoError(t, err)

	req := srv.gotBatchEncrypt.Load()
	require.NotNil(t, req)
	require.Len(t, req.GetItems(), 2)
	assert.Equal(t, "item-0", req.GetItems()[0].GetItemId(), "a missing item ID is generated from its index")
	assert.Equal(t, []byte("first"), req.GetItems()[0].GetPlaintext())
	assert.Equal(t, []byte("n0"), req.GetItems()[0].GetNonce())
	assert.Equal(t, "second", req.GetItems()[1].GetItemId())

	var got struct {
		KeyID        string                   `json:"key_id"`
		SuccessCount int32                    `json:"success_count"`
		FailureCount int32                    `json:"failure_count"`
		Results      []BatchEncryptOutputItem `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "tenant-kek", got.KeyID)
	assert.Equal(t, int32(1), got.SuccessCount)
	assert.Equal(t, int32(1), got.FailureCount)
	require.Len(t, got.Results, 2)
	assert.Equal(t, "success", got.Results[0].Status)
	assert.Equal(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("c"), 40)), got.Results[0].Ciphertext)
	assert.Equal(t, "failed", got.Results[1].Status)
	assert.Equal(t, "quota exceeded", got.Results[1].Error)

	table, err := capture964(t, func() error {
		return runBatchEncrypt(flags(cli.OutputFormatTable), &batchEncryptFlags{keyID: "tenant-kek", inputPath: in})
	})
	require.NoError(t, err)
	assert.Contains(t, table, "Batch encryption completed: 1 succeeded, 1 failed")
	assert.Contains(t, table, "failed: quota exceeded")
	assert.Contains(t, table, "...", "long ciphertexts are truncated")
}

func TestBatchRun964_DecryptMapsItemsAndResults(t *testing.T) {
	srv := newFakeKMSServer964()
	flags := startKMSServer964(t, srv)
	in := inputFile964(t, `[{"ciphertext":"`+b64("c0")+`","context":"aad","nonce":"`+b64("n0")+`","key_version":3},{"item_id":"second","ciphertext":"`+b64("c1")+`"}]`)

	out, err := capture964(t, func() error {
		return runBatchDecrypt(flags(cli.OutputFormatJSON), &batchDecryptFlags{keyID: "tenant-kek", inputPath: in})
	})
	require.NoError(t, err)

	req := srv.gotBatchDecrypt.Load()
	require.NotNil(t, req)
	require.Len(t, req.GetItems(), 2)
	assert.Equal(t, "item-0", req.GetItems()[0].GetItemId())
	assert.Equal(t, []byte("c0"), req.GetItems()[0].GetCiphertext())
	assert.Equal(t, []byte("n0"), req.GetItems()[0].GetNonce())

	var got struct {
		Results []BatchDecryptOutputItem `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Results, 2)
	assert.Equal(t, "success", got.Results[0].Status)
	assert.Equal(t, "failed", got.Results[1].Status)
	assert.Equal(t, "bad tag", got.Results[1].Error)

	table, err := capture964(t, func() error {
		return runBatchDecrypt(flags(cli.OutputFormatTable), &batchDecryptFlags{keyID: "tenant-kek", inputPath: in})
	})
	require.NoError(t, err)
	assert.Contains(t, table, "Batch decryption completed: 1 succeeded, 1 failed")
}

func TestBatchRun964_RejectsBadInput(t *testing.T) {
	srv := newFakeKMSServer964()
	srv.fail = errBackend964
	flags := startKMSServer964(t, srv)
	f := flags(cli.OutputFormatJSON)
	missing := filepath.Join(t.TempDir(), "missing")

	encrypt := func(path string) error { return runBatchEncrypt(f, &batchEncryptFlags{keyID: "k", inputPath: path}) }
	decrypt := func(path string) error { return runBatchDecrypt(f, &batchDecryptFlags{keyID: "k", inputPath: path}) }

	for name, run := range map[string]func(string) error{"encrypt": encrypt, "decrypt": decrypt} {
		t.Run(name, func(t *testing.T) {
			require.ErrorAs(t, run(missing), new(ErrBatchInputRequired))

			var formatErr ErrInvalidBatchFormat
			require.ErrorAs(t, run(inputFile964(t, "not json")), &formatErr)
			require.ErrorAs(t, run(inputFile964(t, "[]")), &formatErr)
			assert.Equal(t, "empty input array", formatErr.Reason)

			var b64Err ErrInvalidBase64
			require.ErrorAs(t, run(inputFile964(t, `[{"item_id":"x","plaintext":"p","ciphertext":"`+b64("c")+`","nonce":"%%"}]`)), &b64Err)
			assert.Equal(t, "nonce for item x", b64Err.Field)

			var opErr ErrBatchOperationFailed
			require.ErrorAs(t, run(inputFile964(t, `[{"plaintext":"p","ciphertext":"`+b64("c")+`"}]`)), &opErr)
			assert.Equal(t, name, opErr.Operation)
			assert.Equal(t, codes.Unavailable, status.Code(opErr.Err))
		})
	}

	var formatErr ErrInvalidBatchFormat
	require.ErrorAs(t, decrypt(inputFile964(t, `[{"item_id":"x"}]`)), &formatErr)
	assert.Equal(t, "missing ciphertext for item x", formatErr.Reason)

	var b64Err ErrInvalidBase64
	require.ErrorAs(t, decrypt(inputFile964(t, `[{"item_id":"x","ciphertext":"%%"}]`)), &b64Err)
	assert.Equal(t, "ciphertext for item x", b64Err.Field)
}

func TestKeyRun964_JSONCarriesTheBackendAnswer(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatJSON)

	out, err := capture964(t, func() error { return runKeyGenerate(f, "tenant-kek", "aes-256", "encrypt", true, true, "", "", "ops") })
	require.NoError(t, err)
	var generated kmssvc.GenerateKeyResult
	require.NoError(t, json.Unmarshal([]byte(out), &generated))
	require.NotNil(t, generated.Key)
	assert.Equal(t, "tenant-kek", generated.Key.KeyID)
	assert.Equal(t, uint64(3), generated.Key.Version)

	out, err = capture964(t, func() error { return runKeyGet(f, "tenant-kek", 3) })
	require.NoError(t, err)
	var got kmssvc.GetKeyResult
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.NotNil(t, got.Metadata)
	assert.Equal(t, "Tenant KEK", got.Metadata.Name)

	out, err = capture964(t, func() error { return runKeyList(f, 10, "") })
	require.NoError(t, err)
	var listed kmssvc.ListKeysResult
	require.NoError(t, json.Unmarshal([]byte(out), &listed))
	require.Len(t, listed.Keys, 1)
	assert.Equal(t, "page-2", listed.NextCursor)

	out, err = capture964(t, func() error { return runKeyDelete(f, "tenant-kek", 7, false) })
	require.NoError(t, err)
	var deleted kmssvc.DeleteKeyResult
	require.NoError(t, json.Unmarshal([]byte(out), &deleted))
	assert.Equal(t, "tenant-kek", deleted.KeyID)

	out, err = capture964(t, func() error { return runKeyRotate(f, "tenant-kek", true) })
	require.NoError(t, err)
	var rotated kmssvc.RotateKeyResult
	require.NoError(t, json.Unmarshal([]byte(out), &rotated))
	assert.Equal(t, uint64(4), rotated.NewVersion)

	out, err = capture964(t, func() error { return runKeyVersions(f, "tenant-kek", 10, "") })
	require.NoError(t, err)
	assert.Equal(t, "tenant-kek", json964(t, out)["key_id"])
}

func TestKeyRun964_TablePrintsTheKey(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatTable)

	cases := []struct {
		name string
		run  func() error
		want []string
	}{
		{"generate", func() error { return runKeyGenerate(f, "tenant-kek", "aes-256", "encrypt", true, true, "", "", "") },
			[]string{"Key generated successfully: tenant-kek", "Tenant KEK", "wraps tenant DEKs"}},
		{"get", func() error { return runKeyGet(f, "tenant-kek", 0) },
			[]string{"tenant-kek", "Tenant KEK", "wraps tenant DEKs", "Updated At"}},
		{"list", func() error { return runKeyList(f, 10, "") }, []string{"tenant-kek", "Total Count", "7", "page-2"}},
		{"delete scheduled", func() error { return runKeyDelete(f, "tenant-kek", 7, false) },
			[]string{"Key tenant-kek scheduled for deletion", "Deletion Date"}},
		{"delete forced", func() error { return runKeyDelete(f, "tenant-kek", 0, true) }, []string{"Key tenant-kek deleted permanently"}},
		{"rotate", func() error { return runKeyRotate(f, "tenant-kek", false) }, []string{"Key tenant-kek rotated successfully", "4"}},
		{"versions", func() error { return runKeyVersions(f, "tenant-kek", 10, "") }, []string{"3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := capture964(t, tc.run)
			require.NoError(t, err)
			for _, want := range tc.want {
				assert.Contains(t, out, want)
			}
		})
	}
}

func TestKeyRun964_ListWithNoKeys(t *testing.T) {
	srv := newFakeKMSServer964()
	srv.listKeys = &platformv1.ListKeysResponse{}
	flags := startKMSServer964(t, srv)

	out, err := capture964(t, func() error { return runKeyList(flags(cli.OutputFormatTable), 10, "") })
	require.NoError(t, err)
	assert.Contains(t, out, "No keys found")
}

func TestKeyRun964_BackendFailureIsWrapped(t *testing.T) {
	srv := newFakeKMSServer964()
	srv.fail = errBackend964
	flags := startKMSServer964(t, srv)
	f := flags(cli.OutputFormatJSON)

	cases := []struct {
		msg string
		run func() error
	}{
		{"failed to generate key", func() error { return runKeyGenerate(f, "k", "aes-256", "encrypt", false, false, "", "", "") }},
		{"failed to get key", func() error { return runKeyGet(f, "k", 0) }},
		{"failed to list keys", func() error { return runKeyList(f, 10, "") }},
		{"failed to delete key", func() error { return runKeyDelete(f, "k", 7, false) }},
		{"failed to rotate key", func() error { return runKeyRotate(f, "k", false) }},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			err := tc.run()
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tc.msg, wrapped.Msg)
			assert.Equal(t, codes.Unavailable, status.Code(errors.Unwrap(err)))
			assert.Contains(t, err.Error(), tc.msg+": ")
		})
	}

	var versionsErr ErrListKeyVersionsFailed
	require.ErrorAs(t, runKeyVersions(f, "k", 10, ""), &versionsErr)
	assert.Equal(t, "k", versionsErr.KeyID)
}

func TestKeyRun964_GenerateRejectsBadArguments(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatJSON)

	var algErr ErrInvalidKeyAlgorithm
	require.ErrorAs(t, runKeyGenerate(f, "k", "rot13", "encrypt", false, false, "", "", ""), &algErr)
	assert.Equal(t, "rot13", algErr.Algorithm)

	require.Error(t, runKeyGenerate(f, "k", "aes-256", "launch", false, false, "", "", ""))
}

func TestKeyRun964_GenerateAppliesTheDisplayName(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatJSON)

	var renamed atomic.Pointer[kms.UpdateKeyMetadataRequest]
	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) {
		return &fakeKMSClient{updateKeyMetadataFn: func(_ context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
			renamed.Store(req)
			return &kms.KeyMetadataResponse{KeyID: req.KeyID, Name: req.Name}, nil
		}}, nil
	}))

	out, err := capture964(t, func() error {
		return runKeyGenerate(f, "tenant-kek", "aes-256", "encrypt", false, false, "Display", "", "")
	})
	require.NoError(t, err)
	require.NotNil(t, renamed.Load())
	assert.Equal(t, "Display", renamed.Load().Name)
	var generated kmssvc.GenerateKeyResult
	require.NoError(t, json.Unmarshal([]byte(out), &generated))
	assert.Equal(t, "Display", generated.Metadata.Name)

	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) { return nil, errFactory964 }))
	require.ErrorIs(t, runKeyGenerate(f, "tenant-kek", "aes-256", "encrypt", false, false, "Display", "", ""), errFactory964)
}

// statusKMS964 is a KMS client whose UpdateKeyStatus is keyStatusFake.
type statusKMS964 struct {
	quicbaassdk.KMSClient
	fake *keyStatusFake
}

func (c statusKMS964) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	return c.fake.UpdateKeyStatus(ctx, req)
}

func TestFactoryRun964_UsesTheFactoryClient(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatJSON)

	fake := &fakeKMSClient{
		revokeKeyFn: func(context.Context, string) error { return nil },
		getKeyMetadataFn: func(_ context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
			return &kms.KeyMetadataResponse{KeyID: keyID, Name: "meta"}, nil
		},
		updateKeyMetadataFn: func(_ context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
			return &kms.KeyMetadataResponse{KeyID: req.KeyID, Name: req.Name}, nil
		},
		getKeyPolicyFn: func(_ context.Context, keyID string) (*kms.KeyPolicy, error) {
			return &kms.KeyPolicy{KeyID: keyID, Version: 1}, nil
		},
		setKeyPolicyFn: func(context.Context, *kms.SetKeyPolicyRequest) error { return nil },
		getSupportedAlgorithmsFn: func(context.Context) (*kms.SupportedAlgorithmsResponse, error) {
			return &kms.SupportedAlgorithmsResponse{Algorithms: []string{"AES-256-GCM"}}, nil
		},
		backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
			return &kms.BackendStatusResponse{BackendType: "software", Status: "healthy"}, nil
		},
	}
	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) { return fake, nil }))

	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{"algorithms", func() error { return runKeyAlgorithms(f) }, "AES-256-GCM"},
		{"status", func() error { return runKMSStatus(f) }, "healthy"},
		{"revoke", func() error { return runKeyRevoke(f, "k1", "compromised") }, "k1"},
		{"metadata get", func() error { return runKeyMetadataGet(f, "k1") }, "meta"},
		{"metadata update", func() error { return runKeyMetadataUpdate(f, "k1", "renamed", "", nil, nil) }, "renamed"},
		{"policy get", func() error { return runKeyPolicyGet(f, "k1") }, "k1"},
		{"policy set", func() error { return runKeyPolicySet(f, "k1", keyPolicySetOptions{Operations: []string{"sign"}}) }, "k1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := capture964(t, tc.run)
			require.NoError(t, err)
			assert.Contains(t, out, tc.want)
		})
	}

	statusFake := &keyStatusFake{}
	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) {
		return statusKMS964{fake: statusFake}, nil
	}))
	out, err := capture964(t, func() error { return runKeyStatus(f, "k1", 2, kms.KeyStatusDisabled) })
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"key_id": "k1", "version": float64(2), "status": "DISABLED"}, json964(t, out))
}

func TestFactoryRun964_FactoryErrorStopsTheVerb(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatJSON)
	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) { return nil, errFactory964 }))
	t.Cleanup(SetSecretsClientFactory(func(*cli.BaseCommand) (quicbaassdk.SecretsClient, error) { return nil, errFactory964 }))
	t.Cleanup(setDEKClientFactory(func(*cli.BaseCommand) (dekclient.Client, error) { return nil, errFactory964 }))
	t.Cleanup(setDEKSafetyClientFactory(func(*cli.BaseCommand) (dekSafetyClient, error) { return nil, errFactory964 }))

	ran := false
	runs := map[string]func() error{
		"algorithms":      func() error { return runKeyAlgorithms(f) },
		"status":          func() error { return runKMSStatus(f) },
		"revoke":          func() error { return runKeyRevoke(f, "k1", "compromised") },
		"metadata get":    func() error { return runKeyMetadataGet(f, "k1") },
		"metadata update": func() error { return runKeyMetadataUpdate(f, "k1", "n", "", nil, nil) },
		"policy get":      func() error { return runKeyPolicyGet(f, "k1") },
		"policy set":      func() error { return runKeyPolicySet(f, "k1", keyPolicySetOptions{}) },
		"key status":      func() error { return runKeyStatus(f, "k1", 0, kms.KeyStatusEnabled) },
		"csr":             func() error { return runKeyCSR(f, "k1", "") },
		"secrets": func() error {
			return runSecrets(f, func(context.Context, quicbaassdk.SecretsClient, *cli.Printer, cli.OutputFormat) error {
				ran = true
				return nil
			})
		},
		"dek": func() error {
			return runDEK(f, func(context.Context, dekclient.Client, *cli.Printer) error {
				ran = true
				return nil
			})
		},
		"dek safety": func() error {
			return runDEKSafety(f, func(context.Context, dekSafetyClient, *cli.Printer) error {
				ran = true
				return nil
			})
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, run(), errFactory964)
		})
	}
	assert.False(t, ran, "no verb runs without its client")
}

func TestFactoryRun964_ActionsGetTheClientAndFormat(t *testing.T) {
	flags := startKMSServer964(t, newFakeKMSServer964())
	f := flags(cli.OutputFormatYAML)

	secrets := &fakeSecretsClient964{}
	t.Cleanup(SetSecretsClientFactory(func(*cli.BaseCommand) (quicbaassdk.SecretsClient, error) { return secrets, nil }))
	var gotFormat cli.OutputFormat
	var gotSecrets quicbaassdk.SecretsClient
	require.NoError(t, runSecrets(f, func(_ context.Context, c quicbaassdk.SecretsClient, p *cli.Printer, format cli.OutputFormat) error {
		require.NotNil(t, p)
		gotSecrets, gotFormat = c, format
		return nil
	}))
	assert.Same(t, secrets, gotSecrets)
	assert.Equal(t, cli.OutputFormatYAML, gotFormat)

	actionErr := errors.New("action failed")
	t.Cleanup(setDEKClientFactory(func(*cli.BaseCommand) (dekclient.Client, error) { return nil, nil }))
	require.ErrorIs(t, runDEK(f, func(context.Context, dekclient.Client, *cli.Printer) error { return actionErr }), actionErr)

	t.Cleanup(setDEKSafetyClientFactory(func(*cli.BaseCommand) (dekSafetyClient, error) { return nil, nil }))
	require.ErrorIs(t, runDEKSafety(f, func(context.Context, dekSafetyClient, *cli.Printer) error { return actionErr }), actionErr)
}

// fakeSecretsClient964 is a SecretsClient identity for the factory test; no
// method is called.
type fakeSecretsClient964 struct {
	quicbaassdk.SecretsClient
}

func TestRun964_NoContextFailsBeforeDialing(t *testing.T) {
	f := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	runs := map[string]func() error{
		"encrypt":         func() error { return runCryptoEncrypt(f, &encryptFlags{}) },
		"decrypt":         func() error { return runCryptoDecrypt(f, &decryptFlags{}) },
		"sign":            func() error { return runCryptoSign(f, &signFlags{}) },
		"verify":          func() error { return runCryptoVerify(f, &verifyFlags{}) },
		"hash":            func() error { return runCryptoHash(f, &hashFlags{}) },
		"hmac":            func() error { return runHMACGenerate(f, &hmacGenerateFlags{}) },
		"hmac verify":     func() error { return runHMACVerify(f, &hmacVerifyFlags{}) },
		"random":          func() error { return runCryptoRandom(f, &randomFlags{numBytes: 1}) },
		"data key":        func() error { return runGenerateDataKey(f, &dataKeyFlags{}) },
		"wrapped key":     func() error { return runGenerateWrappedDataKey(f, &dataKeyFlags{}) },
		"rewrap":          func() error { return runCryptoRewrap(f, &rewrapFlags{}) },
		"batch encrypt":   func() error { return runBatchEncrypt(f, &batchEncryptFlags{}) },
		"batch decrypt":   func() error { return runBatchDecrypt(f, &batchDecryptFlags{}) },
		"key generate":    func() error { return runKeyGenerate(f, "k", "aes-256", "encrypt", false, false, "", "", "") },
		"key get":         func() error { return runKeyGet(f, "k", 0) },
		"key list":        func() error { return runKeyList(f, 1, "") },
		"key delete":      func() error { return runKeyDelete(f, "k", 7, false) },
		"key rotate":      func() error { return runKeyRotate(f, "k", false) },
		"key versions":    func() error { return runKeyVersions(f, "k", 1, "") },
		"key status":      func() error { return runKeyStatus(f, "k", 0, kms.KeyStatusEnabled) },
		"key csr":         func() error { return runKeyCSR(f, "k", "") },
		"algorithms":      func() error { return runKeyAlgorithms(f) },
		"kms status":      func() error { return runKMSStatus(f) },
		"revoke":          func() error { return runKeyRevoke(f, "k", "compromised") },
		"metadata get":    func() error { return runKeyMetadataGet(f, "k") },
		"metadata update": func() error { return runKeyMetadataUpdate(f, "k", "", "", nil, nil) },
		"policy get":      func() error { return runKeyPolicyGet(f, "k") },
		"policy set":      func() error { return runKeyPolicySet(f, "k", keyPolicySetOptions{}) },
		"secrets":         func() error { return runSecrets(f, nil) },
		"dek":             func() error { return runDEK(f, nil) },
		"dek safety":      func() error { return runDEKSafety(f, nil) },
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			require.ErrorAs(t, run(), new(cli.ErrNoContextSet))
		})
	}
}

func TestKeyCSRRun964_WritesACSRTheKMSSigned(t *testing.T) {
	fleetKey := issuancetest.RSAKey(t)
	srv := newFakeKMSServer964()
	srv.signer = &secureboottest.KMS{Key: fleetKey}
	flags := startKMSServer964(t, srv)
	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) {
		return &publicKeyClient{public: pkixDER(t, &fleetKey.PublicKey)}, nil
	}))

	out := filepath.Join(t.TempDir(), "fleet.csr")
	require.NoError(t, runKeyCSR(flags(cli.OutputFormatTable), "rpi/fleet", out))

	written, err := os.ReadFile(out)
	require.NoError(t, err)
	block, _ := pem.Decode(written)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	assert.True(t, fleetKey.PublicKey.Equal(csr.PublicKey))
	assert.Equal(t, "rpi/fleet", csr.Subject.CommonName)

	t.Cleanup(SetKMSClientFactory(func(*cli.BaseCommand) (quicbaassdk.KMSClient, error) {
		return &publicKeyClient{err: errFactory964}, nil
	}))
	var csrErr ErrKeyCSRFailed
	require.ErrorAs(t, runKeyCSR(flags(cli.OutputFormatTable), "rpi/fleet", out), &csrErr)
	assert.Equal(t, "fetching the public key", csrErr.Step)
	assert.ErrorIs(t, csrErr, errFactory964)
	assert.Contains(t, csrErr.Error(), "failed to create a CSR for key rpi/fleet")
}

func TestErrors964_MessagesAndCauses(t *testing.T) {
	cause := errors.New("cause")
	cases := []struct {
		err  error
		want string
	}{
		{ErrAlgorithmsFailed{Err: cause}, "failed to list supported algorithms: cause"},
		{ErrKMSStatusFailed{Err: cause}, "failed to get KMS status: cause"},
		{ErrInvalidSecretValue{Err: cause}, "--value is not valid base64: cause"},
		{&WrappedError{Msg: "context", Err: cause}, "context: cause"},
	}
	for _, tc := range cases {
		assert.EqualError(t, tc.err, tc.want)
		assert.ErrorIs(t, tc.err, cause)
	}
	assert.EqualError(t, ErrDEKStatusEmpty{Path: "/t/a"}, "dek status /t/a: the DEK service returned no DEK metadata")
	assert.Contains(t, ErrKeyVersionOutOfRange{Version: 9}.Error(), "key version 9 is out of range")
}
