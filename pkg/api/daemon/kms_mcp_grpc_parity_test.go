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
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkcrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	service "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// The MCP KMS and secret tools must answer as gRPC does (#304): the same
// success answer, and the same error class for a missing object and for bad
// input. Each test below seeds one in-memory store, serves it through both
// SDK interfaces (go-quicbaas service.* for MCP, the quicbaas clients for
// gRPC), and asks both transports the same question.

const (
	parityKeyID          = "key-1"
	parityKeyName        = "orders"
	parityKeyVersion     = 3
	parityPolicyVersion  = 7
	paritySecretID       = "db/password"
	paritySecretVersion  = 2
	parityRetainVersions = 4
	parityDataKeySize    = 32
	parityMissingID      = "missing"
)

// parityMissing is what the fake SDK answers for an unknown object: the
// SDK's typed NotFound, as go-quicbaas answers it.
func parityMissing(id string) error {
	return sdkerrors.NewNotFound("parity", "no object "+id)
}

// parityStore is the one backend both transports read.
type parityStore struct {
	keys     map[string]string
	secrets  map[string][]byte
	versions map[string]uint64
	rotation map[string]bool
}

func newParityStore() *parityStore {
	return &parityStore{
		keys:     map[string]string{parityKeyID: parityKeyName},
		secrets:  map[string][]byte{paritySecretID: []byte("hunter2")},
		versions: map[string]uint64{paritySecretID: paritySecretVersion},
		rotation: map[string]bool{paritySecretID: true},
	}
}

func (s *parityStore) keyName(keyID string) (string, error) {
	name, ok := s.keys[keyID]
	if !ok {
		return "", parityMissing(keyID)
	}
	return name, nil
}

func (s *parityStore) encrypt(keyID string, plaintext []byte) ([]byte, error) {
	if _, err := s.keyName(keyID); err != nil {
		return nil, err
	}
	return append([]byte(keyID+":"), plaintext...), nil
}

func (s *parityStore) decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if _, err := s.keyName(keyID); err != nil {
		return nil, err
	}
	prefix := []byte(keyID + ":")
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, sdkerrors.NewInvalidInput("parity", "ciphertext not sealed under "+keyID)
	}
	return ciphertext[len(prefix):], nil
}

func (s *parityStore) random(n int) []byte {
	return bytes.Repeat([]byte{0x5a}, n)
}

func (s *parityStore) putSecret(secretID string, data []byte) uint64 {
	s.secrets[secretID] = data
	s.versions[secretID]++
	return s.versions[secretID]
}

func (s *parityStore) secret(secretID string) ([]byte, uint64, error) {
	data, ok := s.secrets[secretID]
	if !ok {
		return nil, 0, parityMissing(secretID)
	}
	return data, s.versions[secretID], nil
}

// rotateSecret stores data as an existing secret's next version and
// returns the old and new version numbers.
func (s *parityStore) rotateSecret(secretID string, data []byte) (uint64, uint64, error) {
	_, oldVersion, err := s.secret(secretID)
	if err != nil {
		return 0, 0, err
	}
	return oldVersion, s.putSecret(secretID, data), nil
}

// rollbackSecret writes a new version of secretID, as a rollback does. The
// store keeps no history, so the new version carries the current data: the
// parity tests compare the versions the transports answer.
func (s *parityStore) rollbackSecret(secretID string, target uint64) (uint64, error) {
	data, current, err := s.secret(secretID)
	if err != nil {
		return 0, err
	}
	if target >= current {
		return 0, sdkerrors.NewInvalidInput("parity", "rollback target is not an earlier version")
	}
	return s.putSecret(secretID, data), nil
}

func (s *parityStore) rotationPolicy(secretID string) error {
	if !s.rotation[secretID] {
		return parityMissing(secretID)
	}
	return nil
}

// newParityMCP serves the store through the go-quicbaas service interfaces
// the MCP provider consumes, behind the MCP tool registry.
func newParityMCP(store *parityStore) *mcp.ToolRegistry {
	kmsService := &lifecycleKMSServiceMock{
		mockKMSServiceForMCPTests: mockKMSServiceForMCPTests{
			getKeyFunc: func(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error) {
				if _, err := store.keyName(req.KeyID); err != nil {
					return nil, err
				}
				return &service.GetKeyResponse{Key: &service.KeyHandle{KeyID: req.KeyID, Version: parityKeyVersion}}, nil
			},
		},
		getKeyMetadataFunc: func(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
			name, err := store.keyName(req.KeyID)
			if err != nil {
				return nil, err
			}
			return &service.GetKeyMetadataResponse{Metadata: &service.KeyMetadata{KeyID: req.KeyID, Name: name}}, nil
		},
		getKeyPolicyFunc: func(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
			if _, err := store.keyName(req.KeyID); err != nil {
				return nil, err
			}
			return &service.GetKeyPolicyResponse{Policy: &service.KeyPolicy{KeyID: req.KeyID, Version: parityPolicyVersion}}, nil
		},
	}
	cryptoService := &mockCryptoServiceForMCPTests{
		encryptFunc: func(ctx context.Context, req *service.EncryptRequest) (*service.EncryptResponse, error) {
			ciphertext, err := store.encrypt(req.KeyID, req.Plaintext)
			if err != nil {
				return nil, err
			}
			return &service.EncryptResponse{KeyID: req.KeyID, Ciphertext: ciphertext, KeyVersion: parityKeyVersion}, nil
		},
		decryptFunc: func(ctx context.Context, req *service.DecryptRequest) (*service.DecryptResponse, error) {
			plaintext, err := store.decrypt(req.KeyID, req.Ciphertext)
			if err != nil {
				return nil, err
			}
			return &service.DecryptResponse{KeyID: req.KeyID, Plaintext: plaintext, KeyVersion: parityKeyVersion}, nil
		},
		generateDataKeyFunc: func(ctx context.Context, req *service.GenerateDataKeyRequest) (*service.GenerateDataKeyResponse, error) {
			plaintext := store.random(parityDataKeySize)
			ciphertext, err := store.encrypt(req.KeyID, plaintext)
			if err != nil {
				return nil, err
			}
			return &service.GenerateDataKeyResponse{
				KeyID:          req.KeyID,
				Plaintext:      plaintext,
				CiphertextBlob: ciphertext,
				Timestamp:      time.Now(),
			}, nil
		},
	}
	secretsService := &lifecycleSecretsServiceMock{
		storeSecretFunc: func(ctx context.Context, req *service.StoreSecretRequest) (*service.StoreSecretResponse, error) {
			version := store.putSecret(req.SecretID, req.Data)
			return &service.StoreSecretResponse{SecretID: req.SecretID, Version: version}, nil
		},
		getSecretFunc: func(ctx context.Context, req *service.GetSecretRequest) (*service.GetSecretResponse, error) {
			data, version, err := store.secret(req.SecretID)
			if err != nil {
				return nil, err
			}
			return &service.GetSecretResponse{SecretID: req.SecretID, Version: version, Data: data}, nil
		},
		getRotationPolicyFunc: func(ctx context.Context, req *service.GetRotationPolicyRequest) (*service.GetRotationPolicyResponse, error) {
			if err := store.rotationPolicy(req.SecretID); err != nil {
				return nil, err
			}
			return &service.GetRotationPolicyResponse{
				SecretID: req.SecretID,
				Policy:   &service.SecretRotationPolicy{Enabled: true, RetainVersions: parityRetainVersions},
			}, nil
		},
		rotateSecretFunc: func(ctx context.Context, req *service.RotateSecretRequest) (*service.RotateSecretResponse, error) {
			oldVersion, newVersion, err := store.rotateSecret(req.SecretID, req.NewData)
			if err != nil {
				return nil, err
			}
			return &service.RotateSecretResponse{SecretID: req.SecretID, OldVersion: oldVersion, NewVersion: newVersion}, nil
		},
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService:     kmsService,
		CryptoService:  cryptoService,
		SecretsService: secretsService,
		Logger:         slog.Default(),
	})
	provider.SetSecretsServer(NewSecretsServerAdapter(&paritySecretsClient{store: store}, slog.Default()))
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// parityKMSClient serves the store through the quicbaas KMS client.
type parityKMSClient struct {
	mockSDKKMSClient
	store *parityStore
}

func (c *parityKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	name, err := c.store.keyName(keyID)
	if err != nil {
		return nil, err
	}
	return &kms.KeyInfo{KeyID: keyID, Name: name, Version: parityKeyVersion}, nil
}

func (c *parityKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	name, err := c.store.keyName(keyID)
	if err != nil {
		return nil, err
	}
	return &kms.KeyMetadataResponse{KeyID: keyID, Name: name, Version: parityKeyVersion}, nil
}

func (c *parityKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	if _, err := c.store.keyName(keyID); err != nil {
		return nil, err
	}
	return &kms.KeyPolicy{KeyID: keyID, Version: parityPolicyVersion}, nil
}

// ImportKey stores the imported key under its name, so the name is its ID.
func (c *parityKMSClient) ImportKey(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
	c.store.keys[req.Name] = req.Name
	return &kms.ImportKeyResponse{KeyID: req.Name, Version: 1, Algorithm: req.Algorithm}, nil
}

func (c *parityKMSClient) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	if _, err := c.store.keyName(req.KeyID); err != nil {
		return nil, err
	}
	return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
}

// ListKeyVersions answers versions 1..parityKeyVersion, the newest enabled.
func (c *parityKMSClient) ListKeyVersions(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
	if _, err := c.store.keyName(keyID); err != nil {
		return nil, err
	}
	versions := make([]kms.KeyVersionInfo, 0, parityKeyVersion)
	for v := 1; v <= parityKeyVersion; v++ {
		info := kms.KeyVersionInfo{Version: v, Status: kms.KeyStatusDisabled, Algorithm: kms.AlgorithmAES256GCM, CreatedAt: time.Unix(int64(100*v), 0)}
		if v == parityKeyVersion {
			info.Status = kms.KeyStatusEnabled
		}
		versions = append(versions, info)
	}
	return &kms.ListKeyVersionsResponse{KeyID: keyID, Versions: versions}, nil
}

// paritySecretsClient serves the store through the quicbaas secrets client.
type paritySecretsClient struct {
	extSecretsClientMock
	store *parityStore
}

func (c *paritySecretsClient) Store(ctx context.Context, req *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	data, _ := req.Data["_raw"].([]byte)
	version := c.store.putSecret(req.Path, data)
	return &secrets.StoreSecretResponse{Version: int(version)}, nil
}

func (c *paritySecretsClient) Get(ctx context.Context, path string, opts ...secrets.GetOption) (*secrets.Secret, error) {
	data, version, err := c.store.secret(path)
	if err != nil {
		return nil, err
	}
	return &secrets.Secret{Path: path, Data: map[string]interface{}{"_raw": data}, Version: int(version)}, nil
}

func (c *paritySecretsClient) GetRotationPolicy(ctx context.Context, secretID string) (*secrets.RotationPolicy, error) {
	if err := c.store.rotationPolicy(secretID); err != nil {
		return nil, err
	}
	return &secrets.RotationPolicy{Enabled: true, RetainVersions: parityRetainVersions}, nil
}

func (c *paritySecretsClient) Rotate(ctx context.Context, req *secrets.RotateSecretRequest) (*secrets.RotateSecretResponse, error) {
	oldVersion, newVersion, err := c.store.rotateSecret(req.SecretID, req.NewData)
	if err != nil {
		return nil, err
	}
	return &secrets.RotateSecretResponse{SecretID: req.SecretID, OldVersion: int(oldVersion), NewVersion: int(newVersion)}, nil
}

func (c *paritySecretsClient) Rollback(ctx context.Context, req *secrets.RollbackSecretRequest) (*secrets.RollbackSecretResponse, error) {
	newVersion, err := c.store.rollbackSecret(req.SecretID, uint64(req.TargetVersion))
	if err != nil {
		return nil, err
	}
	return &secrets.RollbackSecretResponse{SecretID: req.SecretID, NewVersion: int(newVersion)}, nil
}

// newParityCryptoClient serves the store through the quicbaas crypto client.
func newParityCryptoClient(store *parityStore) *platformMockCryptoClient {
	return &platformMockCryptoClient{
		encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
			ciphertext, err := store.encrypt(req.KeyID, req.Plaintext)
			if err != nil {
				return nil, err
			}
			return &quicbaas.EncryptResponse{Ciphertext: ciphertext, KeyVersion: parityKeyVersion}, nil
		},
		decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
			plaintext, err := store.decrypt(req.KeyID, req.Ciphertext)
			if err != nil {
				return nil, err
			}
			return &quicbaas.DecryptResponse{Plaintext: plaintext}, nil
		},
		generateRandomFn: func(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
			return &quicbaas.GenerateRandomResponse{RandomBytes: store.random(req.NumBytes)}, nil
		},
		hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
			return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: append([]byte("digest:"), req.Data...)}, nil
		},
		// The parity "MAC" is the store's seal of the message: keyed, and
		// NotFound under a key the store does not hold.
		generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
			mac, err := store.encrypt(req.KeyID, req.Message)
			if err != nil {
				return nil, err
			}
			return &quicbaas.GenerateHMACResponse{KeyID: req.KeyID, KeyVersion: parityKeyVersion, HMAC: mac, HashAlg: req.HashAlg}, nil
		},
		verifyHMACFn: func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
			mac, err := store.encrypt(req.KeyID, req.Message)
			if err != nil {
				return nil, err
			}
			return &quicbaas.VerifyHMACResponse{Valid: bytes.Equal(mac, req.HMAC)}, nil
		},
		rewrapFn: func(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
			plaintext, err := store.decrypt(req.KeyID, req.Ciphertext)
			if err != nil {
				return nil, err
			}
			ciphertext, err := store.encrypt(req.KeyID, plaintext)
			if err != nil {
				return nil, err
			}
			return &quicbaas.RewrapResponse{
				KeyID:         req.KeyID,
				OldKeyVersion: parityKeyVersion - 1,
				NewKeyVersion: parityKeyVersion,
				Ciphertext:    ciphertext,
			}, nil
		},
		// A batch under a missing key fails whole; a bad item fails alone.
		encryptBatchFn: func(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
			if _, err := store.keyName(req.KeyID); err != nil {
				return nil, err
			}
			results := make([]sdkcrypto.BatchEncryptResult, len(req.Items))
			for i, item := range req.Items {
				ciphertext, err := store.encrypt(req.KeyID, item.Plaintext)
				if err != nil {
					results[i].Error = err.Error()
					continue
				}
				results[i] = sdkcrypto.BatchEncryptResult{Ciphertext: ciphertext, Nonce: store.random(12)}
			}
			return &quicbaas.EncryptBatchResponse{KeyID: req.KeyID, KeyVersion: parityKeyVersion, Results: results}, nil
		},
		decryptBatchFn: func(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error) {
			if _, err := store.keyName(req.KeyID); err != nil {
				return nil, err
			}
			results := make([]sdkcrypto.BatchDecryptResult, len(req.Items))
			for i, item := range req.Items {
				plaintext, err := store.decrypt(req.KeyID, item.Ciphertext)
				if err != nil {
					results[i].Error = err.Error()
					continue
				}
				results[i].Plaintext = plaintext
			}
			return &quicbaas.DecryptBatchResponse{KeyID: req.KeyID, Results: results}, nil
		},
	}
}

// newParityBackendTransports serves one store through the PlatformKMSBackend
// shared by the MCP tools and gRPC KeyManagementService, as the daemon wires it.
func newParityBackendTransports(store *parityStore) (*mcp.ToolRegistry, *grpcapi.KMSGRPCService) {
	backend := NewPlatformKMSBackend(&parityKMSClient{store: store}, newParityCryptoClient(store), slog.Default())
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{KMSBackend: backend, Logger: slog.Default()})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger()), grpcapi.NewKMSGRPCService(logging.DefaultLogger(), backend)
}

// parityTool runs an MCP tool and decodes its JSON answer into out, as an MCP
// client reads it.
func parityTool(t *testing.T, registry *mcp.ToolRegistry, tool string, args map[string]interface{}, out interface{}) error {
	t.Helper()
	result, err := registry.ExecuteTool(context.Background(), tool, args)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, out))
	return nil
}

// mcpErrorClass is the class an MCP client reads for err: the server answers
// the JSON-RPC code for the error's class (pkg/api/mcp toolErrorCode, which
// falls back to errclass), and the client decodes that code to a class.
func mcpErrorClass(err error) codes.Code {
	return mcpwire.ClassForCode(mcpwire.CodeForClass(errclass.Code(err)))
}

// requireSameClass asserts both transports failed with the class want.
func requireSameClass(t *testing.T, mcpErr, grpcErr error, want codes.Code) {
	t.Helper()
	require.Error(t, mcpErr, "MCP")
	require.Error(t, grpcErr, "gRPC")
	assert.Equal(t, want, mcpErrorClass(mcpErr), "MCP class: %v", mcpErr)
	assert.Equal(t, want, status.Code(grpcErr), "gRPC class: %v", grpcErr)
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func TestMCPKMSParity_Keys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools := newParityMCP(newParityStore())
	adapter := NewKMSServerAdapter(&parityKMSClient{store: newParityStore()}, slog.Default())

	t.Run("get_key answers the key", func(t *testing.T) {
		var got service.KeyHandle
		require.NoError(t, parityTool(t, tools, "kms_get_key", map[string]interface{}{"key_id": parityKeyID}, &got))
		want, err := adapter.GetKey(ctx, &pb.GetKeyRequest{KeyId: parityKeyID})
		require.NoError(t, err)
		assert.Equal(t, want.GetKey().GetKeyId(), got.KeyID)
		assert.Equal(t, want.GetKey().GetVersion(), uint64(got.Version))
	})

	t.Run("get_key_metadata answers the metadata", func(t *testing.T) {
		var got service.KeyMetadata
		require.NoError(t, parityTool(t, tools, "kms_get_key_metadata", map[string]interface{}{"key_id": parityKeyID}, &got))
		want, err := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: parityKeyID})
		require.NoError(t, err)
		assert.Equal(t, want.GetMetadata().GetKeyId(), got.KeyID)
		assert.Equal(t, want.GetMetadata().GetName(), got.Name)
	})

	t.Run("get_key not found", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_get_key", map[string]interface{}{"key_id": parityMissingID}, &service.KeyHandle{})
		_, grpcErr := adapter.GetKey(ctx, &pb.GetKeyRequest{KeyId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("get_key_metadata not found", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_get_key_metadata", map[string]interface{}{"key_id": parityMissingID}, &service.KeyMetadata{})
		_, grpcErr := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("get_key without key_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_get_key", map[string]interface{}{}, &service.KeyHandle{})
		_, grpcErr := adapter.GetKey(ctx, &pb.GetKeyRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}

// cryptoAnswer is the JSON shape of the kms_encrypt and kms_decrypt answers.
type cryptoAnswer struct {
	Ciphertext []byte `json:"ciphertext"`
	Plaintext  []byte `json:"plaintext"`
	KeyVersion uint64 `json:"key_version"`
}

func TestMCPKMSParity_CryptoOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools := newParityMCP(newParityStore())
	adapter := NewCryptoServerAdapter(newParityCryptoClient(newParityStore()), slog.Default())
	plaintext := []byte("card 4111")

	t.Run("encrypt answers the ciphertext", func(t *testing.T) {
		var got cryptoAnswer
		args := map[string]interface{}{"key_id": parityKeyID, "plaintext": b64(plaintext)}
		require.NoError(t, parityTool(t, tools, "kms_encrypt", args, &got))
		want, err := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: parityKeyID, Plaintext: plaintext})
		require.NoError(t, err)
		assert.Equal(t, want.GetCiphertext(), got.Ciphertext)
		assert.Equal(t, want.GetKeyVersion(), got.KeyVersion)
	})

	t.Run("decrypt answers the plaintext", func(t *testing.T) {
		ciphertext := append([]byte(parityKeyID+":"), plaintext...)
		var got cryptoAnswer
		args := map[string]interface{}{"key_id": parityKeyID, "ciphertext": b64(ciphertext)}
		require.NoError(t, parityTool(t, tools, "kms_decrypt", args, &got))
		want, err := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: parityKeyID, Ciphertext: ciphertext})
		require.NoError(t, err)
		assert.Equal(t, want.GetPlaintext(), got.Plaintext)
	})

	t.Run("encrypt under a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "plaintext": b64(plaintext)}
		mcpErr := parityTool(t, tools, "kms_encrypt", args, &cryptoAnswer{})
		_, grpcErr := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: parityMissingID, Plaintext: plaintext})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("decrypt under a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "ciphertext": b64(plaintext)}
		mcpErr := parityTool(t, tools, "kms_decrypt", args, &cryptoAnswer{})
		_, grpcErr := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: parityMissingID, Ciphertext: plaintext})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("decrypt a ciphertext the key did not seal", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityKeyID, "ciphertext": b64(plaintext)}
		mcpErr := parityTool(t, tools, "kms_decrypt", args, &cryptoAnswer{})
		_, grpcErr := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: parityKeyID, Ciphertext: plaintext})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("encrypt without key_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_encrypt", map[string]interface{}{"plaintext": b64(plaintext)}, &cryptoAnswer{})
		_, grpcErr := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{Plaintext: plaintext})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("encrypt without plaintext", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_encrypt", map[string]interface{}{"key_id": parityKeyID}, &cryptoAnswer{})
		_, grpcErr := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: parityKeyID})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("decrypt without ciphertext", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_decrypt", map[string]interface{}{"key_id": parityKeyID}, &cryptoAnswer{})
		_, grpcErr := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: parityKeyID})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}

// dataKeyAnswer is the JSON shape of the kms_generate_data_key answer.
type dataKeyAnswer struct {
	KeyID          string `json:"key_id"`
	Plaintext      []byte `json:"plaintext"`
	CiphertextBlob []byte `json:"ciphertext_blob"`
}

// TestMCPKMSParity_DataKeys compares kms_generate_data_key with the
// platform.v1 GenerateDataKey RPC; quicbaas.kms.v1 has no data-key method.
func TestMCPKMSParity_DataKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools := newParityMCP(newParityStore())
	grpcStore := newParityStore()
	backend := NewPlatformKMSBackend(&parityKMSClient{store: grpcStore}, newParityCryptoClient(grpcStore), slog.Default())
	rpc := grpcapi.NewKMSGRPCService(logging.DefaultLogger(), backend)

	t.Run("answers the wrapped key", func(t *testing.T) {
		var got dataKeyAnswer
		require.NoError(t, parityTool(t, tools, "kms_generate_data_key", map[string]interface{}{"key_id": parityKeyID}, &got))
		want, err := rpc.GenerateDataKey(ctx, &platformv1.GenerateDataKeyRequest{KeyId: parityKeyID})
		require.NoError(t, err)
		assert.Equal(t, want.GetKeyId(), got.KeyID)
		assert.Equal(t, want.GetPlaintextKey(), got.Plaintext)
		assert.Equal(t, want.GetEncryptedKey(), got.CiphertextBlob)
	})

	t.Run("under a missing key", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_generate_data_key", map[string]interface{}{"key_id": parityMissingID}, &dataKeyAnswer{})
		_, grpcErr := rpc.GenerateDataKey(ctx, &platformv1.GenerateDataKeyRequest{KeyId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("without key_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_generate_data_key", map[string]interface{}{}, &dataKeyAnswer{})
		_, grpcErr := rpc.GenerateDataKey(ctx, &platformv1.GenerateDataKeyRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}

// digestAnswer is the JSON shape of the kms_hash, kms_hmac, kms_verify_hmac
// and kms_rewrap answers.
type digestAnswer struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	Hash          []byte `json:"hash"`
	HMAC          []byte `json:"hmac"`
	Valid         bool   `json:"valid"`
	Algorithm     int32  `json:"algorithm"`
	SourceVersion uint64 `json:"source_version"`
	TargetVersion uint64 `json:"target_version"`
	Ciphertext    []byte `json:"ciphertext"`
}

// TestMCPKMSParity_DigestAndRewrap compares kms_hash, kms_hmac,
// kms_verify_hmac and kms_rewrap with the platform.v1 RPCs; both call the
// same PlatformKMSBackend method.
func TestMCPKMSParity_DigestAndRewrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools, rpc := newParityBackendTransports(newParityStore())
	message := []byte("ledger line")
	mac := append([]byte(parityKeyID+":"), message...)
	sealed := append([]byte(parityKeyID+":"), message...)
	// MCP arguments arrive as decoded JSON, so numbers are float64.
	sha256 := float64(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256)
	sha1 := float64(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1)

	t.Run("hash answers the digest", func(t *testing.T) {
		var got digestAnswer
		args := map[string]interface{}{"data": b64(message), "algorithm": sha256}
		require.NoError(t, parityTool(t, tools, "kms_hash", args, &got))
		want, err := rpc.Hash(ctx, &platformv1.HashRequest{Data: message, Algorithm: platformv1.HashAlgorithm(sha256)})
		require.NoError(t, err)
		assert.Equal(t, want.GetHash(), got.Hash)
		assert.Equal(t, int32(want.GetAlgorithm()), got.Algorithm)
	})

	t.Run("hmac answers the mac", func(t *testing.T) {
		var got digestAnswer
		args := map[string]interface{}{"key_id": parityKeyID, "message": b64(message)}
		require.NoError(t, parityTool(t, tools, "kms_hmac", args, &got))
		want, err := rpc.HMAC(ctx, &platformv1.HMACRequest{KeyId: parityKeyID, Message: message})
		require.NoError(t, err)
		assert.Equal(t, want.GetHmac(), got.HMAC)
		assert.Equal(t, want.GetKeyVersion(), got.KeyVersion)
	})

	t.Run("verify_hmac answers valid", func(t *testing.T) {
		var got digestAnswer
		args := map[string]interface{}{"key_id": parityKeyID, "message": b64(message), "hmac": b64(mac)}
		require.NoError(t, parityTool(t, tools, "kms_verify_hmac", args, &got))
		want, err := rpc.VerifyHMAC(ctx, &platformv1.VerifyHMACRequest{KeyId: parityKeyID, Message: message, Hmac: mac})
		require.NoError(t, err)
		assert.True(t, want.GetValid())
		assert.Equal(t, want.GetValid(), got.Valid)
	})

	t.Run("rewrap answers the new ciphertext", func(t *testing.T) {
		var got digestAnswer
		args := map[string]interface{}{"key_id": parityKeyID, "ciphertext": b64(sealed)}
		require.NoError(t, parityTool(t, tools, "kms_rewrap", args, &got))
		want, err := rpc.Rewrap(ctx, &platformv1.RewrapRequest{KeyId: parityKeyID, Ciphertext: sealed})
		require.NoError(t, err)
		assert.Equal(t, want.GetCiphertext(), got.Ciphertext)
		assert.Equal(t, want.GetSourceVersion(), got.SourceVersion)
		assert.Equal(t, want.GetTargetVersion(), got.TargetVersion)
	})

	t.Run("hash with an unsupported algorithm", func(t *testing.T) {
		args := map[string]interface{}{"data": b64(message), "algorithm": sha1}
		mcpErr := parityTool(t, tools, "kms_hash", args, &digestAnswer{})
		_, grpcErr := rpc.Hash(ctx, &platformv1.HashRequest{Data: message, Algorithm: platformv1.HashAlgorithm(sha1)})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("hash without data", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_hash", map[string]interface{}{}, &digestAnswer{})
		_, grpcErr := rpc.Hash(ctx, &platformv1.HashRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("hmac under a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "message": b64(message)}
		mcpErr := parityTool(t, tools, "kms_hmac", args, &digestAnswer{})
		_, grpcErr := rpc.HMAC(ctx, &platformv1.HMACRequest{KeyId: parityMissingID, Message: message})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("hmac without message", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_hmac", map[string]interface{}{"key_id": parityKeyID}, &digestAnswer{})
		_, grpcErr := rpc.HMAC(ctx, &platformv1.HMACRequest{KeyId: parityKeyID})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("verify_hmac without hmac", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityKeyID, "message": b64(message)}
		mcpErr := parityTool(t, tools, "kms_verify_hmac", args, &digestAnswer{})
		_, grpcErr := rpc.VerifyHMAC(ctx, &platformv1.VerifyHMACRequest{KeyId: parityKeyID, Message: message})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("rewrap under a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "ciphertext": b64(sealed)}
		mcpErr := parityTool(t, tools, "kms_rewrap", args, &digestAnswer{})
		_, grpcErr := rpc.Rewrap(ctx, &platformv1.RewrapRequest{KeyId: parityMissingID, Ciphertext: sealed})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("rewrap with a source version is refused", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityKeyID, "ciphertext": b64(sealed), "source_version": float64(2)}
		mcpErr := parityTool(t, tools, "kms_rewrap", args, &digestAnswer{})
		_, grpcErr := rpc.Rewrap(ctx, &platformv1.RewrapRequest{KeyId: parityKeyID, Ciphertext: sealed, SourceVersion: 2})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("rewrap without ciphertext", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_rewrap", map[string]interface{}{"key_id": parityKeyID}, &digestAnswer{})
		_, grpcErr := rpc.Rewrap(ctx, &platformv1.RewrapRequest{KeyId: parityKeyID})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}

func TestMCPKMSParity_Policies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools := newParityMCP(newParityStore())
	grpcStore := newParityStore()
	keys := NewKMSServerAdapter(&parityKMSClient{store: grpcStore}, slog.Default())
	secretsAdapter := NewSecretsServerAdapter(&paritySecretsClient{store: grpcStore}, slog.Default())

	t.Run("get_key_policy answers the policy", func(t *testing.T) {
		var got service.KeyPolicy
		require.NoError(t, parityTool(t, tools, "kms_get_key_policy", map[string]interface{}{"key_id": parityKeyID}, &got))
		want, err := keys.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: parityKeyID})
		require.NoError(t, err)
		assert.Equal(t, want.GetPolicy().GetKeyId(), got.KeyID)
		assert.Equal(t, want.GetPolicy().GetVersion(), uint64(got.Version))
	})

	t.Run("secret_get_rotation_policy answers the policy", func(t *testing.T) {
		var got service.GetRotationPolicyResponse
		require.NoError(t, parityTool(t, tools, "secret_get_rotation_policy", map[string]interface{}{"secret_id": paritySecretID}, &got))
		want, err := secretsAdapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: paritySecretID})
		require.NoError(t, err)
		assert.Equal(t, want.GetSecretId(), got.SecretID)
		require.NotNil(t, got.Policy)
		assert.Equal(t, want.GetPolicy().GetEnabled(), got.Policy.Enabled)
		assert.Equal(t, int64(want.GetPolicy().GetRetainVersions()), int64(got.Policy.RetainVersions))
	})

	t.Run("get_key_policy not found", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_get_key_policy", map[string]interface{}{"key_id": parityMissingID}, &service.KeyPolicy{})
		_, grpcErr := keys.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("secret_get_rotation_policy not found", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_get_rotation_policy", map[string]interface{}{"secret_id": parityMissingID}, &service.GetRotationPolicyResponse{})
		_, grpcErr := secretsAdapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("get_key_policy without key_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_get_key_policy", map[string]interface{}{}, &service.KeyPolicy{})
		_, grpcErr := keys.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("secret_get_rotation_policy without secret_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_get_rotation_policy", map[string]interface{}{}, &service.GetRotationPolicyResponse{})
		_, grpcErr := secretsAdapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}

func TestMCPKMSParity_Secrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools := newParityMCP(newParityStore())
	adapter := NewSecretsServerAdapter(&paritySecretsClient{store: newParityStore()}, slog.Default())
	data := []byte("correct horse")

	t.Run("secret_store answers the new version", func(t *testing.T) {
		var got service.StoreSecretResponse
		args := map[string]interface{}{"secret_id": "api/token", "data": b64(data)}
		require.NoError(t, parityTool(t, tools, "secret_store", args, &got))
		want, err := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: "api/token", Data: data})
		require.NoError(t, err)
		assert.Equal(t, want.GetSecretId(), got.SecretID)
		assert.Equal(t, want.GetVersion(), uint64(got.Version))
	})

	t.Run("secret_get answers the secret", func(t *testing.T) {
		var got service.GetSecretResponse
		require.NoError(t, parityTool(t, tools, "secret_get", map[string]interface{}{"secret_id": paritySecretID}, &got))
		want, err := adapter.GetSecret(ctx, &pb.GetSecretRequest{SecretId: paritySecretID})
		require.NoError(t, err)
		assert.Equal(t, want.GetSecretId(), got.SecretID)
		assert.Equal(t, want.GetData(), got.Data)
		assert.Equal(t, want.GetVersion(), uint64(got.Version))
	})

	t.Run("secret_get not found", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_get", map[string]interface{}{"secret_id": parityMissingID}, &service.GetSecretResponse{})
		_, grpcErr := adapter.GetSecret(ctx, &pb.GetSecretRequest{SecretId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("secret_get without secret_id", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_get", map[string]interface{}{}, &service.GetSecretResponse{})
		_, grpcErr := adapter.GetSecret(ctx, &pb.GetSecretRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("secret_store without data", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_store", map[string]interface{}{"secret_id": "api/token"}, &service.StoreSecretResponse{})
		_, grpcErr := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: "api/token"})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("secret_rotate answers both versions", func(t *testing.T) {
		rotated := []byte("battery staple")
		var got service.RotateSecretResponse
		args := map[string]interface{}{"secret_id": "api/token", "new_data": b64(rotated)}
		require.NoError(t, parityTool(t, tools, "secret_rotate", args, &got))
		want, err := adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "api/token", NewData: rotated})
		require.NoError(t, err)
		assert.Equal(t, want.GetSecretId(), got.SecretID)
		assert.Equal(t, want.GetOldVersion(), got.OldVersion)
		assert.Equal(t, want.GetNewVersion(), got.NewVersion)
	})

	t.Run("secret_rotate without new_data", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_rotate", map[string]interface{}{"secret_id": "api/token"}, &service.RotateSecretResponse{})
		_, grpcErr := adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "api/token"})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("secret_rollback without target_version", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "secret_rollback", map[string]interface{}{"secret_id": "api/token"}, &service.RollbackSecretResponse{})
		_, grpcErr := adapter.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: "api/token"})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("secret_rollback answers the version it wrote", func(t *testing.T) {
		const id = "api/rollback"
		storeArgs := map[string]interface{}{"secret_id": id, "data": b64(data)}
		require.NoError(t, parityTool(t, tools, "secret_store", storeArgs, &service.StoreSecretResponse{}))
		rotateArgs := map[string]interface{}{"secret_id": id, "new_data": b64([]byte("rotated"))}
		require.NoError(t, parityTool(t, tools, "secret_rotate", rotateArgs, &service.RotateSecretResponse{}))
		_, err := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: id, Data: data})
		require.NoError(t, err)
		_, err = adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: id, NewData: []byte("rotated")})
		require.NoError(t, err)

		var got service.RollbackSecretResponse
		rollbackArgs := map[string]interface{}{"secret_id": id, "target_version": float64(1)}
		require.NoError(t, parityTool(t, tools, "secret_rollback", rollbackArgs, &got))
		want, err := adapter.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: id, TargetVersion: 1})
		require.NoError(t, err)
		assert.Equal(t, want.GetSecretId(), got.SecretID)
		assert.Equal(t, want.GetNewVersion(), got.NewVersion)
		assert.Equal(t, uint64(3), got.NewVersion, "store writes v1, rotate v2: the rollback writes v3")
	})
}

// TestMCPKMSParity_KeyAdminAndBatch compares kms_import_key,
// kms_update_key_status, kms_list_key_versions, kms_batch_encrypt and
// kms_batch_decrypt with the platform.v1 RPCs; both call the same
// PlatformKMSBackend method. Each answer is decoded into the platform.v1
// reply with encoding/json, the decode the SDK MCP adapter applies, so the
// test also holds the adapter's method-to-tool mapping to a usable answer.
func TestMCPKMSParity_KeyAdminAndBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tools, rpc := newParityBackendTransports(newParityStore())
	aes := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256
	disabled := platformv1.KeyStatus_KEY_STATUS_DISABLED
	sealed := append([]byte(parityKeyID+":"), []byte("row")...)

	t.Run("import_key answers the new key", func(t *testing.T) {
		var got platformv1.ImportKeyResponse
		args := map[string]interface{}{
			"name": "imported", "key_material": b64([]byte("material")),
			"key_spec": map[string]interface{}{"algorithm": float64(aes)},
		}
		require.NoError(t, parityTool(t, tools, "kms_import_key", args, &got))
		want, err := rpc.ImportKey(ctx, &platformv1.ImportKeyRequest{
			Name: "imported", KeyMaterial: []byte("material"),
			KeySpec: &platformv1.KMSKeySpec{Algorithm: aes},
		})
		require.NoError(t, err)
		require.NotNil(t, got.GetKey())
		assert.Equal(t, want.GetKey().GetKeyId(), got.GetKey().GetKeyId())
		assert.Equal(t, want.GetKey().GetVersion(), got.GetKey().GetVersion())
		assert.Equal(t, want.GetKey().GetAlgorithm(), got.GetKey().GetAlgorithm())
		assert.Equal(t, want.GetKey().GetStatus(), got.GetKey().GetStatus())
	})

	t.Run("update_key_status answers the status", func(t *testing.T) {
		var got platformv1.UpdateKeyStatusResponse
		args := map[string]interface{}{"key_id": parityKeyID, "version": float64(2), "status": float64(disabled)}
		require.NoError(t, parityTool(t, tools, "kms_update_key_status", args, &got))
		want, err := rpc.UpdateKeyStatus(ctx, &platformv1.UpdateKeyStatusRequest{KeyId: parityKeyID, Version: 2, Status: disabled})
		require.NoError(t, err)
		assert.Equal(t, want.GetKeyId(), got.GetKeyId())
		assert.Equal(t, want.GetVersion(), got.GetVersion())
		assert.Equal(t, want.GetKeyStatus(), got.GetKeyStatus())
	})

	t.Run("list_key_versions answers every version", func(t *testing.T) {
		var got platformv1.GetKeyVersionsResponse
		require.NoError(t, parityTool(t, tools, "kms_list_key_versions", map[string]interface{}{"key_id": parityKeyID}, &got))
		want, err := rpc.GetKeyVersions(ctx, &platformv1.GetKeyVersionsRequest{KeyId: parityKeyID})
		require.NoError(t, err)
		require.Len(t, got.GetVersions(), len(want.GetVersions()))
		for i, v := range want.GetVersions() {
			assert.Equal(t, v.GetVersion(), got.GetVersions()[i].GetVersion())
			assert.Equal(t, v.GetStatus(), got.GetVersions()[i].GetStatus())
		}
		assert.Equal(t, want.GetHasMore(), got.GetHasMore())
	})

	t.Run("batch_encrypt answers each item", func(t *testing.T) {
		var got platformv1.BatchEncryptResponse
		args := map[string]interface{}{"key_id": parityKeyID, "items": []interface{}{
			map[string]interface{}{"item_id": "a", "plaintext": b64([]byte("row"))},
		}}
		require.NoError(t, parityTool(t, tools, "kms_batch_encrypt", args, &got))
		want, err := rpc.BatchEncrypt(ctx, &platformv1.BatchEncryptRequest{KeyId: parityKeyID, Items: []*platformv1.BatchEncryptItem{
			{ItemId: "a", Plaintext: []byte("row")},
		}})
		require.NoError(t, err)
		require.Len(t, got.GetResults(), 1)
		assert.Equal(t, want.GetSuccessCount(), got.GetSuccessCount())
		r := want.GetResults()[0]
		assert.Equal(t, r.GetItemId(), got.GetResults()[0].GetItemId())
		assert.Equal(t, r.GetStatus().GetSuccess(), got.GetResults()[0].GetStatus().GetSuccess())
		assert.Equal(t, r.GetCiphertext(), got.GetResults()[0].GetCiphertext())
		assert.Equal(t, r.GetKeyVersion(), got.GetResults()[0].GetKeyVersion())
	})

	t.Run("batch_decrypt answers each item", func(t *testing.T) {
		var got platformv1.BatchDecryptResponse
		args := map[string]interface{}{"key_id": parityKeyID, "items": []interface{}{
			map[string]interface{}{"item_id": "a", "ciphertext": b64(sealed)},
			map[string]interface{}{"item_id": "b", "ciphertext": b64([]byte("foreign"))},
		}}
		require.NoError(t, parityTool(t, tools, "kms_batch_decrypt", args, &got))
		want, err := rpc.BatchDecrypt(ctx, &platformv1.BatchDecryptRequest{KeyId: parityKeyID, Items: []*platformv1.BatchDecryptItem{
			{ItemId: "a", Ciphertext: sealed},
			{ItemId: "b", Ciphertext: []byte("foreign")},
		}})
		require.NoError(t, err)
		require.Len(t, got.GetResults(), 2)
		assert.Equal(t, want.GetSuccessCount(), got.GetSuccessCount())
		assert.Equal(t, want.GetFailureCount(), got.GetFailureCount())
		for i, r := range want.GetResults() {
			assert.Equal(t, r.GetItemId(), got.GetResults()[i].GetItemId())
			assert.Equal(t, r.GetStatus().GetSuccess(), got.GetResults()[i].GetStatus().GetSuccess())
			assert.Equal(t, r.GetStatus().GetMessage(), got.GetResults()[i].GetStatus().GetMessage())
			assert.Equal(t, r.GetPlaintext(), got.GetResults()[i].GetPlaintext())
		}
	})

	t.Run("update_key_status of a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "status": float64(disabled)}
		mcpErr := parityTool(t, tools, "kms_update_key_status", args, &platformv1.UpdateKeyStatusResponse{})
		_, grpcErr := rpc.UpdateKeyStatus(ctx, &platformv1.UpdateKeyStatusRequest{KeyId: parityMissingID, Status: disabled})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("list_key_versions of a missing key", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_list_key_versions", map[string]interface{}{"key_id": parityMissingID}, &platformv1.GetKeyVersionsResponse{})
		_, grpcErr := rpc.GetKeyVersions(ctx, &platformv1.GetKeyVersionsRequest{KeyId: parityMissingID})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("batch_encrypt under a missing key", func(t *testing.T) {
		args := map[string]interface{}{"key_id": parityMissingID, "items": []interface{}{
			map[string]interface{}{"plaintext": b64([]byte("row"))},
		}}
		mcpErr := parityTool(t, tools, "kms_batch_encrypt", args, &platformv1.BatchEncryptResponse{})
		_, grpcErr := rpc.BatchEncrypt(ctx, &platformv1.BatchEncryptRequest{KeyId: parityMissingID, Items: []*platformv1.BatchEncryptItem{
			{Plaintext: []byte("row")},
		}})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})

	t.Run("import_key without key_spec", func(t *testing.T) {
		args := map[string]interface{}{"key_material": b64([]byte("material"))}
		mcpErr := parityTool(t, tools, "kms_import_key", args, &platformv1.ImportKeyResponse{})
		_, grpcErr := rpc.ImportKey(ctx, &platformv1.ImportKeyRequest{KeyMaterial: []byte("material")})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("batch_decrypt without items", func(t *testing.T) {
		mcpErr := parityTool(t, tools, "kms_batch_decrypt", map[string]interface{}{"key_id": parityKeyID}, &platformv1.BatchDecryptResponse{})
		_, grpcErr := rpc.BatchDecrypt(ctx, &platformv1.BatchDecryptRequest{KeyId: parityKeyID})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})
}
