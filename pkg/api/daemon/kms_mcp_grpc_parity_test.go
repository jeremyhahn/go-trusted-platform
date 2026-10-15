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
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService:     kmsService,
		CryptoService:  cryptoService,
		SecretsService: secretsService,
		Logger:         slog.Default(),
	})
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
	}
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
}
