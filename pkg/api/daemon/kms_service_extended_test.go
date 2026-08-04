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
	"context"
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
)

// extKMSClientMock embeds mockSDKKMSClient and overrides the key-lifecycle
// verbs with configurable hooks.
type extKMSClientMock struct {
	mockSDKKMSClient

	revokeKeyFn              func(ctx context.Context, keyID string) error
	getKeyMetadataFn         func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error)
	updateKeyMetadataFn      func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error)
	setKeyPolicyFn           func(ctx context.Context, req *kms.SetKeyPolicyRequest) error
	getKeyPolicyFn           func(ctx context.Context, keyID string) (*kms.KeyPolicy, error)
	getSupportedAlgorithmsFn func(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error)
	backendStatusFn          func(ctx context.Context) (*kms.BackendStatusResponse, error)

	lastRevokedKey       string
	lastSetPolicyReq     *kms.SetKeyPolicyRequest
	lastUpdateMetaReq    *kms.UpdateKeyMetadataRequest
	lastMetadataKeyID    string
	lastGetPolicyKeyID   string
	backendStatusInvoked bool
}

var _ quicbaas.KMSClient = (*extKMSClientMock)(nil)

func (m *extKMSClientMock) RevokeKey(ctx context.Context, keyID, _ string) error {
	m.lastRevokedKey = keyID
	if m.revokeKeyFn != nil {
		return m.revokeKeyFn(ctx, keyID)
	}
	return errKMSLifecycleMock{method: "RevokeKey"}
}

func (m *extKMSClientMock) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	m.lastMetadataKeyID = keyID
	if m.getKeyMetadataFn != nil {
		return m.getKeyMetadataFn(ctx, keyID)
	}
	return nil, errKMSLifecycleMock{method: "GetKeyMetadata"}
}

func (m *extKMSClientMock) UpdateKeyMetadata(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
	m.lastUpdateMetaReq = req
	if m.updateKeyMetadataFn != nil {
		return m.updateKeyMetadataFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "UpdateKeyMetadata"}
}

func (m *extKMSClientMock) SetKeyPolicy(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
	m.lastSetPolicyReq = req
	if m.setKeyPolicyFn != nil {
		return m.setKeyPolicyFn(ctx, req)
	}
	return errKMSLifecycleMock{method: "SetKeyPolicy"}
}

func (m *extKMSClientMock) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	m.lastGetPolicyKeyID = keyID
	if m.getKeyPolicyFn != nil {
		return m.getKeyPolicyFn(ctx, keyID)
	}
	return nil, errKMSLifecycleMock{method: "GetKeyPolicy"}
}

func (m *extKMSClientMock) GetSupportedAlgorithms(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
	if m.getSupportedAlgorithmsFn != nil {
		return m.getSupportedAlgorithmsFn(ctx)
	}
	return nil, errKMSLifecycleMock{method: "GetSupportedAlgorithms"}
}

func (m *extKMSClientMock) BackendStatus(ctx context.Context) (*kms.BackendStatusResponse, error) {
	m.backendStatusInvoked = true
	if m.backendStatusFn != nil {
		return m.backendStatusFn(ctx)
	}
	return nil, errKMSLifecycleMock{method: "BackendStatus"}
}

// extSecretsClientMock implements quicbaas.SecretsClient with hooks for
// the rotation-policy pair; all other methods fail.
type extSecretsClientMock struct {
	setRotationPolicyFn func(ctx context.Context, req *secrets.SetRotationPolicyRequest) error
	getRotationPolicyFn func(ctx context.Context, secretID string) (*secrets.RotationPolicy, error)

	lastSetPolicyReq  *secrets.SetRotationPolicyRequest
	lastGetPolicyID   string
	lastDeletedSecret string
}

var _ quicbaas.SecretsClient = (*extSecretsClientMock)(nil)

func (m *extSecretsClientMock) Store(ctx context.Context, req *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	return nil, errKMSLifecycleMock{method: "Store"}
}

func (m *extSecretsClientMock) Get(ctx context.Context, path string, opts ...secrets.GetOption) (*secrets.Secret, error) {
	return nil, errKMSLifecycleMock{method: "Get"}
}

func (m *extSecretsClientMock) List(ctx context.Context, prefix string) (*secrets.ListSecretsResponse, error) {
	return nil, errKMSLifecycleMock{method: "List"}
}

func (m *extSecretsClientMock) Delete(ctx context.Context, path string) error {
	m.lastDeletedSecret = path
	return errKMSLifecycleMock{method: "Delete"}
}

func (m *extSecretsClientMock) Ensure(ctx context.Context, req *secrets.EnsureSecretRequest) (*secrets.EnsureSecretResponse, error) {
	return nil, errKMSLifecycleMock{method: "Ensure"}
}

func (m *extSecretsClientMock) GetVersion(ctx context.Context, req *secrets.GetSecretVersionRequest) (*secrets.SecretVersionInfo, error) {
	return nil, errKMSLifecycleMock{method: "GetVersion"}
}

func (m *extSecretsClientMock) ListVersions(ctx context.Context, secretID string) (*secrets.ListSecretVersionsResponse, error) {
	return nil, errKMSLifecycleMock{method: "ListVersions"}
}

func (m *extSecretsClientMock) Rotate(ctx context.Context, req *secrets.RotateSecretRequest) (*secrets.RotateSecretResponse, error) {
	return nil, errKMSLifecycleMock{method: "Rotate"}
}

func (m *extSecretsClientMock) Rollback(ctx context.Context, req *secrets.RollbackSecretRequest) (*secrets.RollbackSecretResponse, error) {
	return nil, errKMSLifecycleMock{method: "Rollback"}
}

func (m *extSecretsClientMock) UpdateStatus(ctx context.Context, req *secrets.UpdateSecretStatusRequest) error {
	return errKMSLifecycleMock{method: "UpdateStatus"}
}

func (m *extSecretsClientMock) SetRotationPolicy(ctx context.Context, req *secrets.SetRotationPolicyRequest) error {
	m.lastSetPolicyReq = req
	if m.setRotationPolicyFn != nil {
		return m.setRotationPolicyFn(ctx, req)
	}
	return errKMSLifecycleMock{method: "SetRotationPolicy"}
}

func (m *extSecretsClientMock) GetRotationPolicy(ctx context.Context, secretID string) (*secrets.RotationPolicy, error) {
	m.lastGetPolicyID = secretID
	if m.getRotationPolicyFn != nil {
		return m.getRotationPolicyFn(ctx, secretID)
	}
	return nil, errKMSLifecycleMock{method: "GetRotationPolicy"}
}

// requireGRPCCode asserts err is a gRPC status error with the given code.
func requireGRPCCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got %v", err)
	assert.Equal(t, code, st.Code())
}

// =============================================================================
// KMSServerAdapter.RevokeKey
// =============================================================================

func TestKMSServerAdapterRevokeKey(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			revokeKeyFn: func(ctx context.Context, keyID string) error { return nil },
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "key-1", Reason: "compromised"})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.KeyId)
		assert.Equal(t, pb.KeyStatus_KEY_STATUS_DISABLED, resp.Status)
		assert.Equal(t, "key-1", mock.lastRevokedKey)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.RevokeKey(ctx, &pb.RevokeKeyRequest{})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "key-1"})
		requireGRPCCode(t, err, codes.Internal)
	})

	t.Run("NilClient", func(t *testing.T) {
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "key-1"})
		requireGRPCCode(t, err, codes.Unavailable)
	})
}

// =============================================================================
// KMSServerAdapter.GetKeyMetadata / UpdateKeyMetadata
// =============================================================================

func TestKMSServerAdapterGetKeyMetadata(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1700000000, 0)

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			getKeyMetadataFn: func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:              keyID,
					Name:               "prod-key",
					Description:        "production key",
					Algorithm:          kms.AlgorithmAES256GCM,
					Status:             kms.KeyStatusEnabled,
					Usage:              []kms.KeyUsage{kms.KeyUsageEncrypt, kms.KeyUsageDecrypt},
					Version:            3,
					Exportable:         true,
					DeletionProtection: true,
					CreatedAt:          created,
					UpdatedAt:          created.Add(time.Hour),
					Tags:               map[string]string{"env": "prod"},
					Owner:              "alice",
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "key-1"})
		require.NoError(t, err)
		require.NotNil(t, resp.Metadata)
		assert.Equal(t, "key-1", resp.Metadata.KeyId)
		assert.Equal(t, "prod-key", resp.Metadata.Name)
		assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, resp.Metadata.Algorithm)
		assert.Equal(t, pb.KeyStatus_KEY_STATUS_ENABLED, resp.Metadata.Status)
		assert.Equal(t, []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_DECRYPT}, resp.Metadata.Usage)
		assert.Equal(t, uint64(3), resp.Metadata.Version)
		assert.True(t, resp.Metadata.Exportable)
		assert.True(t, resp.Metadata.DeletionProtection)
		assert.Equal(t, created.Unix(), resp.Metadata.CreatedAt)
		assert.Equal(t, created.Add(time.Hour).Unix(), resp.Metadata.UpdatedAt)
		assert.Zero(t, resp.Metadata.LastUsedAt)
		assert.Equal(t, "prod", resp.Metadata.Tags["env"])
		assert.Equal(t, "alice", resp.Metadata.Owner)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("NotFound", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "missing"})
		requireGRPCCode(t, err, codes.NotFound)
	})
}

func TestKMSServerAdapterUpdateKeyMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			updateKeyMetadataFn: func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:       req.KeyID,
					Name:        req.Name,
					Description: req.Description,
					Algorithm:   kms.AlgorithmED25519,
					Tags:        req.Tags,
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{
			KeyId:       "key-1",
			Name:        "renamed",
			Description: "updated",
			Tags:        map[string]string{"team": "sec"},
			RemoveTags:  []string{"old"},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.Metadata)
		assert.Equal(t, "renamed", resp.Metadata.Name)
		assert.Equal(t, "updated", resp.Metadata.Description)
		require.NotNil(t, mock.lastUpdateMetaReq)
		assert.Equal(t, []string{"old"}, mock.lastUpdateMetaReq.RemoveTags)
		assert.Equal(t, "sec", mock.lastUpdateMetaReq.Tags["team"])
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{KeyId: "key-1"})
		requireGRPCCode(t, err, codes.Internal)
	})
}

// =============================================================================
// KMSServerAdapter.SetKeyPolicy / GetKeyPolicy
// =============================================================================

func TestKMSServerAdapterSetKeyPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			setKeyPolicyFn: func(ctx context.Context, req *kms.SetKeyPolicyRequest) error { return nil },
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		expires := time.Now().Add(24 * time.Hour).Unix()
		resp, err := adapter.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{
			KeyId: "key-1",
			Policy: &pb.KeyPolicy{
				Version:           2,
				AllowedOperations: []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN},
				AllowedPrincipals: []string{"user:alice"},
				DeniedPrincipals:  []string{"user:mallory"},
				ExpiresAt:         expires,
				RotationRequired:  true,
				MaxUsageCount:     100,
				RequireMfa:        true,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.KeyId)
		assert.Equal(t, uint64(2), resp.PolicyVersion)

		require.NotNil(t, mock.lastSetPolicyReq)
		policy := mock.lastSetPolicyReq.Policy
		require.NotNil(t, policy)
		assert.Equal(t, "key-1", policy.KeyID)
		assert.Equal(t, []kms.KeyUsage{kms.KeyUsageSign}, policy.AllowedOperations)
		assert.Equal(t, []string{"user:alice"}, policy.AllowedPrincipals)
		assert.Equal(t, []string{"user:mallory"}, policy.DeniedPrincipals)
		assert.Equal(t, expires, policy.ExpiresAt.Unix())
		assert.True(t, policy.RotationRequired)
		assert.Equal(t, uint64(100), policy.MaxUsageCount)
		assert.True(t, policy.RequireMFA)
	})

	t.Run("MissingPolicy", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: "key-1"})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{Policy: &pb.KeyPolicy{}})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: "key-1", Policy: &pb.KeyPolicy{}})
		requireGRPCCode(t, err, codes.Internal)
	})
}

func TestKMSServerAdapterGetKeyPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		updated := time.Unix(1700000123, 0)
		mock := &extKMSClientMock{
			getKeyPolicyFn: func(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
				return &kms.KeyPolicy{
					KeyID:             keyID,
					Version:           7,
					AllowedOperations: []kms.KeyUsage{kms.KeyUsageEncrypt, kms.KeyUsageVerify},
					AllowedPrincipals: []string{"role:admin"},
					RotationRequired:  true,
					MaxUsageCount:     42,
					RequireMFA:        true,
					UpdatedAt:         updated,
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "key-1"})
		require.NoError(t, err)
		require.NotNil(t, resp.Policy)
		assert.Equal(t, "key-1", resp.Policy.KeyId)
		assert.Equal(t, uint64(7), resp.Policy.Version)
		assert.Equal(t, []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_VERIFY}, resp.Policy.AllowedOperations)
		assert.Equal(t, []string{"role:admin"}, resp.Policy.AllowedPrincipals)
		assert.True(t, resp.Policy.RotationRequired)
		assert.Equal(t, uint64(42), resp.Policy.MaxUsageCount)
		assert.True(t, resp.Policy.RequireMfa)
		assert.Equal(t, updated.Unix(), resp.Policy.UpdatedAt)
		assert.Zero(t, resp.Policy.ExpiresAt)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("NotFound", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "missing"})
		requireGRPCCode(t, err, codes.NotFound)
	})
}

// =============================================================================
// KMSServerAdapter.GetSupportedAlgorithms / BackendStatus
// =============================================================================

func TestKMSServerAdapterGetSupportedAlgorithms(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			getSupportedAlgorithmsFn: func(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
				return &kms.SupportedAlgorithmsResponse{Algorithms: []string{"AES-256-GCM", "ED25519"}}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
		require.NoError(t, err)
		assert.Equal(t, []string{"AES-256-GCM", "ED25519"}, resp.Algorithms)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
		requireGRPCCode(t, err, codes.Internal)
	})

	t.Run("NilClient", func(t *testing.T) {
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
		requireGRPCCode(t, err, codes.Unavailable)
	})
}

func TestKMSServerAdapterBackendStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extKMSClientMock{
			backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
				return &kms.BackendStatusResponse{
					BackendType:  "tpm2",
					Status:       "healthy",
					Device:       "/dev/tpmrm0",
					Region:       "",
					KeyID:        "srk",
					PCRBanks:     []string{"SHA256"},
					PCRRegisters: []int{0, 7},
					Capabilities: map[string]bool{"seal": true},
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.BackendStatus(ctx, &pb.BackendStatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, "tpm2", resp.BackendType)
		assert.Equal(t, "healthy", resp.Status)
		assert.Equal(t, "/dev/tpmrm0", resp.Device)
		assert.Equal(t, "srk", resp.KeyId)
		assert.Equal(t, []string{"SHA256"}, resp.PcrBanks)
		assert.Equal(t, []int32{0, 7}, resp.PcrRegisters)
		assert.True(t, resp.Capabilities["seal"])
		assert.True(t, mock.backendStatusInvoked)
		assert.NotZero(t, resp.Timestamp)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewKMSServerAdapter(&extKMSClientMock{}, slog.Default())
		_, err := adapter.BackendStatus(ctx, &pb.BackendStatusRequest{})
		requireGRPCCode(t, err, codes.Internal)
	})
}

// =============================================================================
// SecretsServerAdapter.SetRotationPolicy / GetRotationPolicy
// =============================================================================

func TestSecretsServerAdapterSetRotationPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &extSecretsClientMock{
			setRotationPolicyFn: func(ctx context.Context, req *secrets.SetRotationPolicyRequest) error { return nil },
		}
		adapter := NewSecretsServerAdapter(mock, slog.Default())

		resp, err := adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{
			SecretId: "db/password",
			Policy: &pb.SecretRotationPolicy{
				Enabled:         true,
				IntervalSeconds: 86400,
				RetainVersions:  5,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "db/password", resp.SecretId)
		require.NotNil(t, resp.Policy)
		assert.Equal(t, int32(5), resp.Policy.RetainVersions)

		require.NotNil(t, mock.lastSetPolicyReq)
		assert.Equal(t, "db/password", mock.lastSetPolicyReq.SecretID)
		require.NotNil(t, mock.lastSetPolicyReq.Policy)
		assert.True(t, mock.lastSetPolicyReq.Policy.Enabled)
		assert.Equal(t, 24*time.Hour, mock.lastSetPolicyReq.Policy.Interval)
		assert.Equal(t, 5, mock.lastSetPolicyReq.Policy.RetainVersions)
	})

	t.Run("MissingSecretID", func(t *testing.T) {
		adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
		_, err := adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{Policy: &pb.SecretRotationPolicy{}})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingPolicy", func(t *testing.T) {
		adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
		_, err := adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{SecretId: "db/password"})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("BackendError", func(t *testing.T) {
		adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
		_, err := adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{
			SecretId: "db/password",
			Policy:   &pb.SecretRotationPolicy{},
		})
		requireGRPCCode(t, err, codes.Internal)
	})
}

func TestSecretsServerAdapterGetRotationPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		next := time.Unix(1800000000, 0)
		mock := &extSecretsClientMock{
			getRotationPolicyFn: func(ctx context.Context, secretID string) (*secrets.RotationPolicy, error) {
				return &secrets.RotationPolicy{
					Enabled:        true,
					Interval:       48 * time.Hour,
					NextRotation:   next,
					RetainVersions: 3,
					RotationLambda: "arn:fn",
				}, nil
			},
		}
		adapter := NewSecretsServerAdapter(mock, slog.Default())

		resp, err := adapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: "db/password"})
		require.NoError(t, err)
		assert.Equal(t, "db/password", resp.SecretId)
		require.NotNil(t, resp.Policy)
		assert.True(t, resp.Policy.Enabled)
		assert.Equal(t, int64(48*3600), resp.Policy.IntervalSeconds)
		assert.Equal(t, next.Unix(), resp.Policy.NextRotation)
		assert.Equal(t, int32(3), resp.Policy.RetainVersions)
		assert.Equal(t, "arn:fn", resp.Policy.RotationLambda)
		assert.Equal(t, "db/password", mock.lastGetPolicyID)
	})

	t.Run("MissingSecretID", func(t *testing.T) {
		adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
		_, err := adapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{})
		requireGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("NotFound", func(t *testing.T) {
		adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
		_, err := adapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: "missing"})
		requireGRPCCode(t, err, codes.NotFound)
	})
}

// =============================================================================
// kmsQUICAdapter delegation for the extended verbs
// =============================================================================

func TestKMSQUICAdapterExtendedDelegation(t *testing.T) {
	ctx := context.Background()
	kmsMock := &extKMSClientMock{
		revokeKeyFn: func(ctx context.Context, keyID string) error { return nil },
		getKeyMetadataFn: func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
			return &kms.KeyMetadataResponse{KeyID: keyID}, nil
		},
		updateKeyMetadataFn: func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
			return &kms.KeyMetadataResponse{KeyID: req.KeyID, Name: req.Name}, nil
		},
		setKeyPolicyFn: func(ctx context.Context, req *kms.SetKeyPolicyRequest) error { return nil },
		getKeyPolicyFn: func(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
			return &kms.KeyPolicy{KeyID: keyID}, nil
		},
		getSupportedAlgorithmsFn: func(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
			return &kms.SupportedAlgorithmsResponse{Algorithms: []string{"AES-256-GCM"}}, nil
		},
		backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
			return &kms.BackendStatusResponse{BackendType: "software", Status: "healthy"}, nil
		},
	}
	adapter := newKMSQUICAdapter(
		NewKMSServerAdapter(kmsMock, slog.Default()),
		NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default()),
	)

	t.Run("RevokeKey", func(t *testing.T) {
		resp, err := adapter.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "key-1"})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.KeyId)
	})

	t.Run("GetKeyMetadata", func(t *testing.T) {
		resp, err := adapter.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "key-1"})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.Metadata.KeyId)
	})

	t.Run("UpdateKeyMetadata", func(t *testing.T) {
		resp, err := adapter.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{KeyId: "key-1", Name: "renamed"})
		require.NoError(t, err)
		assert.Equal(t, "renamed", resp.Metadata.Name)
	})

	t.Run("SetKeyPolicy", func(t *testing.T) {
		resp, err := adapter.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: "key-1", Policy: &pb.KeyPolicy{}})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.KeyId)
	})

	t.Run("GetKeyPolicy", func(t *testing.T) {
		resp, err := adapter.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "key-1"})
		require.NoError(t, err)
		assert.Equal(t, "key-1", resp.Policy.KeyId)
	})

	t.Run("GetSupportedAlgorithms", func(t *testing.T) {
		resp, err := adapter.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
		require.NoError(t, err)
		assert.Equal(t, []string{"AES-256-GCM"}, resp.Algorithms)
	})

	t.Run("BackendStatus", func(t *testing.T) {
		resp, err := adapter.BackendStatus(ctx, &pb.BackendStatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, "software", resp.BackendType)
	})

	t.Run("RevokeKeyError", func(t *testing.T) {
		errAdapter := newKMSQUICAdapter(
			NewKMSServerAdapter(&extKMSClientMock{}, slog.Default()),
			NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default()),
		)
		_, err := errAdapter.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "key-1"})
		requireGRPCCode(t, err, codes.Internal)
	})
}
