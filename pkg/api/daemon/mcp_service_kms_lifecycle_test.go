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
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	service "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// lifecycleKMSServiceMock embeds the full baasservice KMS mock and adds
// hookable overrides for the lifecycle verbs under test.
type lifecycleKMSServiceMock struct {
	mockKMSServiceForMCPTests

	revokeKeyFunc         func(ctx context.Context, req *service.RevokeKeyRequest) (*service.RevokeKeyResponse, error)
	getKeyMetadataFunc    func(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error)
	updateKeyMetadataFunc func(ctx context.Context, req *service.UpdateKeyMetadataRequest) (*service.UpdateKeyMetadataResponse, error)
	setKeyPolicyFunc      func(ctx context.Context, req *service.SetKeyPolicyRequest) (*service.SetKeyPolicyResponse, error)
	getKeyPolicyFunc      func(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error)
	backendStatusFunc     func(ctx context.Context) (*service.BackendStatusResponse, error)
}

func (m *lifecycleKMSServiceMock) RevokeKey(ctx context.Context, req *service.RevokeKeyRequest) (*service.RevokeKeyResponse, error) {
	if m.revokeKeyFunc != nil {
		return m.revokeKeyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleKMSServiceMock) GetKeyMetadata(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
	if m.getKeyMetadataFunc != nil {
		return m.getKeyMetadataFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleKMSServiceMock) UpdateKeyMetadata(ctx context.Context, req *service.UpdateKeyMetadataRequest) (*service.UpdateKeyMetadataResponse, error) {
	if m.updateKeyMetadataFunc != nil {
		return m.updateKeyMetadataFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleKMSServiceMock) SetKeyPolicy(ctx context.Context, req *service.SetKeyPolicyRequest) (*service.SetKeyPolicyResponse, error) {
	if m.setKeyPolicyFunc != nil {
		return m.setKeyPolicyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleKMSServiceMock) GetKeyPolicy(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
	if m.getKeyPolicyFunc != nil {
		return m.getKeyPolicyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleKMSServiceMock) BackendStatus(ctx context.Context) (*service.BackendStatusResponse, error) {
	if m.backendStatusFunc != nil {
		return m.backendStatusFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

// lifecycleSecretsServiceMock implements baasservice.SecretsService with
// hookable overrides for the verbs under test.
type lifecycleSecretsServiceMock struct {
	storeSecretFunc       func(ctx context.Context, req *service.StoreSecretRequest) (*service.StoreSecretResponse, error)
	getSecretFunc         func(ctx context.Context, req *service.GetSecretRequest) (*service.GetSecretResponse, error)
	listSecretsFunc       func(ctx context.Context, req *service.ListSecretsRequest) (*service.ListSecretsResponse, error)
	deleteSecretFunc      func(ctx context.Context, req *service.DeleteSecretRequest) (*service.DeleteSecretResponse, error)
	setRotationPolicyFunc func(ctx context.Context, req *service.SetRotationPolicyRequest) (*service.SetRotationPolicyResponse, error)
	getRotationPolicyFunc func(ctx context.Context, req *service.GetRotationPolicyRequest) (*service.GetRotationPolicyResponse, error)
}

var _ service.SecretsService = (*lifecycleSecretsServiceMock)(nil)

func (m *lifecycleSecretsServiceMock) StoreSecret(ctx context.Context, req *service.StoreSecretRequest) (*service.StoreSecretResponse, error) {
	if m.storeSecretFunc != nil {
		return m.storeSecretFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) EnsureSecret(ctx context.Context, req *service.EnsureSecretRequest) (*service.EnsureSecretResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) GetSecret(ctx context.Context, req *service.GetSecretRequest) (*service.GetSecretResponse, error) {
	if m.getSecretFunc != nil {
		return m.getSecretFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) ListSecrets(ctx context.Context, req *service.ListSecretsRequest) (*service.ListSecretsResponse, error) {
	if m.listSecretsFunc != nil {
		return m.listSecretsFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) DeleteSecret(ctx context.Context, req *service.DeleteSecretRequest) (*service.DeleteSecretResponse, error) {
	if m.deleteSecretFunc != nil {
		return m.deleteSecretFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) GetSecretVersion(ctx context.Context, req *service.GetSecretVersionRequest) (*service.GetSecretVersionResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) ListSecretVersions(ctx context.Context, req *service.ListSecretVersionsRequest) (*service.ListSecretVersionsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) RollbackSecret(ctx context.Context, req *service.RollbackSecretRequest) (*service.RollbackSecretResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) RotateSecret(ctx context.Context, req *service.RotateSecretRequest) (*service.RotateSecretResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) SetRotationPolicy(ctx context.Context, req *service.SetRotationPolicyRequest) (*service.SetRotationPolicyResponse, error) {
	if m.setRotationPolicyFunc != nil {
		return m.setRotationPolicyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) GetRotationPolicy(ctx context.Context, req *service.GetRotationPolicyRequest) (*service.GetRotationPolicyResponse, error) {
	if m.getRotationPolicyFunc != nil {
		return m.getRotationPolicyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) UpdateSecretStatus(ctx context.Context, req *service.UpdateSecretStatusRequest) (*service.UpdateSecretStatusResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) GetSecretsByPrefix(ctx context.Context, req *service.GetSecretsByPrefixRequest) (*service.GetSecretsByPrefixResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *lifecycleSecretsServiceMock) WatchSecretsByPrefix(ctx context.Context, req *service.WatchSecretsRequest) (<-chan *service.SecretChange, error) {
	return nil, errors.New("not implemented")
}

// newLifecycleProvider builds an MCP provider with the given KMS and
// secrets service mocks.
func newLifecycleProvider(kms service.KMSService, secretsService service.SecretsService) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService:     kms,
		SecretsService: secretsService,
		Logger:         slog.Default(),
	})
}

// =============================================================================
// MCPServiceProvider KMS lifecycle
// =============================================================================

func TestMCPServiceProviderKMSRevokeKey(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			revokeKeyFunc: func(ctx context.Context, req *service.RevokeKeyRequest) (*service.RevokeKeyResponse, error) {
				assert.Equal(t, "key-1", req.KeyID)
				assert.Equal(t, "compromised", req.Reason)
				return &service.RevokeKeyResponse{KeyID: req.KeyID}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSRevokeKey(ctx, "key-1", "compromised")
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		_, err := provider.KMSRevokeKey(ctx, "", "reason")
		var invalidErr ErrKMSInvalidParameter
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		provider := newLifecycleProvider(nil, nil)
		_, err := provider.KMSRevokeKey(ctx, "key-1", "reason")
		var unavailableErr ErrServiceNotAvailable
		assert.ErrorAs(t, err, &unavailableErr)
	})

	t.Run("BackendError", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		_, err := provider.KMSRevokeKey(ctx, "key-1", "reason")
		var opErr ErrKMSOperationFailed
		assert.ErrorAs(t, err, &opErr)
	})
}

func TestMCPServiceProviderKMSKeyMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("GetSuccess", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			getKeyMetadataFunc: func(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
				return &service.GetKeyMetadataResponse{
					Metadata: &service.KeyMetadata{KeyID: req.KeyID, Name: "test"},
				}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSGetKeyMetadata(ctx, "key-1")
		require.NoError(t, err)
		meta, ok := result.(*service.KeyMetadata)
		require.True(t, ok)
		assert.Equal(t, "key-1", meta.KeyID)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			getKeyMetadataFunc: func(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
				return nil, sdkerrors.NewNotFound("kms", "no key "+req.KeyID)
			},
		}
		provider := newLifecycleProvider(mock, nil)
		_, err := provider.KMSGetKeyMetadata(ctx, "missing")
		var notFoundErr ErrKMSKeyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("UpdateSuccess", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			updateKeyMetadataFunc: func(ctx context.Context, req *service.UpdateKeyMetadataRequest) (*service.UpdateKeyMetadataResponse, error) {
				require.NotNil(t, req.Name)
				assert.Equal(t, "renamed", *req.Name)
				assert.Nil(t, req.Description)
				return &service.UpdateKeyMetadataResponse{
					Metadata: &service.KeyMetadata{KeyID: req.KeyID, Name: *req.Name},
				}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSUpdateKeyMetadata(ctx, &mcp.KMSUpdateKeyMetadataRequest{
			KeyID: "key-1",
			Name:  "renamed",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("UpdateMissingKeyID", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		_, err := provider.KMSUpdateKeyMetadata(ctx, &mcp.KMSUpdateKeyMetadataRequest{})
		var invalidErr ErrKMSInvalidParameter
		assert.ErrorAs(t, err, &invalidErr)
	})
}

func TestMCPServiceProviderKMSKeyPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("SetSuccess", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			setKeyPolicyFunc: func(ctx context.Context, req *service.SetKeyPolicyRequest) (*service.SetKeyPolicyResponse, error) {
				require.NotNil(t, req.Policy)
				assert.Equal(t, "key-1", req.Policy.KeyID)
				assert.Len(t, req.Policy.AllowedOperations, 1)
				assert.True(t, req.Policy.RequireMFA)
				require.NotNil(t, req.Policy.MaxUsageCount)
				assert.Equal(t, uint64(10), *req.Policy.MaxUsageCount)
				require.NotNil(t, req.Policy.ExpiresAt)
				return &service.SetKeyPolicyResponse{KeyID: req.KeyID, PolicyVersion: 1}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSSetKeyPolicy(ctx, &mcp.KMSSetKeyPolicyRequest{
			KeyID:             "key-1",
			AllowedOperations: []string{"sign"},
			RequireMFA:        true,
			MaxUsageCount:     10,
			ExpiresAt:         time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("SetInvalidOperation", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		_, err := provider.KMSSetKeyPolicy(ctx, &mcp.KMSSetKeyPolicyRequest{
			KeyID:             "key-1",
			AllowedOperations: []string{"launch-missiles"},
		})
		require.Error(t, err)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			getKeyPolicyFunc: func(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
				return &service.GetKeyPolicyResponse{
					Policy: &service.KeyPolicy{KeyID: req.KeyID, Version: 3},
				}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSGetKeyPolicy(ctx, "key-1")
		require.NoError(t, err)
		policy, ok := result.(*service.KeyPolicy)
		require.True(t, ok)
		assert.Equal(t, uint64(3), policy.Version)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			getKeyPolicyFunc: func(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
				return nil, sdkerrors.NewNotFound("kms", "no policy for "+req.KeyID)
			},
		}
		provider := newLifecycleProvider(mock, nil)
		_, err := provider.KMSGetKeyPolicy(ctx, "key-1")
		var notFoundErr ErrKMSKeyPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}

// TestMCPServiceProviderKMSLookupClasses checks that a failed key lookup
// keeps the backend's class on MCP, as it does on gRPC (#304): only a
// NotFound backend error answers "key not found".
func TestMCPServiceProviderKMSLookupClasses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found", sdkerrors.NewNotFound("kms", "no key"), codes.NotFound},
		{"invalid input", sdkerrors.NewInvalidInput("kms", "bad key id"), codes.InvalidArgument},
		{"forbidden", sdkerrors.NewForbidden("kms", "no"), codes.PermissionDenied},
		{"unavailable", sdkerrors.NewUnavailable("kms", "down"), codes.Unavailable},
		{"no class", errors.New("key not found"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mock := &lifecycleKMSServiceMock{
				mockKMSServiceForMCPTests: mockKMSServiceForMCPTests{
					getKeyFunc: func(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error) {
						return nil, tt.err
					},
				},
				getKeyMetadataFunc: func(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
					return nil, tt.err
				},
				getKeyPolicyFunc: func(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
					return nil, tt.err
				},
			}
			provider := newLifecycleProvider(mock, nil)

			_, err := provider.KMSGetKey(ctx, "k", 0)
			assert.Equal(t, tt.want, errclass.Code(err), "GetKey: %v", err)
			_, err = provider.KMSGetKeyMetadata(ctx, "k")
			assert.Equal(t, tt.want, errclass.Code(err), "GetKeyMetadata: %v", err)
			_, err = provider.KMSGetKeyPolicy(ctx, "k")
			assert.Equal(t, tt.want, errclass.Code(err), "GetKeyPolicy: %v", err)
		})
	}
}

func TestMCPServiceProviderKMSAlgorithmsAndStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		algorithms, err := provider.KMSGetSupportedAlgorithms(ctx)
		require.NoError(t, err)
		assert.Contains(t, algorithms, "AES-256-GCM")
	})

	t.Run("SupportedAlgorithmsUnavailable", func(t *testing.T) {
		provider := newLifecycleProvider(nil, nil)
		_, err := provider.KMSGetSupportedAlgorithms(ctx)
		var unavailableErr ErrServiceNotAvailable
		assert.ErrorAs(t, err, &unavailableErr)
	})

	t.Run("BackendStatus", func(t *testing.T) {
		mock := &lifecycleKMSServiceMock{
			backendStatusFunc: func(ctx context.Context) (*service.BackendStatusResponse, error) {
				return &service.BackendStatusResponse{BackendType: "software", Status: "healthy"}, nil
			},
		}
		provider := newLifecycleProvider(mock, nil)

		result, err := provider.KMSBackendStatus(ctx)
		require.NoError(t, err)
		statusResp, ok := result.(*service.BackendStatusResponse)
		require.True(t, ok)
		assert.Equal(t, "software", statusResp.BackendType)
	})

	t.Run("BackendStatusError", func(t *testing.T) {
		provider := newLifecycleProvider(&lifecycleKMSServiceMock{}, nil)
		_, err := provider.KMSBackendStatus(ctx)
		var opErr ErrKMSOperationFailed
		assert.ErrorAs(t, err, &opErr)
	})
}

// =============================================================================
// MCPServiceProvider secrets
// =============================================================================

func TestMCPServiceProviderSecretCRUD(t *testing.T) {
	ctx := context.Background()

	t.Run("StoreSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			storeSecretFunc: func(ctx context.Context, req *service.StoreSecretRequest) (*service.StoreSecretResponse, error) {
				assert.Equal(t, "db/password", req.SecretID)
				assert.Equal(t, []byte("hunter2"), req.Data)
				return &service.StoreSecretResponse{SecretID: req.SecretID, Version: 1}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)

		result, err := provider.SecretStore(ctx, &mcp.SecretStoreRequest{
			SecretID: "db/password",
			Data:     []byte("hunter2"),
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("StoreMissingData", func(t *testing.T) {
		provider := newLifecycleProvider(nil, &lifecycleSecretsServiceMock{})
		_, err := provider.SecretStore(ctx, &mcp.SecretStoreRequest{SecretID: "db/password"})
		var invalidErr ErrKMSInvalidParameter
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			getSecretFunc: func(ctx context.Context, req *service.GetSecretRequest) (*service.GetSecretResponse, error) {
				return &service.GetSecretResponse{SecretID: req.SecretID, Version: req.Version, Data: []byte("hunter2")}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)

		result, err := provider.SecretGet(ctx, "db/password", 2)
		require.NoError(t, err)
		resp, ok := result.(*service.GetSecretResponse)
		require.True(t, ok)
		assert.Equal(t, uint64(2), resp.Version)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		provider := newLifecycleProvider(nil, &lifecycleSecretsServiceMock{})
		_, err := provider.SecretGet(ctx, "missing", 0)
		var notFoundErr ErrSecretNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("ListSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			listSecretsFunc: func(ctx context.Context, req *service.ListSecretsRequest) (*service.ListSecretsResponse, error) {
				assert.Equal(t, 25, req.Limit)
				return &service.ListSecretsResponse{}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)

		_, err := provider.SecretList(ctx, 25)
		require.NoError(t, err)
	})

	t.Run("DeleteSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			deleteSecretFunc: func(ctx context.Context, req *service.DeleteSecretRequest) (*service.DeleteSecretResponse, error) {
				return &service.DeleteSecretResponse{}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)
		require.NoError(t, provider.SecretDelete(ctx, "db/password"))
	})

	t.Run("DeleteUnavailable", func(t *testing.T) {
		provider := newLifecycleProvider(nil, nil)
		err := provider.SecretDelete(ctx, "db/password")
		var unavailableErr ErrServiceNotAvailable
		assert.ErrorAs(t, err, &unavailableErr)
	})
}

func TestMCPServiceProviderSecretRotationPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("SetSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			setRotationPolicyFunc: func(ctx context.Context, req *service.SetRotationPolicyRequest) (*service.SetRotationPolicyResponse, error) {
				require.NotNil(t, req.Policy)
				assert.True(t, req.Policy.Enabled)
				assert.Equal(t, time.Hour, req.Policy.Interval)
				assert.Equal(t, 9, req.Policy.RetainVersions)
				return &service.SetRotationPolicyResponse{SecretID: req.SecretID, Policy: req.Policy}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)

		result, err := provider.SecretSetRotationPolicy(ctx, &mcp.SecretSetRotationPolicyRequest{
			SecretID:        "db/password",
			Enabled:         true,
			IntervalSeconds: 3600,
			RetainVersions:  9,
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("SetMissingSecretID", func(t *testing.T) {
		provider := newLifecycleProvider(nil, &lifecycleSecretsServiceMock{})
		_, err := provider.SecretSetRotationPolicy(ctx, &mcp.SecretSetRotationPolicyRequest{})
		var invalidErr ErrKMSInvalidParameter
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		mock := &lifecycleSecretsServiceMock{
			getRotationPolicyFunc: func(ctx context.Context, req *service.GetRotationPolicyRequest) (*service.GetRotationPolicyResponse, error) {
				return &service.GetRotationPolicyResponse{
					SecretID: req.SecretID,
					Policy:   &service.SecretRotationPolicy{RetainVersions: 4},
				}, nil
			},
		}
		provider := newLifecycleProvider(nil, mock)

		result, err := provider.SecretGetRotationPolicy(ctx, "db/password")
		require.NoError(t, err)
		resp, ok := result.(*service.GetRotationPolicyResponse)
		require.True(t, ok)
		assert.Equal(t, 4, resp.Policy.RetainVersions)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		provider := newLifecycleProvider(nil, &lifecycleSecretsServiceMock{})
		_, err := provider.SecretGetRotationPolicy(ctx, "db/password")
		var notFoundErr ErrSecretRotationPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}
