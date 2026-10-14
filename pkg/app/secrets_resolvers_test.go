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

package app

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/dynamicsecrets"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// mockDecrypter — minimal crypto.Decrypter for IDevID resolver tests
// =============================================================================

type mockDecrypter struct {
	publicKey crypto.PublicKey
	decryptFn func(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

func (m *mockDecrypter) Public() crypto.PublicKey { return m.publicKey }

func (m *mockDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if m.decryptFn != nil {
		return m.decryptFn(rand, ciphertext, opts)
	}
	return nil, errors.New("mock: Decrypt not configured")
}

// =============================================================================
// Mock implementations for DynamicSecrets client
// =============================================================================

type mockDynamicSecretsClient struct {
	generateFn func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error)
}

func (m *mockDynamicSecretsClient) CreateRole(ctx context.Context, req *dynamicsecrets.CreateRoleRequest) (*dynamicsecrets.CreateRoleResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) GetRole(ctx context.Context, req *dynamicsecrets.GetRoleRequest) (*dynamicsecrets.GetRoleResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) ListRoles(ctx context.Context, req *dynamicsecrets.ListRolesRequest) (*dynamicsecrets.ListRolesResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) DeleteRole(ctx context.Context, req *dynamicsecrets.DeleteRoleRequest) (*dynamicsecrets.DeleteRoleResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) GenerateCredential(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
	if m.generateFn != nil {
		return m.generateFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockDynamicSecretsClient) RenewLease(ctx context.Context, req *dynamicsecrets.RenewLeaseRequest) (*dynamicsecrets.RenewLeaseResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) RevokeLease(ctx context.Context, req *dynamicsecrets.RevokeLeaseRequest) (*dynamicsecrets.RevokeLeaseResponse, error) {
	return nil, nil
}

func (m *mockDynamicSecretsClient) ListLeases(ctx context.Context, req *dynamicsecrets.ListLeasesRequest) (*dynamicsecrets.ListLeasesResponse, error) {
	return nil, nil
}

// =============================================================================
// Mock implementations for XKMS client
// =============================================================================

type mockXKMSClient struct {
	canSealFn func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error)
	unsealFn  func(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error)
	getKeyFn  func(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error)
}

func (m *mockXKMSClient) CanSeal(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
	if m.canSealFn != nil {
		return m.canSealFn(ctx, backend)
	}
	return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
}

func (m *mockXKMSClient) Unseal(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
	if m.unsealFn != nil {
		return m.unsealFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockXKMSClient) GetKey(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
	if m.getKeyFn != nil {
		return m.getKeyFn(ctx, backend, keyID)
	}
	return nil, errors.New("not implemented")
}

// =============================================================================
// DynamicSecretsResolver tests
// =============================================================================

func TestDynamicSecretsResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewDynamicSecretsResolver(nil, logger)

	assert.Equal(t, bootstrap.SchemeDynamic, resolver.Scheme())
}

func TestDynamicSecretsResolver_Resolve_Success(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	now := time.Now()

	mock := &mockDynamicSecretsClient{
		generateFn: func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
			assert.Equal(t, "database-readonly", req.RoleName)
			assert.Equal(t, time.Duration(0), req.TTL)
			return &dynamicsecrets.GenerateCredentialResponse{
				Credential: &dynamicsecrets.Credential{
					CredentialID: "cred-123",
					Type:         "database",
					Data: map[string]string{
						"username": "db_user_abc",
						"password": "generated-pass",
					},
					LeaseID:   "lease-456",
					CreatedAt: now,
					ExpiresAt: now.Add(time.Hour),
				},
				LeaseID: "lease-456",
			}, nil
		},
	}

	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "dynamic://database-readonly")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the result is valid JSON containing the credential
	var cred dynamicsecrets.Credential
	require.NoError(t, result.WithBytes(func(plaintext []byte) error {
		return json.Unmarshal(plaintext, &cred)
	}))
	assert.Equal(t, "cred-123", cred.CredentialID)
	assert.Equal(t, "database", cred.Type)
	assert.Equal(t, "db_user_abc", cred.Data["username"])
	assert.Equal(t, "generated-pass", cred.Data["password"])
}

func TestDynamicSecretsResolver_Resolve_WithTTL(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	now := time.Now()

	mock := &mockDynamicSecretsClient{
		generateFn: func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
			assert.Equal(t, "api-key", req.RoleName)
			assert.Equal(t, 2*time.Hour, req.TTL)
			return &dynamicsecrets.GenerateCredentialResponse{
				Credential: &dynamicsecrets.Credential{
					CredentialID: "cred-789",
					Type:         "api-key",
					Data:         map[string]string{"key": "abc123"},
					CreatedAt:    now,
					ExpiresAt:    now.Add(2 * time.Hour),
				},
				LeaseID: "lease-789",
			}, nil
		},
	}

	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "dynamic://api-key/2h")
	require.NoError(t, err)
	require.NotNil(t, result)

	var cred dynamicsecrets.Credential
	require.NoError(t, result.WithBytes(func(plaintext []byte) error {
		return json.Unmarshal(plaintext, &cred)
	}))
	assert.Equal(t, "cred-789", cred.CredentialID)
}

func TestDynamicSecretsResolver_Resolve_NilClient(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewDynamicSecretsResolver(nil, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly")
	require.Error(t, err)

	var notAvailableErr ErrDynamicSecretsNotAvailable
	assert.ErrorAs(t, err, &notAvailableErr)
}

func TestDynamicSecretsResolver_Resolve_EmptyRoleName(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockDynamicSecretsClient{}
	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://")
	require.Error(t, err)

	var invalidErr ErrInvalidDynamicURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "empty role name")
}

func TestDynamicSecretsResolver_Resolve_InvalidTTL(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockDynamicSecretsClient{}
	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly/invalid")
	require.Error(t, err)

	var invalidErr ErrInvalidDynamicURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "invalid TTL duration")
}

func TestDynamicSecretsResolver_Resolve_NegativeTTL(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockDynamicSecretsClient{}
	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly/-1h")
	require.Error(t, err)

	var invalidErr ErrInvalidDynamicURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "TTL must be positive")
}

func TestDynamicSecretsResolver_Resolve_InvalidScheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockDynamicSecretsClient{}
	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "kms://path")
	require.Error(t, err)

	var invalidErr ErrInvalidDynamicURI
	assert.ErrorAs(t, err, &invalidErr)
}

func TestDynamicSecretsResolver_Resolve_GenerateFailed(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockDynamicSecretsClient{
		generateFn: func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
			return nil, errors.New("role not found")
		},
	}

	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://nonexistent-role")
	require.Error(t, err)

	var genErr ErrDynamicSecretGenerateFailed
	assert.ErrorAs(t, err, &genErr)
	assert.Equal(t, "nonexistent-role", genErr.RoleName)
}

func TestDynamicSecretsResolver_Resolve_NilCredential(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockDynamicSecretsClient{
		generateFn: func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
			return &dynamicsecrets.GenerateCredentialResponse{
				Credential: nil,
			}, nil
		},
	}

	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly")
	require.Error(t, err)

	var genErr ErrDynamicSecretGenerateFailed
	assert.ErrorAs(t, err, &genErr)
}

func TestDynamicSecretsResolver_Resolve_NilResponse(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockDynamicSecretsClient{
		generateFn: func(ctx context.Context, req *dynamicsecrets.GenerateCredentialRequest) (*dynamicsecrets.GenerateCredentialResponse, error) {
			return nil, nil
		},
	}

	resolver := NewDynamicSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly")
	require.Error(t, err)

	var genErr ErrDynamicSecretGenerateFailed
	assert.ErrorAs(t, err, &genErr)
}

func TestDynamicSecretsResolver_Resolve_CanceledContext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockDynamicSecretsClient{}
	resolver := NewDynamicSecretsResolver(mock, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.Resolve(ctx, "dynamic://database-readonly")
	require.Error(t, err)

	var cancelErr ErrContextCanceled
	assert.ErrorAs(t, err, &cancelErr)
}

func TestDynamicSecretsResolver_NilLogger(t *testing.T) {
	resolver := NewDynamicSecretsResolver(nil, nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, bootstrap.SchemeDynamic, resolver.Scheme())
}

// =============================================================================
// XKMSSecretsResolver tests
// =============================================================================

func TestXKMSSecretsResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewXKMSSecretsResolver(nil, logger)

	assert.Equal(t, bootstrap.SchemeXKMS, resolver.Scheme())
}

func TestXKMSSecretsResolver_CanResolve(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewXKMSSecretsResolver(nil, logger)

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "valid xkms URI",
			uri:      "xkms://software/platform-seal-key",
			expected: true,
		},
		{
			name:     "valid xkms URI tpm2",
			uri:      "xkms://tpm2/srk-auth",
			expected: true,
		},
		{
			name:     "valid xkms URI uppercase",
			uri:      "XKMS://software/key-id",
			expected: true,
		},
		{
			name:     "valid xkms URI mixed case",
			uri:      "Xkms://backend/key",
			expected: true,
		},
		{
			name:     "kms URI should not resolve",
			uri:      "kms://path/to/secret",
			expected: false,
		},
		{
			name:     "dynamic URI should not resolve",
			uri:      "dynamic://role",
			expected: false,
		},
		{
			name:     "plain text should not resolve",
			uri:      "mysecretpassword",
			expected: false,
		},
		{
			name:     "empty string should not resolve",
			uri:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.CanResolve(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestXKMSSecretsResolver_Resolve_ViaGetKey(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
		getKeyFn: func(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
			assert.Equal(t, "software", backend)
			assert.Equal(t, "platform-seal-key", keyID)
			return &xkmssdk.GetKeyResponse{
				KeyInfo: xkmssdk.KeyInfo{
					Backend:   "software",
					KeyID:     "platform-seal-key",
					Algorithm: "AES-256-GCM",
				},
			}, nil
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "xkms://software/platform-seal-key")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the result is valid JSON
	var resp xkmssdk.GetKeyResponse
	require.NoError(t, result.WithBytes(func(plaintext []byte) error {
		return json.Unmarshal(plaintext, &resp)
	}))
	assert.Equal(t, "software", resp.Backend)
	assert.Equal(t, "platform-seal-key", resp.KeyID)
}

func TestXKMSSecretsResolver_Resolve_ViaUnseal(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
		unsealFn: func(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
			assert.Equal(t, "tpm2", req.Backend)
			assert.Equal(t, "srk-auth", req.KeyID)
			return &xkmssdk.UnsealResponse{
				Plaintext: []byte("unsealed-secret-data"),
			}, nil
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "xkms://tpm2/srk-auth")
	require.NoError(t, err)
	require.NoError(t, result.WithBytes(func(plaintext []byte) error {
		assert.Equal(t, []byte("unsealed-secret-data"), plaintext)
		return nil
	}))
}

func TestXKMSSecretsResolver_Resolve_CanSealError_FallsBackToGetKey(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return nil, errors.New("backend not reachable")
		},
		getKeyFn: func(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
			return &xkmssdk.GetKeyResponse{
				KeyInfo: xkmssdk.KeyInfo{
					Backend: backend,
					KeyID:   keyID,
				},
			}, nil
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "xkms://software/my-key")
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestXKMSSecretsResolver_Resolve_NilClient(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewXKMSSecretsResolver(nil, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://software/key-id")
	require.Error(t, err)

	var notAvailableErr ErrXKMSNotAvailable
	assert.ErrorAs(t, err, &notAvailableErr)
}

func TestXKMSSecretsResolver_Resolve_EmptyPath(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://")
	require.Error(t, err)

	var invalidErr ErrInvalidXKMSURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "empty path")
}

func TestXKMSSecretsResolver_Resolve_MissingKeyID(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://software")
	require.Error(t, err)

	var invalidErr ErrInvalidXKMSURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "expected format")
}

func TestXKMSSecretsResolver_Resolve_EmptyBackend(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms:///key-id")
	require.Error(t, err)

	var invalidErr ErrInvalidXKMSURI
	assert.ErrorAs(t, err, &invalidErr)
}

func TestXKMSSecretsResolver_Resolve_EmptyKeyID(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://software/")
	require.Error(t, err)

	var invalidErr ErrInvalidXKMSURI
	assert.ErrorAs(t, err, &invalidErr)
}

func TestXKMSSecretsResolver_Resolve_InvalidScheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "kms://software/key-id")
	require.Error(t, err)

	var invalidErr ErrInvalidXKMSURI
	assert.ErrorAs(t, err, &invalidErr)
}

func TestXKMSSecretsResolver_Resolve_UnsealFailed(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
		unsealFn: func(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
			return nil, errors.New("unseal failed: TPM locked")
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://tpm2/srk-auth")
	require.Error(t, err)

	var unsealErr ErrXKMSUnsealFailed
	assert.ErrorAs(t, err, &unsealErr)
	assert.Equal(t, "tpm2", unsealErr.Backend)
	assert.Equal(t, "srk-auth", unsealErr.KeyID)
}

func TestXKMSSecretsResolver_Resolve_GetKeyFailed(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
		getKeyFn: func(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
			return nil, errors.New("key not found")
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://software/nonexistent-key")
	require.Error(t, err)

	var getKeyErr ErrXKMSGetKeyFailed
	assert.ErrorAs(t, err, &getKeyErr)
	assert.Equal(t, "software", getKeyErr.Backend)
	assert.Equal(t, "nonexistent-key", getKeyErr.KeyID)
}

func TestXKMSSecretsResolver_Resolve_UnsealEmptyPlaintext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
		unsealFn: func(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
			return &xkmssdk.UnsealResponse{Plaintext: nil}, nil
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://tpm2/empty-key")
	require.Error(t, err)

	var notFoundErr bootstrap.ErrSecretNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestXKMSSecretsResolver_Resolve_GetKeyNilResponse(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	mock := &mockXKMSClient{
		canSealFn: func(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
			return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
		getKeyFn: func(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
			return nil, nil
		},
	}

	resolver := NewXKMSSecretsResolver(mock, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "xkms://software/missing-key")
	require.Error(t, err)

	var notFoundErr bootstrap.ErrSecretNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestXKMSSecretsResolver_Resolve_CanceledContext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mock := &mockXKMSClient{}
	resolver := NewXKMSSecretsResolver(mock, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.Resolve(ctx, "xkms://software/key-id")
	require.Error(t, err)

	var cancelErr ErrContextCanceled
	assert.ErrorAs(t, err, &cancelErr)
}

func TestXKMSSecretsResolver_NilLogger(t *testing.T) {
	resolver := NewXKMSSecretsResolver(nil, nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, bootstrap.SchemeXKMS, resolver.Scheme())
}

// =============================================================================
// New error type tests
// =============================================================================

func TestErrDynamicSecretsNotAvailable_Error(t *testing.T) {
	err := ErrDynamicSecretsNotAvailable{}
	assert.Contains(t, err.Error(), "dynamic secrets service is not available")
}

func TestErrInvalidDynamicURI_Error(t *testing.T) {
	err := ErrInvalidDynamicURI{URI: "dynamic://bad", Reason: "test reason"}
	assert.Contains(t, err.Error(), "invalid dynamic URI")
	assert.Contains(t, err.Error(), "dynamic://bad")
	assert.Contains(t, err.Error(), "test reason")
}

func TestErrInvalidDynamicURI_Error_NoReason(t *testing.T) {
	err := ErrInvalidDynamicURI{URI: "dynamic://bad"}
	assert.Contains(t, err.Error(), "invalid dynamic URI")
	assert.Contains(t, err.Error(), "dynamic://bad")
}

func TestErrDynamicSecretGenerateFailed_Error(t *testing.T) {
	cause := errors.New("role not found")
	err := ErrDynamicSecretGenerateFailed{RoleName: "db-role", Cause: cause}
	assert.Contains(t, err.Error(), "failed to generate dynamic credential")
	assert.Contains(t, err.Error(), "db-role")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrDynamicSecretGenerateFailed_Error_NilCause(t *testing.T) {
	err := ErrDynamicSecretGenerateFailed{RoleName: "db-role"}
	assert.Contains(t, err.Error(), "db-role")
	assert.Nil(t, err.Unwrap())
}

func TestErrXKMSNotAvailable_Error(t *testing.T) {
	err := ErrXKMSNotAvailable{}
	assert.Contains(t, err.Error(), "XKMS adapter is not available")
}

func TestErrInvalidXKMSURI_Error(t *testing.T) {
	err := ErrInvalidXKMSURI{URI: "xkms://bad", Reason: "missing key-id"}
	assert.Contains(t, err.Error(), "invalid XKMS URI")
	assert.Contains(t, err.Error(), "xkms://bad")
	assert.Contains(t, err.Error(), "missing key-id")
}

func TestErrInvalidXKMSURI_Error_NoReason(t *testing.T) {
	err := ErrInvalidXKMSURI{URI: "xkms://bad"}
	assert.Contains(t, err.Error(), "invalid XKMS URI")
	assert.Contains(t, err.Error(), "xkms://bad")
}

func TestErrXKMSUnsealFailed_Error(t *testing.T) {
	cause := errors.New("TPM locked")
	err := ErrXKMSUnsealFailed{Backend: "tpm2", KeyID: "srk", Cause: cause}
	assert.Contains(t, err.Error(), "failed to unseal via XKMS")
	assert.Contains(t, err.Error(), "tpm2")
	assert.Contains(t, err.Error(), "srk")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrXKMSUnsealFailed_Error_NilCause(t *testing.T) {
	err := ErrXKMSUnsealFailed{Backend: "tpm2", KeyID: "srk"}
	assert.Contains(t, err.Error(), "tpm2")
	assert.Nil(t, err.Unwrap())
}

func TestErrXKMSGetKeyFailed_Error(t *testing.T) {
	cause := errors.New("not found")
	err := ErrXKMSGetKeyFailed{Backend: "software", KeyID: "key1", Cause: cause}
	assert.Contains(t, err.Error(), "failed to get key from XKMS")
	assert.Contains(t, err.Error(), "software")
	assert.Contains(t, err.Error(), "key1")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrXKMSGetKeyFailed_Error_NilCause(t *testing.T) {
	err := ErrXKMSGetKeyFailed{Backend: "software", KeyID: "key1"}
	assert.Contains(t, err.Error(), "software")
	assert.Nil(t, err.Unwrap())
}

// =============================================================================
// SecretsConfig defaults with new fields
// =============================================================================

func TestSecretsConfig_Default_NewFields(t *testing.T) {
	cfg := DefaultSecretsConfig()

	assert.False(t, cfg.DynamicSecrets, "default should disable DynamicSecrets")
	assert.False(t, cfg.XKMS, "default should disable XKMS")
}

// =============================================================================
// Bootstrap scheme constants
// =============================================================================

func TestBootstrapSchemeConstants(t *testing.T) {
	assert.Equal(t, "dynamic://", bootstrap.SchemeDynamic)
	assert.Equal(t, "xkms://", bootstrap.SchemeXKMS)
}

func TestBootstrapStrategyConstants(t *testing.T) {
	assert.Equal(t, "dynamic", bootstrap.StrategyDynamic)
	assert.Equal(t, "xkms", bootstrap.StrategyXKMS)
}

// =============================================================================
// xkmsKMSClientAdapter tests
// =============================================================================

func TestXKMSKMSClientAdapter_CanSeal(t *testing.T) {
	adapter := &xkmsKMSClientAdapter{}
	ctx := context.Background()

	resp, err := adapter.CanSeal(ctx, "software")
	require.NoError(t, err)
	assert.False(t, resp.CanSeal)
	assert.Equal(t, "software", resp.Backend)
}

func TestXKMSKMSClientAdapter_Unseal(t *testing.T) {
	adapter := &xkmsKMSClientAdapter{}
	ctx := context.Background()

	_, err := adapter.Unseal(ctx, &xkmssdk.UnsealRequest{Backend: "tpm2", KeyID: "key"})
	require.Error(t, err)

	var notAvailableErr ErrXKMSNotAvailable
	assert.ErrorAs(t, err, &notAvailableErr)
}

func TestXKMSKMSClientAdapter_GetKey(t *testing.T) {
	adapter := &xkmsKMSClientAdapter{}
	ctx := context.Background()

	_, err := adapter.GetKey(ctx, "software", "key-id")
	require.Error(t, err)

	var notAvailableErr ErrXKMSNotAvailable
	assert.ErrorAs(t, err, &notAvailableErr)
}

// =============================================================================
// SetupSecretResolvers wiring tests for new resolvers
// =============================================================================

func TestSetupSecretResolvers_DynamicSecretsNoSDK(t *testing.T) {
	logger := logging.DefaultLogger()
	registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
		&SecretsConfig{DynamicSecrets: true})

	require.NoError(t, err)
	require.NotNil(t, registry)
	// DynamicSecrets enabled but no SDK client - resolver not registered (warning logged)
	assert.False(t, registry.IsSecretURI("dynamic://role"))
}

func TestSetupSecretResolvers_XKMSNoSDK(t *testing.T) {
	logger := logging.DefaultLogger()
	registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
		&SecretsConfig{XKMS: true})

	require.NoError(t, err)
	require.NotNil(t, registry)
	// XKMS enabled but no SDK client - resolver not registered (warning logged)
	assert.False(t, registry.IsSecretURI("xkms://backend/key"))
}

// =============================================================================
// IDevIDResolver.CanResolve and Resolve tests (direct — no adapter)
// =============================================================================

// idevidURI constructs a valid idevid:// URI containing base64-encoded
// bytes that the IDevIDResolver will decode and pass to the decrypter.
func idevidURI(payload []byte) string {
	return "idevid://" + base64.StdEncoding.EncodeToString(payload)
}

// TestIDevIDResolver_CanResolve verifies that the resolver correctly handles
// URI scheme matching.
func TestIDevIDResolver_CanResolve(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	// nil decrypter is fine — CanResolve only inspects the URI string.
	resolver := secrets.NewIDevIDResolver(nil, logger)

	tests := []struct {
		uri      string
		expected bool
	}{
		{"idevid://dGVzdA==", true},
		{"idevid:dGVzdA==", true},
		{"IDEVID://uppercase", true},
		{"kms://path/to/secret", false},
		{"file://data", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolver.CanResolve(tt.uri))
		})
	}
}

// TestIDevIDResolver_Resolve_Error verifies that a decryption error is
// propagated by the resolver without modification.
func TestIDevIDResolver_Resolve_Error(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	mock := &mockDecrypter{
		decryptFn: func(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
			return nil, errors.New("decryption failed: invalid ciphertext")
		},
	}
	resolver := secrets.NewIDevIDResolver(mock, logger)

	uri := idevidURI([]byte("fake-ciphertext-bytes"))
	_, err := resolver.Resolve(ctx, uri)
	require.Error(t, err)
}

// TestIDevIDResolver_Resolve_Success verifies that a successful decryption
// produces a qrdb SecretValue with the expected plaintext bytes.
func TestIDevIDResolver_Resolve_Success(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()
	expected := []byte("my-decrypted-secret")

	mock := &mockDecrypter{
		decryptFn: func(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
			// The SecretValue takes ownership of the plaintext and wipes it,
			// so hand over a copy and keep expected intact for the comparison.
			return append([]byte(nil), expected...), nil
		},
	}
	resolver := secrets.NewIDevIDResolver(mock, logger)

	uri := idevidURI([]byte("fake-ciphertext-bytes"))
	result, err := resolver.Resolve(ctx, uri)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NoError(t, result.WithBytes(func(plaintext []byte) error {
		assert.Equal(t, expected, plaintext)
		return nil
	}))
}
