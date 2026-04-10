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
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrNilObjectStore_Error verifies the ErrNilObjectStore error message.
func TestErrNilObjectStore_Error(t *testing.T) {
	err := ErrNilObjectStore{}
	assert.Contains(t, err.Error(), "object store is required but was nil")
}

// TestErrNilObjectStore_ImplementsError verifies the error interface.
func TestErrNilObjectStore_ImplementsError(t *testing.T) {
	var err error = ErrNilObjectStore{}
	assert.NotNil(t, err)
}

// TestEncryptedResolverAdapter_Constructor verifies adapter construction.
func TestEncryptedResolverAdapter_Constructor(t *testing.T) {
	adapter := NewEncryptedResolverAdapter(nil, slog.New(slog.DiscardHandler))
	assert.NotNil(t, adapter)
	assert.Equal(t, "encrypted://", adapter.Scheme())
}

// TestEncryptedResolverAdapter_Constructor_NilLoggerDefault verifies adapter with nil logger.
func TestEncryptedResolverAdapter_Constructor_NilLoggerDefault(t *testing.T) {
	adapter := NewEncryptedResolverAdapter(nil, nil)
	assert.NotNil(t, adapter)
}

// TestLocalSecretsResolver_Resolve_ValidSchemeEmptyPath verifies error for empty path.
func TestLocalSecretsResolver_Resolve_ValidSchemeEmptyPath(t *testing.T) {
	resolver := NewLocalSecretsResolver(nil, nil)
	_, err := resolver.Resolve(context.Background(), "kms://")
	require.Error(t, err)
	var target ErrInvalidKMSURI
	assert.ErrorAs(t, err, &target)
}

// TestLocalSecretsResolver_Resolve_NilSecrets verifies error with nil secrets service.
func TestLocalSecretsResolver_Resolve_NilSecrets(t *testing.T) {
	resolver := NewLocalSecretsResolver(nil, nil)
	_, err := resolver.Resolve(context.Background(), "kms://some/secret")
	require.Error(t, err)
	var target ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &target)
}

// TestApp_DropPrivileges_EmptyUser verifies DropPrivileges with empty user.
func TestApp_DropPrivileges_EmptyUser(t *testing.T) {
	(&App{Logger: logging.DefaultLogger(), RuntimeUser: ""}).DropPrivileges()
}

// TestDefaultCAConfig_HasIdentities verifies the default CA config has identities.
func TestDefaultCAConfig_HasIdentities(t *testing.T) {
	cfg := defaultCAConfig()
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Identity)
}

// TestDefaultCAConfig_KeyAlgorithmStrSet verifies KeyAlgorithmStr is set.
func TestDefaultCAConfig_KeyAlgorithmStrSet(t *testing.T) {
	cfg := defaultCAConfig()
	for i, identity := range cfg.Identity {
		if identity.KeyAlgorithm != 0 {
			assert.NotEmpty(t, identity.KeyAlgorithmStr,
				"identity[%d] should have KeyAlgorithmStr set", i)
		}
	}
}

// TestApp_KMS_WithLogger_NilFactory verifies KMS returns nil when daoFactory is nil.
func TestApp_KMS_WithLogger_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).KMS())
}

// TestApp_QuicBaaSService_WithLogger_NilFactory verifies QuicBaaSService returns nil.
func TestApp_QuicBaaSService_WithLogger_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).QuicBaaSService())
}

// TestApp_QuicBaaSSDKClient_WithLogger_NilFactory verifies SDK client returns nil.
func TestApp_QuicBaaSSDKClient_WithLogger_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).QuicBaaSSDKClient())
}

// TestApp_StartDNS_EmptyDNSConfig verifies StartDNS is no-op with nil DNS config.
func TestApp_StartDNS_EmptyDNSConfig(t *testing.T) {
	(&App{Logger: logging.DefaultLogger(), DNSConfig: nil}).StartDNS()
}

// TestApp_NewCertificateStore_NilObjectStoreOnApp verifies cert store creation error.
func TestApp_NewCertificateStore_NilObjectStoreOnApp(t *testing.T) {
	_, err := (&App{Logger: logging.DefaultLogger()}).NewCertificateStore(nil)
	require.Error(t, err)
	var target ErrNilObjectStore
	assert.ErrorAs(t, err, &target)
}

// TestAllErrors_NonEmpty verifies each error type produces non-empty messages.
func TestAllErrors_NonEmpty(t *testing.T) {
	errs := []error{
		ErrXKMSStorageInit{Path: "/test", Cause: errors.New("test")},
		ErrXKMSBackendInit{Cause: errors.New("test")},
		ErrXKMSServiceInit{Cause: errors.New("test")},
		ErrXKMSKeystoreInit{Cause: errors.New("test")},
		ErrQuicBaaSConfig{Cause: errors.New("test")},
		ErrQuicBaaSFactory{Cause: errors.New("test")},
		ErrQuicBaaSStart{Cause: errors.New("test")},
		ErrPlatformCAInit{Cause: errors.New("test")},
		ErrStorageInit{Cause: errors.New("test")},
		ErrBarrierInit{Cause: errors.New("test")},
		ErrKeyBackendInit{Path: "/test", Cause: errors.New("test")},
		ErrBootstrapStoreInit{Store: "key", CN: "test", Cause: errors.New("test")},
		ErrNilObjectStore{},
	}

	for i, err := range errs {
		assert.NotEmpty(t, err.Error(), "error %d should have non-empty message", i)
	}
}

// TestAutoGenResolver_Resolve_DefaultLength verifies autogen:// uses default 32 bytes.
func TestAutoGenResolver_Resolve_DefaultLength(t *testing.T) {
	resolver := NewAutoGenResolver(slog.New(slog.DiscardHandler))
	result, err := resolver.Resolve(context.Background(), "autogen://")
	require.NoError(t, err)
	assert.Len(t, result, 32)
}

// TestAutoGenResolver_Resolve_NonNumericLength verifies error for non-numeric length.
func TestAutoGenResolver_Resolve_NonNumericLength(t *testing.T) {
	resolver := NewAutoGenResolver(slog.New(slog.DiscardHandler))
	_, err := resolver.Resolve(context.Background(), "autogen://abc")
	require.Error(t, err)
}

// TestAutoGenResolver_Resolve_InvalidScheme verifies error for wrong scheme.
func TestAutoGenResolver_Resolve_WrongScheme(t *testing.T) {
	resolver := NewAutoGenResolver(slog.New(slog.DiscardHandler))
	_, err := resolver.Resolve(context.Background(), "kms://test")
	require.Error(t, err)
}

// TestSecretsServiceClient_StoreSecret_NilService verifies error.
func TestSecretsServiceClient_StoreSecret_NilService(t *testing.T) {
	client := NewSecretsServiceClient(nil, nil)
	err := client.StoreSecret(context.Background(), "test/path", []byte("data"), nil)
	require.Error(t, err)
	var target ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &target)
}

// TestSecretsServiceClient_GetSecret_NilService verifies error.
func TestSecretsServiceClient_GetSecret_NilService(t *testing.T) {
	client := NewSecretsServiceClient(nil, nil)
	_, err := client.GetSecret(context.Background(), "test/path")
	require.Error(t, err)
	var target ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &target)
}

// TestApp_Close_CanceledContext verifies Close with canceled context.
func TestApp_Close_CanceledContext(t *testing.T) {
	app := NewApp()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.NoError(t, app.Close(ctx))
}

// TestApp_FQDN_MultiSubdomain verifies FQDN with multi-level domain.
func TestApp_FQDN_MultiSubdomain(t *testing.T) {
	assert.Equal(t, "node01.us.east.example.com",
		(&App{Hostname: "node01", Domain: "us.east.example.com"}).FQDN())
}
