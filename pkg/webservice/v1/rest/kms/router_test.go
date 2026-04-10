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
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewKMSRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	router := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)

	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
}

func TestRegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test that routes are registered by checking if router can match them
	tests := []struct {
		name   string
		method string
		path   string
	}{
		// Key Management routes
		{"generate key", http.MethodPost, "/api/v1/kms/keys"},
		{"import key", http.MethodPost, "/api/v1/kms/keys/import"},
		{"list keys", http.MethodGet, "/api/v1/kms/keys"},
		{"get key", http.MethodGet, "/api/v1/kms/keys/my-key"},
		{"delete key", http.MethodDelete, "/api/v1/kms/keys/my-key"},
		{"rotate key", http.MethodPost, "/api/v1/kms/keys/my-key/rotate"},
		{"update key status", http.MethodPut, "/api/v1/kms/keys/my-key/status"},
		{"list key versions", http.MethodGet, "/api/v1/kms/keys/my-key/versions"},

		// Crypto routes
		{"encrypt", http.MethodPost, "/api/v1/kms/encrypt/my-key"},
		{"decrypt", http.MethodPost, "/api/v1/kms/decrypt/my-key"},
		{"sign", http.MethodPost, "/api/v1/kms/sign/my-key"},
		{"verify", http.MethodPost, "/api/v1/kms/verify/my-key"},
		{"hmac", http.MethodPost, "/api/v1/kms/hmac/my-key"},
		{"hmac verify", http.MethodPost, "/api/v1/kms/hmac/my-key/verify"},
		{"hash", http.MethodPost, "/api/v1/kms/hash"},
		{"random", http.MethodPost, "/api/v1/kms/random"},

		// DEK Management routes
		{"create dek", http.MethodPost, "/api/v1/kms/deks"},
		{"list deks", http.MethodGet, "/api/v1/kms/deks"},
		{"get dek", http.MethodGet, "/api/v1/kms/deks/tenant/app"},
		{"rotate dek", http.MethodPost, "/api/v1/kms/deks/tenant/app/rotate"},
		{"delete dek", http.MethodDelete, "/api/v1/kms/deks/tenant/app"},
		{"get dek status", http.MethodGet, "/api/v1/kms/deks/tenant/app/status"},

		// Backend routes
		{"backend status", http.MethodGet, "/api/v1/kms/backend/status"},
		{"backend test", http.MethodPost, "/api/v1/kms/backend/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "route should match: %s %s", tt.method, tt.path)
		})
	}
}

func TestKeyManagementRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/kms/keys/encryption-key-1",
			expectedVars: map[string]string{"name": "encryption-key-1"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/keys/master-key/rotate",
			expectedVars: map[string]string{"name": "master-key"},
		},
		{
			method:       http.MethodPut,
			path:         "/api/v1/kms/keys/test-key/status",
			expectedVars: map[string]string{"name": "test-key"},
		},
		{
			method:       http.MethodGet,
			path:         "/api/v1/kms/keys/versioned-key/versions",
			expectedVars: map[string]string{"name": "versioned-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestCryptoRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/encrypt/aes-key",
			expectedVars: map[string]string{"name": "aes-key"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/decrypt/aes-key",
			expectedVars: map[string]string{"name": "aes-key"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/sign/ecdsa-key",
			expectedVars: map[string]string{"name": "ecdsa-key"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/verify/ecdsa-key",
			expectedVars: map[string]string{"name": "ecdsa-key"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/hmac/hmac-key",
			expectedVars: map[string]string{"name": "hmac-key"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/hmac/hmac-key/verify",
			expectedVars: map[string]string{"name": "hmac-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestCryptoRoutes_HashAndRandom(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test routes that don't require key names
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "hash route",
			method: http.MethodPost,
			path:   "/api/v1/kms/hash",
		},
		{
			name:   "random route",
			method: http.MethodPost,
			path:   "/api/v1/kms/random",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "expected route to match: %s %s", tt.method, tt.path)
			// These routes should not have any path variables
			assert.Empty(t, match.Vars, "hash and random routes should not have path variables")
		})
	}
}

func TestHMACVerifyRoute_Priority(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// The /hmac/{name}/verify route should be matched before the /hmac/{name} route
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", nil)
	var match mux.RouteMatch
	matched := router.Match(req, &match)

	require.True(t, matched)
	// Should have "name" as "my-key", not "my-key/verify"
	assert.Equal(t, "my-key", match.Vars["name"], "HMAC verify route should extract correct key name")
}

func TestDEKRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/kms/deks/tenant/app",
			expectedVars: map[string]string{"path": "tenant/app"},
		},
		{
			method:       http.MethodGet,
			path:         "/api/v1/kms/deks/org/team/service",
			expectedVars: map[string]string{"path": "org/team/service"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/kms/deks/tenant/app/rotate",
			expectedVars: map[string]string{"path": "tenant/app"},
		},
		{
			method:       http.MethodGet,
			path:         "/api/v1/kms/deks/tenant/app/status",
			expectedVars: map[string]string{"path": "tenant/app"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "expected route to match: %s %s", tt.method, tt.path)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestBackendRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/kms/backend/status"},
		{http.MethodPost, "/api/v1/kms/backend/test"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched)
		})
	}
}

func TestRoutes_MethodNotAllowed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test that wrong methods don't match
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"PATCH on list keys path", http.MethodPatch, "/api/v1/kms/keys"},
		{"HEAD on generate key path", http.MethodHead, "/api/v1/kms/keys"},
		{"GET on encrypt path", http.MethodGet, "/api/v1/kms/encrypt/key"},
		{"GET on sign path", http.MethodGet, "/api/v1/kms/sign/key"},
		{"GET on verify path", http.MethodGet, "/api/v1/kms/verify/key"},
		{"GET on hmac path", http.MethodGet, "/api/v1/kms/hmac/key"},
		{"GET on hash path", http.MethodGet, "/api/v1/kms/hash"},
		{"GET on random path", http.MethodGet, "/api/v1/kms/random"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			// PATCH and HEAD should not match any of our defined routes
			assert.False(t, matched || match.MatchErr == mux.ErrMethodMismatch, "unexpected method should not have a matching handler")
		})
	}
}

func TestRoutes_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test paths that should not match
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"non-existent resource", http.MethodGet, "/api/v1/kms/nonexistent"},
		{"missing version", http.MethodGet, "/api/kms/keys"},
		{"wrong version", http.MethodGet, "/api/v2/kms/keys"},
		{"incomplete path", http.MethodGet, "/api/v1/kms"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.False(t, matched, "non-existent path should not match: %s", tt.path)
		})
	}
}

func TestBasePath_Constant(t *testing.T) {
	assert.Equal(t, "/api/v1/kms", basePath)
}

func TestRoutes_WithSpecialCharactersInNames(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	tests := []struct {
		name         string
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			name:         "key with hyphens",
			method:       http.MethodGet,
			path:         "/api/v1/kms/keys/my-encryption-key",
			expectedVars: map[string]string{"name": "my-encryption-key"},
		},
		{
			name:         "key with underscores",
			method:       http.MethodGet,
			path:         "/api/v1/kms/keys/my_encryption_key",
			expectedVars: map[string]string{"name": "my_encryption_key"},
		},
		{
			name:         "key with UUID format",
			method:       http.MethodGet,
			path:         "/api/v1/kms/keys/550e8400-e29b-41d4-a716-446655440000",
			expectedVars: map[string]string{"name": "550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name:         "dek with deep path",
			method:       http.MethodGet,
			path:         "/api/v1/kms/deks/org/team/project/service",
			expectedVars: map[string]string{"path": "org/team/project/service"},
		},
		{
			name:         "sign with key name containing numbers",
			method:       http.MethodPost,
			path:         "/api/v1/kms/sign/key123",
			expectedVars: map[string]string{"name": "key123"},
		},
		{
			name:         "hmac with complex key name",
			method:       http.MethodPost,
			path:         "/api/v1/kms/hmac/hmac-sha256-production",
			expectedVars: map[string]string{"name": "hmac-sha256-production"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestRoutes_SubrouterIsolation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	// Register KMS routes
	kmsRouter.RegisterRoutes(router)

	// Add a different route to ensure KMS routes don't interfere
	router.HandleFunc("/api/v1/other", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	// Verify both KMS and other routes work
	kmsReq := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
	var kmsMatch mux.RouteMatch
	assert.True(t, router.Match(kmsReq, &kmsMatch))

	otherReq := httptest.NewRequest(http.MethodGet, "/api/v1/other", nil)
	var otherMatch mux.RouteMatch
	assert.True(t, router.Match(otherReq, &otherMatch))
}

func TestRoutes_HandlerExecution(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	// Create a mock that returns data
	keyMgmt := &mockKeyManagementClient{
		listKeysFn: func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
			return &proto.ListKeysResponse{
				Keys:       []*proto.KeyHandle{},
				TotalCount: 0,
			}, nil
		},
	}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Create a test server
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// The handler should have been called
	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDEKRoutes_NestedPaths(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test deeply nested DEK paths
	tests := []struct {
		name         string
		path         string
		expectedPath string
	}{
		{
			name:         "single level",
			path:         "/api/v1/kms/deks/tenant",
			expectedPath: "tenant",
		},
		{
			name:         "two levels",
			path:         "/api/v1/kms/deks/tenant/app",
			expectedPath: "tenant/app",
		},
		{
			name:         "three levels",
			path:         "/api/v1/kms/deks/org/team/service",
			expectedPath: "org/team/service",
		},
		{
			name:         "four levels",
			path:         "/api/v1/kms/deks/org/team/project/service",
			expectedPath: "org/team/project/service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "expected route to match: %s", tt.path)
			assert.Equal(t, tt.expectedPath, match.Vars["path"])
		})
	}
}

func TestImportKeyRoute_Priority(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// The /keys/import route should be matched before the /keys/{name} route
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", nil)
	var match mux.RouteMatch
	matched := router.Match(req, &match)

	require.True(t, matched)
	// Should NOT have a "name" variable (import is a special route)
	_, hasName := match.Vars["name"]
	assert.False(t, hasName, "import route should not have 'name' variable")
}

func TestDEKStatusRoute_Priority(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// The /deks/{path}/status route should match correctly
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/deks/tenant/app/status", nil)
	var match mux.RouteMatch
	matched := router.Match(req, &match)

	require.True(t, matched)
	// Path should be "tenant/app", not "tenant/app/status"
	assert.Equal(t, "tenant/app", match.Vars["path"])
}

func TestCryptoRoutes_AllOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test all crypto operations with various key names
	tests := []struct {
		name         string
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			name:         "encrypt with simple key",
			method:       http.MethodPost,
			path:         "/api/v1/kms/encrypt/mykey",
			expectedVars: map[string]string{"name": "mykey"},
		},
		{
			name:         "decrypt with UUID key",
			method:       http.MethodPost,
			path:         "/api/v1/kms/decrypt/550e8400-e29b-41d4-a716-446655440000",
			expectedVars: map[string]string{"name": "550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name:         "sign with ed25519 key",
			method:       http.MethodPost,
			path:         "/api/v1/kms/sign/ed25519-signing-key",
			expectedVars: map[string]string{"name": "ed25519-signing-key"},
		},
		{
			name:         "verify with ecdsa key",
			method:       http.MethodPost,
			path:         "/api/v1/kms/verify/ecdsa-p256-key",
			expectedVars: map[string]string{"name": "ecdsa-p256-key"},
		},
		{
			name:         "hmac generation",
			method:       http.MethodPost,
			path:         "/api/v1/kms/hmac/hmac-sha512-key",
			expectedVars: map[string]string{"name": "hmac-sha512-key"},
		},
		{
			name:         "hmac verification",
			method:       http.MethodPost,
			path:         "/api/v1/kms/hmac/hmac-sha512-key/verify",
			expectedVars: map[string]string{"name": "hmac-sha512-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "expected route to match: %s %s", tt.method, tt.path)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal, "expected %s=%s, got %s", key, expectedVal, actualVal)
			}
		})
	}
}

func TestCryptoRoutes_KeylessOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	kmsRouter := NewKMSRouter(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	router := mux.NewRouter()

	kmsRouter.RegisterRoutes(router)

	// Test operations that don't require a key
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "hash computation",
			method: http.MethodPost,
			path:   "/api/v1/kms/hash",
		},
		{
			name:   "random bytes generation",
			method: http.MethodPost,
			path:   "/api/v1/kms/random",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "expected route to match: %s %s", tt.method, tt.path)
			// These routes should have no path variables
			assert.Empty(t, match.Vars, "keyless operations should not have path variables")
		})
	}
}
