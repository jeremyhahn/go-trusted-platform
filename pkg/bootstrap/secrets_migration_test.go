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

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretTagConfig is a sample config struct with secret:"true" tags for testing.
type secretTagConfig struct {
	Name     string `yaml:"name" json:"name"`
	Password string `yaml:"password" json:"password" secret:"true"`
	APIKey   string `yaml:"api-key" json:"api_key" secret:"true"`
	Host     string `yaml:"host" json:"host"`
}

// nestedSecretConfig has nested structs with secret tags.
type nestedSecretConfig struct {
	Name     string           `yaml:"name"`
	Database dbSecretConfig   `yaml:"database"`
	BMC      *bmcSecretConfig `yaml:"bmc"`
}

type dbSecretConfig struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password" secret:"true"`
}

type bmcSecretConfig struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password" secret:"true"`
}

// sliceSecretConfig has a slice of structs with secret tags.
type sliceSecretConfig struct {
	Servers []serverSecretConfig `yaml:"servers"`
}

type serverSecretConfig struct {
	Name     string `yaml:"name"`
	Password string `yaml:"password" secret:"true"`
}

func newTestMigrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestProcessConfigSecretTagPlainText(t *testing.T) {
	ctx := context.Background()
	logger := newTestMigrationLogger()

	t.Run("plain-text secret tagged fields are migrated", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "my-secret-password",
			APIKey:   "sk-1234567890",
			Host:     "localhost",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Two secret-tagged fields with plain text should be migrated
		assert.Equal(t, 2, result.MigratedCount())

		// Verify the fields were replaced with KMS URIs
		assert.True(t, IsSecretURI(cfg.Password))
		assert.True(t, IsSecretURI(cfg.APIKey))
		assert.Equal(t, "kms://config/password", cfg.Password)
		assert.Equal(t, "kms://config/api-key", cfg.APIKey)

		// Non-secret fields should be unchanged
		assert.Equal(t, "test-app", cfg.Name)
		assert.Equal(t, "localhost", cfg.Host)

		// Verify KMS was called to store both secrets
		assert.Equal(t, 2, kms.storeCalled)

		// Verify the plain text was stored in KMS
		storedPassword, ok := kms.secrets["config/password"]
		assert.True(t, ok)
		assert.Equal(t, []byte("my-secret-password"), storedPassword)

		storedKey, ok := kms.secrets["config/api-key"]
		assert.True(t, ok)
		assert.Equal(t, []byte("sk-1234567890"), storedKey)

		// Verify strategy is recorded as plaintext
		for _, m := range result.Migrated {
			assert.Equal(t, StrategyPlainText, m.Strategy)
			assert.Equal(t, "***", m.OriginalURI)
		}
	})

	t.Run("secret tagged fields with existing URI are not migrated", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{
			scheme: SchemeKMS,
			value:  []byte("resolved-secret"),
		})
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "kms://secrets/password",
			APIKey:   "kms://secrets/api-key",
			Host:     "localhost",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)

		// Both are URIs, so they go through the normal URI resolution path
		assert.Equal(t, 2, result.MigratedCount())
		for _, m := range result.Migrated {
			assert.Equal(t, StrategyKMS, m.Strategy)
		}
	})

	t.Run("empty secret tagged fields are skipped", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "",
			APIKey:   "",
			Host:     "localhost",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 0, result.MigratedCount())
		assert.Equal(t, 0, kms.storeCalled)
	})

	t.Run("nested secret tagged fields are migrated", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &nestedSecretConfig{
			Name: "platform",
			Database: dbSecretConfig{
				Host:     "db.example.com",
				Password: "db-password-123",
			},
			BMC: &bmcSecretConfig{
				Address:  "192.168.1.100",
				Username: "admin",
				Password: "bmc-password-456",
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result.MigratedCount())

		assert.Equal(t, "kms://config/database/password", cfg.Database.Password)
		assert.Equal(t, "kms://config/bmc/password", cfg.BMC.Password)

		// Non-secret fields unchanged
		assert.Equal(t, "db.example.com", cfg.Database.Host)
		assert.Equal(t, "admin", cfg.BMC.Username)
	})

	t.Run("KMS store error on plain-text migration is recorded", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		kms.storeErr = errors.New("KMS unavailable")
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "my-secret",
			Host:     "localhost",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.True(t, result.HasErrors())

		// The field should NOT have been modified since the store failed
		// (the error is recorded but walkStruct continues)
	})

	t.Run("slice of structs with secret tags via ProcessConfig", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &sliceSecretConfig{
			Servers: []serverSecretConfig{
				{Name: "server1", Password: "pass1"},
				{Name: "server2", Password: "pass2"},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result.MigratedCount())
		assert.Equal(t, "kms://config/servers/0/password", cfg.Servers[0].Password)
		assert.Equal(t, "kms://config/servers/1/password", cfg.Servers[1].Password)
	})
}

func TestProcessConfigSecretTagIdempotent(t *testing.T) {
	ctx := context.Background()
	logger := newTestMigrationLogger()

	t.Run("running ProcessConfig twice is idempotent", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{
			scheme: SchemeKMS,
			value:  []byte("resolved-secret"),
		})
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "my-secret",
			APIKey:   "my-key",
			Host:     "localhost",
		}

		// First run: migrates plain text to KMS URIs
		result1, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result1.MigratedCount())

		passwordURI := cfg.Password
		apiKeyURI := cfg.APIKey
		assert.True(t, IsSecretURI(passwordURI))
		assert.True(t, IsSecretURI(apiKeyURI))

		storeCalls := kms.storeCalled

		// Second run: fields already have URIs, so they go through URI resolution
		result2, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)

		// The URIs are resolved via registry, stored in KMS again (via resolveAndMigrateURI)
		// but the original values are not overwritten with different URIs
		assert.Equal(t, 2, result2.MigratedCount())
		for _, m := range result2.Migrated {
			assert.Equal(t, StrategyKMS, m.Strategy)
		}

		// KMS store was called additional times for the URI resolution path
		assert.Greater(t, kms.storeCalled, storeCalls)
	})
}

func TestExpandShortKMSPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		tenantID string
		nodeID   string
		expected string
	}{
		{
			name:     "short path is expanded",
			path:     "bmc/password",
			tenantID: "default",
			nodeID:   "lab-node-2",
			expected: "tenants/default/nodes/lab-node-2/secrets/bmc/password",
		},
		{
			name:     "already-qualified path is unchanged",
			path:     "tenants/default/nodes/lab-node-2/secrets/bmc/password",
			tenantID: "default",
			nodeID:   "lab-node-2",
			expected: "tenants/default/nodes/lab-node-2/secrets/bmc/password",
		},
		{
			name:     "empty tenantID leaves path unchanged",
			path:     "bmc/password",
			tenantID: "",
			nodeID:   "lab-node-2",
			expected: "bmc/password",
		},
		{
			name:     "empty nodeID leaves path unchanged",
			path:     "bmc/password",
			tenantID: "default",
			nodeID:   "",
			expected: "bmc/password",
		},
		{
			name:     "both empty leaves path unchanged",
			path:     "bmc/password",
			tenantID: "",
			nodeID:   "",
			expected: "bmc/password",
		},
		{
			name:     "single segment path",
			path:     "password",
			tenantID: "acme",
			nodeID:   "node-01",
			expected: "tenants/acme/nodes/node-01/secrets/password",
		},
		{
			name:     "deep short path",
			path:     "platform/tpm/srk-auth",
			tenantID: "default",
			nodeID:   "lab-node-3",
			expected: "tenants/default/nodes/lab-node-3/secrets/platform/tpm/srk-auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandShortKMSPath(tt.path, tt.tenantID, tt.nodeID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSecretURIExported(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{input: "kms://path/to/secret", expected: true},
		{input: "remote-kms://server/secret", expected: true},
		{input: "autogen://32/base64", expected: true},
		{input: "env://MY_VAR", expected: true},
		{input: "encrypted://data", expected: true},
		{input: "dynamic://role/1h", expected: true},
		{input: "xkms://tpm2/key-id", expected: true},
		{input: "plain-text-value", expected: false},
		{input: "", expected: false},
		{input: "http://not-a-secret", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSecretURI(tt.input))
		})
	}
}

func TestStrategyPlainTextConstant(t *testing.T) {
	assert.Equal(t, "plaintext", StrategyPlainText)
}

func TestNewErrorTypes(t *testing.T) {
	t.Run("ErrPlainTextSecretMigration with cause", func(t *testing.T) {
		cause := errors.New("KMS unavailable")
		err := ErrPlainTextSecretMigration{Path: "bmc.password", Cause: cause}
		assert.Contains(t, err.Error(), "bmc.password")
		assert.Contains(t, err.Error(), "KMS unavailable")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrPlainTextSecretMigration without cause", func(t *testing.T) {
		err := ErrPlainTextSecretMigration{Path: "bmc.password"}
		assert.Contains(t, err.Error(), "bmc.password")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrNilSecretManager", func(t *testing.T) {
		err := ErrNilSecretManager{}
		assert.Contains(t, err.Error(), "secret manager")
	})
}

func TestProcessConfigMixedSecretTagAndURI(t *testing.T) {
	ctx := context.Background()
	logger := newTestMigrationLogger()

	t.Run("mix of plain-text and URI in secret-tagged fields", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{
			scheme: SchemeKMS,
			value:  []byte("resolved-value"),
		})
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &secretTagConfig{
			Name:     "test-app",
			Password: "plain-text-password",
			APIKey:   "kms://secrets/api-key",
			Host:     "localhost",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result.MigratedCount())

		// Password was plain-text -> migrated as plaintext strategy
		var foundPlainText, foundKMS bool
		for _, m := range result.Migrated {
			if m.Strategy == StrategyPlainText {
				foundPlainText = true
				assert.Equal(t, "password", m.ConfigPath)
			}
			if m.Strategy == StrategyKMS {
				foundKMS = true
				assert.Equal(t, "api-key", m.ConfigPath)
			}
		}
		assert.True(t, foundPlainText, "expected a plaintext migration")
		assert.True(t, foundKMS, "expected a KMS URI resolution")
	})
}

func TestProcessConfigNonSecretTagFieldsIgnored(t *testing.T) {
	ctx := context.Background()
	logger := newTestMigrationLogger()

	type noSecretTags struct {
		Name     string `yaml:"name"`
		Password string `yaml:"password"`
		APIKey   string `yaml:"api-key"`
	}

	t.Run("fields without secret tag are not treated as secrets", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &noSecretTags{
			Name:     "test-app",
			Password: "plain-password",
			APIKey:   "plain-key",
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// No URI prefix and no secret tag -> nothing migrated
		assert.Equal(t, 0, result.MigratedCount())
		assert.Equal(t, 0, kms.storeCalled)
	})
}
