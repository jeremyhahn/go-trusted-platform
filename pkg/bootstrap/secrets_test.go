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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretsClient is a mock implementation of SecretsClient for testing.
type mockSecretsClient struct {
	secrets     map[string][]byte
	metadata    map[string]map[string]string
	storeErr    error
	getErr      error
	storeCalled int
	getCalled   int
}

func newMockSecretsClient() *mockSecretsClient {
	return &mockSecretsClient{
		secrets:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
	}
}

func (m *mockSecretsClient) StoreSecret(ctx context.Context, path string, data []byte, metadata map[string]string) error {
	m.storeCalled++
	if m.storeErr != nil {
		return m.storeErr
	}
	m.secrets[path] = data
	m.metadata[path] = metadata
	return nil
}

func (m *mockSecretsClient) GetSecret(ctx context.Context, path string) ([]byte, error) {
	m.getCalled++
	if m.getErr != nil {
		return nil, m.getErr
	}
	if data, ok := m.secrets[path]; ok {
		return data, nil
	}
	return nil, ErrSecretNotFound{Path: path}
}

// mockResolver is a mock implementation of SecretResolver for testing.
type mockResolver struct {
	scheme     string
	resolveErr error
	value      []byte
}

func (m *mockResolver) Scheme() string {
	return m.scheme
}

func (m *mockResolver) Resolve(ctx context.Context, uri string) ([]byte, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	return m.value, nil
}

func (m *mockResolver) CanResolve(uri string) bool {
	return strings.HasPrefix(uri, m.scheme)
}

// testConfig is a sample config struct for testing.
type testConfig struct {
	Name     string       `yaml:"name" json:"name"`
	Password string       `yaml:"password" json:"password"`
	APIKey   string       `yaml:"api-key" json:"api_key"`
	Database dbConfig     `yaml:"database" json:"database"`
	Nested   *nestedCfg   `yaml:"nested" json:"nested"`
	Items    []itemConfig `yaml:"items" json:"items"`
}

type dbConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type nestedCfg struct {
	Secret string `yaml:"secret" json:"secret"`
	Inner  *innerCfg
}

type innerCfg struct {
	Token string `yaml:"token" json:"token"`
}

type itemConfig struct {
	ID       string `yaml:"id" json:"id"`
	Password string `yaml:"password" json:"password"`
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewSecretManager(t *testing.T) {
	logger := newTestLogger()
	registry := NewResolverRegistry(logger)
	kms := newMockSecretsClient()

	tests := []struct {
		name       string
		registry   *ResolverRegistry
		kms        SecretsClient
		configPath string
		logger     *slog.Logger
		wantErr    bool
		errType    error
	}{
		{
			name:       "valid parameters",
			registry:   registry,
			kms:        kms,
			configPath: "config",
			logger:     logger,
			wantErr:    false,
		},
		{
			name:       "nil registry",
			registry:   nil,
			kms:        kms,
			configPath: "config",
			logger:     logger,
			wantErr:    true,
			errType:    ErrNilRegistry{},
		},
		{
			name:       "nil KMS client",
			registry:   registry,
			kms:        nil,
			configPath: "config",
			logger:     logger,
			wantErr:    true,
			errType:    ErrNilKMSClient{},
		},
		{
			name:       "nil logger",
			registry:   registry,
			kms:        kms,
			configPath: "config",
			logger:     nil,
			wantErr:    true,
			errType:    ErrNilLogger{},
		},
		{
			name:       "empty config path is valid",
			registry:   registry,
			kms:        kms,
			configPath: "",
			logger:     logger,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, err := NewSecretManager(tt.registry, tt.kms, tt.configPath, tt.logger)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				assert.Nil(t, sm)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, sm)
			}
		})
	}
}

func TestResolverRegistry(t *testing.T) {
	logger := newTestLogger()

	t.Run("register and resolve", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		resolver := &mockResolver{
			scheme: SchemeKMS,
			value:  []byte("test-secret"),
		}

		registry.Register(resolver)

		ctx := context.Background()
		data, err := registry.Resolve(ctx, "kms://path/to/secret")
		require.NoError(t, err)
		assert.Equal(t, []byte("test-secret"), data)
	})

	t.Run("no resolver for URI", func(t *testing.T) {
		registry := NewResolverRegistry(logger)

		ctx := context.Background()
		_, err := registry.Resolve(ctx, "unknown://path/to/secret")
		require.Error(t, err)
		assert.IsType(t, ErrNoResolverForURI{}, err)
	})

	t.Run("CanResolve", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		resolver := &mockResolver{scheme: SchemeKMS}
		registry.Register(resolver)

		assert.True(t, registry.CanResolve("kms://path"))
		assert.False(t, registry.CanResolve("remote-kms://path"))
	})
}

func TestBuildFieldPath(t *testing.T) {
	type testStruct struct {
		YAMLField      string `yaml:"yaml-field"`
		JSONField      string `json:"json_field"`
		MapstructField string `mapstructure:"mapstruct-field"`
		MultiTag       string `yaml:"yaml-name" json:"json_name"`
		TagWithOptions string `yaml:"tagged,omitempty"`
		SkippedField   string `yaml:"-"`
		NoTag          string
	}

	tests := []struct {
		name       string
		parentPath string
		fieldIdx   int
		expected   string
	}{
		{name: "yaml tag", parentPath: "parent", fieldIdx: 0, expected: "parent.yaml-field"},
		{name: "json tag fallback", parentPath: "parent", fieldIdx: 1, expected: "parent.json_field"},
		{name: "mapstructure tag fallback", parentPath: "parent", fieldIdx: 2, expected: "parent.mapstruct-field"},
		{name: "yaml takes precedence", parentPath: "parent", fieldIdx: 3, expected: "parent.yaml-name"},
		{name: "tag with options strips options", parentPath: "parent", fieldIdx: 4, expected: "parent.tagged"},
		{name: "empty parent path", parentPath: "", fieldIdx: 0, expected: "yaml-field"},
		{name: "no tag uses lowercase field name", parentPath: "parent", fieldIdx: 6, expected: "parent.notag"},
		{name: "skipped field returns empty", parentPath: "parent", fieldIdx: 5, expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s testStruct
			val := reflect.ValueOf(s)
			typ := val.Type()
			field := typ.Field(tt.fieldIdx)

			result := buildFieldPath(tt.parentPath, field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildKMSPath(t *testing.T) {
	logger := newTestLogger()
	registry := NewResolverRegistry(logger)
	kms := newMockSecretsClient()

	t.Run("with config path prefix", func(t *testing.T) {
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)
		result := sm.buildKMSPath("kms.backends.tpm2.srk-auth")
		assert.Equal(t, "config/kms/backends/tpm2/srk-auth", result)
	})

	t.Run("without config path prefix", func(t *testing.T) {
		sm, err := NewSecretManager(registry, kms, "", logger)
		require.NoError(t, err)
		result := sm.buildKMSPath("database.password")
		assert.Equal(t, "database/password", result)
	})

	t.Run("with array indices", func(t *testing.T) {
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)
		result := sm.buildKMSPath("items[0].password")
		assert.Equal(t, "config/items/0/password", result)
	})
}

func TestProcessConfigWithMapFields(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithMap struct {
		Name    string            `yaml:"name"`
		Secrets map[string]string `yaml:"secrets"`
	}

	t.Run("map with secret values logs warning", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithMap{
			Name:    "test",
			Secrets: map[string]string{"key1": "kms://secret/key1"},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.True(t, result.HasErrors())
	})

	t.Run("empty map is handled", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithMap{Name: "test", Secrets: map[string]string{}}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.False(t, result.HasErrors())
	})
}

func TestProcessConfigWithSliceOfPointers(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithPtrSlice struct {
		Items []*itemConfig `yaml:"items"`
	}

	t.Run("slice of pointers to structs", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithPtrSlice{
			Items: []*itemConfig{
				{ID: "item1", Password: "kms://items/1/password"},
				{ID: "item2", Password: "kms://items/2/password"},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result.MigratedCount())
	})

	t.Run("slice with nil pointer is skipped", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithPtrSlice{
			Items: []*itemConfig{
				{ID: "item1", Password: "kms://items/1/password"},
				nil, // nil pointer should be skipped
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// Should migrate 1 secret (the non-nil pointer)
		assert.Equal(t, 1, result.MigratedCount())
	})
}

func TestProcessConfigWithSliceOfStrings(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithStringSlice struct {
		Secrets []string `yaml:"secrets"`
	}

	t.Run("slice of secret strings", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithStringSlice{Secrets: []string{"kms://secrets/1", "kms://secrets/2"}}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 2, result.MigratedCount())
	})
}

func TestProcessConfigWithMapOfPointers(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithPtrMap struct {
		Databases map[string]*dbConfig `yaml:"databases"`
	}

	t.Run("map of pointer structs with secrets", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithPtrMap{
			Databases: map[string]*dbConfig{
				"primary": {Host: "localhost", Password: "kms://db/primary/password"},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// Map pointer values ARE addressable and processable
		assert.Equal(t, 1, result.MigratedCount())
	})
}

func TestProcessConfigWithIntKeyMap(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithIntKeyMap struct {
		Items map[int]string `yaml:"items"`
	}

	t.Run("map with int keys containing secrets", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithIntKeyMap{Items: map[int]string{1: "kms://items/1"}}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// Map string values trigger ErrMapValueImmutable
		assert.True(t, result.HasErrors())
	})
}

func TestMigratedSecret(t *testing.T) {
	ms := MigratedSecret{
		ConfigPath:  "database.password",
		KMSPath:     "kms://config/database/password",
		Strategy:    StrategyRemoteKMS,
		OriginalURI: "remote-kms://***",
	}

	assert.Equal(t, "database.password", ms.ConfigPath)
	assert.Equal(t, "kms://config/database/password", ms.KMSPath)
	assert.Equal(t, StrategyRemoteKMS, ms.Strategy)
	assert.Equal(t, "remote-kms://***", ms.OriginalURI)
}

func TestProcessConfigWithMapOfStructValues(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithStructMap struct {
		Databases map[string]dbConfig `yaml:"databases"`
	}

	t.Run("map of struct values with secrets", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithStructMap{
			Databases: map[string]dbConfig{
				"primary":   {Host: "localhost", Password: "kms://db/primary/password"},
				"secondary": {Host: "replica", Password: "kms://db/secondary/password"},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// Map struct values are not addressable, so secrets cannot be migrated
		// They should be processed but not modifiable
		assert.NotNil(t, result)
	})
}

func TestProcessConfigWithEmptySlice(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithEmptySlice struct {
		Items []itemConfig `yaml:"items"`
	}

	t.Run("empty slice is handled", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithEmptySlice{Items: []itemConfig{}}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 0, result.MigratedCount())
	})
}

func TestProcessConfigWithNilSlice(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithNilSlice struct {
		Items []itemConfig `yaml:"items"`
	}

	t.Run("nil slice is handled", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithNilSlice{Items: nil}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 0, result.MigratedCount())
	})
}

func TestProcessConfigWithNilMap(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithNilMap struct {
		Secrets map[string]string `yaml:"secrets"`
	}

	t.Run("nil map is handled", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithNilMap{Secrets: nil}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 0, result.MigratedCount())
	})
}

func TestProcessConfigDeepNesting(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type level4 struct {
		Secret string `yaml:"secret"`
	}
	type level3 struct {
		Level4 level4 `yaml:"level4"`
	}
	type level2 struct {
		Level3 level3 `yaml:"level3"`
	}
	type level1 struct {
		Level2 level2 `yaml:"level2"`
	}
	type rootConfig struct {
		Level1 level1 `yaml:"level1"`
	}

	t.Run("deeply nested structs", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("deep-secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &rootConfig{
			Level1: level1{
				Level2: level2{
					Level3: level3{
						Level4: level4{
							Secret: "kms://deep/secret",
						},
					},
				},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 1, result.MigratedCount())
	})
}

func TestProcessConfigSliceErrorPropagation(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithSlice struct {
		Items []*itemConfig `yaml:"items"`
	}

	t.Run("resolution error in slice element is recorded", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{
			scheme:     SchemeKMS,
			resolveErr: errors.New("resolution failed in slice"),
		})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithSlice{
			Items: []*itemConfig{
				{ID: "1", Password: "kms://items/1"},
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.True(t, result.HasErrors())
	})
}

func TestProcessConfigWithMapNilPointerValue(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type configWithPtrMap struct {
		Databases map[string]*dbConfig `yaml:"databases"`
	}

	t.Run("map with nil pointer value is skipped", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &configWithPtrMap{
			Databases: map[string]*dbConfig{
				"primary": nil,
			},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, 0, result.MigratedCount())
		assert.False(t, result.HasErrors())
	})
}

func TestBuildFieldPathEdgeCases(t *testing.T) {
	type edgeCases struct {
		EmptyYAML    string `yaml:""`
		OnlyOptions  string `yaml:",omitempty"`
		DashYAML     string `yaml:"-"`
		NoTags       string
		MultiOptions string `yaml:"multi,omitempty,inline"`
	}

	tests := []struct {
		name       string
		parentPath string
		fieldIdx   int
		expected   string
	}{
		{name: "empty yaml tag uses json or field name", parentPath: "parent", fieldIdx: 0, expected: "parent.emptyyaml"},
		{name: "only options uses field name", parentPath: "parent", fieldIdx: 1, expected: "parent.onlyoptions"},
		{name: "multi options strips all options", parentPath: "parent", fieldIdx: 4, expected: "parent.multi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s edgeCases
			val := reflect.ValueOf(s)
			typ := val.Type()
			field := typ.Field(tt.fieldIdx)

			result := buildFieldPath(tt.parentPath, field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskURIEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "very long literal", input: strings.Repeat("x", 1000), expected: "***"},
		{name: "kms with long path", input: "kms://very/long/path/to/secret", expected: "kms://***"},
		{name: "whitespace only", input: "   ", expected: "***"},
		{name: "newline chars", input: "secret\nwith\nnewlines", expected: "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskURI(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMigrateToKMSPath(t *testing.T) {
	logger := newTestLogger()
	registry := NewResolverRegistry(logger)
	kms := newMockSecretsClient()

	t.Run("complex config path with arrays", func(t *testing.T) {
		sm, err := NewSecretManager(registry, kms, "app", logger)
		require.NoError(t, err)

		path := sm.buildKMSPath("certificate-authority.identity[0].keystores[1].password")
		assert.Equal(t, "app/certificate-authority/identity/0/keystores/1/password", path)
	})

	t.Run("path with multiple dots", func(t *testing.T) {
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		path := sm.buildKMSPath("a.b.c.d.e.f")
		assert.Equal(t, "config/a/b/c/d/e/f", path)
	})
}

func TestProcessConfigMixedSliceTypes(t *testing.T) {
	logger := newTestLogger()
	ctx := context.Background()

	type mixedConfig struct {
		Strings  []string      `yaml:"strings"`
		Items    []itemConfig  `yaml:"items"`
		PtrItems []*itemConfig `yaml:"ptr-items"`
	}

	t.Run("mixed slice types", func(t *testing.T) {
		registry := NewResolverRegistry(logger)
		registry.Register(&mockResolver{scheme: SchemeKMS, value: []byte("secret")})

		kms := newMockSecretsClient()
		sm, err := NewSecretManager(registry, kms, "config", logger)
		require.NoError(t, err)

		cfg := &mixedConfig{
			Strings:  []string{"kms://string/1", "plain-text"},
			Items:    []itemConfig{{ID: "1", Password: "kms://items/1"}},
			PtrItems: []*itemConfig{{ID: "2", Password: "kms://ptr-items/2"}},
		}

		result, err := sm.ProcessConfig(ctx, cfg)
		require.NoError(t, err)
		// 1 string + 1 item + 1 ptr-item = 3 migrated
		assert.Equal(t, 3, result.MigratedCount())
	})
}
