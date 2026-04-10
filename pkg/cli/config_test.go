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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfigPath_WithHomeDir(t *testing.T) {
	path := DefaultConfigPath()

	assert.NotEmpty(t, path)
	// Should contain .platformctl
	assert.Contains(t, path, ".platformctl")
	assert.Contains(t, path, "config.yaml")
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	require.NotNil(t, config)
	assert.Equal(t, "local", config.CurrentContext)
	assert.Len(t, config.Contexts, 1)

	ctx := config.Contexts[0]
	assert.Equal(t, "local", ctx.Name)
	assert.Equal(t, ContextTypeLocal, ctx.Type)
	require.NotNil(t, ctx.Local)
	assert.Equal(t, "/run/platformd.sock", ctx.Local.SocketPath)
}

func TestLoadConfig_NonExistentFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nonexistent.yaml")

	config, err := LoadConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	// Should return default config when file doesn't exist
	assert.Equal(t, "local", config.CurrentContext)
}

func TestLoadConfig_ValidFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Create a valid config file
	yamlContent := `current_context: remote-prod
contexts:
  - name: remote-prod
    type: remote
    remote:
      server: https://prod.example.com:8443
      ca_cert: /etc/certs/ca.crt
      client_cert: /etc/certs/client.crt
      client_key: /etc/certs/client.key
  - name: local-dev
    type: local
    local:
      socket_path: /tmp/platformd.sock
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0600)
	require.NoError(t, err)

	config, err := LoadConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, "remote-prod", config.CurrentContext)
	assert.Len(t, config.Contexts, 2)

	// Verify first context
	ctx1 := config.Contexts[0]
	assert.Equal(t, "remote-prod", ctx1.Name)
	assert.Equal(t, ContextTypeRemote, ctx1.Type)
	require.NotNil(t, ctx1.Remote)
	assert.Equal(t, "https://prod.example.com:8443", ctx1.Remote.Server)

	// Verify second context
	ctx2 := config.Contexts[1]
	assert.Equal(t, "local-dev", ctx2.Name)
	assert.Equal(t, ContextTypeLocal, ctx2.Type)
	require.NotNil(t, ctx2.Local)
	assert.Equal(t, "/tmp/platformd.sock", ctx2.Local.SocketPath)
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0600)
	require.NoError(t, err)

	config, err := LoadConfig(configPath)

	require.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestLoadConfig_EmptyPath(t *testing.T) {
	// When path is empty, should use default path
	// This test verifies that LoadConfig("") works correctly regardless of
	// whether the default config file exists or not
	config, err := LoadConfig("")

	require.NoError(t, err)
	require.NotNil(t, config)
	// Config should have at least one context and a current context set
	assert.NotEmpty(t, config.CurrentContext)
	assert.NotEmpty(t, config.Contexts)
}

func TestConfig_Save_Success(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "save-test", "config.yaml")

	config := &Config{
		CurrentContext: "test-context",
		Contexts: []*Context{
			{
				Name: "test-context",
				Type: ContextTypeLocal,
				Local: &LocalContext{
					SocketPath: "/tmp/test.sock",
				},
			},
		},
	}

	err := config.Save(configPath)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(configPath)
	require.NoError(t, err)

	// Load and verify
	loaded, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "test-context", loaded.CurrentContext)
	assert.Len(t, loaded.Contexts, 1)
}

func TestConfig_Save_CreatesDirectory(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nested", "dir", "config.yaml")

	config := DefaultConfig()
	err := config.Save(configPath)

	require.NoError(t, err)

	// Verify directory was created
	dir := filepath.Dir(configPath)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestConfig_Save_EmptyPath(t *testing.T) {
	config := DefaultConfig()

	// Save to default path - this might fail in test environment
	// but should not panic
	err := config.Save("")

	// Don't assert success or failure, just that it doesn't panic
	_ = err
}

func TestConfig_GetCurrentContext_Success(t *testing.T) {
	config := &Config{
		CurrentContext: "test-ctx",
		Contexts: []*Context{
			{
				Name: "test-ctx",
				Type: ContextTypeLocal,
			},
		},
	}

	ctx, err := config.GetCurrentContext()

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "test-ctx", ctx.Name)
}

func TestConfig_GetCurrentContext_NoContextSet(t *testing.T) {
	config := &Config{
		CurrentContext: "",
		Contexts:       []*Context{},
	}

	ctx, err := config.GetCurrentContext()

	require.Error(t, err)
	assert.Nil(t, ctx)
	assert.IsType(t, ErrNoContextSet{}, err)
}

func TestConfig_GetCurrentContext_ContextNotFound(t *testing.T) {
	config := &Config{
		CurrentContext: "missing",
		Contexts: []*Context{
			{Name: "existing"},
		},
	}

	ctx, err := config.GetCurrentContext()

	require.Error(t, err)
	assert.Nil(t, ctx)
	assert.IsType(t, ErrContextNotFound{}, err)
}

func TestConfig_GetContext_Success(t *testing.T) {
	config := &Config{
		Contexts: []*Context{
			{Name: "ctx1", Type: ContextTypeLocal},
			{Name: "ctx2", Type: ContextTypeRemote},
		},
	}

	ctx, err := config.GetContext("ctx2")

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "ctx2", ctx.Name)
	assert.Equal(t, ContextTypeRemote, ctx.Type)
}

func TestConfig_GetContext_NotFound(t *testing.T) {
	config := &Config{
		Contexts: []*Context{
			{Name: "ctx1"},
		},
	}

	ctx, err := config.GetContext("nonexistent")

	require.Error(t, err)
	assert.Nil(t, ctx)
	assert.IsType(t, ErrContextNotFound{}, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestConfig_AddContext_New(t *testing.T) {
	config := &Config{
		Contexts: []*Context{},
	}

	newCtx := &Context{
		Name: "new-ctx",
		Type: ContextTypeLocal,
	}

	config.AddContext(newCtx)

	assert.Len(t, config.Contexts, 1)
	assert.Equal(t, "new-ctx", config.Contexts[0].Name)
}

func TestConfig_AddContext_Update(t *testing.T) {
	config := &Config{
		Contexts: []*Context{
			{
				Name: "existing",
				Type: ContextTypeLocal,
				Local: &LocalContext{
					SocketPath: "/old/path.sock",
				},
			},
		},
	}

	updatedCtx := &Context{
		Name: "existing",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/new/path.sock",
		},
	}

	config.AddContext(updatedCtx)

	assert.Len(t, config.Contexts, 1)
	assert.Equal(t, "/new/path.sock", config.Contexts[0].Local.SocketPath)
}

func TestConfig_AddContext_Multiple(t *testing.T) {
	config := &Config{
		Contexts: []*Context{},
	}

	config.AddContext(&Context{Name: "ctx1", Type: ContextTypeLocal})
	config.AddContext(&Context{Name: "ctx2", Type: ContextTypeRemote})
	config.AddContext(&Context{Name: "ctx3", Type: ContextTypeLocal})

	assert.Len(t, config.Contexts, 3)
}

func TestConfig_RemoveContext_Success(t *testing.T) {
	config := &Config{
		CurrentContext: "other",
		Contexts: []*Context{
			{Name: "ctx1"},
			{Name: "ctx2"},
			{Name: "ctx3"},
		},
	}

	err := config.RemoveContext("ctx2")

	require.NoError(t, err)
	assert.Len(t, config.Contexts, 2)
	assert.Equal(t, "ctx1", config.Contexts[0].Name)
	assert.Equal(t, "ctx3", config.Contexts[1].Name)
}

func TestConfig_RemoveContext_NotFound(t *testing.T) {
	config := &Config{
		Contexts: []*Context{
			{Name: "ctx1"},
		},
	}

	err := config.RemoveContext("nonexistent")

	require.Error(t, err)
	assert.IsType(t, ErrContextNotFound{}, err)
	assert.Len(t, config.Contexts, 1)
}

func TestConfig_RemoveContext_ClearsCurrentContext(t *testing.T) {
	config := &Config{
		CurrentContext: "to-remove",
		Contexts: []*Context{
			{Name: "to-remove"},
			{Name: "other"},
		},
	}

	err := config.RemoveContext("to-remove")

	require.NoError(t, err)
	assert.Equal(t, "", config.CurrentContext)
	assert.Len(t, config.Contexts, 1)
}

func TestConfig_RemoveContext_OnlyOne(t *testing.T) {
	config := &Config{
		CurrentContext: "only",
		Contexts: []*Context{
			{Name: "only"},
		},
	}

	err := config.RemoveContext("only")

	require.NoError(t, err)
	assert.Empty(t, config.Contexts)
	assert.Equal(t, "", config.CurrentContext)
}

func TestConfig_SetCurrentContext_Success(t *testing.T) {
	config := &Config{
		CurrentContext: "old",
		Contexts: []*Context{
			{Name: "old"},
			{Name: "new"},
		},
	}

	err := config.SetCurrentContext("new")

	require.NoError(t, err)
	assert.Equal(t, "new", config.CurrentContext)
}

func TestConfig_SetCurrentContext_NotFound(t *testing.T) {
	config := &Config{
		CurrentContext: "current",
		Contexts: []*Context{
			{Name: "current"},
		},
	}

	err := config.SetCurrentContext("nonexistent")

	require.Error(t, err)
	assert.IsType(t, ErrContextNotFound{}, err)
	// Current context should remain unchanged
	assert.Equal(t, "current", config.CurrentContext)
}

func TestAutoDetectContext_NotRoot_NoEnv(t *testing.T) {
	// Clear environment variables
	os.Unsetenv("PLATFORMCTL_SERVER")
	os.Unsetenv("PLATFORMCTL_CA_CERT")
	os.Unsetenv("PLATFORMCTL_CLIENT_CERT")
	os.Unsetenv("PLATFORMCTL_CLIENT_KEY")

	ctx, err := AutoDetectContext()

	// Should fail if not root and no env vars
	if os.Geteuid() != 0 {
		require.Error(t, err)
		assert.Nil(t, ctx)
		assert.IsType(t, ErrAutoDetectionFailed{}, err)
	}
}

func TestAutoDetectContext_WithServerEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("PLATFORMCTL_SERVER", "https://test.example.com:8443")
	os.Setenv("PLATFORMCTL_CA_CERT", "/path/to/ca.crt")
	os.Setenv("PLATFORMCTL_CLIENT_CERT", "/path/to/client.crt")
	os.Setenv("PLATFORMCTL_CLIENT_KEY", "/path/to/client.key")

	defer func() {
		os.Unsetenv("PLATFORMCTL_SERVER")
		os.Unsetenv("PLATFORMCTL_CA_CERT")
		os.Unsetenv("PLATFORMCTL_CLIENT_CERT")
		os.Unsetenv("PLATFORMCTL_CLIENT_KEY")
	}()

	ctx, err := AutoDetectContext()

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "remote-auto", ctx.Name)
	assert.Equal(t, ContextTypeRemote, ctx.Type)
	require.NotNil(t, ctx.Remote)
	assert.Equal(t, "https://test.example.com:8443", ctx.Remote.Server)
	assert.Equal(t, "/path/to/ca.crt", ctx.Remote.CACert)
	assert.Equal(t, "/path/to/client.crt", ctx.Remote.ClientCert)
	assert.Equal(t, "/path/to/client.key", ctx.Remote.ClientKey)
}

func TestAutoDetectContext_WithServerOnly(t *testing.T) {
	os.Setenv("PLATFORMCTL_SERVER", "https://minimal.example.com:8443")

	defer os.Unsetenv("PLATFORMCTL_SERVER")

	ctx, err := AutoDetectContext()

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "remote-auto", ctx.Name)
	assert.Equal(t, ContextTypeRemote, ctx.Type)
	require.NotNil(t, ctx.Remote)
	assert.Equal(t, "https://minimal.example.com:8443", ctx.Remote.Server)
	assert.Empty(t, ctx.Remote.CACert)
	assert.Empty(t, ctx.Remote.ClientCert)
	assert.Empty(t, ctx.Remote.ClientKey)
}

func TestConfig_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "roundtrip.yaml")

	original := &Config{
		CurrentContext: "prod",
		Contexts: []*Context{
			{
				Name: "prod",
				Type: ContextTypeRemote,
				Remote: &RemoteContext{
					Server:     "https://prod.example.com:8443",
					CACert:     "/certs/ca.crt",
					ClientCert: "/certs/client.crt",
					ClientKey:  "/certs/client.key",
				},
			},
			{
				Name: "local",
				Type: ContextTypeLocal,
				Local: &LocalContext{
					SocketPath: "/run/platformd.sock",
				},
			},
		},
	}

	// Save
	err := original.Save(configPath)
	require.NoError(t, err)

	// Load
	loaded, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Compare
	assert.Equal(t, original.CurrentContext, loaded.CurrentContext)
	assert.Len(t, loaded.Contexts, 2)

	// Verify prod context
	prodCtx, err := loaded.GetContext("prod")
	require.NoError(t, err)
	assert.Equal(t, ContextTypeRemote, prodCtx.Type)
	assert.NotNil(t, prodCtx.Remote)
	assert.Equal(t, "https://prod.example.com:8443", prodCtx.Remote.Server)

	// Verify local context
	localCtx, err := loaded.GetContext("local")
	require.NoError(t, err)
	assert.Equal(t, ContextTypeLocal, localCtx.Type)
	assert.NotNil(t, localCtx.Local)
	assert.Equal(t, "/run/platformd.sock", localCtx.Local.SocketPath)
}

func TestConfig_EmptyContexts(t *testing.T) {
	config := &Config{
		CurrentContext: "",
		Contexts:       []*Context{},
	}

	// GetCurrentContext should fail
	ctx, err := config.GetCurrentContext()
	assert.Error(t, err)
	assert.Nil(t, ctx)

	// GetContext should fail
	ctx, err = config.GetContext("any")
	assert.Error(t, err)
	assert.Nil(t, ctx)

	// RemoveContext should fail
	err = config.RemoveContext("any")
	assert.Error(t, err)

	// SetCurrentContext should fail
	err = config.SetCurrentContext("any")
	assert.Error(t, err)
}

func TestConfig_FilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "permissions.yaml")

	config := DefaultConfig()
	err := config.Save(configPath)
	require.NoError(t, err)

	info, err := os.Stat(configPath)
	require.NoError(t, err)

	// Check that file is created with 0600 permissions
	mode := info.Mode()
	assert.Equal(t, os.FileMode(0600), mode.Perm())
}
