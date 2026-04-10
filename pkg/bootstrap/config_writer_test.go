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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// testLogger creates a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// sampleConfig is a test YAML configuration
const sampleConfig = `# Platform configuration
platform:
  name: test-platform
  version: "1.0"

# Certificate Authority settings
certificate-authority:
  # Identity configurations
  identity:
    - name: root-ca
      keystores:
        tpm2:
          srk-auth: original-srk-password
          hierarchy-auth: original-hierarchy-password
        pkcs11:
          pin: original-pin
    - name: intermediate-ca
      keystores:
        tpm2:
          srk-auth: intermediate-srk-password

# Database settings
database:
  host: localhost
  port: 5432
  password: db-password
`

func TestNewConfigWriter(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		logger  *slog.Logger
		wantErr bool
		errType error
	}{
		{
			name:    "valid inputs",
			path:    "/tmp/config.yaml",
			logger:  testLogger(),
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			logger:  testLogger(),
			wantErr: true,
			errType: ErrEmptyPath{},
		},
		{
			name:    "nil logger",
			path:    "/tmp/config.yaml",
			logger:  nil,
			wantErr: true,
			errType: ErrNilLogger{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer, err := NewConfigWriter(tt.path, tt.logger)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				assert.Nil(t, writer)
			} else {
				require.NoError(t, err)
				require.NotNil(t, writer)
				assert.Equal(t, tt.path, writer.Path())
			}
		})
	}
}

func TestConfigWriter_Backup(t *testing.T) {
	t.Run("successful backup", func(t *testing.T) {
		// Create temp directory and config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		backupPath, err := writer.Backup()
		require.NoError(t, err)
		assert.NotEmpty(t, backupPath)
		assert.True(t, strings.HasSuffix(backupPath, ".backup.yaml"))

		// Verify backup contents match original
		originalData, err := os.ReadFile(configPath)
		require.NoError(t, err)
		backupData, err := os.ReadFile(backupPath)
		require.NoError(t, err)
		assert.Equal(t, originalData, backupData)

		// Verify backup has restrictive permissions
		info, err := os.Stat(backupPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("file not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "nonexistent.yaml")

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		_, err = writer.Backup()
		require.Error(t, err)
		var notFoundErr ErrConfigFileNotFound
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

func TestConfigWriter_Restore(t *testing.T) {
	t.Run("successful restore", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		backupPath := filepath.Join(tmpDir, "config.backup.yaml")

		// Create original file
		originalContent := []byte("original: content\n")
		modifiedContent := []byte("modified: content\n")

		err := os.WriteFile(backupPath, originalContent, 0644)
		require.NoError(t, err)
		err = os.WriteFile(configPath, modifiedContent, 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		err = writer.Restore(backupPath)
		require.NoError(t, err)

		// Verify restore was successful
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Equal(t, originalContent, data)
	})

	t.Run("backup not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		err = writer.Restore("/nonexistent/backup.yaml")
		require.Error(t, err)
		var notFoundErr ErrBackupNotFound
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

func TestConfigWriter_UpdateSecretReferences(t *testing.T) {
	t.Run("single update", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:          "certificate-authority.identity[0].keystores.tpm2.srk-auth",
				KMSReference:  "kms://config/ca/identity/0/keystores/tpm2/srk-auth",
				OriginalValue: "original-srk-password",
			},
		}

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		// Verify the update
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "kms://config/ca/identity/0/keystores/tpm2/srk-auth")
		assert.NotContains(t, string(data), "original-srk-password")
	})

	t.Run("multiple updates", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:          "certificate-authority.identity[0].keystores.tpm2.srk-auth",
				KMSReference:  "kms://ca/srk-auth",
				OriginalValue: "original-srk-password",
			},
			{
				Path:          "certificate-authority.identity[0].keystores.pkcs11.pin",
				KMSReference:  "kms://ca/pkcs11-pin",
				OriginalValue: "original-pin",
			},
			{
				Path:          "database.password",
				KMSReference:  "kms://db/password",
				OriginalValue: "db-password",
			},
		}

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "kms://ca/srk-auth")
		assert.Contains(t, string(data), "kms://ca/pkcs11-pin")
		assert.Contains(t, string(data), "kms://db/password")
	})

	t.Run("empty updates", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		err = writer.UpdateSecretReferences([]SecretUpdate{})
		require.Error(t, err)
		var emptyErr ErrEmptyUpdates
		assert.True(t, errors.As(err, &emptyErr))
	})

	t.Run("file not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "nonexistent.yaml")

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{Path: "some.path", KMSReference: "kms://test"},
		}

		err = writer.UpdateSecretReferences(updates)
		require.Error(t, err)
		var notFoundErr ErrConfigFileNotFound
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("invalid path skipped", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		// Mix valid and invalid paths - valid ones should still be applied
		updates := []SecretUpdate{
			{
				Path:         "nonexistent.path",
				KMSReference: "kms://invalid",
			},
			{
				Path:         "database.password",
				KMSReference: "kms://db/password",
			},
		}

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "kms://db/password")
	})
}

func TestConfigWriter_DryRun(t *testing.T) {
	t.Run("reports valid updates", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:          "certificate-authority.identity[0].keystores.tpm2.srk-auth",
				KMSReference:  "kms://ca/srk-auth",
				OriginalValue: "original-srk-password",
			},
			{
				Path:          "database.password",
				KMSReference:  "kms://db/password",
				OriginalValue: "db-password",
			},
		}

		validUpdates, err := writer.DryRun(updates)
		require.NoError(t, err)
		assert.Len(t, validUpdates, 2)

		// Verify file was NOT modified
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "original-srk-password")
		assert.Contains(t, string(data), "db-password")
	})

	t.Run("filters invalid paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:         "nonexistent.path",
				KMSReference: "kms://invalid",
			},
			{
				Path:         "database.password",
				KMSReference: "kms://db/password",
			},
		}

		validUpdates, err := writer.DryRun(updates)
		require.NoError(t, err)
		assert.Len(t, validUpdates, 1)
		assert.Equal(t, "database.password", validUpdates[0].Path)
	})

	t.Run("empty updates", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		_, err = writer.DryRun([]SecretUpdate{})
		require.Error(t, err)
		var emptyErr ErrEmptyUpdates
		assert.True(t, errors.As(err, &emptyErr))
	})
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantErr    bool
		errType    error
		segmentLen int
	}{
		{
			name:       "simple path",
			path:       "database.password",
			wantErr:    false,
			segmentLen: 2,
		},
		{
			name:       "path with array index",
			path:       "identity[0].name",
			wantErr:    false,
			segmentLen: 3, // identity, [0], name
		},
		{
			name:       "complex path",
			path:       "certificate-authority.identity[0].keystores.tpm2.srk-auth",
			wantErr:    false,
			segmentLen: 6, // certificate-authority, identity, [0], keystores, tpm2, srk-auth
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
			errType: ErrInvalidYAMLPath{},
		},
		{
			name:    "empty segment",
			path:    "database..password",
			wantErr: true,
			errType: ErrInvalidYAMLPath{},
		},
		{
			name:    "invalid characters",
			path:    "database.pass@word",
			wantErr: true,
			errType: ErrInvalidYAMLPath{},
		},
		{
			name:       "multiple array indices",
			path:       "items[0].subitems[1].value",
			wantErr:    false,
			segmentLen: 5, // items, [0], subitems, [1], value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, err := parsePath(tt.path)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, segments, tt.segmentLen)
			}
		})
	}
}

func TestConfigWriter_AtomicWrite(t *testing.T) {
	t.Run("preserves permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		// Create file with specific permissions
		err := os.WriteFile(configPath, []byte("original: content\n"), 0640)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:         "original",
				KMSReference: "kms://updated",
			},
		}

		// Create a simple config for update
		simpleConfig := "original: test-value\n"
		err = os.WriteFile(configPath, []byte(simpleConfig), 0640)
		require.NoError(t, err)

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		// Verify permissions preserved
		info, err := os.Stat(configPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
	})
}

func TestConfigWriter_BackupAndRestore_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	// Create backup
	backupPath, err := writer.Backup()
	require.NoError(t, err)

	// Apply updates
	updates := []SecretUpdate{
		{
			Path:          "certificate-authority.identity[0].keystores.tpm2.srk-auth",
			KMSReference:  "kms://ca/srk-auth",
			OriginalValue: "original-srk-password",
		},
	}

	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	// Verify update applied
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "kms://ca/srk-auth")

	// Restore from backup
	err = writer.Restore(backupPath)
	require.NoError(t, err)

	// Verify restoration
	data, err = os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "original-srk-password")
	assert.NotContains(t, string(data), "kms://ca/srk-auth")
}

func TestSecretUpdate_Struct(t *testing.T) {
	update := SecretUpdate{
		Path:          "certificate-authority.identity[0].keystores.tpm2.srk-auth",
		KMSReference:  "kms://config/ca/identity/0/keystores/tpm2/srk-auth",
		OriginalValue: "original-password",
	}

	assert.Equal(t, "certificate-authority.identity[0].keystores.tpm2.srk-auth", update.Path)
	assert.Equal(t, "kms://config/ca/identity/0/keystores/tpm2/srk-auth", update.KMSReference)
	assert.Equal(t, "original-password", update.OriginalValue)
}

func TestErrors(t *testing.T) {
	t.Run("ErrConfigFileNotFound", func(t *testing.T) {
		err := ErrConfigFileNotFound{Path: "/etc/config.yaml"}
		assert.Contains(t, err.Error(), "/etc/config.yaml")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ErrInvalidYAMLPath", func(t *testing.T) {
		err := ErrInvalidYAMLPath{Path: "bad..path", Reason: "empty segment"}
		assert.Contains(t, err.Error(), "bad..path")
		assert.Contains(t, err.Error(), "empty segment")
	})

	t.Run("ErrPathNotFound", func(t *testing.T) {
		err := ErrPathNotFound{Path: "missing.key"}
		assert.Contains(t, err.Error(), "missing.key")
	})

	t.Run("ErrBackupFailed", func(t *testing.T) {
		cause := errors.New("permission denied")
		err := ErrBackupFailed{Path: "/config.yaml", Err: cause}
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Contains(t, err.Error(), "permission denied")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrRestoreFailed", func(t *testing.T) {
		cause := errors.New("disk full")
		err := ErrRestoreFailed{
			BackupPath: "/backup.yaml",
			TargetPath: "/config.yaml",
			Err:        cause,
		}
		assert.Contains(t, err.Error(), "/backup.yaml")
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Contains(t, err.Error(), "disk full")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrIndexOutOfBounds", func(t *testing.T) {
		err := ErrIndexOutOfBounds{Path: "items[5]", Index: 5, Size: 3}
		assert.Contains(t, err.Error(), "5")
		assert.Contains(t, err.Error(), "3")
		assert.Contains(t, err.Error(), "items[5]")
	})

	t.Run("ErrUnexpectedNodeType", func(t *testing.T) {
		err := ErrUnexpectedNodeType{
			Path:     "items",
			Expected: "sequence",
			Got:      "mapping",
		}
		assert.Contains(t, err.Error(), "items")
		assert.Contains(t, err.Error(), "sequence")
		assert.Contains(t, err.Error(), "mapping")
	})

	t.Run("ErrDryRunMode", func(t *testing.T) {
		err := ErrDryRunMode{UpdateCount: 5}
		assert.Contains(t, err.Error(), "5")
		assert.Contains(t, err.Error(), "dry-run")
	})
}

func TestNodeKindString(t *testing.T) {
	tests := []struct {
		name     string
		kind     yaml.Kind
		expected string
	}{
		{"document", yaml.DocumentNode, "document"},
		{"sequence", yaml.SequenceNode, "sequence"},
		{"mapping", yaml.MappingNode, "mapping"},
		{"scalar", yaml.ScalarNode, "scalar"},
		{"alias", yaml.AliasNode, "alias"},
		{"unknown", yaml.Kind(255), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nodeKindString(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigWriter_ArrayIndexOutOfBounds(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	// Try to access array index that doesn't exist
	updates := []SecretUpdate{
		{
			Path:         "certificate-authority.identity[99].keystores.tpm2.srk-auth",
			KMSReference: "kms://test",
		},
	}

	// The update should not cause an error, but should skip the invalid path
	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	// Verify the file wasn't modified with invalid data
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "kms://test")
}

func TestConfigWriter_NestedMapUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	nestedConfig := `nested:
  level1:
    level2:
      level3:
        secret: original-value
`
	err := os.WriteFile(configPath, []byte(nestedConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{
			Path:          "nested.level1.level2.level3.secret",
			KMSReference:  "kms://deeply/nested/secret",
			OriginalValue: "original-value",
		},
	}

	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "kms://deeply/nested/secret")
	assert.NotContains(t, string(data), "original-value")
}

func TestConfigWriter_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write invalid YAML
	invalidYAML := `this is: [invalid: yaml
`
	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{Path: "some.path", KMSReference: "kms://test"},
	}

	err = writer.UpdateSecretReferences(updates)
	require.Error(t, err)
	var parseErr ErrParseYAML
	assert.True(t, errors.As(err, &parseErr))
}

func TestConfigWriter_SecondArrayElement(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	// Update the second identity's srk-auth
	updates := []SecretUpdate{
		{
			Path:          "certificate-authority.identity[1].keystores.tpm2.srk-auth",
			KMSReference:  "kms://intermediate/srk-auth",
			OriginalValue: "intermediate-srk-password",
		},
	}

	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "kms://intermediate/srk-auth")
	assert.NotContains(t, string(data), "intermediate-srk-password")
	// First identity should still have original value
	assert.Contains(t, string(data), "original-srk-password")
}

func TestConfigWriterErrors(t *testing.T) {
	t.Run("ErrEmptyPath", func(t *testing.T) {
		err := ErrEmptyPath{}
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("ErrEmptyUpdates", func(t *testing.T) {
		err := ErrEmptyUpdates{}
		assert.Contains(t, err.Error(), "no secret updates")
	})

	t.Run("ErrWriteFailed", func(t *testing.T) {
		cause := errors.New("write error")
		err := ErrWriteFailed{Path: "/config.yaml", Err: cause}
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Contains(t, err.Error(), "write error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrWriteFailed without cause", func(t *testing.T) {
		err := ErrWriteFailed{Path: "/config.yaml"}
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrAtomicWriteFailed", func(t *testing.T) {
		cause := errors.New("rename error")
		err := ErrAtomicWriteFailed{TempPath: "/tmp/config.tmp", TargetPath: "/config.yaml", Err: cause}
		assert.Contains(t, err.Error(), "/tmp/config.tmp")
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Contains(t, err.Error(), "rename error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrParseYAML", func(t *testing.T) {
		cause := errors.New("yaml parse error")
		err := ErrParseYAML{Path: "/config.yaml", Err: cause}
		assert.Contains(t, err.Error(), "/config.yaml")
		assert.Contains(t, err.Error(), "yaml parse error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrBackupNotFound", func(t *testing.T) {
		err := ErrBackupNotFound{Path: "/backup.yaml"}
		assert.Contains(t, err.Error(), "/backup.yaml")
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestConfigWriter_NavigateToNilRoot(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte("key: value\n"), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	// Internally tests navigateToNode with empty segments
	updates := []SecretUpdate{
		{
			Path:         "key",
			KMSReference: "kms://test",
		},
	}

	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "kms://test")
}

func TestConfigWriter_SequenceAccess(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	arrayConfig := `items:
  - value: secret1
  - value: secret2
  - value: secret3
`
	err := os.WriteFile(configPath, []byte(arrayConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	t.Run("update middle element", func(t *testing.T) {
		updates := []SecretUpdate{
			{
				Path:         "items[1].value",
				KMSReference: "kms://items/1/value",
			},
		}

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "kms://items/1/value")
		assert.Contains(t, string(data), "secret1") // First element unchanged
		assert.Contains(t, string(data), "secret3") // Last element unchanged
	})
}

func TestConfigWriter_NodeTypeErrors(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	t.Run("expected sequence got scalar", func(t *testing.T) {
		scalarConfig := `items: not-an-array
`
		err := os.WriteFile(configPath, []byte(scalarConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:         "items[0].value",
				KMSReference: "kms://test",
			},
		}

		// Should not error, but skip the invalid path
		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "kms://test")
	})

	t.Run("expected mapping got sequence", func(t *testing.T) {
		sequenceConfig := `items:
  - first
  - second
`
		err := os.WriteFile(configPath, []byte(sequenceConfig), 0644)
		require.NoError(t, err)

		writer, err := NewConfigWriter(configPath, testLogger())
		require.NoError(t, err)

		updates := []SecretUpdate{
			{
				Path:         "items.nonexistent",
				KMSReference: "kms://test",
			},
		}

		err = writer.UpdateSecretReferences(updates)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "kms://test")
	})
}

func TestConfigWriter_DryRunFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{Path: "some.path", KMSReference: "kms://test"},
	}

	_, err = writer.DryRun(updates)
	require.Error(t, err)
	var notFoundErr ErrConfigFileNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestConfigWriter_MultipleArrayIndices(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	nestedArrayConfig := `matrix:
  - row:
      - cell: value00
      - cell: value01
  - row:
      - cell: value10
      - cell: value11
`
	err := os.WriteFile(configPath, []byte(nestedArrayConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{
			Path:         "matrix[1].row[1].cell",
			KMSReference: "kms://matrix/1/row/1/cell",
		},
	}

	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "kms://matrix/1/row/1/cell")
	assert.Contains(t, string(data), "value00") // Other cells unchanged
}

func TestParsePath_Validation(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		shouldFail bool
	}{
		{name: "valid simple", path: "database.password", shouldFail: false},
		{name: "valid with hyphen", path: "certificate-authority.identity", shouldFail: false},
		{name: "valid with underscore", path: "my_config.my_secret", shouldFail: false},
		{name: "valid with number", path: "config1.secret2", shouldFail: false},
		{name: "invalid space", path: "database. password", shouldFail: true},
		{name: "invalid special", path: "database!password", shouldFail: true},
		{name: "invalid colon", path: "database:password", shouldFail: true},
		{name: "leading dot", path: ".database.password", shouldFail: true},
		{name: "trailing dot", path: "database.password.", shouldFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, err := parsePath(tt.path)
			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, segments)
			}
		})
	}
}

func TestConfigWriter_EmptyConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write empty YAML (valid but empty document)
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{Path: "some.path", KMSReference: "kms://test"},
	}

	// Should not panic, just skip the update
	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)
}

func TestConfigWriter_NullDocument(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write explicit null
	err := os.WriteFile(configPath, []byte("null\n"), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	updates := []SecretUpdate{
		{Path: "some.path", KMSReference: "kms://test"},
	}

	// Should handle gracefully
	err = writer.UpdateSecretReferences(updates)
	require.NoError(t, err)
}

func TestConfigWriter_BackupTimestampFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(sampleConfig), 0644)
	require.NoError(t, err)

	writer, err := NewConfigWriter(configPath, testLogger())
	require.NoError(t, err)

	backupPath, err := writer.Backup()
	require.NoError(t, err)

	// Verify backup filename contains expected patterns
	assert.Contains(t, backupPath, "config.")
	assert.Contains(t, backupPath, ".backup.yaml")

	// Verify timestamp format (YYYYMMDD-HHMMSS)
	base := filepath.Base(backupPath)
	parts := strings.Split(base, ".")
	assert.Equal(t, 4, len(parts)) // config, timestamp, backup, yaml
	assert.Equal(t, "config", parts[0])
	assert.Equal(t, "backup", parts[2])
	assert.Equal(t, "yaml", parts[3])

	// Timestamp should be valid format
	timestamp := parts[1]
	assert.Regexp(t, `^\d{8}-\d{6}$`, timestamp)
}
