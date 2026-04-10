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

package iso

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestCopyPlatformConfig(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		configPath string
		setup      func() error
		wantErr    bool
		errType    string
	}{
		{
			name:       "empty config path returns error",
			configPath: "",
			wantErr:    true,
			errType:    "ErrPlatformConfigRequired",
		},
		{
			name:       "config file not found",
			configPath: filepath.Join(tmpDir, "nonexistent-config.yaml"),
			wantErr:    true,
			errType:    "ErrPlatformConfigNotFound",
		},
		{
			name:       "config missing seal-pcrs",
			configPath: filepath.Join(tmpDir, "config-no-pcrs.yaml"),
			setup: func() error {
				content := `
tpm:
  enabled: true
`
				return os.WriteFile(filepath.Join(tmpDir, "config-no-pcrs.yaml"), []byte(content), 0644)
			},
			wantErr: true,
			errType: "ErrPlatformConfigMissingSealPCRs",
		},
		{
			name:       "valid config with seal-pcrs",
			configPath: filepath.Join(tmpDir, "valid-config.yaml"),
			setup: func() error {
				content := `
tpm:
  enabled: true
  seal-pcrs:
    - 0
    - 7
    - 9
`
				return os.WriteFile(filepath.Join(tmpDir, "valid-config.yaml"), []byte(content), 0644)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			isoDir := filepath.Join(tmpDir, tt.name, "iso")
			os.MkdirAll(isoDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
				Platform: PlatformConfig{
					PlatformType: PlatformTypeServer,
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.CopyPlatformConfig(ctx, tt.configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyPlatformConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify config was copied if no error
			if !tt.wantErr && err == nil {
				destPath := filepath.Join(isoDir, "configs", "installer.yaml")
				if _, err := os.Stat(destPath); os.IsNotExist(err) {
					t.Error("Platform config was not copied to destination")
				}
			}
		})
	}
}

func TestCopyCABundle(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		bundlePath string
		setup      func() error
		wantErr    bool
	}{
		{
			name:       "empty bundle path returns nil",
			bundlePath: "",
			wantErr:    false,
		},
		{
			name:       "bundle file not found",
			bundlePath: filepath.Join(tmpDir, "nonexistent-ca.pem"),
			wantErr:    true,
		},
		{
			name:       "valid CA bundle",
			bundlePath: filepath.Join(tmpDir, "ca-bundle.pem"),
			setup: func() error {
				content := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegRbgvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96r0BYeIHtg3pXJVEgT
/M/L3JZ7j3lLklN3yJ+aSSSrZjY3gJuVvPNt6JZ5J3Db1dWBqJnBJDrWQ2QHBR3v
AgMBAAGjUzBRMB0GA1UdDgQWBBQqzMjVxY9pQ6iJ7sQFq3V3BRChOTAfBgNVHSME
GDAWgBQqzMjVxY9pQ6iJ7sQFq3V3BRChOTAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAXBZQcV7Qn4g8MH6h3bk5QHKI3gTJ6bV6B+LQFZ4y/pWB5L5v
pS+v3hI+SJn+YNFD8VFbYJpKMvvFsQK4rE/wRQ==
-----END CERTIFICATE-----`
				return os.WriteFile(filepath.Join(tmpDir, "ca-bundle.pem"), []byte(content), 0644)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			isoDir := filepath.Join(tmpDir, tt.name, "iso")
			os.MkdirAll(isoDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.CopyCABundle(ctx, tt.bundlePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyCABundle() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify CA bundle was copied if no error and path was provided
			if !tt.wantErr && err == nil && tt.bundlePath != "" {
				destPath := filepath.Join(isoDir, "configs", "ca-bundle.pem")
				if _, err := os.Stat(destPath); os.IsNotExist(err) {
					t.Error("CA bundle was not copied to destination")
				}
			}
		})
	}
}

func TestApplySecurityOverrides(t *testing.T) {
	tests := []struct {
		name      string
		config    *PlatformISOConfig
		inputYAML string
		wantFIPS  bool
		wantFIDO2 bool
		wantTPM   bool
		wantPBKDF string
		wantErr   bool
	}{
		{
			name: "apply FIPS override",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					FIPS:        true,
					EnableFIDO2: false,
					TPM: TPMConfig{
						AutoUnseal: false,
					},
				},
			},
			inputYAML: `
os:
  os: alpine
disk:
  encryption:
    pbkdf: argon2id
`,
			wantFIPS:  true,
			wantPBKDF: "pbkdf2",
			wantErr:   false,
		},
		{
			name: "apply FIDO2 override",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					FIPS:        false,
					EnableFIDO2: true,
					TPM: TPMConfig{
						AutoUnseal: false,
					},
				},
			},
			inputYAML: `
os:
  os: alpine
  enable-fido2: false
`,
			wantFIDO2: true,
			wantErr:   false,
		},
		{
			name: "apply TPM sealing override",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					FIPS: false,
					TPM: TPMConfig{
						AutoUnseal: true,
					},
				},
			},
			inputYAML: `
os:
  os: alpine
enable-tpm-sealing: false
`,
			wantTPM: true,
			wantErr: false,
		},
		{
			name: "apply lockdown override",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					Lockdown:     true,
					LockdownMode: "integrity",
					TPM: TPMConfig{
						AutoUnseal: false,
					},
				},
			},
			inputYAML: `
os:
  os: alpine
  lockdown: false
`,
			wantErr: false,
		},
		{
			name: "invalid YAML returns error",
			config: &PlatformISOConfig{
				Security: SecurityConfig{},
			},
			inputYAML: `
invalid yaml [
  not valid
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customizer := NewCustomizer(tt.config, logging.DefaultLogger())

			result, err := customizer.applySecurityOverrides([]byte(tt.inputYAML))
			if (err != nil) != tt.wantErr {
				t.Errorf("applySecurityOverrides() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			resultStr := string(result)

			// Check FIPS mode PBKDF override
			if tt.wantPBKDF != "" && !strings.Contains(resultStr, tt.wantPBKDF) {
				t.Errorf("Expected PBKDF %s in result, got: %s", tt.wantPBKDF, resultStr)
			}

			// Check TPM sealing override
			if tt.wantTPM && !strings.Contains(resultStr, "enable-tpm-sealing: true") {
				t.Errorf("Expected enable-tpm-sealing: true in result")
			}
		})
	}
}
