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

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
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

// TestApplySecurityOverrides_SecureBootCoherence asserts the build flag is
// the single source of truth for the baked config's secure-boot.enabled
// (#50): building with Secure Boot forces enabled (with a media-staged DB
// signing ref when none is configured), building without forces disabled —
// so the ISO can never generate-and-enroll keys while shipping an unsigned
// UKI, or the reverse.
func TestApplySecurityOverrides_SecureBootCoherence(t *testing.T) {
	cases := []struct {
		name        string
		secureBoot  bool
		inputYAML   string
		wantEnabled bool
		wantMediaDB bool
	}{
		{
			name:       "SB build forces enabled on a section without it",
			secureBoot: true,
			inputYAML: `
os:
  os: alpine
secure-boot:
  key-path: /boot/efi/secure-boot/db.key
  cert-path: /boot/efi/secure-boot/db.crt
`,
			wantEnabled: true,
			wantMediaDB: true,
		},
		{
			name:        "SB build creates the section when absent",
			secureBoot:  true,
			inputYAML:   "os:\n  os: alpine\n",
			wantEnabled: true,
			wantMediaDB: true,
		},
		{
			name:       "SB build preserves an existing db ref",
			secureBoot: true,
			inputYAML: `
secure-boot:
  enabled: true
  resign-mode: remote
  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }
`,
			wantEnabled: true,
			wantMediaDB: false,
		},
		{
			name:       "non-SB build forces disabled",
			secureBoot: false,
			inputYAML: `
secure-boot:
  enabled: true
`,
			wantEnabled: false,
			wantMediaDB: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			customizer := NewCustomizer(&PlatformISOConfig{
				Security: SecurityConfig{SecureBoot: tc.secureBoot},
			}, logging.DefaultLogger())

			out, err := customizer.applySecurityOverrides([]byte(tc.inputYAML))
			if err != nil {
				t.Fatalf("applySecurityOverrides: %v", err)
			}

			var parsed map[string]interface{}
			if err := yaml.Unmarshal(out, &parsed); err != nil {
				t.Fatalf("parse output: %v", err)
			}
			sb, _ := parsed["secure-boot"].(map[interface{}]interface{})
			if tc.wantEnabled || tc.inputYAML != "os:\n  os: alpine\n" {
				if sb == nil {
					t.Fatal("secure-boot section missing from output")
				}
			}
			if sb != nil {
				enabled, _ := sb["enabled"].(bool)
				if enabled != tc.wantEnabled {
					t.Errorf("secure-boot.enabled = %v, want %v", enabled, tc.wantEnabled)
				}
				db, hasDB := sb["db"].(map[interface{}]interface{})
				if tc.wantMediaDB {
					if !hasDB {
						t.Fatal("expected a media-staged db signing ref")
					}
					if keyURI, _ := db["key-uri"].(string); keyURI != "file://"+SecureBootKeysMediaDir+"/DB.key" {
						t.Errorf("db.key-uri = %q, want media-staged path", keyURI)
					}
					if certURI, _ := db["cert-uri"].(string); certURI != "file://"+SecureBootKeysMediaDir+"/DB.crt" {
						t.Errorf("db.cert-uri = %q, want media-staged path", certURI)
					}
					if mode, _ := sb["resign-mode"].(string); mode != "local" {
						t.Errorf("resign-mode = %q, want local for media-staged signing", mode)
					}
				}
				if tc.name == "SB build preserves an existing db ref" {
					if !hasDB {
						t.Fatal("existing db ref must survive")
					}
					if keyURI, _ := db["key-uri"].(string); keyURI != "kms://platform/secureboot/db" {
						t.Errorf("existing db.key-uri mutated: %q", keyURI)
					}
					if certURI, _ := db["cert-uri"].(string); certURI != "kms://platform/secureboot/db-cert" {
						t.Errorf("existing db.cert-uri mutated: %q", certURI)
					}
					if mode, _ := sb["resign-mode"].(string); mode != "remote" {
						t.Errorf("existing resign-mode mutated: %q", mode)
					}
				}
			}
		})
	}
}

// TestCopySecureBootKeys_FailClosedWhenEnabled asserts key staging cannot
// soft-fail under an SB-enabled build (#50): the security override bakes
// media-staged db refs, so a build that warns past missing keys would ship
// enabled: true with dangling file:// references.
func TestCopySecureBootKeys_FailClosedWhenEnabled(t *testing.T) {
	t.Run("SB build fails on missing staged DB material", func(t *testing.T) {
		work := t.TempDir()
		isoDir := t.TempDir()
		// Keys dir exists but holds no DB.key/DB.crt and generation is
		// impossible (unwritable path forces ensure to fail... simplest:
		// pre-create empty dir; ensure will attempt generation).
		keysDir := t.TempDir()

		customizer := NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: true},
			Directories: DirectoryConfig{
				Work: work,
				ISO:  isoDir,
				Keys: keysDir,
			},
		}, logging.DefaultLogger())

		err := customizer.CopySecureBootKeys(context.Background())
		if err == nil {
			// Generation may have SUCCEEDED (the customizer can generate
			// keys) — then the staged media must carry DB.key and DB.crt.
			for _, required := range []string{"DB.key", "DB.crt"} {
				if _, statErr := os.Stat(filepath.Join(isoDir, SecureBootKeysISODirName, required)); statErr != nil {
					t.Fatalf("SB build reported success but staged media lacks %s", required)
				}
			}
			return
		}
		// Or it failed loudly — also acceptable; never silent success
		// without the referenced material.
	})

	t.Run("non-SB build still soft-fails", func(t *testing.T) {
		customizer := NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: false},
			Directories: DirectoryConfig{
				Work: t.TempDir(),
				ISO:  t.TempDir(),
				Keys: "/nonexistent/keys-dir-that-cannot-be-created/x",
			},
		}, logging.DefaultLogger())

		if err := customizer.CopySecureBootKeys(context.Background()); err != nil {
			t.Fatalf("non-SB build must tolerate missing keys, got %v", err)
		}
	})
}

// TestCopySecureBootKeys_RemoteSigningNeedsNoLocalKeys asserts a build whose
// baked config preserves a remote/KMS db ref neither requires local key
// material nor embeds private keys in the ISO — only certificates (for
// enrollment) are staged.
func TestCopySecureBootKeys_RemoteSigningNeedsNoLocalKeys(t *testing.T) {
	isoDir := t.TempDir()
	keysDir := t.TempDir()
	// Local material exists — the remote build must stage certs only.
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("private"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), genTestCertPEM(t), 0644))

	customizer := NewCustomizer(&PlatformISOConfig{
		Security: SecurityConfig{SecureBoot: true},
		Directories: DirectoryConfig{
			Work: t.TempDir(),
			ISO:  isoDir,
			Keys: keysDir,
		},
	}, logging.DefaultLogger())

	// Finalize the config first, as iso create does: an existing remote
	// db ref is preserved → media signing NOT required.
	_, err := customizer.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  resign-mode: remote
  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }
`))
	require.NoError(t, err)
	require.True(t, customizer.sbMediaSigningKnown)
	require.False(t, customizer.sbMediaSigning)

	require.NoError(t, customizer.CopySecureBootKeys(context.Background()))

	if _, err := os.Stat(filepath.Join(isoDir, SecureBootKeysISODirName, "DB.key")); err == nil {
		t.Error("remote-signing build must NOT embed the private DB key in the ISO")
	}
	if _, err := os.Stat(filepath.Join(isoDir, SecureBootKeysISODirName, "DB.crt")); err != nil {
		t.Error("certificates must still be staged for enrollment")
	}
}

// TestCopySecureBootKeys_EnforcingFailsClosed asserts a baked config with
// secure-boot.enforce: true can never produce a successful build without
// the PK/KEK enrollment certificates positively staged (round-9 review):
// the installer resolves them from the staged media and warns past their
// absence, so the BUILD is the only gate between "enforce requested" and a
// node with no enforcement.
func TestCopySecureBootKeys_EnforcingFailsClosed(t *testing.T) {
	enforcingRemoteYAML := `
secure-boot:
  enabled: true
  enforce: true
  resign-mode: remote
  pk: { key-uri: "kms://platform/secureboot/pk" }
  kek: { key-uri: "kms://platform/secureboot/kek" }
  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }
`
	newEnforcing := func(t *testing.T, keysDir string) *Customizer {
		t.Helper()
		c := NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: true},
			Directories: DirectoryConfig{
				Work: t.TempDir(),
				ISO:  t.TempDir(),
				Keys: keysDir,
			},
		}, logging.DefaultLogger())
		_, err := c.applySecurityOverrides([]byte(enforcingRemoteYAML))
		require.NoError(t, err)
		require.True(t, c.sbEnforce)
		require.False(t, c.sbMediaSigning)
		return c
	}

	t.Run("remote signing with unavailable keys directory is a build error", func(t *testing.T) {
		c := newEnforcing(t, "/nonexistent/keys-dir-that-cannot-be-created/x")
		require.Error(t, c.CopySecureBootKeys(context.Background()),
			"enforce requested but enrollment artifacts cannot be prepared — the build must fail")
	})

	t.Run("remote signing without staged PK/KEK certificates is a build error", func(t *testing.T) {
		keysDir := t.TempDir()
		// DB pair present so no generation runs; enrollment certs absent.
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("private"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), genTestCertPEM(t), 0644))
		c := newEnforcing(t, keysDir)
		err := c.CopySecureBootKeys(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "PK.crt")
	})

	t.Run("staged non-certificate PK material is a build error", func(t *testing.T) {
		keysDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("private"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), genTestCertPEM(t), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "PK.crt"), genTestCertPEM(t), 0644))
		// KEK.crt is garbage — it will be skipped by the public-artifact
		// allowlist and therefore missing from the staged media.
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "KEK.crt"), []byte("not a cert"), 0644))
		c := newEnforcing(t, keysDir)
		err := c.CopySecureBootKeys(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "KEK.crt")
	})

	t.Run("full public enrollment set builds and stages", func(t *testing.T) {
		keysDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("private"), 0600))
		for _, name := range []string{"DB.crt", "PK.crt", "KEK.crt"} {
			require.NoError(t, os.WriteFile(filepath.Join(keysDir, name), genTestCertPEM(t), 0644))
		}
		c := newEnforcing(t, keysDir)
		require.NoError(t, c.CopySecureBootKeys(context.Background()))
		for _, name := range []string{"PK.crt", "KEK.crt"} {
			_, err := os.Stat(filepath.Join(c.config.Directories.ISO, SecureBootKeysISODirName, name))
			require.NoError(t, err, "%s must be staged for enrollment", name)
		}
	})

	t.Run("non-media file pk cert-uri fails the override pass", func(t *testing.T) {
		c := NewCustomizer(&PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}, logging.DefaultLogger())
		_, err := c.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  enforce: true
  pk: { key-uri: "kms://platform/secureboot/pk", cert-uri: "file:///etc/keys/PK.crt" }
  kek: { key-uri: "kms://platform/secureboot/kek" }
  db: { key-uri: "kms://platform/secureboot/db" }
`))
		require.Error(t, err, "a file:// PK cert outside the media cannot exist in the install environment")
	})

	t.Run("missing pk key-uri fails the override pass", func(t *testing.T) {
		// SecureBootConfig.Validate requires pk/kek key-uris when enforce
		// is set — the build must surface that, not the target install
		// (round-10 review).
		c := NewCustomizer(&PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}, logging.DefaultLogger())
		_, err := c.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  enforce: true
  kek: { key-uri: "kms://platform/secureboot/kek" }
  db: { key-uri: "kms://platform/secureboot/db" }
`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "pk.key-uri")
	})

	t.Run("unsupported kek key-uri scheme fails the override pass", func(t *testing.T) {
		c := NewCustomizer(&PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}, logging.DefaultLogger())
		_, err := c.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  enforce: true
  pk: { key-uri: "kms://platform/secureboot/pk" }
  kek: { key-uri: "https://example/kek" }
  db: { key-uri: "kms://platform/secureboot/db" }
`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "kek.key-uri")
	})

	t.Run("custom media pk/kek cert names are required as staged", func(t *testing.T) {
		c := NewCustomizer(&PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}, logging.DefaultLogger())
		_, err := c.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  enforce: true
  pk: { key-uri: "kms://platform/secureboot/pk", cert-uri: "file://` + SecureBootKeysMediaDir + `/custom-pk.crt" }
  kek: { key-uri: "kms://platform/secureboot/kek", cert-uri: "file://` + SecureBootKeysMediaDir + `/custom-kek.crt" }
  db: { key-uri: "kms://platform/secureboot/db" }
`))
		require.NoError(t, err)
		require.Equal(t, "custom-pk.crt", c.sbPKCertFile)
		require.Equal(t, "custom-kek.crt", c.sbKEKCertFile)
	})
}

// TestCopySecureBootKeys_RemoteSigningNeverGeneratesKeys asserts a
// remote/KMS-signing build never runs local key generation (round-15
// review): the remote contract is that no local private signing key is
// needed — or produced. An empty keys directory stays empty; an enforcing
// remote build without its enrollment certificates fails without creating
// any key material on the build host.
func TestCopySecureBootKeys_RemoteSigningNeverGeneratesKeys(t *testing.T) {
	remoteYAML := func(enforce string) []byte {
		return []byte(`
secure-boot:
  enabled: true
` + enforce + `
  pk: { key-uri: "kms://platform/secureboot/pk" }
  kek: { key-uri: "kms://platform/secureboot/kek" }
  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }
`)
	}
	newRemote := func(t *testing.T, keysDir string, enforce bool) *Customizer {
		t.Helper()
		c := NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: true},
			Directories: DirectoryConfig{
				Work: t.TempDir(),
				ISO:  t.TempDir(),
				Keys: keysDir,
			},
		}, logging.DefaultLogger())
		enforceLine := ""
		if enforce {
			enforceLine = "  enforce: true"
		}
		_, err := c.applySecurityOverrides(remoteYAML(enforceLine))
		require.NoError(t, err)
		require.False(t, c.sbMediaSigning)
		return c
	}

	t.Run("empty keys directory stays empty", func(t *testing.T) {
		keysDir := t.TempDir()
		c := newRemote(t, keysDir, false)
		require.NoError(t, c.CopySecureBootKeys(context.Background()))
		entries, err := os.ReadDir(keysDir)
		require.NoError(t, err)
		require.Empty(t, entries, "remote signing must not generate local key material")
	})

	t.Run("missing keys directory is tolerated without generation", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "never-created")
		c := newRemote(t, missing, false)
		require.NoError(t, c.CopySecureBootKeys(context.Background()))
		_, err := os.Stat(missing)
		require.True(t, os.IsNotExist(err), "remote signing must not create the keys directory")
	})

	t.Run("enforcing remote build fails without generating keys", func(t *testing.T) {
		keysDir := t.TempDir()
		c := newRemote(t, keysDir, true)
		require.Error(t, c.CopySecureBootKeys(context.Background()),
			"enforce without staged PK/KEK enrollment certificates must fail")
		entries, err := os.ReadDir(keysDir)
		require.NoError(t, err)
		require.Empty(t, entries, "the failure must not have generated key material")
	})
}

// TestCopySecureBootKeys_ReplacesStaleDestination asserts staging REPLACES
// the ISO's secure-boot-keys directory (round-11 review): a private key
// already present in the extracted base ISO tree must not survive a
// remote/KMS-signing build — the allowlist only filters what THIS build
// copies, so merging would ship the stale key.
func TestCopySecureBootKeys_ReplacesStaleDestination(t *testing.T) {
	isoDir := t.TempDir()
	keysDir := t.TempDir()
	keyPEM, certPEM := genTestSigningPairPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), keyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), certPEM, 0644))

	// A stale private key from a previous build / repacked base ISO.
	staleDir := filepath.Join(isoDir, SecureBootKeysISODirName)
	require.NoError(t, os.MkdirAll(staleDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(staleDir, "DB.key"), []byte("stale private key"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(staleDir, "leftover.p8"), []byte("stale pkcs8"), 0600))

	c := NewCustomizer(&PlatformISOConfig{
		Security: SecurityConfig{SecureBoot: true},
		Directories: DirectoryConfig{
			Work: t.TempDir(),
			ISO:  isoDir,
			Keys: keysDir,
		},
	}, logging.DefaultLogger())
	_, err := c.applySecurityOverrides([]byte(`
secure-boot:
  enabled: true
  resign-mode: remote
  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }
`))
	require.NoError(t, err)
	require.NoError(t, c.CopySecureBootKeys(context.Background()))

	for _, stale := range []string{"DB.key", "leftover.p8"} {
		if _, statErr := os.Stat(filepath.Join(staleDir, stale)); statErr == nil {
			t.Errorf("stale %s survived a remote/KMS-signing build — the destination must be replaced, not merged", stale)
		}
	}
	if _, statErr := os.Stat(filepath.Join(staleDir, "DB.crt")); statErr != nil {
		t.Error("the certificate from THIS build must still be staged")
	}
}

// TestCopySecureBootKeys_RejectsSelfReferentialKeysDir asserts staging
// refuses to run when the configured keys directory IS the ISO staging
// directory (directly or through a symlink): replacement would delete the
// operator's source keys before they could be copied (round-13 review).
func TestCopySecureBootKeys_RejectsSelfReferentialKeysDir(t *testing.T) {
	newConfig := func(isoDir, keysDir string) *Customizer {
		return NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: true},
			Directories: DirectoryConfig{
				Work: t.TempDir(),
				ISO:  isoDir,
				Keys: keysDir,
			},
		}, logging.DefaultLogger())
	}
	seedKeys := func(t *testing.T, dir string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(dir, 0755))
		keyPEM, certPEM := genTestSigningPairPEM(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.key"), keyPEM, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.crt"), certPEM, 0644))
	}

	t.Run("keys dir inside the ISO staging dir is rejected, keys survive", func(t *testing.T) {
		isoDir := t.TempDir()
		keysDir := filepath.Join(isoDir, SecureBootKeysISODirName)
		seedKeys(t, keysDir)
		err := newConfig(isoDir, keysDir).CopySecureBootKeys(context.Background())
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(keysDir, "DB.key"))
		require.NoError(t, statErr, "the source keys must never be deleted")
	})

	t.Run("keys dir reaching the staging dir through a symlink is rejected", func(t *testing.T) {
		isoDir := t.TempDir()
		staging := filepath.Join(isoDir, SecureBootKeysISODirName)
		seedKeys(t, staging)
		link := filepath.Join(t.TempDir(), "keys-link")
		require.NoError(t, os.Symlink(staging, link))
		err := newConfig(isoDir, link).CopySecureBootKeys(context.Background())
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(staging, "DB.key"))
		require.NoError(t, statErr, "the source keys must never be deleted")
	})

	t.Run("keys dir BENEATH the staging dir is rejected, keys survive", func(t *testing.T) {
		// Replacing the staging directory would take this descendant
		// source with it (round-14 review).
		isoDir := t.TempDir()
		keysDir := filepath.Join(isoDir, SecureBootKeysISODirName, "source")
		seedKeys(t, keysDir)
		err := newConfig(isoDir, keysDir).CopySecureBootKeys(context.Background())
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(keysDir, "DB.key"))
		require.NoError(t, statErr, "the source keys must never be deleted")
	})

	t.Run("keys dir as an ANCESTOR of the staging dir is rejected, keys survive", func(t *testing.T) {
		// Staging into a subtree of the source would destructively
		// replace part of the source (round-14 review).
		keysDir := t.TempDir()
		seedKeys(t, keysDir)
		isoDir := keysDir // destDir = keysDir/secure-boot-keys, a child of the source
		err := newConfig(isoDir, keysDir).CopySecureBootKeys(context.Background())
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(keysDir, "DB.key"))
		require.NoError(t, statErr, "the source keys must never be deleted")
	})
}

// TestCopySecureBootKeys_RejectsUnusableSigningPair asserts the
// media-signing gate validates usable signing material, not just filenames
// (round-11 review): a malformed key, a malformed certificate, or a valid
// but mismatched pair must fail the BUILD — the installer would otherwise
// fail to sign or verify the UKI on the target.
func TestCopySecureBootKeys_RejectsUnusableSigningPair(t *testing.T) {
	keyPEM, certPEM := genTestSigningPairPEM(t)
	otherKeyPEM, _ := genTestSigningPairPEM(t)

	cases := map[string]struct{ key, cert []byte }{
		"malformed key":               {[]byte("-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n"), certPEM},
		"malformed certificate":       {keyPEM, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n")},
		"valid but mismatched pair":   {otherKeyPEM, certPEM},
		"key that is not PEM at all":  {[]byte("raw bytes"), certPEM},
		"cert that is not PEM at all": {keyPEM, []byte("raw bytes")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			keysDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), tc.key, 0600))
			require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), tc.cert, 0644))
			c := NewCustomizer(&PlatformISOConfig{
				Security: SecurityConfig{SecureBoot: true},
				Directories: DirectoryConfig{
					Work: t.TempDir(),
					ISO:  t.TempDir(),
					Keys: keysDir,
				},
			}, logging.DefaultLogger())
			require.Error(t, c.CopySecureBootKeys(context.Background()),
				"unusable staged DB material must fail the build")
		})
	}

	t.Run("matched pair passes", func(t *testing.T) {
		keysDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), keyPEM, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), certPEM, 0644))
		c := NewCustomizer(&PlatformISOConfig{
			Security: SecurityConfig{SecureBoot: true},
			Directories: DirectoryConfig{
				Work: t.TempDir(),
				ISO:  t.TempDir(),
				Keys: keysDir,
			},
		}, logging.DefaultLogger())
		require.NoError(t, c.CopySecureBootKeys(context.Background()))
	})
}

// TestCopySecureBootKeys_MediaSigningDecision asserts the override records
// the media-signing decision for both db-ref shapes.
func TestCopySecureBootKeys_MediaSigningDecision(t *testing.T) {
	customizer := NewCustomizer(&PlatformISOConfig{
		Security: SecurityConfig{SecureBoot: true},
	}, logging.DefaultLogger())

	_, err := customizer.applySecurityOverrides([]byte("os:\n  os: alpine\n"))
	require.NoError(t, err)
	require.True(t, customizer.sbMediaSigning, "injected media db ref means media signing")

	_, err = customizer.applySecurityOverrides([]byte(`
secure-boot:
  db: { key-uri: "file:///media/cdrom/secure-boot-keys/DB.key", cert-uri: "file:///media/cdrom/secure-boot-keys/DB.crt" }
`))
	require.NoError(t, err)
	require.True(t, customizer.sbMediaSigning, "an existing media ref also means media signing")
}

// TestClassifySecureBootDBRef asserts an SB-enabled baked config cannot
// carry a db signing reference the installer could never resolve: a missing
// half, a mixed media/remote pair, a non-media file:// path, or a media
// reference that is not a plain filename. Custom media filenames are
// classified with their exact names so staging verifies the right files.
func TestClassifySecureBootDBRef(t *testing.T) {
	media := "file://" + SecureBootKeysMediaDir

	cases := []struct {
		name         string
		keyURI       string
		certURI      string
		wantErr      bool
		wantKeyFile  string
		wantCertFile string
	}{
		{name: "empty pair", wantErr: true},
		// cert-uri is optional per SecureBootConfig.Validate: a media key
		// derives the sibling DB.crt (loadFileURISecureBootSigner).
		{name: "missing cert-uri derives DB.crt", keyURI: media + "/DB.key", wantKeyFile: "DB.key", wantCertFile: "DB.crt"},
		{name: "missing key-uri", certURI: media + "/DB.crt", wantErr: true},
		{name: "mixed media and remote", keyURI: media + "/DB.key", certURI: "kms://platform/secureboot/db-cert", wantErr: true},
		{name: "non-media file path", keyURI: "file:///etc/keys/DB.key", certURI: "file:///etc/keys/DB.crt", wantErr: true},
		{name: "media ref with traversal", keyURI: media + "/../evil.key", certURI: media + "/DB.crt", wantErr: true},
		{name: "media ref with nested path", keyURI: media + "/sub/DB.key", certURI: media + "/DB.crt", wantErr: true},
		{name: "remote pair", keyURI: "kms://platform/secureboot/db", certURI: "kms://platform/secureboot/db-cert"},
		{name: "default media pair", keyURI: media + "/DB.key", certURI: media + "/DB.crt", wantKeyFile: "DB.key", wantCertFile: "DB.crt"},
		{name: "custom media filenames", keyURI: media + "/custom.key", certURI: media + "/custom.crt", wantKeyFile: "custom.key", wantCertFile: "custom.crt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyFile, certFile, err := classifySecureBootDBRef(tc.keyURI, tc.certURI)
			if tc.wantErr {
				require.Error(t, err)
				var typed *MessageError
				require.ErrorAs(t, err, &typed)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantKeyFile, keyFile)
			require.Equal(t, tc.wantCertFile, certFile)
		})
	}
}

// TestApplySecurityOverrides_RejectsUnresolvableDBRefs asserts the override
// pass fails the BUILD — a typed error, not a classification — when the
// existing db section cannot be resolved at install time.
func TestApplySecurityOverrides_RejectsUnresolvableDBRefs(t *testing.T) {
	for name, dbYAML := range map[string]string{
		"empty db map":  `  db: {}`,
		"non-media ref": `  db: { key-uri: "file:///etc/keys/DB.key", cert-uri: "file:///etc/keys/DB.crt" }`,
	} {
		t.Run(name, func(t *testing.T) {
			config := &PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}
			c := NewCustomizer(config, logging.DefaultLogger())
			input := "secure-boot:\n  enabled: true\n" + dbYAML + "\n"
			_, err := c.applySecurityOverrides([]byte(input))
			require.Error(t, err)
			var typed *MessageError
			require.ErrorAs(t, err, &typed)
		})
	}
}

// TestApplySecurityOverrides_AcceptsKeyOnlyDBRefs asserts the override pass
// accepts the two supported cert-uri-omitted configurations (round-8
// review): a media file:// key derives the sibling DB.crt for staging
// verification, and a kms:// key stays a remote pair needing no local keys.
func TestApplySecurityOverrides_AcceptsKeyOnlyDBRefs(t *testing.T) {
	t.Run("media key derives DB.crt", func(t *testing.T) {
		config := &PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}
		c := NewCustomizer(config, logging.DefaultLogger())
		input := "secure-boot:\n  enabled: true\n  db: { key-uri: \"file://" +
			SecureBootKeysMediaDir + "/DB.key\" }\n"
		_, err := c.applySecurityOverrides([]byte(input))
		require.NoError(t, err)
		require.True(t, c.sbMediaSigning)
		require.Equal(t, "DB.key", c.sbMediaKeyFile)
		require.Equal(t, "DB.crt", c.sbMediaCertFile)
	})

	t.Run("kms key stays remote", func(t *testing.T) {
		config := &PlatformISOConfig{Security: SecurityConfig{SecureBoot: true}}
		c := NewCustomizer(config, logging.DefaultLogger())
		input := "secure-boot:\n  enabled: true\n  db: { key-uri: \"kms://platform/secureboot/db\" }\n"
		_, err := c.applySecurityOverrides([]byte(input))
		require.NoError(t, err)
		require.False(t, c.sbMediaSigning)
	})
}

// TestCopySecureBootKeys_CustomMediaFilenamesVerified asserts the staging
// verification checks the EXACT filenames the baked config references: a
// config naming custom.key/custom.crt fails the build when only the default
// DB pair exists on the media.
func TestCopySecureBootKeys_CustomMediaFilenamesVerified(t *testing.T) {
	isoDir := t.TempDir()
	keysDir := t.TempDir()
	// Only the default pair exists — the referenced custom pair does not.
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("k"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), []byte("c"), 0644))

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{ISO: isoDir, Keys: keysDir, Work: t.TempDir()},
		Security:    SecurityConfig{SecureBoot: true},
	}
	c := NewCustomizer(config, logging.DefaultLogger())
	media := "file://" + SecureBootKeysMediaDir
	input := "secure-boot:\n  enabled: true\n" +
		`  db: { key-uri: "` + media + `/custom.key", cert-uri: "` + media + `/custom.crt" }` + "\n"
	_, err := c.applySecurityOverrides([]byte(input))
	require.NoError(t, err)
	require.True(t, c.sbMediaSigning)

	err = c.CopySecureBootKeys(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "custom.key")
}

// TestCopySecureBootKeys_RemoteSigningAllowlist asserts the remote/KMS path
// stages ONLY content-validated public enrollment artifacts: private
// material under ANY extension (DB.key, DB.pem, signing.p8, and a
// DER-encoded private key named DB.der) must not reach the ISO, while real
// certificates and signature lists are staged. .auth files are excluded
// wholesale (round-12 review): their PKCS#7 SignedData carries
// unconstrained fields structural parsing cannot prove free of smuggled
// secrets, and nothing in the install flow consumes them.
func TestCopySecureBootKeys_RemoteSigningAllowlist(t *testing.T) {
	isoDir := t.TempDir()
	keysDir := t.TempDir()

	fixtures := map[string][]byte{
		// Private / non-public material — must never be staged.
		"DB.key":     []byte("private"),
		"DB.pem":     genTestKeyPEM(t),
		"signing.p8": genTestKeyDER(t),
		"DB.der":     genTestKeyDER(t), // DER private key hiding under a cert extension
		"fake.crt":   []byte("not a certificate"),
		"notes.txt":  []byte("readme"),
		// An auth descriptor is a plausible enrollment artifact but its
		// signature blobs are an unverifiable smuggling channel — never
		// staged, whatever it contains.
		"PK.auth": genTestESL(t),
		// Public enrollment artifacts — must be staged.
		"DB.crt":  genTestCertPEM(t),
		"KEK.cer": genTestCertDER(t),
		"db.esl":  genTestESL(t),
	}
	for name, data := range fixtures {
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, name), data, 0644))
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{ISO: isoDir, Keys: keysDir, Work: t.TempDir()},
		Security:    SecurityConfig{SecureBoot: true},
	}
	c := NewCustomizer(config, logging.DefaultLogger())
	input := "secure-boot:\n  enabled: true\n" +
		`  db: { key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert" }` + "\n"
	_, err := c.applySecurityOverrides([]byte(input))
	require.NoError(t, err)
	require.False(t, c.sbMediaSigning)

	require.NoError(t, c.CopySecureBootKeys(context.Background()))

	staged := filepath.Join(isoDir, SecureBootKeysISODirName)
	for _, mustNotShip := range []string{"DB.key", "DB.pem", "signing.p8", "DB.der", "fake.crt", "notes.txt", "PK.auth"} {
		_, err := os.Stat(filepath.Join(staged, mustNotShip))
		require.True(t, os.IsNotExist(err), "%s must not be embedded for a remote-signing build", mustNotShip)
	}
	for _, mustShip := range []string{"DB.crt", "KEK.cer", "db.esl"} {
		_, err := os.Stat(filepath.Join(staged, mustShip))
		require.NoError(t, err, "%s is a public enrollment artifact and must be staged", mustShip)
	}
}

// genTestCertDER returns a self-signed certificate in raw DER form.
func genTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-secure-boot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// genTestCertPEM returns a self-signed certificate in PEM form.
func genTestCertPEM(t *testing.T) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: genTestCertDER(t)})
}

// genTestSigningPairPEM returns a MATCHED private key + self-signed
// certificate pair in PEM form, as the staged DB signing material the
// installer's file:// signing path accepts.
func genTestSigningPairPEM(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-db-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// genTestKeyDER returns a PKCS#8 private key in raw DER form.
func genTestKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

// genTestKeyPEM returns a PKCS#8 private key in PEM form.
func genTestKeyPEM(t *testing.T) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: genTestKeyDER(t)})
}

// genTestESL returns a strictly valid EFI_SIGNATURE_LIST holding one real
// X.509 certificate, built through the repository's UEFI encoder.
func genTestESL(t *testing.T) []byte {
	t.Helper()
	return uefi.NewSignatureListFromCert(genTestCertDER(t), uefi.GUID{}).Bytes()
}

// TestClassifySecureBootDBRef_SchemeRules asserts the classifier enforces
// the installer's URI scheme rules at BUILD time: only kms:// (remote) and
// media file:// references are accepted, schemes case-insensitively — an
// https:// pair would otherwise pass the build and deterministically fail
// SecureBootConfig.Validate on the target.
func TestClassifySecureBootDBRef_SchemeRules(t *testing.T) {
	media := "file://" + SecureBootKeysMediaDir

	t.Run("https pair is rejected", func(t *testing.T) {
		_, _, err := classifySecureBootDBRef("https://example/db", "https://example/db-cert")
		require.Error(t, err)
		var typed *MessageError
		require.ErrorAs(t, err, &typed)
		require.Contains(t, err.Error(), "kms://")
	})

	t.Run("kms and https mixed is rejected", func(t *testing.T) {
		_, _, err := classifySecureBootDBRef("kms://platform/secureboot/db", "https://example/db-cert")
		require.Error(t, err)
	})

	t.Run("uppercase KMS scheme is accepted as remote", func(t *testing.T) {
		keyFile, certFile, err := classifySecureBootDBRef(
			"KMS://platform/secureboot/db", "KMS://platform/secureboot/db-cert")
		require.NoError(t, err)
		require.Empty(t, keyFile)
		require.Empty(t, certFile)
	})

	t.Run("uppercase FILE scheme is classified as media", func(t *testing.T) {
		keyFile, certFile, err := classifySecureBootDBRef(
			"FILE://"+SecureBootKeysMediaDir+"/DB.key", media+"/DB.crt")
		require.NoError(t, err)
		require.Equal(t, "DB.key", keyFile)
		require.Equal(t, "DB.crt", certFile)
	})

	// SecureBootConfig.Validate requires only db.key-uri; an omitted
	// cert-uri is a supported configuration the build must accept
	// (round-8 review): the installer derives the sibling DB.crt beside
	// a file:// key, and a kms:// signer returns the certificate with
	// the signature.
	t.Run("media key with omitted cert-uri derives the sibling DB.crt", func(t *testing.T) {
		keyFile, certFile, err := classifySecureBootDBRef(media+"/custom.key", "")
		require.NoError(t, err)
		require.Equal(t, "custom.key", keyFile)
		require.Equal(t, "DB.crt", certFile)
	})

	t.Run("kms key with omitted cert-uri is a remote pair", func(t *testing.T) {
		keyFile, certFile, err := classifySecureBootDBRef("kms://platform/secureboot/db", "")
		require.NoError(t, err)
		require.Empty(t, keyFile)
		require.Empty(t, certFile)
	})

	t.Run("non-media file key with omitted cert-uri is rejected", func(t *testing.T) {
		_, _, err := classifySecureBootDBRef("file:///etc/keys/DB.key", "")
		require.Error(t, err)
	})
}

// TestParsesAsCertificates_RejectsSmuggledMaterial asserts the certificate
// identifier consumes the ENTIRE input: a valid PEM certificate with raw DER
// private-key bytes appended (or prepended, or a foreign PEM block between
// certificates) must be rejected, or a remote-signing ISO would embed the
// whole file — private key included.
func TestParsesAsCertificates_RejectsSmuggledMaterial(t *testing.T) {
	cert := genTestCertPEM(t)
	keyDER := genTestKeyDER(t)
	keyPEM := genTestKeyPEM(t)

	require.True(t, parsesAsCertificates(cert), "plain PEM certificate must be accepted")
	require.True(t, parsesAsCertificates(append(append([]byte{}, cert...), cert...)),
		"concatenated PEM certificates must be accepted")
	require.True(t, parsesAsCertificates(genTestCertDER(t)), "raw DER certificate must be accepted")

	require.False(t, parsesAsCertificates(append(append([]byte{}, cert...), keyDER...)),
		"PEM certificate with trailing DER private key must be rejected")
	require.False(t, parsesAsCertificates(append(append([]byte{}, keyDER...), cert...)),
		"leading DER private key before a PEM certificate must be rejected")
	require.False(t, parsesAsCertificates(append(append([]byte{}, cert...), keyPEM...)),
		"PEM certificate followed by a PEM private key must be rejected")
	require.False(t, parsesAsCertificates(append(append([]byte{}, genTestCertDER(t)...), keyDER...)),
		"DER certificate with trailing DER private key must be rejected")
	require.False(t, parsesAsCertificates(nil), "empty input must be rejected")
}

// TestValidSignatureList_RejectsSmuggledHeaderBytes asserts the exploit
// from the round-5 review is closed: an "ESL" whose entire body is claimed
// as an optional header (ListSize = file length, HeaderSize = ListSize-28,
// SignatureSize = 0) can carry arbitrary secret bytes and must be
// rejected, as must empty lists, non-public signature types, and
// non-certificate X.509 entries.
func TestValidSignatureList_RejectsSmuggledHeaderBytes(t *testing.T) {
	key := genTestKeyDER(t)

	smuggled := make([]byte, 28+len(key))
	binary.LittleEndian.PutUint32(smuggled[16:20], uint32(28+len(key))) // ListSize
	binary.LittleEndian.PutUint32(smuggled[20:24], uint32(len(key)))    // HeaderSize
	binary.LittleEndian.PutUint32(smuggled[24:28], 0)                   // SignatureSize
	copy(smuggled[28:], key)
	require.False(t, validSignatureList(smuggled),
		"private material smuggled as an ESL optional header must be rejected")

	empty := make([]byte, 28)
	binary.LittleEndian.PutUint32(empty[16:20], 28)
	require.False(t, validSignatureList(empty), "an empty signature list enrolls nothing and must be rejected")

	// A structurally valid X.509-typed list whose entry is NOT a
	// certificate must be rejected.
	bogus := uefi.NewSignatureListFromCert(key, uefi.GUID{}).Bytes()
	require.False(t, validSignatureList(bogus), "a non-certificate payload in an X.509 list must be rejected")

	require.True(t, validSignatureList(genTestESL(t)), "a real certificate list must be accepted")
}

// TestCopySecureBootKeys_NetworkServedMediaCarriesNoPrivateKeys: a medium
// served over the network (a netboot media set) stages only public
// enrollment material and generates nothing — with Secure Boot off, where an
// ISO keeps its historical full key set, and with remote signing — and
// refuses a config that would sign with media-staged keys.
func TestCopySecureBootKeys_NetworkServedMediaCarriesNoPrivateKeys(t *testing.T) {
	served := func(t *testing.T, secureBoot bool, keysDir string) *Customizer {
		t.Helper()
		return NewCustomizer(&PlatformISOConfig{
			Security:    SecurityConfig{SecureBoot: secureBoot, PublicKeysOnly: true},
			Directories: DirectoryConfig{Work: t.TempDir(), ISO: t.TempDir(), Keys: keysDir},
		}, logging.DefaultLogger())
	}
	keysWithPrivate := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		keyPath, _ := authenticodetest.WriteKeyPair(t, dir)
		require.FileExists(t, keyPath)
		return dir
	}

	t.Run("Secure Boot off: public material only, nothing generated", func(t *testing.T) {
		keysDir := keysWithPrivate(t)
		c := served(t, false, keysDir)
		require.NoError(t, c.CopySecureBootKeys(context.Background()))
		staged := filepath.Join(c.config.Directories.ISO, SecureBootKeysISODirName)
		assert.FileExists(t, filepath.Join(staged, "DB.crt"))
		assert.NoFileExists(t, filepath.Join(staged, "DB.key"))

		empty := t.TempDir()
		require.NoError(t, served(t, false, empty).CopySecureBootKeys(context.Background()))
		entries, err := os.ReadDir(empty)
		require.NoError(t, err)
		assert.Empty(t, entries, "no key generation for a served medium")
	})

	t.Run("media signing is refused", func(t *testing.T) {
		c := served(t, true, keysWithPrivate(t))
		err := c.CopySecureBootKeys(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network-served medium cannot sign with media-staged Secure Boot keys")
	})
}
