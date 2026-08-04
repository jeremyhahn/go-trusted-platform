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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// The Secure Boot key staging contract: CopySecureBootKeys stages the DB
// keypair at <iso-root>/secure-boot-keys, which the Alpine live environment
// mounts at /media/cdrom/secure-boot-keys. Every generated installer config
// MUST reference exactly that location — a URI pointing anywhere else (the
// historical /tmp/secureboot-keys bug) silently degrades every ISO install to
// on-node key generation, orphaning the certificates staged on the media.

func TestSecureBootKeysMediaDirMatchesISOStaging(t *testing.T) {
	want := "/media/cdrom/" + SecureBootKeysISODirName
	if SecureBootKeysMediaDir != want {
		t.Fatalf("SecureBootKeysMediaDir = %q, want %q", SecureBootKeysMediaDir, want)
	}
	if SecureBootKeysISODirName != "secure-boot-keys" {
		t.Fatalf("SecureBootKeysISODirName = %q, want secure-boot-keys", SecureBootKeysISODirName)
	}
}

func TestBuildInstallerConfigSecureBootMediaURIs(t *testing.T) {
	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://example.com",
		},
		RootFS: RootFSConfig{
			Type: "ext4",
		},
		Security: SecurityConfig{
			SecureBoot: true,
		},
	}

	customizer := NewCustomizer(config, nil)
	cfg, err := customizer.buildInstallerConfig()
	if err != nil {
		t.Fatalf("buildInstallerConfig: %v", err)
	}

	if cfg.SecureBoot == nil {
		t.Fatal("SecureBoot config not generated")
	}
	if !cfg.SecureBoot.Enabled {
		t.Error("SecureBoot.Enabled = false, want true")
	}
	if cfg.SecureBoot.ResignMode != installer.SecureBootResignModeLocal {
		t.Errorf("ResignMode = %q, want %q", cfg.SecureBoot.ResignMode, installer.SecureBootResignModeLocal)
	}

	wantKey := "file://" + SecureBootKeysMediaDir + "/DB.key"
	wantCert := "file://" + SecureBootKeysMediaDir + "/DB.crt"
	if cfg.SecureBoot.DB.KeyURI != wantKey {
		t.Errorf("DB.KeyURI = %q, want %q", cfg.SecureBoot.DB.KeyURI, wantKey)
	}
	if cfg.SecureBoot.DB.CertURI != wantCert {
		t.Errorf("DB.CertURI = %q, want %q", cfg.SecureBoot.DB.CertURI, wantCert)
	}

	// The generated config must satisfy the installer's own validation.
	if err := cfg.SecureBoot.Validate(); err != nil {
		t.Errorf("generated SecureBoot config fails installer validation: %v", err)
	}
}

func TestBuildInstallerConfigSecureBootDisabled(t *testing.T) {
	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://example.com",
		},
		RootFS: RootFSConfig{
			Type: "ext4",
		},
	}

	customizer := NewCustomizer(config, nil)
	cfg, err := customizer.buildInstallerConfig()
	if err != nil {
		t.Fatalf("buildInstallerConfig: %v", err)
	}
	if cfg.SecureBoot != nil {
		t.Errorf("SecureBoot config generated despite disabled setting: %+v", cfg.SecureBoot)
	}
}

func TestGenerateInstallConfigSecureBootMediaURIs(t *testing.T) {
	buildConfig := &ISOBuildConfig{
		AlpineVersion: "3.22.2",
		SecureBoot:    true,
	}

	cfg := buildConfig.generateInstallConfig()
	if cfg.SecureBoot == nil {
		t.Fatal("SecureBoot config not generated")
	}

	wantKey := "file://" + SecureBootKeysMediaDir + "/DB.key"
	wantCert := "file://" + SecureBootKeysMediaDir + "/DB.crt"
	if cfg.SecureBoot.DB.KeyURI != wantKey {
		t.Errorf("DB.KeyURI = %q, want %q", cfg.SecureBoot.DB.KeyURI, wantKey)
	}
	if cfg.SecureBoot.DB.CertURI != wantCert {
		t.Errorf("DB.CertURI = %q, want %q", cfg.SecureBoot.DB.CertURI, wantCert)
	}
	if err := cfg.SecureBoot.Validate(); err != nil {
		t.Errorf("generated SecureBoot config fails installer validation: %v", err)
	}
}

func TestGenerateInstallConfigSecureBootDisabled(t *testing.T) {
	buildConfig := &ISOBuildConfig{AlpineVersion: "3.22.2"}
	cfg := buildConfig.generateInstallConfig()
	if cfg.SecureBoot != nil {
		t.Errorf("SecureBoot config generated despite disabled setting: %+v", cfg.SecureBoot)
	}
}
