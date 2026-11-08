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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

// writeCert writes a self-signed certificate for a fresh key at path (none
// when path is empty) and returns both.
func writeCert(t *testing.T, path, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, cert := secureboottest.KeyPair(t, cn)
	if path != "" {
		require.NoError(t, os.WriteFile(path, secureboottest.PEM(cert), 0o644))
	}
	return key, cert
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "platform.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	cert, err := authenticode.LoadCertificate(path)
	require.NoError(t, err)
	return cert
}

// signs asserts the material's DB signer produces a PE that verifies and is
// signed by want.
func signs(t *testing.T, m *SecureBootMaterial, want *x509.Certificate) {
	t.Helper()
	var signed bytes.Buffer
	require.NoError(t, m.DB.Sign(bytes.NewReader(authenticodetest.MinimalPE(authenticodetest.MachineARM64)), &signed))
	verifier := authenticode.NewVerifier(context.Background(), nil)
	require.NoError(t, verifier.Verify(bytes.NewReader(signed.Bytes())))
	embedded, err := verifier.ExtractCertificate(bytes.NewReader(signed.Bytes()))
	require.NoError(t, err)
	assert.True(t, embedded.Equal(want))

	// The same key, as a plain signer, signs the diskless root manifest.
	require.NotNil(t, m.DBKey)
	assert.True(t, m.DBCert.Equal(want))
	digest := sha256.Sum256([]byte("manifest"))
	sig, err := m.DBKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	algorithm := x509.SHA256WithRSA
	if _, ok := want.PublicKey.(*ecdsa.PublicKey); ok {
		algorithm = x509.ECDSAWithSHA256
	}
	require.NoError(t, want.CheckSignature(algorithm, []byte("manifest"), sig), "signed by the DB certificate's key")
}

func TestResolveSecureBootMaterial_Off(t *testing.T) {
	m, err := ResolveSecureBootMaterial(context.Background(), &ISOBuildConfig{}, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestResolveSecureBootMaterial_KeysDir(t *testing.T) {
	keys := t.TempDir()
	_, dbCertPath := authenticodetest.WriteKeyPair(t, keys)
	_, pk := writeCert(t, filepath.Join(keys, "PK.crt"), "PK")
	_, kek := writeCert(t, filepath.Join(keys, "KEK.crt"), "KEK")
	build := &ISOBuildConfig{SecureBoot: true, KeysDir: keys, WorkDir: t.TempDir()}

	m, err := ResolveSecureBootMaterial(context.Background(), build, nil, nil)
	require.NoError(t, err)
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "PK.crt")).Equal(pk))
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "KEK.crt")).Equal(kek))
	db := readCert(t, dbCertPath)
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "DB.crt")).Equal(db))
	signs(t, m, db)
}

func TestResolveSecureBootMaterial_MediaReferencesNameTheFiles(t *testing.T) {
	keys, work := t.TempDir(), t.TempDir()
	keyPath, certPath := authenticodetest.WriteKeyPair(t, keys)
	require.NoError(t, os.Rename(keyPath, filepath.Join(keys, "custom.key")))
	require.NoError(t, os.Rename(certPath, filepath.Join(keys, "custom.crt")))
	writeCert(t, filepath.Join(keys, "PK.crt"), "PK")
	writeCert(t, filepath.Join(keys, "KEK.crt"), "KEK")
	config := writeConfig(t, work, `secure-boot:
  enabled: true
  db:
    key-uri: file://`+SecureBootKeysMediaDir+`/custom.key
    cert-uri: file://`+SecureBootKeysMediaDir+`/custom.crt
`)
	build := &ISOBuildConfig{SecureBoot: true, KeysDir: keys, WorkDir: work, PlatformConfigFile: config}

	m, err := ResolveSecureBootMaterial(context.Background(), build, nil, nil)
	require.NoError(t, err)
	signs(t, m, readCert(t, filepath.Join(keys, "custom.crt")))
}

func TestResolveSecureBootMaterial_KMS(t *testing.T) {
	work := t.TempDir()
	_, pk := writeCert(t, "", "PK")
	_, kek := writeCert(t, "", "KEK")
	dbKey, db := writeCert(t, "", "DB")
	config := writeConfig(t, work, `secure-boot:
  enabled: true
  resign-mode: remote
  pk: {key-uri: "kms://platform/secureboot/pk", cert-uri: "kms://platform/secureboot/pk-cert"}
  kek: {key-uri: "kms://platform/secureboot/kek"}
  db: {key-uri: "kms://platform/secureboot/db", cert-uri: "kms://platform/secureboot/db-cert"}
`)
	opened := 0
	clients := func() (*KMSClients, error) {
		opened++
		return &KMSClients{KMS: &secureboottest.KMS{Key: dbKey}, CA: &secureboottest.CA{Certs: map[string]*x509.Certificate{
			"platform/secureboot/pk-cert": pk, "platform/secureboot/kek": kek, "platform/secureboot/db-cert": db,
		}}}, nil
	}
	build := &ISOBuildConfig{SecureBoot: true, WorkDir: work, PlatformConfigFile: config}

	m, err := ResolveSecureBootMaterial(context.Background(), build, clients, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, opened, "one connection for every reference")
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "PK.crt")).Equal(pk))
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "KEK.crt")).Equal(kek), "no cert-uri: fetched by the key's id")
	assert.True(t, readCert(t, filepath.Join(m.CertDir, "DB.crt")).Equal(db))
	signs(t, m, db)
}

func TestResolveSecureBootMaterial_Failures(t *testing.T) {
	work := t.TempDir()
	kmsConfig := writeConfig(t, work, "secure-boot:\n  enabled: true\n  db: {key-uri: \"kms://db\"}\n")
	var materialErr *SecureBootMaterialError
	for name, tc := range map[string]struct {
		build   *ISOBuildConfig
		clients KMSClientsFunc
	}{
		"kms reference without a client": {&ISOBuildConfig{SecureBoot: true, WorkDir: work, KeysDir: t.TempDir(), PlatformConfigFile: kmsConfig}, nil},
		"client that cannot connect": {&ISOBuildConfig{SecureBoot: true, WorkDir: work, KeysDir: t.TempDir(), PlatformConfigFile: kmsConfig},
			func() (*KMSClients, error) { return nil, errors.New("refused") }},
		"keys directory without certificates": {&ISOBuildConfig{SecureBoot: true, WorkDir: work, KeysDir: t.TempDir()}, nil},
		"missing platform config":             {&ISOBuildConfig{SecureBoot: true, WorkDir: work, PlatformConfigFile: filepath.Join(work, "absent.yaml")}, nil},
		"unparseable platform config":         {&ISOBuildConfig{SecureBoot: true, WorkDir: work, PlatformConfigFile: writeConfig(t, t.TempDir(), "secure-boot: [")}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveSecureBootMaterial(context.Background(), tc.build, tc.clients, nil)
			require.ErrorAs(t, err, &materialErr)
			assert.NotEmpty(t, err.Error())
		})
	}

	t.Run("certificates present but no DB key", func(t *testing.T) {
		keys := t.TempDir()
		for _, role := range []string{"PK", "KEK", "DB"} {
			writeCert(t, filepath.Join(keys, role+".crt"), role)
		}
		_, err := ResolveSecureBootMaterial(context.Background(), &ISOBuildConfig{SecureBoot: true, WorkDir: work, KeysDir: keys}, nil, nil)
		require.ErrorAs(t, err, &materialErr)
	})
}

func stageBuild(t *testing.T, machine elf.Machine) *ISOBuildConfig {
	t.Helper()
	bins := t.TempDir()
	for _, name := range []string{"platformd", "platformctl", "platformctl-static", "platform-initrd", "gatewayd"} {
		diskimagetest.WriteELF(t, filepath.Join(bins, name), machine)
	}
	build := DefaultISOBuildConfig()
	build.WorkDir = t.TempDir()
	build.PlatformVersion = "1.0.0-test"
	build.PlatformdBinary = filepath.Join(bins, "platformd")
	build.PlatformctlBinary = filepath.Join(bins, "platformctl")
	build.PlatformctlStaticBinary = filepath.Join(bins, "platformctl-static")
	build.PlatformConfigFile = writeConfig(t, t.TempDir(), "os:\n  hostname: node\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: false\n")
	build.PreFetch = false
	build.SecureBoot = false
	build.Architecture = "x86_64"
	return build
}

func TestStageInstallMedia(t *testing.T) {
	build := stageBuild(t, elf.EM_X86_64)
	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(media.WorkDir, "media"), media.Dir)
	assert.Nil(t, media.SecureBoot, "Secure Boot is off")
	for _, rel := range []string{
		"platformd-bin/platformd",
		"platformd-bin/platformctl",
		"platformd-bin/platformctl-static",
		"configs/installer.yaml",
		"dracut-platformd/90platformd/module-setup.sh",
	} {
		assert.FileExists(t, filepath.Join(media.Dir, rel))
	}
}

func TestStageInstallMedia_Failures(t *testing.T) {
	var stageErr *StageMediaError

	_, err := StageInstallMedia(context.Background(), &ISOBuildConfig{}, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.ErrorAs(t, err, &stageErr)

	wrongArch := stageBuild(t, elf.EM_AARCH64)
	_, err = StageInstallMedia(context.Background(), wrongArch, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.ErrorAs(t, err, &stageErr)
	assert.Equal(t, "staging the install media", stageErr.Step, "an aarch64 platformd on x86_64 media")
}
