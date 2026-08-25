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

package installer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func writeTestCertPEM(t *testing.T, path, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0644))
}

// TestEnforceSecureBoot_NoopWhenDisabled verifies the safe DEFAULT: enforcement
// is a no-op unless BOTH enabled and enforce are set. These cases must return
// nil without touching any signer, efivarfs, or the disk.
func TestEnforceSecureBoot_NoopWhenDisabled(t *testing.T) {
	cases := []struct {
		name string
		sb   *SecureBootConfig
	}{
		{"nil secure boot", nil},
		{"disabled even if enforce set", &SecureBootConfig{Enabled: false, Enforce: true}},
		{"enabled but enforce off (default)", &SecureBootConfig{Enabled: true, Enforce: false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i := &installer{
				logger: logging.DefaultLogger(),
				config: &Config{OS: &OSConfig{}, SecureBoot: c.sb},
			}
			require.NoError(t, i.enforceSecureBoot(context.Background(), nil))
		})
	}
}

// TestEnforceSecureBoot_SkipsWhenDBUnavailable verifies the step-2 guard: when
// the DB signing material cannot be resolved (here an invalid backend, which
// fails before any filesystem write), enforcement is skipped and the install is
// NOT aborted.
func TestEnforceSecureBoot_SkipsWhenDBUnavailable(t *testing.T) {
	keysDir := t.TempDir()
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{Hostname: "test"},
			SecureBoot: &SecureBootConfig{
				Enabled: true,
				Enforce: true,
				DB: SecureBootKeyRef{
					KeyConfig: common.KeyConfig{StoreType: "not-a-backend"},
					KeyURI:    "file://" + filepath.Join(keysDir, "DB.key"),
				},
				PK:  SecureBootKeyRef{KeyURI: "file://pk"},
				KEK: SecureBootKeyRef{KeyURI: "file://kek"},
			},
		},
	}

	// Invalid backend -> resolveSecureBootSigner errors before generating keys
	// -> warn-and-skip, never a failed install.
	require.NoError(t, i.enforceSecureBoot(context.Background(), nil))

	// No key material should have been produced under the temp keys directory.
	entries, err := os.ReadDir(keysDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "no keys should be generated when the DB backend is invalid")
}

// TestResolveSecureBootEnrollCerts_FromFileURIs resolves PK and KEK certificates
// from file:// cert-uri references.
func TestResolveSecureBootEnrollCerts_FromFileURIs(t *testing.T) {
	dir := t.TempDir()
	pkPath := filepath.Join(dir, "mypk.crt")
	kekPath := filepath.Join(dir, "mykek.crt")
	writeTestCertPEM(t, pkPath, "PK")
	writeTestCertPEM(t, kekPath, "KEK")

	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{
			Enabled: true,
			Enforce: true,
			PK:      SecureBootKeyRef{CertURI: "file://" + pkPath},
			KEK:     SecureBootKeyRef{CertURI: "file://" + kekPath},
			DB:      SecureBootKeyRef{KeyURI: "file://" + filepath.Join(dir, "DB.key")},
		}},
	}

	pk, kek, err := i.resolveSecureBootEnrollCerts()
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, kek)
	assert.Equal(t, "PK", pk.Subject.CommonName)
	assert.Equal(t, "KEK", kek.Subject.CommonName)
}

// writeTestCertDER writes a self-signed certificate as raw DER.
func writeTestCertDER(t *testing.T, path, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, der, 0644))
}

// TestResolveSecureBootEnrollCerts_DERFiles resolves PK/KEK certificates
// stored as raw DER. The ISO build's enforcement gate stages any artifact
// that positively parses as certificate material — PEM or DER — so the
// installer must accept both: a DER cert that passed the build but failed
// here would make enforceSecureBoot warn-and-skip, shipping a node with
// enforce requested and no enforcement (#50, round-10 review).
func TestResolveSecureBootEnrollCerts_DERFiles(t *testing.T) {
	dir := t.TempDir()
	pkPath := filepath.Join(dir, "PK.der")
	kekPath := filepath.Join(dir, "KEK.der")
	writeTestCertDER(t, pkPath, "PK-DER")
	writeTestCertDER(t, kekPath, "KEK-DER")

	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{
			Enabled: true,
			Enforce: true,
			PK:      SecureBootKeyRef{CertURI: "file://" + pkPath},
			KEK:     SecureBootKeyRef{CertURI: "file://" + kekPath},
			DB:      SecureBootKeyRef{KeyURI: "file://" + filepath.Join(dir, "DB.key")},
		}},
	}

	pk, kek, err := i.resolveSecureBootEnrollCerts()
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, kek)
	assert.Equal(t, "PK-DER", pk.Subject.CommonName)
	assert.Equal(t, "KEK-DER", kek.Subject.CommonName)
}

// TestValidateSecureBootSigningPair verifies the exported build-gate check
// accepts exactly what loadFileURISecureBootSigner accepts — a parseable
// PEM key + certificate with matching public keys — and rejects malformed
// or mismatched material typed.
func TestValidateSecureBootSigningPair(t *testing.T) {
	dir := t.TempDir()
	writePair := func(t *testing.T, name string) (keyPath, certPath string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		keyPath = filepath.Join(dir, name+".key")
		certPath = filepath.Join(dir, name+".crt")
		require.NoError(t, os.WriteFile(keyPath,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
		require.NoError(t, os.WriteFile(certPath,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644))
		return keyPath, certPath
	}

	keyA, certA := writePair(t, "pair-a")
	keyB, _ := writePair(t, "pair-b")
	garbage := filepath.Join(dir, "garbage")
	require.NoError(t, os.WriteFile(garbage, []byte("not pem"), 0600))

	require.NoError(t, ValidateSecureBootSigningPair(keyA, certA), "a matched pair must validate")
	require.Error(t, ValidateSecureBootSigningPair(keyB, certA), "a mismatched pair must be rejected")
	require.Error(t, ValidateSecureBootSigningPair(garbage, certA), "a malformed key must be rejected")
	require.Error(t, ValidateSecureBootSigningPair(keyA, garbage), "a malformed certificate must be rejected")
	require.Error(t, ValidateSecureBootSigningPair(filepath.Join(dir, "missing"), certA), "a missing key must be rejected")
}

// TestParsePEMCertificate_RejectsGarbage asserts the DER fallback does not
// weaken the parser: non-certificate bytes still fail typed.
func TestParsePEMCertificate_RejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.crt")
	require.NoError(t, os.WriteFile(garbage, []byte("neither PEM nor DER"), 0644))
	_, err := parsePEMCertificate(garbage)
	require.Error(t, err)
}

// TestResolveSecureBootEnrollCerts_MissingCertErrors verifies a typed Secure
// Boot error when neither a cert-uri nor an on-disk PK.crt can be resolved.
func TestResolveSecureBootEnrollCerts_MissingCertErrors(t *testing.T) {
	dir := t.TempDir()
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{
			Enabled: true,
			Enforce: true,
			// No file:// cert-uris; the on-node dir fallback has no PK.crt.
			DB: SecureBootKeyRef{KeyURI: "file://" + filepath.Join(dir, "DB.key")},
		}},
	}

	_, _, err := i.resolveSecureBootEnrollCerts()
	require.Error(t, err)
	var ierr *InstallerError
	require.ErrorAs(t, err, &ierr)
	assert.Equal(t, ErrorTypeSecureBoot, ierr.Type)
}

// TestFileURIPath covers the case-insensitive file:// scheme extraction and the
// non-file:// (kms://, empty) cases.
func TestFileURIPath(t *testing.T) {
	assert.Equal(t, "/etc/secureboot/PK.crt", fileURIPath("file:///etc/secureboot/PK.crt"))
	assert.Equal(t, "/etc/secureboot/PK.crt", fileURIPath("FILE:///etc/secureboot/PK.crt"))
	assert.Equal(t, "", fileURIPath("kms://platform/secureboot/pk-cert"))
	assert.Equal(t, "", fileURIPath(""))
	assert.Equal(t, "", fileURIPath("file:/"))
}

// TestSecureBootKeysDir verifies the on-node default and the file:// DB key-uri
// override (install-media paths are absent on the test host, so the fallback is
// always taken).
func TestSecureBootKeysDir(t *testing.T) {
	def := &installer{logger: logging.DefaultLogger(), config: &Config{SecureBoot: &SecureBootConfig{}}}
	assert.Equal(t, "/mnt/etc/trusted-platform/secure-boot", def.secureBootKeysDir())

	custom := &installer{logger: logging.DefaultLogger(), config: &Config{SecureBoot: &SecureBootConfig{
		DB: SecureBootKeyRef{KeyURI: "file:///custom/sb/DB.key"},
	}}}
	assert.Equal(t, "/mnt/custom/sb", custom.secureBootKeysDir())
}

// TestSignUKI_DisabledNoop verifies the new gate: signing is skipped (no error,
// no signer resolution) when Secure Boot is nil or disabled.
func TestSignUKI_DisabledNoop(t *testing.T) {
	nilSB := &installer{logger: logging.DefaultLogger(), config: &Config{OS: &OSConfig{}}}
	require.NoError(t, nilSB.signUKI(context.Background(), nil))

	disabled := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{OS: &OSConfig{}, SecureBoot: &SecureBootConfig{Enabled: false}},
	}
	require.NoError(t, disabled.signUKI(context.Background(), nil))
}
