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
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestMediaSigningEnabled pins the predicate that CopySecureBootKeys and
// signISOBootloader share.
//
// It is extracted precisely so those two cannot drift: one demands the key
// material and the other consumes it, and a build that demanded keys without
// using them -- or worse, used them without demanding them -- would be the
// two-lists-that-must-agree defect. If this table changes, both behaviours
// change together, which is the point.
func TestMediaSigningEnabled(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secureBoot bool
		known      bool
		signing    bool
		want       bool
	}{
		{"secure boot off is never media signing", false, true, true, false},
		{"secure boot off, nothing known", false, false, false, false},
		{"secure boot on, overrides not yet applied, assumed signing", true, false, false, true},
		{"secure boot on, finalized config signs", true, true, true, true},
		{"secure boot on, finalized config does not sign (remote/KMS)", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Customizer{
				config:              &PlatformISOConfig{Security: SecurityConfig{SecureBoot: tc.secureBoot}},
				sbMediaSigningKnown: tc.known,
				sbMediaSigning:      tc.signing,
			}
			assert.Equal(t, tc.want, c.mediaSigningEnabled())
		})
	}
}

// writeSigningPair writes a usable DB key/cert pair into dir, or a deliberately
// mismatched one when mismatch is set.
func writeSigningPair(t *testing.T, dir string, mismatch bool) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certKey := key
	if mismatch {
		certKey, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test db"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
}

func newSigningCustomizer(t *testing.T, isoDir string, secureBoot bool) *Customizer {
	t.Helper()
	return &Customizer{
		logger: logging.DefaultLogger(),
		config: &PlatformISOConfig{
			Security:    SecurityConfig{SecureBoot: secureBoot},
			Directories: DirectoryConfig{ISO: isoDir},
		},
		sbMediaSigningKnown: true,
		sbMediaSigning:      secureBoot,
	}
}

// TestSignISOBootloader_NoOpWithoutMediaSigning verifies the build that never
// asked for Secure Boot is untouched -- no key material required, and the
// bootloader left byte-identical.
func TestSignISOBootloader_NoOpWithoutMediaSigning(t *testing.T) {
	isoDir := t.TempDir()
	efiPath := filepath.Join(isoDir, "bootx64.efi")
	require.NoError(t, os.WriteFile(efiPath, []byte("not a PE, and never read"), 0o644))

	c := newSigningCustomizer(t, isoDir, false)

	require.NoError(t, c.signISOBootloader(context.Background(), efiPath),
		"a build without media signing must not require signing material")

	data, err := os.ReadFile(efiPath)
	require.NoError(t, err)
	assert.Equal(t, "not a PE, and never read", string(data),
		"the bootloader must be untouched when signing is not requested")
}

// TestSignISOBootloader_FailsClosed is the security assertion.
//
// When the build signs with media-staged keys, an ISO whose bootloader could
// not be signed must FAIL THE BUILD. Emitting it would produce media that is
// silently rejected by enforcing firmware at boot -- the exact failure #59
// exists to remove, reintroduced as a warning nobody reads.
func TestSignISOBootloader_FailsClosed(t *testing.T) {
	t.Run("staged key material missing", func(t *testing.T) {
		isoDir := t.TempDir()
		efiPath := filepath.Join(isoDir, "bootx64.efi")
		require.NoError(t, os.WriteFile(efiPath, []byte("pe"), 0o644))

		c := newSigningCustomizer(t, isoDir, true)

		err := c.signISOBootloader(context.Background(), efiPath)
		require.Error(t, err, "media signing with no staged DB pair must fail the build, not warn")
		assert.Contains(t, err.Error(), "signer could not be built")
	})

	t.Run("staged pair is mismatched", func(t *testing.T) {
		isoDir := t.TempDir()
		efiPath := filepath.Join(isoDir, "bootx64.efi")
		require.NoError(t, os.WriteFile(efiPath, []byte("pe"), 0o644))
		writeSigningPair(t, filepath.Join(isoDir, SecureBootKeysISODirName), true)

		c := newSigningCustomizer(t, isoDir, true)

		err := c.signISOBootloader(context.Background(), efiPath)
		require.Error(t, err, "a cert that does not match the key must fail the build")
	})

	t.Run("bootloader is not a valid PE", func(t *testing.T) {
		isoDir := t.TempDir()
		efiPath := filepath.Join(isoDir, "bootx64.efi")
		require.NoError(t, os.WriteFile(efiPath, []byte("definitely not a PE binary"), 0o644))
		writeSigningPair(t, filepath.Join(isoDir, SecureBootKeysISODirName), false)

		c := newSigningCustomizer(t, isoDir, true)

		err := c.signISOBootloader(context.Background(), efiPath)
		require.Error(t, err, "an unsignable bootloader must fail the build rather than ship unsigned")
	})
}

// TestSignISOBootloader_UsesTheBakedFilenames verifies the staged filenames the
// baked config names are honoured, not the DB.key/DB.crt default. A build whose
// config references custom.key must sign with custom.key or fail -- silently
// falling back to the default pair would sign with the wrong key and produce
// media the target's enrolled DB does not trust.
func TestSignISOBootloader_UsesTheBakedFilenames(t *testing.T) {
	isoDir := t.TempDir()
	efiPath := filepath.Join(isoDir, "bootx64.efi")
	require.NoError(t, os.WriteFile(efiPath, []byte("pe"), 0o644))

	// Stage the DEFAULT pair, then ask for a custom one that is not there.
	writeSigningPair(t, filepath.Join(isoDir, SecureBootKeysISODirName), false)

	c := newSigningCustomizer(t, isoDir, true)
	c.sbMediaKeyFile, c.sbMediaCertFile = "custom.key", "custom.crt"

	err := c.signISOBootloader(context.Background(), efiPath)
	require.Error(t, err,
		"the configured filenames must be used; falling back to DB.key would sign with the wrong key")
}
