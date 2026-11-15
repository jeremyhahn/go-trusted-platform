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
	"bytes"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// directTestCertPEM returns a PEM-encoded self-signed certificate; isCA
// selects whether it is a CA certificate.
func directTestCertPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "direct-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// runDirect writes bundle to a temp file and runs `bootstrap direct`
// with the given extra arguments.
func runDirect(t *testing.T, bundle []byte, args ...string) (string, error) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(bundlePath, bundle, 0o600))
	cmd := newCanonicalDirectCmd(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--bundle", bundlePath}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestCanonicalDirect_ValidCABundle(t *testing.T) {
	out, err := runDirect(t, directTestCertPEM(t, true))
	require.NoError(t, err)
	assert.Contains(t, out, "Direct CA bundle accepted")
}

func TestCanonicalDirect_NotPEM(t *testing.T) {
	_, err := runDirect(t, []byte("not a pem bundle\n"))
	var notPEM ErrDirectBundleNotPEM
	require.ErrorAs(t, err, &notPEM)
}

func TestCanonicalDirect_NonCACert(t *testing.T) {
	_, err := runDirect(t, directTestCertPEM(t, false))
	var noCA ErrDirectBundleNoCA
	require.ErrorAs(t, err, &noCA)
}

func TestCanonicalDirect_InvalidCertBlock(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := runDirect(t, bad)
	var invalid ErrDirectBundleInvalidCert
	require.ErrorAs(t, err, &invalid)
}

func TestCanonicalDirect_InstallToCertPath(t *testing.T) {
	bundle := directTestCertPEM(t, true)
	certPath := filepath.Join(t.TempDir(), "nested", "platform-ca.crt")
	out, err := runDirect(t, bundle, "--install-to-system-trust", "--cert-path", certPath)
	require.NoError(t, err)
	assert.Contains(t, out, certPath)
	written, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, bundle, written)
}

// TestCanonicalDirect_RejectsCombinedCertAndKey proves a bundle that carries a
// private key next to a valid CA certificate is refused before anything is
// written: the key must never reach the world-readable trust directory.
func TestCanonicalDirect_RejectsCombinedCertAndKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	bundle := append(directTestCertPEM(t, true), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	certPath := filepath.Join(t.TempDir(), "nested", "platform-ca.crt")
	_, err = runDirect(t, bundle, "--install-to-system-trust", "--cert-path", certPath)
	var nonCert ErrDirectBundleNonCertificateBlock
	require.ErrorAs(t, err, &nonCert)
	assert.Equal(t, "PRIVATE KEY", nonCert.Type)
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert path must not exist, stat: %v", statErr)
}

// TestCanonicalDirect_InstallsOnlyCertificates proves text around the PEM
// blocks is not copied into the trust store: only the re-encoded
// certificates are written.
func TestCanonicalDirect_InstallsOnlyCertificates(t *testing.T) {
	certPEM := directTestCertPEM(t, true)
	bundle := append(append([]byte("# operator note\n"), certPEM...), []byte("# trailer\n")...)
	certPath := filepath.Join(t.TempDir(), "platform-ca.crt")
	_, err := runDirect(t, bundle, "--install-to-system-trust", "--cert-path", certPath)
	require.NoError(t, err)
	written, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, certPEM, written)
}

// TestCanonicalDirect_RejectsMalformedPEMBlock proves a damaged PEM block is
// refused even when a valid CA sits next to it, before or after, and that an
// existing trust file is left as it was: pem.Decode would otherwise skip the
// damaged block and install an incomplete bundle.
func TestCanonicalDirect_RejectsMalformedPEMBlock(t *testing.T) {
	validCA := directTestCertPEM(t, true)
	other := directTestCertPEM(t, true)
	truncated := other[:len(other)/2]
	badBase64 := []byte("-----BEGIN CERTIFICATE-----\n!!!not*base64!!!\n-----END CERTIFICATE-----\n")
	noEnd := bytes.Replace(other, []byte("-----END CERTIFICATE-----"), nil, 1)
	tests := []struct {
		name   string
		bundle []byte
	}{
		{"truncated after CA", append(append([]byte{}, validCA...), truncated...)},
		{"truncated before CA", append(append([]byte{}, truncated...), validCA...)},
		{"bad base64 after CA", append(append([]byte{}, validCA...), badBase64...)},
		{"bad base64 before CA", append(append([]byte{}, badBase64...), validCA...)},
		{"missing END after CA", append(append([]byte{}, validCA...), noEnd...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPath := filepath.Join(t.TempDir(), "platform-ca.crt")
			previous := []byte("previous trust anchors\n")
			require.NoError(t, os.WriteFile(certPath, previous, 0o600))
			_, err := runDirect(t, tt.bundle, "--install-to-system-trust", "--cert-path", certPath)
			var malformed ErrDirectBundleMalformedPEM
			require.ErrorAs(t, err, &malformed)
			written, err := os.ReadFile(certPath)
			require.NoError(t, err)
			assert.Equal(t, previous, written, "existing trust file must stay unchanged")
		})
	}
}

// TestCanonicalDirect_AcceptsTwoCAsWithText proves ordinary text around and
// between well-formed blocks is still accepted and both CAs are installed.
func TestCanonicalDirect_AcceptsTwoCAsWithText(t *testing.T) {
	first := directTestCertPEM(t, true)
	second := directTestCertPEM(t, true)
	var bundle []byte
	bundle = append(bundle, "# root one\n"...)
	bundle = append(bundle, first...)
	bundle = append(bundle, "\n# root two\n"...)
	bundle = append(bundle, second...)
	bundle = append(bundle, "# end\n"...)
	certPath := filepath.Join(t.TempDir(), "platform-ca.crt")
	_, err := runDirect(t, bundle, "--install-to-system-trust", "--cert-path", certPath)
	require.NoError(t, err)
	written, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, first...), second...), written)
}

func TestCanonicalDirect_NoInstallByDefault(t *testing.T) {
	cmd := newCanonicalDirectCmd(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	installFlag := cmd.Flag("install-to-system-trust")
	require.NotNil(t, installFlag)
	assert.Equal(t, "false", installFlag.DefValue)
	certFlag := cmd.Flag("cert-path")
	require.NotNil(t, certFlag)
	assert.Equal(t, defaultCertPath, certFlag.DefValue)
}
