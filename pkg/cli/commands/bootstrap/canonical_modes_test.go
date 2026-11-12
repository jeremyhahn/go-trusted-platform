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

func TestCanonicalDirect_NoInstallByDefault(t *testing.T) {
	cmd := newCanonicalDirectCmd(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	installFlag := cmd.Flag("install-to-system-trust")
	require.NotNil(t, installFlag)
	assert.Equal(t, "false", installFlag.DefValue)
	certFlag := cmd.Flag("cert-path")
	require.NotNil(t, certFlag)
	assert.Equal(t, defaultCertPath, certFlag.DefValue)
}
