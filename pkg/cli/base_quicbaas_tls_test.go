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

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/stretchr/testify/require"
)

// writeTestCACert writes a self-signed CA certificate PEM into a temp
// directory and returns its path and the parsed certificate.
func writeTestCACert(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "quicbaas test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path, cert
}

// newLocalQuicBaaSBaseCommand builds a BaseCommand for a local context
// against a test platformd socket, with the quicbaas connection on a
// Unix socket and the given quicbaas CA file.
func newLocalQuicBaaSBaseCommand(t *testing.T, quicbaasCACert string) *BaseCommand {
	t.Helper()
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "platformd.sock")
	_, cleanup := startTestGRPCServer(t, socketPath)
	t.Cleanup(cleanup)

	testCtx := &Context{
		Name: "quicbaas-tls",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath:        socketPath,
			QuicBaaSAddr:      filepath.Join(dir, "quicbaas.sock"),
			QuicBaaSTransport: "unix",
			QuicBaaSCACert:    quicbaasCACert,
		},
	}
	flags := &CommonFlags{
		NoColor:    true,
		GetContext: func() (*Context, error) { return testCtx, nil },
	}
	base, err := NewBaseCommand(flags)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.Close()) })
	return base
}

// TestNewBaseCommand_LocalQuicBaaSTLSReachesSDK verifies a local
// context's quicbaas TLS files reach the quicbaas SDK: its Unix
// transport refuses to build without TLS, so Client.QuicBaaS() succeeds
// only if the CA arrived.
func TestNewBaseCommand_LocalQuicBaaSTLSReachesSDK(t *testing.T) {
	caPath, _ := writeTestCACert(t)
	base := newLocalQuicBaaSBaseCommand(t, caPath)

	q, err := base.Client().QuicBaaS()
	require.NoError(t, err)
	require.NotNil(t, q)
}

// TestNewBaseCommand_LocalQuicBaaSWithoutTLS verifies a local context
// with no quicbaas TLS files fails with the typed error when a verb
// opens the quicbaas client, and leaves the platformd connection usable.
func TestNewBaseCommand_LocalQuicBaaSWithoutTLS(t *testing.T) {
	base := newLocalQuicBaaSBaseCommand(t, "")

	_, err := base.Client().QuicBaaS()
	require.ErrorAs(t, err, new(platform.ErrQuicBaaSTLSNotConfigured))
}

// TestContextToSDKOptions_LocalQuicBaaSTLS verifies the local quicbaas
// CA becomes the quicbaas TLS configuration only: the platformd Unix
// connection authenticates by peer credentials and gets no TLS.
func TestContextToSDKOptions_LocalQuicBaaSTLS(t *testing.T) {
	caPath, caCert := writeTestCACert(t)
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{
		SocketPath:     "/run/platformd.sock",
		QuicBaaSCACert: caPath,
	}}

	opts, err := contextToSDKOptions(ctx)
	require.NoError(t, err)
	require.NotNil(t, opts.QuicBaaSTLSConfig)
	want := x509.NewCertPool()
	want.AddCert(caCert)
	require.True(t, opts.QuicBaaSTLSConfig.RootCAs.Equal(want), "quicbaas RootCAs must hold the context's CA")
	require.Nil(t, opts.TLSConfig, "the platformd Unix connection must not get the quicbaas TLS")
}

// TestContextToSDKOptions_RemoteQuicBaaSUsesRemoteTLS verifies a remote
// context hands its ca_cert to the quicbaas connection as well as to
// the platformd one.
func TestContextToSDKOptions_RemoteQuicBaaSUsesRemoteTLS(t *testing.T) {
	caPath, caCert := writeTestCACert(t)
	ctx := &Context{Type: ContextTypeRemote, Remote: &RemoteContext{
		Server: "platform.example.com:10443",
		CACert: caPath,
	}}

	opts, err := contextToSDKOptions(ctx)
	require.NoError(t, err)
	require.NotNil(t, opts.QuicBaaSTLSConfig)
	want := x509.NewCertPool()
	want.AddCert(caCert)
	require.True(t, opts.QuicBaaSTLSConfig.RootCAs.Equal(want))
	require.NotNil(t, opts.TLSConfig)
}

// TestContextToSDKOptions_QuicBaaSCACertUnreadable verifies a quicbaas
// CA path that cannot be read fails the context with the typed error
// instead of dropping TLS.
func TestContextToSDKOptions_QuicBaaSCACertUnreadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-ca.crt")
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{
		SocketPath:     "/run/platformd.sock",
		QuicBaaSCACert: missing,
	}}

	_, err := contextToSDKOptions(ctx)
	var loadFailed ErrTLSCACertLoadFailed
	require.ErrorAs(t, err, &loadFailed)
	require.Equal(t, missing, loadFailed.Path)
}
