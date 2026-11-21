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

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	daemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// cliLifecycleCA answers only the trust-path calls; any other method panics
// through the nil embedded interface, so a call outside the trust path shows.
type cliLifecycleCA struct {
	quicbaasca.CACertificateAuthority
	root, inter *x509.Certificate
}

func (c *cliLifecycleCA) IsInitialized() bool { return true }

func (c *cliLifecycleCA) TrustedRoot() (*x509.Certificate, error) { return c.root, nil }

func (c *cliLifecycleCA) TrustedIntermediate() (*x509.Certificate, error) { return c.inter, nil }

func newCLILifecycleCA(t *testing.T) *cliLifecycleCA {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cli lifecycle root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "cli lifecycle intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	inter, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)
	return &cliLifecycleCA{root: root, inter: inter}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// startDaemonCAServer serves the daemon's real CA service over a Unix socket
// in t.TempDir(), its trust bundle written to trustPath.
func startDaemonCAServer(t *testing.T, ca quicbaasca.CACertificateAuthority, trustPath string) func(cli.OutputFormat) *cli.CommonFlags {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterCAServiceServer(gs, daemon.NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(trustPath))
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})

	return func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
}

func TestRunInstallUninstall_ThroughTheDaemonCAService(t *testing.T) {
	ca := newCLILifecycleCA(t)
	rootPEM := certPEM(ca.root)
	fullPEM := append(append([]byte{}, rootPEM...), certPEM(ca.inter)...)
	newTrustPath := func(t *testing.T) string {
		return filepath.Join(t.TempDir(), "trusted-platform-ca.crt")
	}

	t.Run("install root only", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, ca, trustPath)
		out, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), false) })
		require.NoError(t, err)
		assert.Equal(t, "[INFO] CA certificates installed; run update-ca-certificates to refresh the system trust store\n\n"+
			"Certificates Installed: 1\nInstall Path: "+trustPath+"\n", out)
		got, err := os.ReadFile(trustPath)
		require.NoError(t, err)
		assert.Equal(t, rootPEM, got)
	})

	t.Run("install again answers already installed", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, ca, trustPath)
		_, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), false) })
		require.NoError(t, err)
		out, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), false) })
		require.NoError(t, err)
		assert.Equal(t, "[INFO] CA certificates already installed\n\n"+
			"Certificates Installed: 0\nInstall Path: "+trustPath+"\n", out)
	})

	t.Run("install with intermediates as JSON", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, ca, trustPath)
		out, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatJSON), true) })
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &got), out)
		assert.EqualValues(t, 2, got["CertificatesInstalled"])
		assert.Equal(t, trustPath, got["InstallPath"])
		msg, _ := got["Message"].(string)
		assert.Regexp(t, "^CA certificates installed", msg)
		file, err := os.ReadFile(trustPath)
		require.NoError(t, err)
		assert.Equal(t, fullPEM, file)
	})

	t.Run("uninstall after the full install", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, ca, trustPath)
		_, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), true) })
		require.NoError(t, err)
		out, err := captureStdout(t, func() error { return runUninstall(flags(cli.OutputFormatTable), true) })
		require.NoError(t, err)
		assert.Equal(t, "[INFO] CA certificates removed; run update-ca-certificates to refresh the system trust store\n\n"+
			"Certificates Removed: 2\n", out)
		_, err = os.Stat(trustPath)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("uninstall with nothing installed", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, ca, trustPath)
		out, err := captureStdout(t, func() error { return runUninstall(flags(cli.OutputFormatTable), true) })
		require.NoError(t, err)
		assert.Equal(t, "[INFO] nothing installed\n\nCertificates Removed: 0\n", out)
	})

	t.Run("uninstall refuses a foreign file", func(t *testing.T) {
		trustPath := newTrustPath(t)
		require.NoError(t, os.WriteFile(trustPath, []byte("not ours"), 0o644))
		flags := startDaemonCAServer(t, ca, trustPath)
		_, err := captureStdout(t, func() error { return runUninstall(flags(cli.OutputFormatTable), true) })
		var failed ErrUninstallCertificatesFailed
		require.True(t, errors.As(err, &failed), "got %v", err)
		got, rerr := os.ReadFile(trustPath)
		require.NoError(t, rerr)
		assert.Equal(t, "not ours", string(got))
	})

	t.Run("no CA", func(t *testing.T) {
		trustPath := newTrustPath(t)
		flags := startDaemonCAServer(t, nil, trustPath)
		_, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), false) })
		var failed ErrInstallCertificatesFailed
		require.True(t, errors.As(err, &failed), "got %v", err)
		assert.Contains(t, failed.Reason, daemon.ErrCANotInitialized{}.Error())
		_, err = os.Stat(trustPath)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}
