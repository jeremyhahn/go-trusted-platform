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

package deployer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer/quicagent"
)

const agentName = "deploy-target.test"

// mtlsFiles are PEM files for one test CA, an agent certificate and a
// deployer client certificate issued by it.
type mtlsFiles struct {
	ca, agentCert, agentKey, deployerCert, deployerKey string
}

func writeMTLS(t *testing.T) mtlsFiles {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "deploy test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
		return p
	}
	leaf := func(prefix string, serial int64, usage x509.ExtKeyUsage, dns ...string) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: prefix},
			DNSNames:     dns,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return write(prefix+".crt", "CERTIFICATE", der), write(prefix+".key", "EC PRIVATE KEY", keyDER)
	}
	f := mtlsFiles{ca: write("ca.pem", "CERTIFICATE", caDER)}
	f.agentCert, f.agentKey = leaf("agent", 2, x509.ExtKeyUsageServerAuth, agentName)
	f.deployerCert, f.deployerKey = leaf("deployer", 3, x509.ExtKeyUsageClientAuth)
	return f
}

// startAgent runs the deploy agent on loopback the way cmd/deploy-agent
// does (ServerTLSConfig from files, ListenAndServe) and returns its port.
func startAgent(t *testing.T, f mtlsFiles) int {
	t.Helper()
	tlsConf, err := quicagent.ServerTLSConfig(f.agentCert, f.agentKey, f.ca)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- quicagent.ListenAndServe(ctx, "127.0.0.1:0", tlsConf,
			slog.New(slog.NewTextHandler(io.Discard, nil)), func(a net.Addr) { addrCh <- a })
	}()
	var addr net.Addr
	select {
	case addr = <-addrCh:
	case err := <-done:
		t.Fatalf("agent stopped before listening: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	return addr.(*net.UDPAddr).Port
}

// fakeRuntime is a container runtime stand-in: it logs every call, has no
// image (so the deployer pulls), and prints a container id for run.
func fakeRuntime(t *testing.T) (path, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	path = filepath.Join(dir, "runtime")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + strconv.Quote(log) + "\n" +
		"case \"$1 $2\" in\n" +
		"  \"image inspect\") exit 1 ;;\n" +
		"esac\n" +
		"case \"$1\" in\n" +
		"  run) echo cid-over-quic ;;\n" +
		"esac\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, log
}

// TestDeployOverQUICAgentWithoutSSH deploys the bootstrap container to a
// target that runs only the QUIC deploy agent: the config names no SSH
// user, key or known_hosts, so an SSH path could not connect. Deploy
// stages the manifest and the netboot media through the agent, pulls the
// image and starts the container; Teardown runs through it too.
func TestDeployOverQUICAgentWithoutSSH(t *testing.T) {
	f := writeMTLS(t)
	port := startAgent(t, f)
	runtime, callLog := fakeRuntime(t)

	manifest := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("nodes: []\n"), 0o644))
	dataDir := filepath.Join(t.TempDir(), "bootstrap")

	config := &deployer.DeployConfig{
		Host:             "127.0.0.1",
		Transport:        deployer.TransportQUIC,
		AgentPort:        port,
		AgentCertPath:    f.deployerCert,
		AgentKeyPath:     f.deployerKey,
		AgentCAPath:      f.ca,
		AgentServerName:  agentName,
		ContainerRuntime: runtime,
		ContainerImage:   "example.test/pxeboot:1",
		ManifestPath:     manifest,
		DataDir:          dataDir,
		NetbootMediaDir:  deployer.PiBuildForTest(t, "kernel over quic"),
	}
	d := deployer.NewLinuxDeployer(slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := d.Deploy(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, "cid-over-quic", res.ContainerID)
	assert.True(t, res.Running)

	got, err := os.ReadFile(filepath.Join(dataDir, "manifest.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "nodes: []\n", string(got), "the manifest is staged through the agent")
	kernel, err := os.ReadFile(filepath.Join(dataDir, "media", "aarch64-rpi", "vmlinuz-rpi"))
	require.NoError(t, err)
	assert.Equal(t, "kernel over quic", string(kernel), "the netboot media is staged through the agent")

	require.NoError(t, d.Teardown(ctx, config))

	calls, err := os.ReadFile(callLog)
	require.NoError(t, err)
	log := string(calls)
	assert.Contains(t, log, "pull example.test/pxeboot:1")
	assert.Contains(t, log, "\nrun ", "the container is started on the target")
	assert.Equal(t, 2, strings.Count(log, "image inspect"), "one local and one remote image probe")
}

// TestDeployOverQUICRefusesAnUntrustedAgent: the deployer verifies the
// agent against agent_ca, and an agent whose certificate another CA
// issued is refused before anything runs (no SSH fallback).
func TestDeployOverQUICRefusesAnUntrustedAgent(t *testing.T) {
	agentSide := writeMTLS(t)
	deployerSide := writeMTLS(t)
	port := startAgent(t, agentSide)
	runtime, callLog := fakeRuntime(t)

	config := &deployer.DeployConfig{
		Host:             "127.0.0.1",
		Transport:        deployer.TransportQUIC,
		AgentPort:        port,
		AgentCertPath:    deployerSide.deployerCert,
		AgentKeyPath:     deployerSide.deployerKey,
		AgentCAPath:      deployerSide.ca,
		AgentServerName:  agentName,
		ContainerRuntime: runtime,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := deployer.NewLinuxDeployer(nil).Teardown(ctx, config)
	var connErr quicagent.ErrConnect
	require.ErrorAs(t, err, &connErr)
	_, statErr := os.Stat(callLog)
	assert.True(t, os.IsNotExist(statErr), "no command ran on the target")
}
