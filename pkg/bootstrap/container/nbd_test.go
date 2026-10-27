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

package container

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// nbdManifest lists nbd-01 under two MACs, as BuildManifest writes a
// multi-NIC node, beside an installed node the export server must ignore.
const nbdManifest = `nodes:
  - mac: "aa:bb:cc:dd:ee:01"
    role: "control-plane"
    hostname: "cp-01"
  - mac: "dc:a6:32:01:36:c2"
    role: "worker"
    hostname: "nbd-01"
    boot_model: "diskless-nbd"
  - mac: "dc:a6:32:01:36:c3"
    role: "worker"
    hostname: "nbd-01"
    boot_model: "diskless-nbd"
  - mac: "dc:a6:32:01:36:c4"
    role: "worker"
    hostname: "nbd-02"
    boot_model: "diskless-nbd"
`

// nbdCredentials writes a CA bundle and a server certificate and key it
// issued, as PEM files in a temporary directory.
func nbdCredentials(t *testing.T) (caFile, certFile, keyFile string) {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(bundle.ServerCert.PrivateKey)
	require.NoError(t, err)

	dir := t.TempDir()
	caFile = filepath.Join(dir, "ca.pem")
	certFile = filepath.Join(dir, "server.pem")
	keyFile = filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(caFile, bundle.CACertPEM, 0o600))
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bundle.ServerCert.Certificate[0]}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return caFile, certFile, keyFile
}

// validNBDConfig is a complete NBD section with real credentials.
func validNBDConfig(t *testing.T) NBDConfig {
	t.Helper()
	caFile, certFile, keyFile := nbdCredentials(t)
	return NBDConfig{
		ListenAddr: "127.0.0.1:" + strconv.Itoa(nbd.DefaultPort),
		VolumeDir:  t.TempDir(),
		VolumeSize: 1 << 20,
		CAFile:     caFile,
		CertFile:   certFile,
		KeyFile:    keyFile,
	}
}

func TestManifest_NBDIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(path, []byte(nbdManifest), 0o600))
	manifest, err := LoadManifest(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"nbd-01", "nbd-02"}, manifest.nbdIdentities(),
		"only diskless-nbd nodes are served, and a node with two MACs once")
}

func TestManifest_NBDIdentities_NoneWithoutDisklessNBDNodes(t *testing.T) {
	manifest := &Manifest{Nodes: []ManifestEntry{
		{MAC: "aa:bb:cc:dd:ee:01", Hostname: "cp-01"},
		{MAC: "aa:bb:cc:dd:ee:02", Hostname: "ram-01", BootModel: "diskless"},
	}}
	assert.Empty(t, manifest.nbdIdentities())
}

func TestNBDConfig_Validate(t *testing.T) {
	valid := NBDConfig{ListenAddr: "192.0.2.1:10809", VolumeSize: 1 << 30, CAFile: "ca.pem", CertFile: "server.pem", KeyFile: "server.key"}
	require.NoError(t, valid.validate())

	cases := []struct {
		field  string
		mutate func(*NBDConfig)
	}{
		{"nbd.listen_addr", func(c *NBDConfig) { c.ListenAddr = "" }},
		{"nbd.listen_addr", func(c *NBDConfig) { c.ListenAddr = "192.0.2.1" }},
		{"nbd.volume_size", func(c *NBDConfig) { c.VolumeSize = 0 }},
		{"nbd.volume_size", func(c *NBDConfig) { c.VolumeSize = -512 }},
		{"nbd.ca_file", func(c *NBDConfig) { c.CAFile = "" }},
		{"nbd.cert_file", func(c *NBDConfig) { c.CertFile = "" }},
		{"nbd.key_file", func(c *NBDConfig) { c.KeyFile = "" }},
	}
	for _, tc := range cases {
		c := valid
		tc.mutate(&c)
		var invalid ErrInvalidServerConfig
		err := c.validate()
		if !errors.As(err, &invalid) || invalid.Field != tc.field {
			t.Errorf("validate(%+v) = %v, want ErrInvalidServerConfig{%s}", c, err, tc.field)
		}
	}
}

func TestServerConfig_ApplyDefaults_NBD(t *testing.T) {
	derived := &ServerConfig{DataDir: "/data", DHCPConfig: DHCPConfig{ServerIP: "192.0.2.1"}}
	derived.ApplyDefaults()
	assert.Equal(t, "192.0.2.1:10809", derived.NBD.ListenAddr, "the provisioning address on the NBD port")
	assert.Equal(t, "/data/nbd", derived.NBD.VolumeDir)

	explicit := &ServerConfig{
		DataDir:    "/data",
		DHCPConfig: DHCPConfig{ServerIP: "192.0.2.1"},
		NBD:        NBDConfig{ListenAddr: "192.0.2.2:20809", VolumeDir: "/srv/nbd"},
	}
	explicit.ApplyDefaults()
	assert.Equal(t, "192.0.2.2:20809", explicit.NBD.ListenAddr)
	assert.Equal(t, "/srv/nbd", explicit.NBD.VolumeDir)
}

// TestServerConfig_ApplyDefaults_NBDNoServerIP leaves the address unset
// rather than inventing one; validation then names the missing field.
func TestServerConfig_ApplyDefaults_NBDNoServerIP(t *testing.T) {
	c := &ServerConfig{}
	c.ApplyDefaults()
	assert.Empty(t, c.NBD.ListenAddr)
}

func TestNewNBDServer(t *testing.T) {
	manifest := &Manifest{Nodes: []ManifestEntry{{MAC: "dc:a6:32:01:36:c2", Hostname: "nbd-01", BootModel: nbd.BootModel}}}
	config := &ServerConfig{NBD: validNBDConfig(t)}

	server, err := newNBDServer(config, manifest, testLogger())
	require.NoError(t, err)
	require.NotNil(t, server)
	require.NoError(t, server.Close())
}

// TestNewNBDServer_NoneWithoutDisklessNBDNodes keeps NBD configuration
// optional for every container that serves no such node.
func TestNewNBDServer_NoneWithoutDisklessNBDNodes(t *testing.T) {
	manifest := &Manifest{Nodes: []ManifestEntry{{MAC: "aa:bb:cc:dd:ee:01", Hostname: "cp-01"}}}
	server, err := newNBDServer(&ServerConfig{}, manifest, testLogger())
	require.NoError(t, err)
	assert.Nil(t, server)
}

// TestNBDVolumes_LocalFilesUnderVolumeDir pins the store this boot node
// uses: one file per device under NBDConfig.VolumeDir, which the installed
// UKI route reads through the same provider the export server writes.
func TestNBDVolumes_LocalFilesUnderVolumeDir(t *testing.T) {
	dir := t.TempDir()
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: dir}})
	require.NoError(t, err)

	require.NoError(t, volumes.Create("nbd-01", 4096))
	path, err := volumes.Attach("nbd-01")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "nbd-01.img"), path)
}

func TestNBDVolumes_RefusesAnEmptyVolumeDir(t *testing.T) {
	volumes, err := nbdVolumes(&ServerConfig{})
	var invalid nbd.ErrInvalidConfig
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "VolumeDir", invalid.Field)
	assert.Nil(t, volumes)
}

func TestNewNBDServer_Errors(t *testing.T) {
	manifest := &Manifest{Nodes: []ManifestEntry{{MAC: "dc:a6:32:01:36:c2", Hostname: "nbd-01", BootModel: nbd.BootModel}}}

	t.Run("incomplete config", func(t *testing.T) {
		config := &ServerConfig{NBD: validNBDConfig(t)}
		config.NBD.CAFile = ""
		var invalid ErrInvalidServerConfig
		_, err := newNBDServer(config, manifest, testLogger())
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "nbd.ca_file", invalid.Field)
	})

	t.Run("missing key", func(t *testing.T) {
		config := &ServerConfig{NBD: validNBDConfig(t)}
		config.NBD.KeyFile = filepath.Join(t.TempDir(), "absent.key")
		var credentials ErrNBDCredentials
		_, err := newNBDServer(config, manifest, testLogger())
		require.ErrorAs(t, err, &credentials)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("key that does not match the certificate", func(t *testing.T) {
		config := &ServerConfig{NBD: validNBDConfig(t)}
		_, _, otherKey := nbdCredentials(t)
		config.NBD.KeyFile = otherKey
		var credentials ErrNBDCredentials
		_, err := newNBDServer(config, manifest, testLogger())
		require.ErrorAs(t, err, &credentials)
	})

	t.Run("volume size the export server refuses", func(t *testing.T) {
		config := &ServerConfig{NBD: validNBDConfig(t)}
		config.NBD.VolumeSize = 1000
		var invalid nbd.ErrInvalidConfig
		_, err := newNBDServer(config, manifest, testLogger())
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "VolumeSize", invalid.Field)
	})
}

// TestNewServer_DisklessNBDNodeRequiresNBDConfig refuses to build a
// container that names a diskless-nbd node it could not serve.
func TestNewServer_DisklessNBDNodeRequiresNBDConfig(t *testing.T) {
	var invalid ErrInvalidServerConfig
	_, err := newTestContainer(t, nbdManifest)
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "nbd.volume_size", invalid.Field)
}

func TestErrNBDCredentials(t *testing.T) {
	err := ErrNBDCredentials{CertFile: "/certs/nbd.pem", KeyFile: "/certs/nbd.key", Err: io.ErrUnexpectedEOF}
	assert.Contains(t, err.Error(), "/certs/nbd.pem")
	assert.Contains(t, err.Error(), "/certs/nbd.key")
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// logSignal is a slog handler that closes seen when a record with the
// given message arrives, so a test waits on the event, not on a timer.
type logSignal struct {
	message string
	seen    chan struct{}
	once    sync.Once
}

func newLogSignal(message string) *logSignal {
	return &logSignal{message: message, seen: make(chan struct{})}
}

func (h *logSignal) Enabled(context.Context, slog.Level) bool { return true }

func (h *logSignal) Handle(_ context.Context, record slog.Record) error {
	if record.Message == h.message {
		h.once.Do(func() { close(h.seen) })
	}
	return nil
}

func (h *logSignal) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *logSignal) WithGroup(string) slog.Handler { return h }

// nbdStartConfig is a container config on loopback that serves the
// manifest's diskless-nbd nodes on nbdListen. An empty nbdListen gets a
// free loopback port distinct from the container's other TCP ports.
func nbdStartConfig(t *testing.T, nbdListen string) (config *ServerConfig, deviceScriptPort int) {
	t.Helper()
	dataDir := testDataDir(t, x86Set())
	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(nbdManifest), 0o600))

	// One allocation per protocol, so no two listeners share a port (#936).
	tcpPorts := freeTCPPorts(t, 3)
	udpPorts := freeUDPPorts(t, 2)
	if nbdListen == "" {
		nbdListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPorts[2]))
	}
	nbdConfig := validNBDConfig(t)
	nbdConfig.ListenAddr = nbdListen
	deviceScriptPort = tcpPorts[0]
	return &ServerConfig{
		Interface:        "lo",
		HTTPPort:         tcpPorts[1],
		TFTPPort:         udpPorts[0],
		DeviceScriptPort: deviceScriptPort,
		FirmwareDir:      fixtureFirmwareDir(t),
		FirmwareOffline:  true,
		ManifestPath:     manifestPath,
		DataDir:          dataDir,
		MediaDir:         filepath.Join(dataDir, "media"),
		DHCPConfig: DHCPConfig{
			ServerIP:   "127.0.0.1",
			RangeStart: "127.0.0.2",
			RangeEnd:   "127.0.0.3",
			SubnetMask: "255.255.255.0",
			Port:       udpPorts[1],
		},
		NBD: nbdConfig,
	}, deviceScriptPort
}

// TestStart_ServesNBDForDisklessNBDNodes runs the container and checks
// that the NBD export server answers on its address with the newstyle
// greeting, and that stopping the container closes it.
func TestStart_ServesNBDForDisklessNBDNodes(t *testing.T) {
	_, nbdAddr, cancel, startErr := startNBDContainer(t)
	deadline := time.After(5 * time.Second)

	conn, err := net.Dial("tcp", nbdAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	greeting := make([]byte, 16)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)
	assert.Equal(t, "NBDMAGICIHAVEOPT", string(greeting))
	require.NoError(t, conn.Close())

	cancel()
	select {
	case err := <-startErr:
		require.NoError(t, err)
	case <-deadline:
		t.Fatal("Start did not return after its context was cancelled")
	}
	if conn, err := net.Dial("tcp", nbdAddr); err == nil {
		_ = conn.Close()
		t.Fatal("the NBD listener outlived the container")
	}
}

func TestStop_ClosesTheNBDListenerBeforeItReturns(t *testing.T) {
	srv, nbdAddr, cancel, startErr := startNBDContainer(t)

	require.NoError(t, srv.Stop())
	if conn, err := net.Dial("tcp", nbdAddr); err == nil {
		_ = conn.Close()
		t.Fatal("the NBD listener outlived Stop")
	}

	cancel()
	select {
	case err := <-startErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}

// startNBDContainer starts a container serving one diskless-nbd node and
// returns once its NBD export server listens. cancel stops Start, whose
// result arrives on startErr.
func startNBDContainer(t *testing.T) (srv *Server, nbdAddr string, cancel context.CancelFunc, startErr <-chan error) {
	t.Helper()
	config, _ := nbdStartConfig(t, "")
	listening := newLogSignal("nbd export server listening")
	srv, err := NewServer(config, slog.New(listening))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- srv.Start(ctx) }()

	select {
	case <-listening.seen:
	case err := <-result:
		t.Fatalf("Start returned before the NBD server listened: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the NBD server never listened")
	}
	return srv, config.NBD.ListenAddr, cancel, result
}

// TestStart_NBDBindFailureKeepsDeviceScriptDown: the device-script port is
// the deploy gate's readiness signal, so it must not answer when the NBD
// listener, which a diskless-nbd node's root depends on, could not bind.
func TestStart_NBDBindFailureKeepsDeviceScriptDown(t *testing.T) {
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer squatter.Close()

	config, deviceScriptPort := nbdStartConfig(t, squatter.Addr().String())
	srv, err := NewServer(config, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start(ctx) }()

	select {
	case err := <-startErr:
		var failed ErrServerStartFailed
		require.ErrorAs(t, err, &failed)
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Start error = %v; want the squatted NBD port's address-already-in-use", err)
		}
	case <-ctx.Done():
		t.Fatal("Start neither returned nor failed within the deadline")
	}

	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(deviceScriptPort))); err == nil {
		_ = conn.Close()
		t.Fatal("the device-script listener bound although the NBD listener did not")
	}
}
