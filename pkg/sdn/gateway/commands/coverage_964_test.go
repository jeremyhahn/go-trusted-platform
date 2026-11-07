package commands

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// TestTypedErrors_MessageAndCause checks that every typed error names the
// operator-facing detail it carries and keeps its cause reachable through
// errors.Is, so a caller can match on the underlying failure.
func TestTypedErrors_MessageAndCause(t *testing.T) {
	cause := errors.New("root cause")
	tests := []struct {
		name     string
		err      error
		contains []string
		cause    error
	}{
		{"config section", &ErrConfigSection{Section: "sdn", Cause: cause}, []string{"section sdn", "root cause"}, cause},
		{"sdn required", &ErrSDNRequiredForService{Service: "firewall"}, []string{"service firewall", "ovs: subsection"}, nil},
		{"no zone networks", &ErrNoZoneNetworks{Service: "zones"}, []string{"service zones", "sdn.environment"}, nil},
		{"ovs client init", &ErrOVSClientInit{Socket: "/run/ovs.sock", Cause: cause}, []string{"/run/ovs.sock", "root cause"}, cause},
		{"ovs connect", &ErrOVSConnectFailed{Socket: "/run/ovs.sock", Cause: cause}, []string{"connecting to OVSDB at /run/ovs.sock", "root cause"}, cause},
		{"bridge", &ErrBridgeNotProvisioned{Bridge: "br-int", Cause: cause}, []string{"bridge br-int", "root cause"}, cause},
		{"ca file with cause", &ErrCAFileLoadFailed{Path: "/etc/ca.pem", Cause: cause}, []string{"/etc/ca.pem", "root cause"}, cause},
		{"ca file empty", &ErrCAFileLoadFailed{Path: "/etc/ca.pem"}, []string{"/etc/ca.pem", "no certificates found"}, nil},
		{"id cert mismatch", &ErrGatewayIDCertMismatch{GatewayID: "gw-1", CertCN: "gw-2", CertFile: "/etc/c.pem"}, []string{`"gw-1"`, `"gw-2"`, "/etc/c.pem"}, nil},
		{"id not reportable", &ErrGatewayIDNotReportable{GatewayID: " gw-1"}, []string{`" gw-1"`, "whitespace"}, nil},
		{"tofu dir unset", &ErrTOFUPinDirUnset{}, []string{"--data-dir is empty"}, nil},
		{"tofu dir unusable", &ErrTOFUPinDirUnusable{Dir: "/var/tofu", Cause: cause}, []string{"/var/tofu", "root cause"}, cause},
		{"overlay record missing", &ErrOverlayPlatformRecordMissing{Record: "device 42", Cause: cause}, []string{"no device 42", "root cause"}, cause},
		{"ipam with cause", &ErrOverlayIPAMAllocation{IP: "10.0.0.x", Reason: "unparsable", Cause: cause}, []string{`"10.0.0.x"`, "unparsable", "root cause"}, cause},
		{"ipam without cause", &ErrOverlayIPAMAllocation{IP: "10.0.0.1", Reason: "outside the fabric"}, []string{`"10.0.0.1"`, "outside the fabric"}, nil},
		{"config unreadable", &ErrServiceConfigUnreadable{Process: "proxy", Cause: cause}, []string{"service proxy", "root cause"}, cause},
		{"stale sweep", &ErrStaleTunnelSweep{Cause: cause}, []string{"stale tunnel state", "root cause"}, cause},
		{"tunnels record", &ErrTunnelsRecord{Path: "/var/rec", Cause: cause}, []string{"record /var/rec", "root cause"}, cause},
		{"hosts nothing", &ErrProcessHostsNothing{Process: "vpn"}, []string{"service vpn", "none of its services"}, nil},
		{"ipc failed", &ErrServiceIPCFailed{Process: "vpn", Cause: cause}, []string{"service vpn", "root cause"}, cause},
		{"metrics listen", &ErrMetricsListen{Address: "127.0.0.1:1", Cause: cause}, []string{"listen on 127.0.0.1:1", "root cause"}, cause},
		{"metrics serve", &ErrMetricsServe{Address: "127.0.0.1:1", Cause: cause}, []string{"serving 127.0.0.1:1", "root cause"}, cause},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, want := range tc.contains {
				assert.Contains(t, msg, want)
			}
			if tc.cause != nil {
				assert.ErrorIs(t, tc.err, tc.cause)
			}
		})
	}
}

// TestErrOverlayPlatformRecordMissing_MatchesTheSentinel checks that a
// missing platformd record matches the gateway's not-found sentinel as well
// as its own cause.
func TestErrOverlayPlatformRecordMissing_MatchesTheSentinel(t *testing.T) {
	cause := errors.New("not found")
	err := &ErrOverlayPlatformRecordMissing{Record: "device 7", Cause: cause}
	assert.ErrorIs(t, err, gateway.ErrOverlayRecordNotFound)
	assert.ErrorIs(t, err, cause)
}

// TestMetricsServer_NilReceiver checks that an unconfigured (nil) metrics
// server is a safe no-op on every method serve calls.
func TestMetricsServer_NilReceiver(t *testing.T) {
	var s *MetricsServer
	assert.Empty(t, s.Addr())
	assert.NoError(t, s.Serve())
	assert.NoError(t, s.Shutdown())
	assert.Empty(t, (&MetricsServer{}).Addr(), "a server without a listener has no address")
}

// TestServe_RunsAndStopsTheMetricsEndpoint checks that serve starts the
// configured metrics endpoint with the gateway and shuts it down cleanly
// on the signal.
func TestServe_RunsAndStopsTheMetricsEndpoint(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer
	sweeps := &sweepRecorder{}
	yaml := bgpOnlyConfig(t) + "metrics:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n"

	err := serve(serveConfig(t, yaml), slog.New(slog.NewTextHandler(&logged, nil)), signals, sweeps.sweep)

	require.NoError(t, err)
	out := logged.String()
	assert.Contains(t, out, "Gateway metrics endpoint started")
	assert.NotContains(t, out, "Gateway metrics endpoint shutdown failed")
	assert.NotContains(t, out, "Gateway metrics endpoint exited with error")
	assert.Contains(t, out, "Gateway daemon stopped")
}

// TestServe_RefusesAnUnbindableMetricsPort checks that a metrics port that
// is already taken fails the boot before the datapath starts.
func TestServe_RefusesAnUnbindableMetricsPort(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, taken.Close()) })
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer
	yaml := bgpOnlyConfig(t) + "metrics:\n  enabled: true\n  listen: \"" + taken.Addr().String() + "\"\n"

	err = serve(serveConfig(t, yaml), slog.New(slog.NewTextHandler(&logged, nil)), signals, (&sweepRecorder{}).sweep)

	var listenErr *ErrMetricsListen
	require.True(t, errors.As(err, &listenErr), "got %v", err)
	assert.Equal(t, taken.Addr().String(), listenErr.Address)
	assert.NotContains(t, logged.String(), "Gateway daemon started")
}

// TestWriteTunnelsRecord checks the record is created when named, skipped
// when not, and that a filesystem failure surfaces as *ErrTunnelsRecord.
func TestWriteTunnelsRecord(t *testing.T) {
	t.Run("no record is a no-op", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "absent")
		require.NoError(t, writeTunnelsRecord(dir, ""))
		assert.NoDirExists(t, dir)
	})
	t.Run("creates the data dir and the record", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "data")
		record := filepath.Join(dir, "tunnels")
		require.NoError(t, writeTunnelsRecord(dir, record))
		assert.FileExists(t, record)
	})
	t.Run("a data dir that is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		record := filepath.Join(file, "tunnels")
		var recErr *ErrTunnelsRecord
		require.True(t, errors.As(writeTunnelsRecord(file, record), &recErr))
		assert.Equal(t, record, recErr.Path)
	})
	t.Run("a record path that is a directory", func(t *testing.T) {
		dir := t.TempDir()
		var recErr *ErrTunnelsRecord
		require.True(t, errors.As(writeTunnelsRecord(dir, dir), &recErr))
		assert.Equal(t, dir, recErr.Path)
	})
}

// TestReporterRootCAs checks the control-plane CA bundle is loaded from the
// configured file, refused when missing or empty, and absent when neither a
// file nor a platform anchor is configured.
func TestReporterRootCAs(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(valid, selfSignedPEM(t), 0o600))
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a certificate"), 0o600))
	missing := filepath.Join(dir, "missing.pem")

	pool, err := reporterRootCAs(context.Background(), &controlplane.Config{CAFile: valid}, nil)
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.False(t, pool.Equal(x509.NewCertPool()), "the pool holds the bundle's certificate")

	var loadErr *ErrCAFileLoadFailed
	_, err = reporterRootCAs(context.Background(), &controlplane.Config{CAFile: missing}, nil)
	require.True(t, errors.As(err, &loadErr), "got %v", err)
	assert.ErrorIs(t, err, os.ErrNotExist)

	_, err = reporterRootCAs(context.Background(), &controlplane.Config{CAFile: garbage}, nil)
	require.True(t, errors.As(err, &loadErr), "got %v", err)
	assert.Equal(t, garbage, loadErr.Path)
	assert.NoError(t, loadErr.Cause)

	pool, err = reporterRootCAs(context.Background(), &controlplane.Config{}, nil)
	require.NoError(t, err)
	assert.Nil(t, pool, "no file and no anchor leaves the system roots")
}

// TestBuildAuditSink checks a disabled audit section installs no sink and an
// enabled one builds the SDK sink without dialing quicbaasd up front.
func TestBuildAuditSink(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	assert.Nil(t, buildAuditSink(proxysvc.AuditConfig{}, logger))

	sink := buildAuditSink(proxysvc.AuditConfig{Enabled: true, QuicBaaSAddr: "127.0.0.1:1", Service: "gatewayd"}, logger)
	require.NotNil(t, sink)
	assert.IsType(t, &proxysvc.SDKAuditSink{}, sink)
}

// selfSignedPEM returns a PEM-encoded self-signed CA certificate.
// controlPlaneYAML returns a `control-plane:` section with the TLS fixture
// identity, pointed at a local port nothing listens on.
func controlPlaneYAML(t *testing.T, gatewayID string) string {
	t.Helper()
	certFile, keyFile, caFile := writeTLSFixtures(t)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := closed.Addr().String()
	require.NoError(t, closed.Close())
	return "control-plane:\n  enabled: true\n  base-url: https://" + addr +
		"\n  gateway-id: " + gatewayID +
		"\n  cert-file: " + certFile + "\n  key-file: " + keyFile + "\n  ca-file: " + caFile + "\n"
}

// TestServe_RunsTheReporterAndReconciler checks that an enabled
// control-plane section starts the telemetry reporter and the
// desired-config reconciler with the gateway, and that both are drained
// on the signal before the gateway stops.
func TestServe_RunsTheReporterAndReconciler(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer
	yaml := bgpOnlyConfig(t) + controlPlaneYAML(t, tlsFixtureCN)

	err := serve(serveConfig(t, yaml), slog.New(slog.NewTextHandler(&logged, nil)), signals, (&sweepRecorder{}).sweep)

	require.NoError(t, err)
	out := logged.String()
	assert.Contains(t, out, "Control-plane telemetry reporter started")
	assert.Contains(t, out, "Desired-config reconciler started")
	assert.Contains(t, out, "Gateway daemon stopped")
}

// TestServe_RefusesAReporterItCannotBuild checks that a control-plane
// identity the certificate does not carry fails the boot before the
// datapath starts.
func TestServe_RefusesAReporterItCannotBuild(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer
	yaml := bgpOnlyConfig(t) + controlPlaneYAML(t, "not-the-certificate-cn")

	err := serve(serveConfig(t, yaml), slog.New(slog.NewTextHandler(&logged, nil)), signals, (&sweepRecorder{}).sweep)

	var mismatch *ErrGatewayIDCertMismatch
	require.True(t, errors.As(err, &mismatch), "got %v", err)
	assert.Equal(t, tlsFixtureCN, mismatch.CertCN)
	assert.NotContains(t, logged.String(), "Gateway daemon started")
}

// TestServe_RefusesAnInvalidControlPlaneSection checks that serve stops at
// configuration load when the control-plane section is unusable.
func TestServe_RefusesAnInvalidControlPlaneSection(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	yaml := bgpOnlyConfig(t) + "control-plane:\n  enabled: true\n  base-url: https://127.0.0.1:1\n"

	err := serve(serveConfig(t, yaml), slog.New(slog.NewTextHandler(io.Discard, nil)), signals, (&sweepRecorder{}).sweep)

	var section *ErrConfigSection
	require.True(t, errors.As(err, &section), "got %v", err)
	assert.Equal(t, "control-plane", section.Section)
}

// fakeOVSDB is an in-memory OVSDB endpoint on a unix socket: it answers
// every transact with one select result holding bridgeRows, and reports on
// closed when the gateway drops its connection.
type fakeOVSDB struct {
	socket string
	closed chan struct{}
}

func newFakeOVSDB(t *testing.T, bridgeRows []map[string]interface{}) *fakeOVSDB {
	t.Helper()
	// t.TempDir embeds the subtest name, which can push the socket path past
	// the 108-byte Unix address limit; a short /tmp prefix stays within it.
	dir, err := os.MkdirTemp("/tmp", "gwovsdb")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "db.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	result, err := json.Marshal([]ovs.OperationResult{{Rows: bridgeRows}})
	require.NoError(t, err)
	f := &fakeOVSDB{socket: socket, closed: make(chan struct{})}
	// accepted carries the one connection (nil when Accept failed) so the
	// cleanup can close it even when the gateway leaked it.
	accepted := make(chan net.Conn, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
		defer close(f.closed)
		decoder := json.NewDecoder(conn)
		encoder := json.NewEncoder(conn)
		for {
			var req ovs.JSONRPCRequest
			if err := decoder.Decode(&req); err != nil {
				return
			}
			if err := encoder.Encode(&ovs.JSONRPCResponse{ID: req.ID, Result: result}); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		if conn := <-accepted; conn != nil {
			require.NoError(t, conn.Close())
		}
		wg.Wait()
	})
	return f
}

// requireClosed fails unless the gateway has closed its OVSDB connection.
func (f *fakeOVSDB) requireClosed(t *testing.T) {
	t.Helper()
	select {
	case <-f.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the OVSDB connection was left open")
	}
}

func fakeOVSDBConfig(socket string) *sdn.Config {
	return &sdn.Config{
		Enabled:     true,
		OVS:         &sdn.OVSConfig{Socket: socket, Bridge: "br-fabric"},
		Environment: &netplan.Environment{ID: 4},
	}
}

// TestBuildGatewayRuntime_AgainstAnOVSDB checks assembly against a live
// OVSDB connection: a provisioned bridge yields a runtime bound to it, and
// every refusal after the connect releases the connection.
func TestBuildGatewayRuntime_AgainstAnOVSDB(t *testing.T) {
	bridge := []map[string]interface{}{{"_uuid": []interface{}{"uuid", "b1"}, "name": "br-fabric"}}

	t.Run("a provisioned bridge yields the runtime", func(t *testing.T) {
		db := newFakeOVSDB(t, bridge)
		rt, err := buildGatewayRuntime(context.Background(), fakeOVSDBConfig(db.socket), "", false, testLogger())
		require.NoError(t, err)
		require.NotNil(t, rt)
		assert.Equal(t, "br-fabric", rt.Bridge)
		assert.NotNil(t, rt.Controller)
		assert.NotNil(t, rt.CTZones)
		assert.Nil(t, rt.OverlayOpenFlow, "no overlay was asked for")
		client, ok := rt.OVS.(*ovs.Client)
		require.True(t, ok)
		require.NoError(t, client.Close())
		db.requireClosed(t)
	})

	t.Run("a missing bridge is refused and the connection released", func(t *testing.T) {
		db := newFakeOVSDB(t, nil)
		_, err := buildGatewayRuntime(context.Background(), fakeOVSDBConfig(db.socket), "", false, testLogger())
		var bridgeErr *ErrBridgeNotProvisioned
		require.True(t, errors.As(err, &bridgeErr), "got %v", err)
		assert.Equal(t, "br-fabric", bridgeErr.Bridge)
		assert.ErrorIs(t, err, ovs.ErrBridgeNotFound)
		db.requireClosed(t)
	})

	t.Run("an overlay without its OpenFlow socket is refused and the connection released", func(t *testing.T) {
		db := newFakeOVSDB(t, bridge)
		_, err := buildGatewayRuntime(context.Background(), fakeOVSDBConfig(db.socket), "", true, testLogger())
		var connectErr *ErrOVSConnectFailed
		require.True(t, errors.As(err, &connectErr), "got %v", err)
		assert.Equal(t, db.socket, connectErr.Socket)
		db.requireClosed(t)
	})
}

// TestReporterRootCAs_FallsBackToThePlatformAnchor checks that without a
// ca-file the control plane is verified against the platform anchor, and
// that an anchor whose bundle is missing fails rather than trusting nothing.
func TestReporterRootCAs_FallsBackToThePlatformAnchor(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "platform-ca.pem")
	anchor, err := buildPlatformAnchor(&ServeConfig{PlatformCAFile: bundle})
	require.NoError(t, err)

	_, err = reporterRootCAs(context.Background(), &controlplane.Config{}, anchor)
	require.Error(t, err, "an undelivered platform bundle must not verify the control plane")

	require.NoError(t, os.WriteFile(bundle, selfSignedPEM(t), 0o600))
	pool, err := reporterRootCAs(context.Background(), &controlplane.Config{}, anchor)
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.False(t, pool.Equal(x509.NewCertPool()), "the pool holds the platform CA")
}

// TestOverlayPlatformdConfig_Defaults checks the overlay dials platformd
// over its local socket unless the proxy section says otherwise.
func TestOverlayPlatformdConfig_Defaults(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *ServeConfig
		wantProtocol string
		wantSocket   string
	}{
		{"no configuration", nil, proxysvc.PlatformdProtocolUnix, proxysvc.DefaultPlatformdSocket},
		{"no proxy section", &ServeConfig{}, proxysvc.PlatformdProtocolUnix, proxysvc.DefaultPlatformdSocket},
		{"a socket without a protocol", &ServeConfig{Proxy: &proxysvc.Config{Platformd: proxysvc.PlatformdConfig{Socket: "/run/p.sock"}}},
			proxysvc.PlatformdProtocolUnix, "/run/p.sock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pcfg := overlayPlatformdConfig(tc.cfg)
			assert.Equal(t, tc.wantProtocol, pcfg.Protocol)
			assert.Equal(t, tc.wantSocket, pcfg.Socket)
		})
	}
}

// TestClientCertCommonName_RefusesAnUnparsableLeaf checks that a keypair
// whose leaf DER does not parse is refused with the parse error rather
// than reported as an empty identity.
func TestClientCertCommonName_RefusesAnUnparsableLeaf(t *testing.T) {
	cn, err := clientCertCommonName(&tls.Certificate{Certificate: [][]byte{[]byte("not DER")}})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrClientCertEmpty)
	assert.Empty(t, cn)
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "coverage-964 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
