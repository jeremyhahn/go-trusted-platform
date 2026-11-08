package commands

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sweepRecorder stands in for the netlink sweep: it counts the sweeps and
// fails them with err.
type sweepRecorder struct {
	calls     int
	inventory string
	err       error
}

func (r *sweepRecorder) sweep(_ *slog.Logger, inventory string) error {
	r.calls++
	r.inventory = inventory
	return r.err
}

// serveConfig is a viper holding the given gatewayd YAML and a data dir.
func serveConfig(t *testing.T, yaml string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
	v.Set("data-dir", t.TempDir())
	return v
}

// TestServeStopsOnASignalSentWhileStarting pins the stop path for a SIGTERM
// that arrives before the gateway has finished starting: it waits until the
// gateway is up and then shuts it down in order. runServe registered for the
// signal only after startup, so a stop sent earlier killed gatewayd with
// Go's default action ("signal: terminated") and ran no shutdown at all.
func TestServeStopsOnASignalSentWhileStarting(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer

	// A BGP-only gateway that never ran tunnels may run without
	// CAP_NET_ADMIN, where an XFRM dump fails with EPERM; it must not sweep.
	sweeps := &sweepRecorder{err: &tunnel.ErrIPsecSweepFailed{Op: "list SAs", Cause: syscall.EPERM}}

	err := serve(serveConfig(t, bgpOnlyConfig(t)), slog.New(slog.NewTextHandler(&logged, nil)), signals, sweeps.sweep)

	require.NoError(t, err)
	assert.Zero(t, sweeps.calls, "a gateway with no record of tunnels needs no privileged sweep")
	out := logged.String()
	assert.Contains(t, out, "Gateway daemon started")
	assert.Contains(t, out, `msg="Received signal, shutting down" signal=terminated`)
	assert.Contains(t, out, "Gateway daemon stopped")
}

func TestServeRefusesABadConfigWithoutStarting(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer

	sweeps := &sweepRecorder{}

	err := serve(serveConfig(t, "metrics:\n  enabled: true\n  listen: \"nonsense\"\n"), slog.New(slog.NewTextHandler(&logged, nil)), signals, sweeps.sweep)

	var listenErr *ErrMetricsListen
	require.True(t, errors.As(err, &listenErr), "got %v", err)
	assert.Len(t, signals, 1, "a refused config must not reach the wait for a stop")
	assert.NotContains(t, logged.String(), "Gateway daemon started")
	assert.Zero(t, sweeps.calls, "a refused config touches no kernel state")
}

func TestServeFailsWhenTheStaleTunnelSweepFails(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer
	cause := &tunnel.ErrIPsecSweepFailed{Op: "list SAs", Cause: syscall.EPERM}
	sweeps := &sweepRecorder{err: cause}
	v := serveConfig(t, bgpOnlyConfig(t))
	record := writeRecord(t, v.GetString("data-dir"))

	err := serve(v, slog.New(slog.NewTextHandler(&logged, nil)), signals, sweeps.sweep)

	var sweepErr *ErrStaleTunnelSweep
	require.True(t, errors.As(err, &sweepErr), "got %v", err)
	assert.ErrorIs(t, err, cause)
	assert.Len(t, signals, 1, "a failed sweep must not reach the wait for a stop")
	assert.NotContains(t, logged.String(), "Gateway daemon started")
	assert.FileExists(t, record, "the record survives a failed sweep so the next start sweeps again")
}

// TestServeSweepsWithoutAGatewaySection pins that a configuration with no
// `gateway:` section (proxy only) is a start with zero tunnels: a killed
// tunnel-enabled predecessor's record sends it through the sweep.
func TestServeSweepsWithoutAGatewaySection(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	cause := &tunnel.ErrIPsecSweepFailed{Op: "list SAs", Cause: syscall.EPERM}
	sweeps := &sweepRecorder{err: cause}
	v := serveConfig(t, "{}\n")
	record := writeRecord(t, v.GetString("data-dir"))

	err := serve(v, slog.New(slog.NewTextHandler(io.Discard, nil)), signals, sweeps.sweep)

	var sweepErr *ErrStaleTunnelSweep
	require.True(t, errors.As(err, &sweepErr), "got %v", err)
	assert.Equal(t, 1, sweeps.calls)
	assert.FileExists(t, record, "the record survives a failed sweep so the next start sweeps again")
}

// writeRecord writes the tunnels record a start with tunnels leaves under
// dataDir and returns its path.
func writeRecord(t *testing.T, dataDir string) string {
	t.Helper()
	record := filepath.Join(dataDir, gatewayTunnelsRecord)
	require.NoError(t, os.WriteFile(record, nil, 0o600))
	return record
}

func TestSweepDroppedTunnels(t *testing.T) {
	withTunnels := &gateway.GatewayConfig{Tunnels: []gateway.TunnelConfig{{Name: "gre-pri"}}}
	tests := []struct {
		name       string
		gateway    *gateway.GatewayConfig
		noDataDir  bool
		record     bool
		inventory  bool
		calls      int
		wantRecord bool
	}{
		{name: "no gateway section after tunnels ran", record: true, inventory: true, calls: 1},
		{name: "no gateway section, never ran tunnels", calls: 0},
		{name: "never ran tunnels", gateway: &gateway.GatewayConfig{}, calls: 0},
		{name: "last tunnel removed", gateway: &gateway.GatewayConfig{}, record: true, calls: 1},
		{name: "inventory outlived its record", gateway: &gateway.GatewayConfig{}, inventory: true, calls: 1},
		{name: "no data directory", gateway: &gateway.GatewayConfig{}, noDataDir: true, calls: 1},
		{name: "tunnels configured", gateway: withTunnels, calls: 0, wantRecord: true},
		{
			name:       "routing uplinks configured",
			gateway:    &gateway.GatewayConfig{RoutingUplinks: []gateway.RoutingUplinkConfig{{Name: "wan0"}}},
			calls:      0,
			wantRecord: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ServeConfig{Gateway: tt.gateway, DataDir: filepath.Join(t.TempDir(), "state")}
			if tt.noDataDir {
				cfg.DataDir = ""
			}
			if tt.record {
				require.NoError(t, os.MkdirAll(cfg.DataDir, 0o700))
				writeRecord(t, cfg.DataDir)
			}
			if tt.inventory {
				require.NoError(t, os.MkdirAll(cfg.DataDir, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(cfg.DataDir, gatewayIPsecInventory), []byte("[]"), 0o600))
			}
			sweeps := &sweepRecorder{}

			require.NoError(t, sweepDroppedTunnels(cfg, sweeps.sweep, slog.Default()))

			assert.Equal(t, tt.calls, sweeps.calls)
			if cfg.DataDir == "" {
				assert.Empty(t, sweeps.inventory, "without a data directory no ESP inventory proves a pair the platform's")
				return
			}
			if tt.calls > 0 {
				assert.Equal(t, filepath.Join(cfg.DataDir, gatewayIPsecInventory), sweeps.inventory,
					"the sweep removes only what the data directory's ESP inventory records")
			}
			_, err := os.Stat(filepath.Join(cfg.DataDir, gatewayTunnelsRecord))
			assert.Equal(t, tt.wantRecord, err == nil, "record present: %v", err)
		})
	}
}

func TestSweepDroppedTunnels_RecordUnusable(t *testing.T) {
	// A data directory that is a file can neither hold nor be searched for
	// the record, so neither branch may guess.
	dataDir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(dataDir, nil, 0o600))
	tests := []struct {
		name    string
		gateway *gateway.GatewayConfig
	}{
		{name: "recording tunnels", gateway: &gateway.GatewayConfig{Tunnels: []gateway.TunnelConfig{{Name: "gre-pri"}}}},
		{name: "checking for tunnels", gateway: &gateway.GatewayConfig{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sweeps := &sweepRecorder{}

			err := sweepDroppedTunnels(&ServeConfig{Gateway: tt.gateway, DataDir: dataDir}, sweeps.sweep, slog.Default())

			var recordErr *ErrTunnelsRecord
			require.ErrorAs(t, err, &recordErr)
			assert.Equal(t, filepath.Join(dataDir, gatewayTunnelsRecord), recordErr.Path)
			assert.Zero(t, sweeps.calls)
		})
	}
}
