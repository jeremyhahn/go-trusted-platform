package commands

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// bgpOnlyConfig is a gatewayd configuration whose one enabled service is
// the routing service's BGP speaker: it starts in-process, unprivileged, on
// a loopback port nothing holds.
func bgpOnlyConfig(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	return fmt.Sprintf("gateway:\n  enabled: true\n  id: gw-test\n  bgp:\n    asn: 64512\n    router-id: 192.0.2.1\n    listen-port: %s\n    listen-addresses: [%s]\n", port, host)
}

// useGlobalServeConfig loads yaml into the global viper runServe reads, and
// afterwards puts the global back as root.go's init left it.
func useGlobalServeConfig(t *testing.T, yaml string) {
	t.Helper()
	restore := func() {
		viper.Reset()
		require.NoError(t, viper.BindPFlags(rootCmd.PersistentFlags()))
	}
	restore()
	t.Cleanup(restore)
	sweep := serveIPsecSweep
	serveIPsecSweep = func(*slog.Logger, string) error { return nil }
	t.Cleanup(func() { serveIPsecSweep = sweep })
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(yaml)))
	viper.Set("data-dir", t.TempDir())
}

// TestRunServeTakesASIGTERMDeliveredMidStart reproduces the teardown of
// TestGatewaydSupervisorDeathLeavesTheDatapath (test/integration/proxy,
// supervisor_test.go:336 then :860): the test's probes pass before gatewayd
// has logged "Gateway daemon started", and the cleanup's real SIGTERM lands
// while gatewayd is still starting. A runServe that registered for SIGTERM
// only after startup had no handler then: gatewayd died by Go's default
// action ("signal: terminated", supervisor_test.go:870) with no shutdown.
//
// runServe's first log line is held on a full stdout pipe while the signal
// is delivered, so the signal lands inside startup on every run. The test
// registers for SIGTERM too, which keeps the test binary alive: a runServe
// that misses the signal shows here as one that never stops.
func TestRunServeTakesASIGTERMDeliveredMidStart(t *testing.T) {
	useGlobalServeConfig(t, bgpOnlyConfig(t))

	delivered := make(chan os.Signal, 1)
	signal.Notify(delivered, syscall.SIGTERM)
	defer signal.Stop(delivered)

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer func() { assert.NoError(t, reader.Close()) }()
	// Fd leaves the write end in blocking mode; filling the pipe makes the
	// next write, runServe's first log line, wait until the pipe is read.
	capacity, err := unix.FcntlInt(writer.Fd(), unix.F_GETPIPE_SZ, 0)
	require.NoError(t, err)
	_, err = writer.Write(make([]byte, capacity))
	require.NoError(t, err)

	stdout, logger := os.Stdout, slog.Default()
	os.Stdout = writer
	restore := func() {
		os.Stdout = stdout
		slog.SetDefault(logger)
	}

	done := make(chan error, 1)
	go func() { done <- runServe(serveCmd, nil) }()

	// buildServeLogger replaces the default logger just before the first
	// log line, so from then on runServe is at most at that blocked write:
	// startup has not begun.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for slog.Default() == logger {
		<-ticker.C
	}
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	<-delivered

	logged := make(chan []byte, 1)
	go func() {
		out, err := io.ReadAll(reader)
		assert.NoError(t, err)
		logged <- out
	}()

	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	var stopped bool
	select {
	case err = <-done:
		stopped = true
	case <-deadline.C:
	}
	restore()
	require.NoError(t, writer.Close())
	out := strings.TrimLeft(string(<-logged), "\x00") // drop the filler
	require.True(t, stopped, "runServe did not stop on a SIGTERM delivered while it was starting; it logged:\n%s", out)
	require.NoError(t, err)
	assert.Contains(t, out, "Gateway daemon started")
	assert.Contains(t, out, "Received signal, shutting down")
	assert.Contains(t, out, "Gateway daemon stopped")
}
