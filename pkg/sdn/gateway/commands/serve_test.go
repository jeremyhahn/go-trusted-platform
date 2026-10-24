package commands

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	err := serve(serveConfig(t, bgpOnlyConfig(t)), slog.New(slog.NewTextHandler(&logged, nil)), signals)

	require.NoError(t, err)
	out := logged.String()
	assert.Contains(t, out, "Gateway daemon started")
	assert.Contains(t, out, `msg="Received signal, shutting down" signal=terminated`)
	assert.Contains(t, out, "Gateway daemon stopped")
}

func TestServeRefusesABadConfigWithoutStarting(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var logged bytes.Buffer

	err := serve(serveConfig(t, "metrics:\n  enabled: true\n  listen: \"nonsense\"\n"), slog.New(slog.NewTextHandler(&logged, nil)), signals)

	var listenErr *ErrMetricsListen
	require.True(t, errors.As(err, &listenErr), "got %v", err)
	assert.Len(t, signals, 1, "a refused config must not reach the wait for a stop")
	assert.NotContains(t, logged.String(), "Gateway daemon started")
}
