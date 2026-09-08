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

package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDaemonViper builds an isolated viper with the daemon listener
// defaults, flag bindings and env bindings installed — the same wiring
// platformd's root and serve commands install on the global instance.
func newDaemonViper(t *testing.T) (*viper.Viper, *pflag.FlagSet) {
	t.Helper()
	v := viper.New()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	SetDaemonListenerDefaults(v)
	require.NoError(t, BindDaemonListenerFlags(v, flags))
	BindDaemonListenerEnv(v, "PLATFORMD")
	return v, flags
}

func TestDefaultDaemonListeners_AreLoopback(t *testing.T) {
	d := DefaultDaemonListeners()
	for name, l := range map[string]Listener{"rest": d.REST, "grpc": d.GRPC, "quic": d.QUIC, "mcp": d.MCP} {
		assert.Equal(t, LoopbackBindHost, l.BindHost, name)
		assert.Positive(t, l.Port, name)
	}
	assert.Equal(t, "127.0.0.1:8443", d.REST.Address())
	assert.Equal(t, "127.0.0.1:10443", d.GRPC.Address())
	assert.Equal(t, "127.0.0.1:9444", d.QUIC.Address())
	assert.Equal(t, "127.0.0.1:9445", d.MCP.Address())
	require.NoError(t, d.Validate())
}

func TestDaemonListener_Address(t *testing.T) {
	cases := map[string]struct {
		l    Listener
		want string
	}{
		"ipv4":        {Listener{BindHost: "10.0.0.5", Port: 8443}, "10.0.0.5:8443"},
		"ipv6":        {Listener{BindHost: "::1", Port: 8443}, "[::1]:8443"},
		"hostname":    {Listener{BindHost: "cp.example", Port: 1}, "cp.example:1"},
		"unspecified": {Listener{BindHost: "", Port: 8443}, ":8443"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, c.want, c.l.Address())
		})
	}
}

func TestDaemonListener_Network(t *testing.T) {
	assert.Equal(t, "tcp4", Listener{BindHost: "127.0.0.1"}.Network("tcp"))
	assert.Equal(t, "tcp6", Listener{BindHost: "::1"}.Network("tcp"))
	assert.Equal(t, "udp6", Listener{BindHost: "fe80::1"}.Network("udp"))
	assert.Equal(t, "tcp", Listener{BindHost: "cp.example"}.Network("tcp"))
	assert.Equal(t, "tcp", Listener{BindHost: ""}.Network("tcp"))
}

func TestDaemonListeners_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*DaemonListeners)
		want   error
	}{
		"port zero":       {func(d *DaemonListeners) { d.REST.Port = 0 }, &ErrInvalidListenerPort{}},
		"port too large":  {func(d *DaemonListeners) { d.GRPC.Port = 70000 }, &ErrInvalidListenerPort{}},
		"host with port":  {func(d *DaemonListeners) { d.QUIC.BindHost = "127.0.0.1:1" }, &ErrInvalidBindHost{}},
		"host with space": {func(d *DaemonListeners) { d.MCP.BindHost = "bad host" }, &ErrInvalidBindHost{}},
		"bracketed ipv6":  {func(d *DaemonListeners) { d.MCP.BindHost = "[::1]" }, &ErrInvalidBindHost{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := DefaultDaemonListeners()
			c.mutate(&d)
			err := d.Validate()
			require.Error(t, err)
			switch c.want.(type) {
			case *ErrInvalidListenerPort:
				var e *ErrInvalidListenerPort
				assert.True(t, errors.As(err, &e), "got %v", err)
				assert.NotEmpty(t, e.Transport)
			case *ErrInvalidBindHost:
				var e *ErrInvalidBindHost
				assert.True(t, errors.As(err, &e), "got %v", err)
				assert.NotEmpty(t, e.Transport)
			}
		})
	}
	t.Run("unspecified host is valid", func(t *testing.T) {
		d := DefaultDaemonListeners()
		d.REST.BindHost = ""
		require.NoError(t, d.Validate())
	})
	t.Run("all interfaces is valid", func(t *testing.T) {
		d := DefaultDaemonListeners()
		d.REST.BindHost = "0.0.0.0"
		d.GRPC.BindHost = "::"
		require.NoError(t, d.Validate())
	})
}

// TestResolveDaemonListeners_Precedence is the config contract: each field
// is settable by file, env and flag, and flags > env > file > defaults.
func TestResolveDaemonListeners_Precedence(t *testing.T) {
	t.Run("defaults alone", func(t *testing.T) {
		v, _ := newDaemonViper(t)
		got, err := ResolveDaemonListeners(v)
		require.NoError(t, err)
		assert.Equal(t, DefaultDaemonListeners(), got)
	})

	t.Run("file overrides defaults", func(t *testing.T) {
		v, _ := newDaemonViper(t)
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(`
daemon:
  rest:
    bind-host: 0.0.0.0
    port: 18443
  grpc:
    bind-host: "::"
`)))
		got, err := ResolveDaemonListeners(v)
		require.NoError(t, err)
		assert.Equal(t, "0.0.0.0:18443", got.REST.Address())
		assert.Equal(t, "[::]:10443", got.GRPC.Address(), "unset port keeps the default")
		assert.Equal(t, DefaultDaemonListeners().QUIC, got.QUIC, "untouched transport keeps its defaults")
	})

	t.Run("env overrides file", func(t *testing.T) {
		v, _ := newDaemonViper(t)
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader("daemon:\n  rest:\n    bind-host: 0.0.0.0\n    port: 18443\n")))
		t.Setenv("PLATFORMD_DAEMON_REST_BIND_HOST", "10.1.1.1")
		t.Setenv("PLATFORMD_DAEMON_REST_PORT", "28443")
		t.Setenv("PLATFORMD_DAEMON_MCP_BIND_HOST", "10.1.1.2")
		got, err := ResolveDaemonListeners(v)
		require.NoError(t, err)
		assert.Equal(t, "10.1.1.1:28443", got.REST.Address())
		assert.Equal(t, "10.1.1.2:9445", got.MCP.Address())
	})

	t.Run("flag overrides env and file", func(t *testing.T) {
		v, flags := newDaemonViper(t)
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader("daemon:\n  quic:\n    bind-host: 0.0.0.0\n    port: 19444\n")))
		t.Setenv("PLATFORMD_DAEMON_QUIC_BIND_HOST", "10.1.1.1")
		t.Setenv("PLATFORMD_DAEMON_QUIC_PORT", "29444")
		require.NoError(t, flags.Parse([]string{"--quic-bind-host=10.9.9.9", "--quic-port=39444", "--grpc-port=31043"}))
		got, err := ResolveDaemonListeners(v)
		require.NoError(t, err)
		assert.Equal(t, "10.9.9.9:39444", got.QUIC.Address())
		assert.Equal(t, "127.0.0.1:31043", got.GRPC.Address(), "a flag changes only what it names")
	})

	t.Run("an unchanged flag does not shadow file or env", func(t *testing.T) {
		v, flags := newDaemonViper(t)
		require.NoError(t, flags.Parse([]string{"--rest-port=8443"}))
		t.Setenv("PLATFORMD_DAEMON_GRPC_PORT", "20443")
		got, err := ResolveDaemonListeners(v)
		require.NoError(t, err)
		assert.Equal(t, 20443, got.GRPC.Port)
	})

	t.Run("invalid resolved value is a typed error", func(t *testing.T) {
		v, _ := newDaemonViper(t)
		t.Setenv("PLATFORMD_DAEMON_REST_PORT", "0")
		_, err := ResolveDaemonListeners(v)
		var e *ErrInvalidListenerPort
		require.True(t, errors.As(err, &e), "got %v", err)
		assert.Equal(t, "rest", e.Transport)
	})
}

func TestBindDaemonListenerFlags_RegistersEveryFlag(t *testing.T) {
	v := viper.New()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	require.NoError(t, BindDaemonListenerFlags(v, flags))
	for _, name := range []string{
		"rest-bind-host", "rest-port", "grpc-bind-host", "grpc-port",
		"quic-bind-host", "quic-port", "mcp-bind-host", "mcp-port",
	} {
		assert.NotNil(t, flags.Lookup(name), name)
	}
	assert.Equal(t, "8443", flags.Lookup("rest-port").DefValue)
	assert.Equal(t, LoopbackBindHost, flags.Lookup("grpc-bind-host").DefValue)
}

func TestBindDaemonListenerFlags_RefusesDuplicateRegistration(t *testing.T) {
	v := viper.New()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	require.NoError(t, BindDaemonListenerFlags(v, flags))
	err := BindDaemonListenerFlags(v, flags)
	var e *ErrFlagAlreadyBound
	require.True(t, errors.As(err, &e), "got %v", err)
}

func TestDaemonListenerErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrInvalidListenerPort{Transport: "rest", Port: 0}).Error(), "rest")
	assert.Contains(t, (&ErrInvalidBindHost{Transport: "grpc", Host: "x y"}).Error(), "grpc")
	assert.Contains(t, (&ErrFlagAlreadyBound{Flag: "rest-port"}).Error(), "rest-port")
}
