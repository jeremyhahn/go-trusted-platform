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

package ipxe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// otherLoopback is a second loopback address. Linux routes all of
// 127.0.0.0/8 to lo, so it binds without any host configuration. A bind
// on it at a server's port succeeds only when the server holds one
// address, not the unspecified one: that is how these tests tell a
// configured bind host from every interface.
const otherLoopback = "127.0.0.2"

// unassignedHost is a TEST-NET-1 address (RFC 5737) no host holds, so
// binding it fails with EADDRNOTAVAIL.
const unassignedHost = "192.0.2.1"

func TestServerConfig_ListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		bindHost string
		want     string
	}{
		{name: "default is every interface", bindHost: DefaultBindHost, want: ":8080"},
		{name: "IPv4 host", bindHost: "192.0.2.1", want: "192.0.2.1:8080"},
		{name: "IPv6 host", bindHost: "fd00::1", want: "[fd00::1]:8080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ServerConfig{BindHost: tc.bindHost}
			assert.Equal(t, tc.want, cfg.listenAddr(8080))
		})
	}
}

func TestDefaultServerConfig_BindHost(t *testing.T) {
	assert.Equal(t, DefaultBindHost, DefaultServerConfig().BindHost)
}

func TestServerConfig_Validate_BindHost(t *testing.T) {
	tests := []struct {
		name     string
		bindHost string
		wantErr  bool
	}{
		{name: "empty", bindHost: "", wantErr: false},
		{name: "IPv4", bindHost: "192.0.2.1", wantErr: false},
		{name: "IPv6", bindHost: "fd00::1", wantErr: false},
		{name: "unspecified", bindHost: "0.0.0.0", wantErr: false},
		{name: "hostname", bindHost: "pxe.example.com", wantErr: true},
		{name: "truncated address", bindHost: "10.4.5", wantErr: true},
		{name: "host and port", bindHost: "192.0.2.1:8080", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.BindHost = tc.bindHost
			cfg.BootEntries = []BootEntry{{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"}}

			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidBindHost), "got %v", err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestServerConfig_GetServerIP_BindHost(t *testing.T) {
	t.Run("a specific bind host is the server IP", func(t *testing.T) {
		cfg := &ServerConfig{BindHost: "192.0.2.1"}
		ip, err := cfg.GetServerIP()
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", ip)
	})

	t.Run("an explicit DHCP server IP wins over the bind host", func(t *testing.T) {
		cfg := &ServerConfig{BindHost: "192.0.2.1", DHCPServerIP: "192.0.2.2"}
		ip, err := cfg.GetServerIP()
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", ip)
	})

	t.Run("the unspecified address falls through to the interface", func(t *testing.T) {
		cfg := &ServerConfig{BindHost: "0.0.0.0", Interface: "no-such-iface0"}
		_, err := cfg.GetServerIP()
		assert.Error(t, err)
	})
}

// startHTTPServer starts an HTTP server on cfg and returns once it is
// bound, or returns the Start error when the bind fails.
func startHTTPServer(t *testing.T, cfg *ServerConfig) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	server := NewHTTPServer(cfg, logging.DefaultLogger())
	bound := newBoundSignal()
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx, bound) }()

	select {
	case <-bound:
	case err := <-errCh:
		cancel()
		return err
	}
	t.Cleanup(func() {
		cancel()
		<-errCh
	})
	return nil
}

// startTFTPServer is startHTTPServer for the TFTP server, with the
// required firmware preloaded and downloads forbidden.
func startTFTPServer(t *testing.T, cfg *ServerConfig) error {
	t.Helper()
	cfg.FirmwareDir = t.TempDir()
	cfg.FirmwareOffline = true
	server := NewTFTPServer(cfg, net.ParseIP("127.0.0.1"), logging.DefaultLogger())
	server.firmwareMu.Lock()
	server.firmware["ipxe.efi"] = []byte("test firmware")
	server.firmwareMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	bound := newBoundSignal()
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx, bound) }()

	select {
	case <-bound:
	case err := <-errCh:
		cancel()
		return err
	}
	t.Cleanup(func() {
		cancel()
		<-errCh
	})
	return nil
}

func TestHTTPServer_BindsBindHost(t *testing.T) {
	tests := []struct {
		name          string
		bindHost      string
		otherBindFree bool
	}{
		{name: "configured host only", bindHost: "127.0.0.1", otherBindFree: true},
		{name: "default holds every interface", bindHost: DefaultBindHost, otherBindFree: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := freeTCPPort(t)
			cfg := DefaultServerConfig()
			cfg.BindHost = tc.bindHost
			cfg.HTTPPort = port
			require.NoError(t, startHTTPServer(t, cfg))

			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			require.NoError(t, err, "the server answers on 127.0.0.1")
			require.NoError(t, conn.Close())

			other, err := net.Listen("tcp", net.JoinHostPort(otherLoopback, strconv.Itoa(port)))
			if tc.otherBindFree {
				require.NoError(t, err, "a server bound to %s must leave %s free", tc.bindHost, otherLoopback)
				require.NoError(t, other.Close())
				return
			}
			require.Error(t, err, "a server on every interface holds %s too", otherLoopback)
		})
	}
}

func TestHTTPServer_BindHostNotOnHost(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BindHost = unassignedHost
	cfg.HTTPPort = freeTCPPort(t)
	assert.Error(t, startHTTPServer(t, cfg), "binding an address the host does not hold must fail")
}

func TestTFTPServer_BindsBindHost(t *testing.T) {
	tests := []struct {
		name          string
		bindHost      string
		otherBindFree bool
	}{
		{name: "configured host only", bindHost: "127.0.0.1", otherBindFree: true},
		{name: "default holds every interface", bindHost: DefaultBindHost, otherBindFree: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := freeUDPPort(t)
			cfg := &ServerConfig{BindHost: tc.bindHost, TFTPPort: port}
			require.NoError(t, startTFTPServer(t, cfg))

			other, err := net.ListenPacket("udp", net.JoinHostPort(otherLoopback, strconv.Itoa(port)))
			if tc.otherBindFree {
				require.NoError(t, err, "a server bound to %s must leave %s free", tc.bindHost, otherLoopback)
				require.NoError(t, other.Close())
				return
			}
			require.Error(t, err, "a server on every interface holds %s too", otherLoopback)
		})
	}
}

func TestTFTPServer_BindHostNotOnHost(t *testing.T) {
	cfg := &ServerConfig{BindHost: unassignedHost, TFTPPort: freeUDPPort(t)}
	assert.Error(t, startTFTPServer(t, cfg), "binding an address the host does not hold must fail")
}
