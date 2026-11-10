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

package webservice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// TestWebServerV1_Listener_DefaultIsUnspecified pins the webservice's
// defaults layer (#552): with no bind-host it listens on every interface
// and every family, on both the plaintext and the TLS port.
func TestWebServerV1_Listener_DefaultIsUnspecified(t *testing.T) {
	server := &WebServerV1{config: &v1.Config{Port: 8080, TLSPort: 8443}}

	web := server.listener(server.config.Port)
	assert.Equal(t, ":8080", web.Address())
	assert.Equal(t, "tcp", web.Network("tcp"))

	tlsL := server.listener(server.config.TLSPort)
	assert.Equal(t, ":8443", tlsL.Address())
	assert.Equal(t, "udp", tlsL.Network("udp"))
}

// TestWebServerV1_Listener_BindHostPinsTheFamily proves the configured
// bind-host reaches the listener verbatim and selects its address family.
func TestWebServerV1_Listener_BindHostPinsTheFamily(t *testing.T) {
	cases := map[string]struct {
		host     string
		wantAddr string
		wantTCP  string
		wantUDP  string
	}{
		"ipv4 literal": {"198.51.100.140", "198.51.100.140:8443", "tcp4", "udp4"},
		"ipv6 literal": {"fd00::1", "[fd00::1]:8443", "tcp6", "udp6"},
		"hostname":     {"cp.platform.internal", "cp.platform.internal:8443", "tcp", "udp"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := &WebServerV1{config: &v1.Config{BindHost: c.host, TLSPort: 8443}}
			l := server.listener(server.config.TLSPort)
			assert.Equal(t, c.wantAddr, l.Address())
			assert.Equal(t, c.wantTCP, l.Network("tcp"))
			assert.Equal(t, c.wantUDP, l.Network("udp"))
		})
	}
}

// TestWebServerV1_Listener_BindsWhatItResolved opens a real socket on the
// loopback address the config names, port 0, and checks the kernel gave
// back the same host — the resolved value is what is bound, not a literal.
func TestWebServerV1_Listener_BindsWhatItResolved(t *testing.T) {
	server := &WebServerV1{config: &v1.Config{BindHost: "127.0.0.1", Port: 0}}
	l := server.listener(server.config.Port)
	ln, err := net.Listen(l.Network("tcp"), l.Address())
	require.NoError(t, err)
	defer ln.Close()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
}
