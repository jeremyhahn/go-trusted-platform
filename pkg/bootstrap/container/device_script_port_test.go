// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"testing"
)

// TestServerConfig_ApplyDefaults_DeviceScriptPortDerivesFromHTTP pins the
// default. Before the port was configurable the device-script listener
// was hardcoded to HTTPPort+1, so the default has to keep deriving from
// HTTPPort rather than settle on a flat 8081 — otherwise moving the HTTP
// port would silently leave this listener behind on the old offset.
func TestServerConfig_ApplyDefaults_DeviceScriptPortDerivesFromHTTP(t *testing.T) {
	cases := []struct {
		name     string
		httpPort int
		want     int
	}{
		{"default http port", 0, DefaultHTTPPort + DeviceScriptPortOffset},
		{"moved http port carries it along", 9000, 9001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &ServerConfig{HTTPPort: tc.httpPort}
			c.ApplyDefaults()
			if c.DeviceScriptPort != tc.want {
				t.Fatalf("DeviceScriptPort = %d, want %d", c.DeviceScriptPort, tc.want)
			}
		})
	}
}

// TestServerConfig_ApplyDefaults_DeviceScriptPortOverrideHonoured is the
// whole point of the change: an operator whose deployer already has
// something on the derived port must be able to move this listener
// without moving the HTTP port too.
func TestServerConfig_ApplyDefaults_DeviceScriptPortOverrideHonoured(t *testing.T) {
	c := &ServerConfig{HTTPPort: 8080, DeviceScriptPort: 18081}
	c.ApplyDefaults()
	if c.DeviceScriptPort != 18081 {
		t.Fatalf("DeviceScriptPort = %d, want the configured 18081", c.DeviceScriptPort)
	}
	if c.HTTPPort != 8080 {
		t.Fatalf("HTTPPort = %d, want 8080 — moving one port must not move the other", c.HTTPPort)
	}
}

func validServerConfig() *ServerConfig {
	return &ServerConfig{
		ManifestPath: "/data/manifest.yaml",
		MediaDir:     "/data/media",
		DHCPConfig: DHCPConfig{
			ServerIP:   "198.51.100.91",
			RangeStart: "198.51.100.100",
			RangeEnd:   "198.51.100.200",
			SubnetMask: "255.255.255.0",
		},
	}
}

// TestServerConfig_Validate_DeviceScriptPortRange covers the bounds.
func TestServerConfig_Validate_DeviceScriptPortRange(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		c := validServerConfig()
		c.DeviceScriptPort = port
		var invalid ErrInvalidServerConfig
		err := c.Validate()
		if !errors.As(err, &invalid) || invalid.Field != "device_script_port" {
			t.Fatalf("Validate(port=%d) = %v, want ErrInvalidServerConfig{device_script_port}", port, err)
		}
	}
}

// TestServerConfig_Validate_DeviceScriptPortCollision refuses a config
// that points both listeners at one port. Left to bind time this shows
// up as the server reporting "address already in use" against itself,
// with nothing naming the actual mistake.
func TestServerConfig_Validate_DeviceScriptPortCollision(t *testing.T) {
	c := validServerConfig()
	c.HTTPPort = 8080
	c.DeviceScriptPort = 8080

	var invalid ErrInvalidServerConfig
	err := c.Validate()
	if !errors.As(err, &invalid) || invalid.Field != "device_script_port" {
		t.Fatalf("Validate = %v, want ErrInvalidServerConfig{device_script_port}", err)
	}
}

// TestServerConfig_Validate_DeviceScriptPortAcceptsDistinct keeps the
// collision check from rejecting ordinary configurations.
func TestServerConfig_Validate_DeviceScriptPortAcceptsDistinct(t *testing.T) {
	c := validServerConfig()
	c.HTTPPort = 8080
	c.DeviceScriptPort = 18081
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

// TestServer_DeviceScriptAddr asserts the address the listener binds,
// without binding it. The failure this change exists to fix IS the bind,
// so a test that has to bind in order to observe the address cannot
// cover the case that matters.
func TestServer_DeviceScriptAddr(t *testing.T) {
	cases := []struct {
		name     string
		httpPort int
		devPort  int
		serverIP string
		wantAddr string
	}{
		{"derived default", 8080, 0, "198.51.100.91", "198.51.100.91:8081"},
		{"explicit override", 8080, 18081, "198.51.100.91", "198.51.100.91:18081"},
		{"derived from a moved http port", 9000, 0, "10.0.0.1", "10.0.0.1:9001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &ServerConfig{
				HTTPPort:         tc.httpPort,
				DeviceScriptPort: tc.devPort,
				DHCPConfig:       DHCPConfig{ServerIP: tc.serverIP},
			}}
			if got := s.deviceScriptAddr(); got != tc.wantAddr {
				t.Fatalf("deviceScriptAddr() = %q, want %q", got, tc.wantAddr)
			}
		})
	}
}
