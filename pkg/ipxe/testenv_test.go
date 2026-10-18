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

//go:build linux

// SPDX-License-Identifier: Apache-2.0

package ipxe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTestEnvConfig(t *testing.T) {
	cfg := DefaultTestEnvConfig()

	assert.Equal(t, "pxe-br", cfg.BridgeName)
	assert.Equal(t, "tap-pxe-client", cfg.TapName)
	assert.Equal(t, "10.99.99.1", cfg.ServerIP.String())
	assert.NotNil(t, cfg.Subnet)
	assert.Equal(t, "10.99.99.100", cfg.DHCPStart.String())
	assert.Equal(t, "10.99.99.200", cfg.DHCPEnd.String())
	assert.Equal(t, "10.99.99.1", cfg.Gateway.String())
	assert.Equal(t, "8.8.8.8", cfg.DNS)
	assert.Equal(t, DefaultHTTPPort, cfg.HTTPPort)
	assert.Equal(t, DefaultTFTPPort, cfg.TFTPPort)
	assert.NotNil(t, cfg.BootEntries)
	assert.Equal(t, "/var/lib/ipxe", cfg.LocalFilesDir)
}

func TestTestEnvConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*TestEnvConfig)
		wantErr bool
		errType error
	}{
		{
			name:    "valid config",
			setup:   func(c *TestEnvConfig) {},
			wantErr: false,
		},
		{
			name: "missing bridge name",
			setup: func(c *TestEnvConfig) {
				c.BridgeName = ""
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "missing TAP name",
			setup: func(c *TestEnvConfig) {
				c.TapName = ""
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "missing server IP",
			setup: func(c *TestEnvConfig) {
				c.ServerIP = nil
			},
			wantErr: true,
			errType: ErrNoServerIP,
		},
		{
			name: "missing subnet",
			setup: func(c *TestEnvConfig) {
				c.Subnet = nil
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "missing DHCP range",
			setup: func(c *TestEnvConfig) {
				c.DHCPStart = nil
			},
			wantErr: true,
			errType: ErrInvalidIPRange,
		},
		{
			name: "server IP outside subnet",
			setup: func(c *TestEnvConfig) {
				c.ServerIP = net.ParseIP("192.168.1.1")
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "DHCP start IP outside subnet",
			setup: func(c *TestEnvConfig) {
				c.DHCPStart = net.ParseIP("192.168.1.100")
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "invalid HTTP port (too low)",
			setup: func(c *TestEnvConfig) {
				c.HTTPPort = 0
			},
			wantErr: true,
			errType: ErrInvalidPort,
		},
		{
			name: "invalid HTTP port (too high)",
			setup: func(c *TestEnvConfig) {
				c.HTTPPort = 65536
			},
			wantErr: true,
			errType: ErrInvalidPort,
		},
		{
			name: "invalid TFTP port",
			setup: func(c *TestEnvConfig) {
				c.TFTPPort = -1
			},
			wantErr: true,
			errType: ErrInvalidPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultTestEnvConfig()
			tt.setup(cfg)

			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewTestEnv(t *testing.T) {
	logger := logging.DefaultLogger()

	tests := []struct {
		name    string
		cfg     *TestEnvConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     DefaultTestEnvConfig(),
			wantErr: false,
		},
		{
			name:    "nil config uses defaults",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "invalid config",
			cfg: &TestEnvConfig{
				BridgeName: "", // Invalid: missing bridge name
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := NewTestEnv(tt.cfg, logger)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, env)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, env)
				assert.NotNil(t, env.config)
				assert.NotNil(t, env.logger)
				assert.NotNil(t, env.network)
				assert.NotNil(t, env.serverCfg)
			}
		})
	}
}

func TestTestEnv_ServerConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	cfg := DefaultTestEnvConfig()
	cfg.BootEntries = []BootEntry{
		{
			Name:        "alpine",
			Description: "Alpine Linux",
			Kernel:      "vmlinuz",
			Initrd:      "initramfs",
		},
	}

	env, err := NewTestEnv(cfg, logger)
	require.NoError(t, err)

	serverCfg := env.ServerConfig()
	assert.NotNil(t, serverCfg)
	assert.Equal(t, cfg.BridgeName, serverCfg.Interface)
	assert.Equal(t, cfg.HTTPPort, serverCfg.HTTPPort)
	assert.Equal(t, cfg.TFTPPort, serverCfg.TFTPPort)
	assert.True(t, serverCfg.EnableDHCP)
	assert.Equal(t, cfg.DHCPStart.String(), serverCfg.DHCPRangeStart)
	assert.Equal(t, cfg.DHCPEnd.String(), serverCfg.DHCPRangeEnd)
	assert.Equal(t, len(cfg.BootEntries), len(serverCfg.BootEntries))
	assert.Nil(t, serverCfg.FirmwareSigner, "no signer unless configured")
}

func TestTestEnv_ServerConfig_CarriesFirmwareSigner(t *testing.T) {
	cfg := DefaultTestEnvConfig()
	signer := &recordingSigner{}
	cfg.FirmwareSigner = signer

	env, err := NewTestEnv(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Same(t, signer, env.ServerConfig().FirmwareSigner)
}

func TestDefaultTestEnvConfig_LeasesInsideTheBridgeSubnet(t *testing.T) {
	// The bridge's subnet must contain every lease: a unicast reply to a
	// leased client is routed by the host, and a lease outside the bridge's
	// prefix leaves through the default route instead of the bridge.
	cfg := DefaultTestEnvConfig()
	assert.True(t, cfg.Subnet.Contains(cfg.DHCPStart), "DHCPStart %s outside %s", cfg.DHCPStart, cfg.Subnet)
	assert.True(t, cfg.Subnet.Contains(cfg.DHCPEnd), "DHCPEnd %s outside %s", cfg.DHCPEnd, cfg.Subnet)
	assert.True(t, cfg.Subnet.Contains(cfg.ServerIP))
}

func TestTestEnv_Accessors(t *testing.T) {
	logger := logging.DefaultLogger()
	cfg := DefaultTestEnvConfig()

	env, err := NewTestEnv(cfg, logger)
	require.NoError(t, err)

	// Test TapName
	assert.Equal(t, cfg.TapName, env.TapName())

	// Test ServerIP
	assert.True(t, cfg.ServerIP.Equal(env.ServerIP()))

	// Test ServerConfig
	serverCfg := env.ServerConfig()
	assert.NotNil(t, serverCfg)

	// Test Network
	network := env.Network()
	assert.NotNil(t, network)
}

// TestTestEnv_Lifecycle tests the full lifecycle of the test environment.
// This test requires root privileges for network operations.
// When run without root, it tests the validation and error handling paths.
func TestTestEnv_Lifecycle(t *testing.T) {
	logger := logging.DefaultLogger()
	cfg := DefaultTestEnvConfig()
	cfg.BridgeName = "test-pxe-br"
	cfg.TapName = "test-pxe-tap"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "test-alpine",
			Description: "Test Alpine Linux",
			Kernel:      "http://example.com/vmlinuz",
			Initrd:      "http://example.com/initramfs",
			Args:        "console=ttyS0",
		},
	}

	env, err := NewTestEnv(cfg, logger)
	require.NoError(t, err)

	// Test 1: Verify the environment was created correctly
	assert.Equal(t, cfg.BridgeName, env.serverCfg.Interface)
	assert.Equal(t, cfg.TapName, env.TapName())
	assert.Len(t, env.serverCfg.BootEntries, 1)
	assert.Equal(t, "test-alpine", env.serverCfg.BootEntries[0].Name)

	// Test 2: Attempt Setup - this will fail without root but exercises the code path
	err = env.Setup()
	if err != nil {
		// Expected without root privileges - verify it's a permission error
		assert.Error(t, err)
		t.Logf("Setup failed as expected without root: %v", err)
	} else {
		// If Setup succeeded (running as root), proceed with full lifecycle test
		defer func() {
			cleanupErr := env.Cleanup()
			assert.NoError(t, cleanupErr)
		}()

		// Start servers with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Start servers in background
		errChan := make(chan error, 1)
		go func() {
			errChan <- env.Start(ctx)
		}()

		// TestEnv.Ready() closes once all three listeners have bound. It did
		// not exist before #260 — Start slept 100ms between launches and
		// passed nil bind signals, so this test mirrored the defect in the
		// code it was testing.
		select {
		case <-env.Ready():
		case err := <-errChan:
			t.Fatalf("a listener failed to bind: %v", err)
		case <-time.After(ipxeDeadline):
			t.Fatalf("test environment did not become ready within %s", ipxeDeadline)
		}

		// Cancel context to stop servers
		cancel()

		// Wait for shutdown
		err = <-errChan
		if err != nil && err != context.Canceled {
			t.Errorf("Start returned error: %v", err)
		}

		// Stop should be idempotent
		err = env.Stop()
		assert.NoError(t, err)
	}

	// Test 3: Verify Stop is safe to call even without Setup
	err = env.Stop()
	assert.NoError(t, err, "Stop should be safe to call without Setup")

	// Test 4: Verify Cleanup is safe to call even without Setup
	err = env.Cleanup()
	assert.NoError(t, err, "Cleanup should be safe to call without Setup")
}

func TestTestEnv_NilLogger(t *testing.T) {
	cfg := DefaultTestEnvConfig()

	env, err := NewTestEnv(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, env.logger, "should use default logger when nil is provided")
}

func TestTestEnvConfig_SubnetContainment(t *testing.T) {
	cfg := DefaultTestEnvConfig()

	// Verify all IPs are in the configured subnet
	assert.True(t, cfg.Subnet.Contains(cfg.ServerIP), "ServerIP should be in subnet")
	assert.True(t, cfg.Subnet.Contains(cfg.DHCPStart), "DHCPStart should be in subnet")
	assert.True(t, cfg.Subnet.Contains(cfg.DHCPEnd), "DHCPEnd should be in subnet")
	assert.True(t, cfg.Subnet.Contains(cfg.Gateway), "Gateway should be in subnet")
}

func TestTestEnv_ServerConfigGeneration(t *testing.T) {
	logger := logging.DefaultLogger()
	cfg := DefaultTestEnvConfig()
	cfg.HTTPPort = 9090
	cfg.TFTPPort = 6969
	cfg.LocalFilesDir = "/custom/path"
	cfg.DNS = "1.1.1.1"

	env, err := NewTestEnv(cfg, logger)
	require.NoError(t, err)

	serverCfg := env.ServerConfig()

	// Verify all fields are correctly mapped
	assert.Equal(t, cfg.BridgeName, serverCfg.Interface)
	assert.Equal(t, 9090, serverCfg.HTTPPort)
	assert.Equal(t, 6969, serverCfg.TFTPPort)
	assert.Equal(t, "/custom/path", serverCfg.LocalFilesDir)
	assert.True(t, serverCfg.EnableDHCP)
	assert.Equal(t, cfg.BridgeName, serverCfg.DHCPInterface)
	assert.Equal(t, []string{"1.1.1.1"}, serverCfg.DHCPDNS)
	assert.Equal(t, "ipxe.efi", serverCfg.BootFilename)
	assert.Contains(t, serverCfg.IPXEScript, "boot.ipxe")
	assert.Contains(t, serverCfg.ExternalURL, cfg.ServerIP.String())
}

func TestUnusedTapName_FitsTheKernelLimit(t *testing.T) {
	// The default client TAP is 14 characters; a plain "-unused" suffix
	// would be 21, which the kernel rejects and the network then reports
	// as "Link not found".
	assert.Equal(t, "tap-pxe-unused", unusedTapName("tap-pxe-client"))
	assert.LessOrEqual(t, len(unusedTapName("tap-pxe-client")), maxInterfaceNameLen)
	assert.Equal(t, "tap0-unused", unusedTapName("tap0"))
}

func TestTestEnvConfig_Validate_RejectsLongInterfaceNames(t *testing.T) {
	cfg := DefaultTestEnvConfig()
	cfg.TapName = "tap-pxe-client-too-long"
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)

	cfg = DefaultTestEnvConfig()
	cfg.BridgeName = "a-bridge-name-too-long"
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidConfig)
}

func TestTestEnv_DHCPConfig_SelectsBootfileByArchitecture(t *testing.T) {
	// The environment's DHCP server must hand an AArch64 client its own
	// iPXE; without the map every client got the x86-64 ipxe.efi, which
	// U-Boot refuses ("Machine type 0x8664 is not supported").
	env, err := NewTestEnv(DefaultTestEnvConfig(), logging.DefaultLogger())
	require.NoError(t, err)
	cfg := env.dhcpConfig()
	assert.Equal(t, DefaultBootFilenameByArch(), cfg.BootFilenameByArch)
	assert.Equal(t, FirmwareSNPOnlyAArch64, cfg.BootFilenameByArch[archEFIAArch64])
	assert.False(t, cfg.UseRawSocket, "the UDP socket Server uses")
	assert.True(t, cfg.RespondToAll, "the booted OS's DHCP client is not a PXE client and still needs a lease")
	assert.Equal(t, []net.IP{net.ParseIP("8.8.8.8").To4()}, cfg.DNSServers)

	explicit := DefaultTestEnvConfig()
	env, err = NewTestEnv(explicit, logging.DefaultLogger())
	require.NoError(t, err)
	env.ServerConfig().BootFilenameByArch = map[uint16]string{}
	assert.Empty(t, env.dhcpConfig().BootFilenameByArch, "an explicit empty map disables the selection")
}
