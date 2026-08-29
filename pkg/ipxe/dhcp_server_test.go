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
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPacketConn implements net.PacketConn for testing.
type mockPacketConn struct {
	writtenData []byte
	writtenAddr net.Addr
	writeErr    error
	closed      bool
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writtenData = make([]byte, len(p))
	copy(m.writtenData, p)
	m.writtenAddr = addr
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 67}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// mockPacketConnFactory implements PacketConnFactory for testing.
type mockPacketConnFactory struct {
	conn    net.PacketConn
	err     error
	called  bool
	iface   string
	ip      net.IP
	rawSock bool
}

func (f *mockPacketConnFactory) CreateConn(iface string, serverIP net.IP, useRawSocket bool) (net.PacketConn, error) {
	f.called = true
	f.iface = iface
	f.ip = serverIP
	f.rawSock = useRawSocket
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

// TestNewDHCPServer_ConnFactory tests that connection factory is properly initialized.
func TestNewDHCPServer_ConnFactory(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.200"),
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())

	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.connFactory, "connFactory should be initialized")

	// Verify it's the default factory
	_, ok := server.connFactory.(*DefaultPacketConnFactory)
	assert.True(t, ok, "connFactory should be DefaultPacketConnFactory")
}

// TestDHCPServer_SetConnFactory tests setting a custom connection factory.
func TestDHCPServer_SetConnFactory(t *testing.T) {
	server := createTestDHCPServer(t)

	mockFactory := &mockPacketConnFactory{}
	server.SetConnFactory(mockFactory)

	assert.Equal(t, mockFactory, server.connFactory)
}

// TestDHCPServer_Start tests the DHCP server Start method.
func TestDHCPServer_Start(t *testing.T) {
	t.Run("returns error when connection factory fails", func(t *testing.T) {
		server := createTestDHCPServer(t)

		mockFactory := &mockPacketConnFactory{
			err: errors.New("failed to create connection"),
		}
		server.SetConnFactory(mockFactory)

		ctx := context.Background()
		err := server.Start(ctx, nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create connection")
		assert.True(t, mockFactory.called)
	})

	t.Run("passes correct parameters to connection factory", func(t *testing.T) {
		config := &DHCPConfig{
			Interface:    "eth0",
			ServerIP:     net.ParseIP("10.0.0.1"),
			RangeStart:   net.ParseIP("10.0.0.100"),
			RangeEnd:     net.ParseIP("10.0.0.200"),
			UseRawSocket: true,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mockFactory := &mockPacketConnFactory{
			err: errors.New("expected failure"),
		}
		server.SetConnFactory(mockFactory)

		ctx := context.Background()
		_ = server.Start(ctx, nil)

		assert.True(t, mockFactory.called)
		assert.Equal(t, "eth0", mockFactory.iface)
		assert.True(t, mockFactory.ip.Equal(net.ParseIP("10.0.0.1")))
		assert.True(t, mockFactory.rawSock)
	})

	t.Run("shuts down on context cancellation", func(t *testing.T) {
		server := createTestDHCPServer(t)

		mockConn := &mockPacketConn{}
		mockFactory := &mockPacketConnFactory{
			conn: mockConn,
		}
		server.SetConnFactory(mockFactory)

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- server.Start(ctx, nil)
		}()

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		// Cancel context to trigger shutdown
		cancel()

		// Wait for server to shut down
		select {
		case err := <-done:
			// Should complete without error (context cancellation is normal)
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down in time")
		}

		assert.True(t, mockConn.closed, "connection should be closed on shutdown")
	})
}

// TestDefaultPacketConnFactory tests the default connection factory.
func TestDefaultPacketConnFactory(t *testing.T) {
	t.Run("creates instance", func(t *testing.T) {
		factory := &DefaultPacketConnFactory{}
		assert.NotNil(t, factory)
	})

	// Note: We can't test CreateConn with real sockets in unit tests
	// because it requires root access. The integration tests cover this.
}

// TestNewDHCPServer_Success tests successful creation of DHCP server.
func TestNewDHCPServer_Success(t *testing.T) {
	tests := []struct {
		name   string
		config *DHCPConfig
	}{
		{
			name: "minimal valid config",
			config: &DHCPConfig{
				ServerIP:   net.ParseIP("192.168.1.1"),
				RangeStart: net.ParseIP("192.168.1.100"),
				RangeEnd:   net.ParseIP("192.168.1.200"),
			},
		},
		{
			name: "full config",
			config: &DHCPConfig{
				Interface:      "eth0",
				ServerIP:       net.ParseIP("10.0.0.1"),
				BroadcastIP:    net.ParseIP("10.0.0.255"),
				SubnetMask:     net.ParseIP("255.255.255.0"),
				RangeStart:     net.ParseIP("10.0.0.50"),
				RangeEnd:       net.ParseIP("10.0.0.100"),
				LeaseTime:      2 * time.Hour,
				Router:         net.ParseIP("10.0.0.1"),
				DNSServers:     []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
				TFTPServerName: "pxeserver",
				TFTPServerIP:   net.ParseIP("10.0.0.1"),
				BootFilename:   "ipxe.efi",
				IPXEScript:     "http://10.0.0.1:8080/boot.ipxe",
			},
		},
		{
			name: "config with default lease time",
			config: &DHCPConfig{
				ServerIP:   net.ParseIP("172.16.0.1"),
				RangeStart: net.ParseIP("172.16.0.10"),
				RangeEnd:   net.ParseIP("172.16.0.50"),
				LeaseTime:  0, // Should default to DefaultLeaseTime
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			server, err := NewDHCPServer(tt.config, logger)

			require.NoError(t, err)
			require.NotNil(t, server)
			assert.Equal(t, tt.config.ServerIP, server.serverIP)
			assert.NotNil(t, server.leases)
			assert.Equal(t, tt.config.RangeStart, server.nextIP)

			// Verify default lease time is applied when not set
			if tt.config.LeaseTime == 0 {
				assert.Equal(t, DefaultLeaseTime, server.config.LeaseTime)
			}
		})
	}
}

// TestNewDHCPServer_NilLogger tests that nil logger defaults to default logger.
func TestNewDHCPServer_NilLogger(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.200"),
	}

	server, err := NewDHCPServer(config, nil)

	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.logger)
}

// TestNewDHCPServer_BroadcastIPCalculation tests automatic broadcast IP calculation.
func TestNewDHCPServer_BroadcastIPCalculation(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		SubnetMask: net.ParseIP("255.255.255.0"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.200"),
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())

	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, net.ParseIP("192.168.1.255").To4(), server.broadcastIP.To4())
}

// TestNewDHCPServer_Errors tests error cases for DHCP server creation.
func TestNewDHCPServer_Errors(t *testing.T) {
	tests := []struct {
		name        string
		config      *DHCPConfig
		expectedErr error
	}{
		{
			name:        "nil config",
			config:      nil,
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "missing server IP",
			config: &DHCPConfig{
				ServerIP:   nil,
				RangeStart: net.ParseIP("192.168.1.100"),
				RangeEnd:   net.ParseIP("192.168.1.200"),
			},
			expectedErr: ErrNoServerIP,
		},
		{
			name: "missing range start",
			config: &DHCPConfig{
				ServerIP:   net.ParseIP("192.168.1.1"),
				RangeStart: nil,
				RangeEnd:   net.ParseIP("192.168.1.200"),
			},
			expectedErr: ErrInvalidIPRange,
		},
		{
			name: "missing range end",
			config: &DHCPConfig{
				ServerIP:   net.ParseIP("192.168.1.1"),
				RangeStart: net.ParseIP("192.168.1.100"),
				RangeEnd:   nil,
			},
			expectedErr: ErrInvalidIPRange,
		},
		{
			name: "missing both range start and end",
			config: &DHCPConfig{
				ServerIP:   net.ParseIP("192.168.1.1"),
				RangeStart: nil,
				RangeEnd:   nil,
			},
			expectedErr: ErrInvalidIPRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewDHCPServer(tt.config, logging.DefaultLogger())

			assert.Nil(t, server)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.expectedErr),
				"expected error %v, got %v", tt.expectedErr, err)
		})
	}
}

// TestDHCPServer_IsPXEClient tests PXE client detection.
func TestDHCPServer_IsPXEClient(t *testing.T) {
	server := createTestDHCPServer(t)

	tests := []struct {
		name     string
		setupReq func(*dhcpv4.DHCPv4)
		expected bool
	}{
		{
			name: "PXEClient vendor class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00000:UNDI:002001"))
			},
			expected: true,
		},
		{
			name: "PXEClient vendor class exact",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
			},
			expected: true,
		},
		{
			name: "client system architecture option",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// Option 93 - Client System Architecture Type
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x07}))
			},
			expected: true,
		},
		{
			name: "non-PXE client no options",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// No PXE-related options
			},
			expected: false,
		},
		{
			name: "non-PXE client different vendor class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("MSFT 5.0"))
			},
			expected: false,
		},
		{
			name: "short vendor class not matching",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("PXE"))
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createBaseDHCPRequest(t)
			tt.setupReq(req)

			result := server.isPXEClient(req)

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDHCPServer_IsIPXEClient tests iPXE client detection.
func TestDHCPServer_IsIPXEClient(t *testing.T) {
	server := createTestDHCPServer(t)

	tests := []struct {
		name     string
		setupReq func(*dhcpv4.DHCPv4)
		expected bool
	}{
		{
			name: "iPXE user class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionUserClassInformation, []byte("iPXE")))
			},
			expected: true,
		},
		{
			name: "iPXE vendor class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("iPXE"))
			},
			expected: true,
		},
		{
			name: "PXEClient not iPXE",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00000:UNDI:002001"))
			},
			expected: false,
		},
		{
			name: "no user class or vendor class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// No iPXE-related options
			},
			expected: false,
		},
		{
			name: "different user class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionUserClassInformation, []byte("SomeOtherClient")))
			},
			expected: false,
		},
		{
			name: "empty user class",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionUserClassInformation, []byte{}))
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createBaseDHCPRequest(t)
			tt.setupReq(req)

			result := server.isIPXEClient(req)

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDHCPServer_GetClientArch tests client architecture extraction.
func TestDHCPServer_GetClientArch(t *testing.T) {
	server := createTestDHCPServer(t)

	tests := []struct {
		name     string
		setupReq func(*dhcpv4.DHCPv4)
		expected uint16
	}{
		{
			name: "EFI x64 architecture",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// Option 93 with value 0x0007 (EFI x64)
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x07}))
			},
			expected: archEFIx64,
		},
		{
			name: "EFI x86 architecture",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x06}))
			},
			expected: archEFIx86,
		},
		{
			name: "BIOS x86 architecture",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x00}))
			},
			expected: archBIOSx86,
		},
		{
			name: "EFI BC architecture",
			setupReq: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x09}))
			},
			expected: archEFIBC,
		},
		{
			name: "no architecture option defaults to BIOS",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// No option 93
			},
			expected: archBIOSx86,
		},
		{
			name: "short architecture option defaults to BIOS",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// Only 1 byte instead of 2
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x07}))
			},
			expected: archBIOSx86,
		},
		{
			name: "high byte non-zero",
			setupReq: func(req *dhcpv4.DHCPv4) {
				// High byte 0x01, low byte 0x00 = 256
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x01, 0x00}))
			},
			expected: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createBaseDHCPRequest(t)
			tt.setupReq(req)

			result := server.getClientArch(req)

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDHCPServer_GetOrAssignIP tests IP assignment logic.
func TestDHCPServer_GetOrAssignIP(t *testing.T) {
	t.Run("assigns new IP to new MAC", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		ip, err := server.getOrAssignIP(mac)

		require.NoError(t, err)
		assert.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})

	t.Run("reuses existing valid lease", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First assignment
		ip1, err := server.getOrAssignIP(mac)
		require.NoError(t, err)

		// Second assignment should return same IP
		ip2, err := server.getOrAssignIP(mac)
		require.NoError(t, err)
		assert.True(t, ip1.Equal(ip2))
	})

	t.Run("reassigns IP after lease expiration", func(t *testing.T) {
		server := createTestDHCPServer(t)
		server.config.LeaseTime = 1 * time.Millisecond // Very short lease
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First assignment
		_, err := server.getOrAssignIP(mac)
		require.NoError(t, err)

		// Wait for lease to expire
		time.Sleep(5 * time.Millisecond)

		// Should get a new IP (or same IP if pool allows)
		ip2, err := server.getOrAssignIP(mac)
		require.NoError(t, err)
		assert.NotNil(t, ip2)
	})

	t.Run("assigns different IPs to different MACs", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")

		ip1, err := server.getOrAssignIP(mac1)
		require.NoError(t, err)

		ip2, err := server.getOrAssignIP(mac2)
		require.NoError(t, err)

		assert.False(t, ip1.Equal(ip2), "different MACs should get different IPs")
	})

	t.Run("returns error when no IPs available", func(t *testing.T) {
		// Create server with only 1 IP in range
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.100"), // Only 1 IP
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")

		// First assignment should succeed
		_, err = server.getOrAssignIP(mac1)
		require.NoError(t, err)

		// Second assignment should fail (no IPs left)
		_, err = server.getOrAssignIP(mac2)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoAvailableIPs))
	})
}

// TestDHCPServer_ConfirmLease tests lease confirmation logic.
func TestDHCPServer_ConfirmLease(t *testing.T) {
	t.Run("confirms existing lease", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First get an IP
		ip1, err := server.getOrAssignIP(mac)
		require.NoError(t, err)

		// Confirm the lease
		ip2, err := server.confirmLease(mac, ip1)
		require.NoError(t, err)
		assert.True(t, ip1.Equal(ip2))
	})

	t.Run("extends lease expiration on confirmation", func(t *testing.T) {
		server := createTestDHCPServer(t)
		server.config.LeaseTime = time.Hour
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// Get initial IP
		_, err := server.getOrAssignIP(mac)
		require.NoError(t, err)

		server.mu.RLock()
		initialExpiry := server.leases[mac.String()].ExpiresAt
		server.mu.RUnlock()

		// Wait a bit
		time.Sleep(10 * time.Millisecond)

		// Confirm lease
		_, err = server.confirmLease(mac, nil)
		require.NoError(t, err)

		server.mu.RLock()
		newExpiry := server.leases[mac.String()].ExpiresAt
		server.mu.RUnlock()

		assert.True(t, newExpiry.After(initialExpiry))
	})

	t.Run("creates new lease when none exists", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		requestedIP := net.ParseIP("192.168.1.150")

		ip, err := server.confirmLease(mac, requestedIP)
		require.NoError(t, err)
		assert.NotNil(t, ip)
	})

	t.Run("returns error when no IPs available for new lease", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.100"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")

		// Take the only available IP
		_, err = server.getOrAssignIP(mac1)
		require.NoError(t, err)

		// Try to confirm lease for new MAC
		_, err = server.confirmLease(mac2, nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoAvailableIPs))
	})
}

// TestDHCPServer_FindAvailableIP tests IP finding logic.
func TestDHCPServer_FindAvailableIP(t *testing.T) {
	t.Run("finds first available IP", func(t *testing.T) {
		server := createTestDHCPServer(t)

		ip := server.findAvailableIP()

		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})

	t.Run("skips in-use IPs", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")

		// Take first IP
		_, err := server.getOrAssignIP(mac1)
		require.NoError(t, err)

		// Next available should be .101
		ip := server.findAvailableIP()
		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.101")))
	})

	t.Run("wraps nextIP pointer after reaching range end", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.102"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		// Allocate all IPs: .100, .101, .102
		mac1, _ := net.ParseMAC("00:11:22:33:44:51")
		mac2, _ := net.ParseMAC("00:11:22:33:44:52")
		mac3, _ := net.ParseMAC("00:11:22:33:44:53")

		_, err = server.getOrAssignIP(mac1)
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac2)
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac3)
		require.NoError(t, err)

		// After allocating .102, nextIP should wrap to .100
		server.mu.RLock()
		nextIP := server.nextIP
		server.mu.RUnlock()

		assert.True(t, nextIP.Equal(net.ParseIP("192.168.1.100")),
			"nextIP should wrap to range start, got %s", nextIP)
	})

	t.Run("wraps around to beginning of range when searching", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.102"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		// Allocate .100, .101, .102
		mac1, _ := net.ParseMAC("00:11:22:33:44:51")
		mac2, _ := net.ParseMAC("00:11:22:33:44:52")
		mac3, _ := net.ParseMAC("00:11:22:33:44:53")

		_, err = server.getOrAssignIP(mac1)
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac2)
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac3)
		require.NoError(t, err)

		// Now expire the first lease (.100)
		server.mu.Lock()
		server.leases[mac1.String()].ExpiresAt = time.Now().Add(-time.Hour)
		server.mu.Unlock()

		// Should find .100 via wrap-around
		ip := server.findAvailableIP()
		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})

	t.Run("finds IP in second half via wrap-around loop", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.103"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		// Allocate .100, .101
		mac1, _ := net.ParseMAC("00:11:22:33:44:51")
		mac2, _ := net.ParseMAC("00:11:22:33:44:52")

		_, err = server.getOrAssignIP(mac1) // Gets .100
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac2) // Gets .101
		require.NoError(t, err)

		// Now manually set nextIP to .103 (end of range)
		server.mu.Lock()
		server.nextIP = net.ParseIP("192.168.1.103").To4()
		server.mu.Unlock()

		// Allocate .103
		mac3, _ := net.ParseMAC("00:11:22:33:44:53")
		_, err = server.getOrAssignIP(mac3) // Gets .103
		require.NoError(t, err)

		// Now expire .100 and try to find - should use wrap-around loop
		server.mu.Lock()
		server.leases[mac1.String()].ExpiresAt = time.Now().Add(-time.Hour)
		server.mu.Unlock()

		// findAvailableIP should wrap around and find .100
		ip := server.findAvailableIP()
		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")),
			"expected 192.168.1.100, got %s", ip)
	})

	t.Run("returns nil when all IPs are in use", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.101"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")

		_, err = server.getOrAssignIP(mac1)
		require.NoError(t, err)
		_, err = server.getOrAssignIP(mac2)
		require.NoError(t, err)

		// No IPs left
		ip := server.findAvailableIP()
		assert.Nil(t, ip)
	})

	t.Run("skips expired leases in first loop", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.102"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mac1, _ := net.ParseMAC("00:11:22:33:44:51")
		_, err = server.getOrAssignIP(mac1) // Gets .100
		require.NoError(t, err)

		// Expire the lease
		server.mu.Lock()
		server.leases[mac1.String()].ExpiresAt = time.Now().Add(-time.Hour)
		// Reset nextIP to .100 to test first loop expired check
		server.nextIP = net.ParseIP("192.168.1.100").To4()
		server.mu.Unlock()

		// Should reuse .100 since lease is expired
		ip := server.findAvailableIP()
		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})
}

// TestDHCPServer_FindAvailableIP_WrapAroundLoop tests the wrap-around loop (lines 496-516).
func TestDHCPServer_FindAvailableIP_WrapAroundLoop(t *testing.T) {
	t.Run("wrap-around finds available IP before nextIP", func(t *testing.T) {
		// Setup: Range .100-.104, nextIP set to .102
		// Leases: .102, .103, .104 are taken (active)
		// Available: .100, .101
		// Expected: First loop searches .102-.104 (all taken), then wrap-around
		//           finds .100
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.104"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		// Manually create leases for .102, .103, .104 (active)
		server.mu.Lock()
		server.leases["mac1"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
			IP:        net.ParseIP("192.168.1.102").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.leases["mac2"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
			IP:        net.ParseIP("192.168.1.103").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.leases["mac3"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
			IP:        net.ParseIP("192.168.1.104").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// Set nextIP to .102 so first loop starts there
		server.nextIP = net.ParseIP("192.168.1.102").To4()
		server.mu.Unlock()

		// findAvailableIP should:
		// 1. First loop: check .102 (taken), .103 (taken), .104 (taken)
		// 2. Wrap-around loop: check .100 (available) -> return .100
		ip := server.findAvailableIP()

		require.NotNil(t, ip, "should find available IP via wrap-around")
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")),
			"expected 192.168.1.100, got %s", ip)
	})

	t.Run("wrap-around finds second available IP when first is taken", func(t *testing.T) {
		// Setup: Range .100-.104, nextIP set to .103
		// Leases: .100, .103, .104 are taken (active)
		// Available: .101, .102
		// Expected: First loop searches .103-.104 (all taken), then wrap-around
		//           checks .100 (taken), then finds .101
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.104"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		server.mu.Lock()
		// .100 is taken
		server.leases["mac1"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
			IP:        net.ParseIP("192.168.1.100").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// .103 is taken
		server.leases["mac2"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
			IP:        net.ParseIP("192.168.1.103").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// .104 is taken
		server.leases["mac3"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
			IP:        net.ParseIP("192.168.1.104").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// Set nextIP to .103
		server.nextIP = net.ParseIP("192.168.1.103").To4()
		server.mu.Unlock()

		ip := server.findAvailableIP()

		require.NotNil(t, ip, "should find available IP via wrap-around")
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.101")),
			"expected 192.168.1.101, got %s", ip)
	})

	t.Run("wrap-around returns nil when all IPs exhausted", func(t *testing.T) {
		// Setup: Range .100-.102, nextIP set to .101
		// Leases: .100, .101, .102 are all taken (active)
		// Expected: First loop searches .101-.102 (all taken), then wrap-around
		//           searches .100 (taken), then returns nil
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.102"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		server.mu.Lock()
		server.leases["mac1"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
			IP:        net.ParseIP("192.168.1.100").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.leases["mac2"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
			IP:        net.ParseIP("192.168.1.101").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.leases["mac3"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
			IP:        net.ParseIP("192.168.1.102").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// Set nextIP to .101 (middle of range)
		server.nextIP = net.ParseIP("192.168.1.101").To4()
		server.mu.Unlock()

		ip := server.findAvailableIP()

		assert.Nil(t, ip, "should return nil when all IPs exhausted after wrap-around")
	})

	t.Run("wrap-around skips expired leases", func(t *testing.T) {
		// Setup: Range .100-.103, nextIP set to .102
		// Leases: .100 expired, .101 active, .102 active, .103 active
		// Expected: First loop searches .102-.103 (all taken), then wrap-around
		//           checks .100 (expired, so available) -> return .100
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.103"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		server.mu.Lock()
		// .100 is expired
		server.leases["mac1"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
			IP:        net.ParseIP("192.168.1.100").To4(),
			ExpiresAt: time.Now().Add(-time.Hour), // Expired
		}
		// .101 is active
		server.leases["mac2"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
			IP:        net.ParseIP("192.168.1.101").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// .102 is active
		server.leases["mac3"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
			IP:        net.ParseIP("192.168.1.102").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// .103 is active
		server.leases["mac4"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x04},
			IP:        net.ParseIP("192.168.1.103").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		// Set nextIP to .102
		server.nextIP = net.ParseIP("192.168.1.102").To4()
		server.mu.Unlock()

		ip := server.findAvailableIP()

		require.NotNil(t, ip, "should find expired IP via wrap-around")
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")),
			"expected 192.168.1.100 (expired lease), got %s", ip)
	})

	t.Run("wrap-around updates nextIP correctly", func(t *testing.T) {
		// Setup: Range .100-.104, nextIP set to .103
		// Leases: .103, .104 are taken (active)
		// Available: .100, .101, .102
		// Expected: After finding .100 via wrap-around, nextIP should be .101
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.104"),
			LeaseTime:  time.Hour,
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		server.mu.Lock()
		server.leases["mac1"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
			IP:        net.ParseIP("192.168.1.103").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.leases["mac2"] = &lease{
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
			IP:        net.ParseIP("192.168.1.104").To4(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		server.nextIP = net.ParseIP("192.168.1.103").To4()
		server.mu.Unlock()

		ip := server.findAvailableIP()

		require.NotNil(t, ip)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")),
			"expected 192.168.1.100, got %s", ip)

		// Verify nextIP was updated to .101
		server.mu.RLock()
		nextIP := server.nextIP
		server.mu.RUnlock()

		assert.True(t, nextIP.Equal(net.ParseIP("192.168.1.101")),
			"nextIP should be 192.168.1.101 after wrap-around, got %s", nextIP)
	})
}

// TestIncrementIP tests IP incrementing.
func TestIncrementIP(t *testing.T) {
	tests := []struct {
		name     string
		input    net.IP
		expected net.IP
	}{
		{
			name:     "simple increment",
			input:    net.ParseIP("192.168.1.100"),
			expected: net.ParseIP("192.168.1.101"),
		},
		{
			name:     "increment with byte overflow",
			input:    net.ParseIP("192.168.1.255"),
			expected: net.ParseIP("192.168.2.0"),
		},
		{
			name:     "increment with multiple byte overflow",
			input:    net.ParseIP("192.168.255.255"),
			expected: net.ParseIP("192.169.0.0"),
		},
		{
			name:     "increment at network boundary",
			input:    net.ParseIP("10.0.0.255"),
			expected: net.ParseIP("10.0.1.0"),
		},
		{
			name:     "increment at max IP rollover",
			input:    net.ParseIP("255.255.255.255"),
			expected: net.ParseIP("0.0.0.0"),
		},
		{
			name:     "increment zero IP",
			input:    net.ParseIP("0.0.0.0"),
			expected: net.ParseIP("0.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := incrementIP(tt.input.To4())

			assert.True(t, result.To4().Equal(tt.expected.To4()),
				"expected %s, got %s", tt.expected, result)
		})
	}
}

// TestIncrementIP_DoesNotModifyOriginal verifies incrementIP creates a copy.
func TestIncrementIP_DoesNotModifyOriginal(t *testing.T) {
	original := net.ParseIP("192.168.1.100").To4()
	originalCopy := make(net.IP, len(original))
	copy(originalCopy, original)

	_ = incrementIP(original)

	assert.True(t, original.Equal(originalCopy),
		"original IP should not be modified")
}

// TestCompareIPs tests IP comparison.
func TestCompareIPs(t *testing.T) {
	tests := []struct {
		name     string
		a        net.IP
		b        net.IP
		expected int
	}{
		{
			name:     "equal IPs",
			a:        net.ParseIP("192.168.1.100"),
			b:        net.ParseIP("192.168.1.100"),
			expected: 0,
		},
		{
			name:     "a less than b (last octet)",
			a:        net.ParseIP("192.168.1.100"),
			b:        net.ParseIP("192.168.1.200"),
			expected: -1,
		},
		{
			name:     "a greater than b (last octet)",
			a:        net.ParseIP("192.168.1.200"),
			b:        net.ParseIP("192.168.1.100"),
			expected: 1,
		},
		{
			name:     "a less than b (third octet)",
			a:        net.ParseIP("192.168.1.100"),
			b:        net.ParseIP("192.168.2.100"),
			expected: -1,
		},
		{
			name:     "a greater than b (first octet)",
			a:        net.ParseIP("200.168.1.100"),
			b:        net.ParseIP("192.168.1.100"),
			expected: 1,
		},
		{
			name:     "compare with zero IP",
			a:        net.ParseIP("0.0.0.0"),
			b:        net.ParseIP("0.0.0.1"),
			expected: -1,
		},
		{
			name:     "compare max IPs",
			a:        net.ParseIP("255.255.255.255"),
			b:        net.ParseIP("255.255.255.254"),
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareIPs(tt.a, tt.b)

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDHCPServer_AddPXEOptions tests PXE option configuration.
func TestDHCPServer_AddPXEOptions(t *testing.T) {
	tests := []struct {
		name             string
		isIPXE           bool
		clientArch       uint16
		ipxeScript       string
		bootFilename     string
		tftpServerName   string
		tftpServerIP     net.IP
		expectedBootFile string
		expectedServerIP net.IP
		expectedHostname string
	}{
		{
			name:             "iPXE client with script",
			isIPXE:           true,
			clientArch:       archEFIx64,
			ipxeScript:       "http://192.168.1.1:8080/boot.ipxe",
			bootFilename:     "ipxe.efi",
			expectedBootFile: "http://192.168.1.1:8080/boot.ipxe",
		},
		{
			name:             "iPXE client without script",
			isIPXE:           true,
			clientArch:       archEFIx64,
			ipxeScript:       "",
			bootFilename:     "ipxe.efi",
			expectedBootFile: "",
		},
		{
			name:             "non-iPXE client with boot filename",
			isIPXE:           false,
			clientArch:       archEFIx64,
			ipxeScript:       "http://192.168.1.1:8080/boot.ipxe",
			bootFilename:     "ipxe.efi",
			tftpServerName:   "pxeserver",
			tftpServerIP:     net.ParseIP("192.168.1.1"),
			expectedBootFile: "ipxe.efi",
			expectedServerIP: net.ParseIP("192.168.1.1"),
			expectedHostname: "pxeserver",
		},
		{
			name:             "non-iPXE client without boot filename",
			isIPXE:           false,
			clientArch:       archBIOSx86,
			ipxeScript:       "",
			bootFilename:     "",
			expectedBootFile: "",
		},
		{
			name:             "non-iPXE client with TFTP server only",
			isIPXE:           false,
			clientArch:       archEFIx64,
			bootFilename:     "undionly.kpxe",
			tftpServerName:   "",
			tftpServerIP:     net.ParseIP("10.0.0.5"),
			expectedBootFile: "undionly.kpxe",
			expectedServerIP: net.ParseIP("10.0.0.5"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &DHCPConfig{
				ServerIP:       net.ParseIP("192.168.1.1"),
				RangeStart:     net.ParseIP("192.168.1.100"),
				RangeEnd:       net.ParseIP("192.168.1.200"),
				IPXEScript:     tt.ipxeScript,
				BootFilename:   tt.bootFilename,
				TFTPServerName: tt.tftpServerName,
				TFTPServerIP:   tt.tftpServerIP,
			}
			server, err := NewDHCPServer(config, logging.DefaultLogger())
			require.NoError(t, err)

			// Create a reply packet
			req := createBaseDHCPRequest(t)
			reply, err := dhcpv4.NewReplyFromRequest(req)
			require.NoError(t, err)

			server.addPXEOptions(reply, tt.clientArch, tt.isIPXE)

			assert.Equal(t, tt.expectedBootFile, reply.BootFileName)
			if tt.expectedServerIP != nil {
				assert.True(t, reply.ServerIPAddr.Equal(tt.expectedServerIP))
			}
			if tt.expectedHostname != "" {
				assert.Equal(t, tt.expectedHostname, reply.ServerHostName)
			}
		})
	}
}

// TestDHCPServer_BootFilenameForArch covers the arch-aware boot
// filename selection: legacy BIOS PXE clients (arch 0x0000) must
// receive an MBR-style binary like undionly.kpxe, UEFI x64 clients
// (0x0007) must receive a 64-bit EFI binary, etc. Pre-fix behavior
// served ipxe.efi to every client and silently broke legacy BIOS
// PXE ROMs — this test guards against regressing back to that.
func TestDHCPServer_BootFilenameForArch(t *testing.T) {
	cfg := &DHCPConfig{
		ServerIP:           net.ParseIP("192.168.1.1"),
		RangeStart:         net.ParseIP("192.168.1.100"),
		RangeEnd:           net.ParseIP("192.168.1.200"),
		BootFilename:       "ipxe.efi",
		BootFilenameByArch: DefaultBootFilenameByArch(),
	}
	server, err := NewDHCPServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	cases := []struct {
		name string
		arch uint16
		want string
	}{
		{"legacy BIOS x86 -> undionly.kpxe", archBIOSx86, "undionly.kpxe"},
		{"UEFI IA32 -> ipxe32.efi", archEFIx86, "ipxe32.efi"},
		{"UEFI x64 -> ipxe.efi", archEFIx64, "ipxe.efi"},
		{"UEFI bytecode -> ipxe.efi", archEFIBC, "ipxe.efi"},
		{"unmapped arch falls back to BootFilename", uint16(0x00FF), "ipxe.efi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := server.bootFilenameForArch(tc.arch)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDHCPServer_BootFilenameForArch_EmptyMap exercises the
// backwards-compatibility path: an operator who explicitly sets
// BootFilenameByArch to an empty map (not nil) intentionally
// disables arch-aware selection and expects every client to receive
// the single BootFilename value.
func TestDHCPServer_BootFilenameForArch_EmptyMap(t *testing.T) {
	cfg := &DHCPConfig{
		ServerIP:           net.ParseIP("192.168.1.1"),
		RangeStart:         net.ParseIP("192.168.1.100"),
		RangeEnd:           net.ParseIP("192.168.1.200"),
		BootFilename:       "ipxe.efi",
		BootFilenameByArch: map[uint16]string{},
	}
	server, err := NewDHCPServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	for _, arch := range []uint16{archBIOSx86, archEFIx86, archEFIx64, archEFIBC} {
		assert.Equal(t, "ipxe.efi", server.bootFilenameForArch(arch))
	}
}

// TestDefaultBootFilenameByArch verifies the standard mapping that
// ships when the operator hasn't customized it. Filenames here are
// load-bearing — they must match the entries TFTPServer.loadFirmware
// caches under those names, or the DHCP server will hand clients a
// path their TFTP fetch can never resolve.
func TestDefaultBootFilenameByArch(t *testing.T) {
	m := DefaultBootFilenameByArch()
	assert.Equal(t, "undionly.kpxe", m[archBIOSx86])
	assert.Equal(t, "ipxe32.efi", m[archEFIx86])
	assert.Equal(t, "ipxe.efi", m[archEFIx64])
	assert.Equal(t, "ipxe.efi", m[archEFIBC])
}

// TestDHCPServer_AddPXEOptions_ArchAware verifies that addPXEOptions
// now selects the boot filename from the arch map. Pre-fix it
// always used config.BootFilename — a legacy-BIOS PXE ROM (arch 0)
// would receive ipxe.efi (a UEFI binary) and silently fail.
func TestDHCPServer_AddPXEOptions_ArchAware(t *testing.T) {
	cfg := &DHCPConfig{
		ServerIP:           net.ParseIP("192.168.1.1"),
		RangeStart:         net.ParseIP("192.168.1.100"),
		RangeEnd:           net.ParseIP("192.168.1.200"),
		BootFilename:       "ipxe.efi",
		BootFilenameByArch: DefaultBootFilenameByArch(),
		TFTPServerIP:       net.ParseIP("192.168.1.1"),
	}
	server, err := NewDHCPServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	req := createBaseDHCPRequest(t)

	t.Run("legacy BIOS PXE gets undionly.kpxe", func(t *testing.T) {
		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		server.addPXEOptions(reply, archBIOSx86, false)
		assert.Equal(t, "undionly.kpxe", reply.BootFileName)
	})
	t.Run("UEFI x64 still gets ipxe.efi", func(t *testing.T) {
		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		server.addPXEOptions(reply, archEFIx64, false)
		assert.Equal(t, "ipxe.efi", reply.BootFileName)
	})
}

// TestDHCPServer_SendDHCPReply tests DHCP reply sending logic.
func TestDHCPServer_SendDHCPReply(t *testing.T) {
	t.Run("sends to relay agent when giaddr set", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createBaseDHCPRequest(t)
		req.GatewayIPAddr = net.ParseIP("10.0.0.1")

		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		err = server.sendDHCPReply(mockConn, nil, req, reply)
		require.NoError(t, err)

		assert.NotNil(t, mockConn.writtenData)
		udpAddr, ok := mockConn.writtenAddr.(*net.UDPAddr)
		require.True(t, ok)
		assert.True(t, udpAddr.IP.Equal(net.ParseIP("10.0.0.1")))
		assert.Equal(t, 67, udpAddr.Port)
	})

	t.Run("broadcasts when client IP unspecified", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createBaseDHCPRequest(t)
		req.ClientIPAddr = net.IPv4zero

		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		err = server.sendDHCPReply(mockConn, nil, req, reply)
		require.NoError(t, err)

		assert.NotNil(t, mockConn.writtenData)
		udpAddr, ok := mockConn.writtenAddr.(*net.UDPAddr)
		require.True(t, ok)
		assert.Equal(t, 68, udpAddr.Port)
	})

	t.Run("unicasts to client IP when specified", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createBaseDHCPRequest(t)
		req.ClientIPAddr = net.ParseIP("192.168.1.50")
		req.SetUnicast() // Mark as unicast

		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		err = server.sendDHCPReply(mockConn, nil, req, reply)
		require.NoError(t, err)

		assert.NotNil(t, mockConn.writtenData)
		udpAddr, ok := mockConn.writtenAddr.(*net.UDPAddr)
		require.True(t, ok)
		assert.True(t, udpAddr.IP.Equal(net.ParseIP("192.168.1.50")))
		assert.Equal(t, 68, udpAddr.Port)
	})

	t.Run("returns error on write failure", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{
			writeErr: errors.New("write failed"),
		}

		req := createBaseDHCPRequest(t)
		reply, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		err = server.sendDHCPReply(mockConn, nil, req, reply)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "write failed")
	})
}

// TestDHCPServer_HandleDHCP tests the main DHCP handler routing.
func TestDHCPServer_HandleDHCP(t *testing.T) {
	t.Run("handles discover message for PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createPXEDiscoverRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDHCP(mockConn, peer, req)

		// Verify an offer was sent
		assert.NotNil(t, mockConn.writtenData)
	})

	t.Run("handles request message for PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		// First get an IP via discover
		discoverReq := createPXEDiscoverRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}
		server.handleDHCP(mockConn, peer, discoverReq)

		// Now send a request
		requestReq := createPXERequestRequest(t, net.ParseIP("192.168.1.100"))
		server.handleDHCP(mockConn, peer, requestReq)

		// Verify an ACK was sent
		assert.NotNil(t, mockConn.writtenData)
	})

	t.Run("ignores non-PXE discover", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createBaseDHCPRequest(t) // Non-PXE request
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDHCP(mockConn, peer, req)

		// No response should be sent
		assert.Nil(t, mockConn.writtenData)
	})

	t.Run("handles release message", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, err := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		)
		require.NoError(t, err)

		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		// Should not panic
		server.handleDHCP(mockConn, peer, req)
	})

	t.Run("ignores unknown message types", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, err := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
		)
		require.NoError(t, err)

		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDHCP(mockConn, peer, req)

		// No response should be sent
		assert.Nil(t, mockConn.writtenData)
	})
}

// TestDHCPServer_HandleDiscover tests DHCP discover handling.
func TestDHCPServer_HandleDiscover(t *testing.T) {
	t.Run("sends offer for PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createPXEDiscoverRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDiscover(mockConn, peer, req)

		assert.NotNil(t, mockConn.writtenData)
		// Parse the response to verify it's an offer
		resp, err := dhcpv4.FromBytes(mockConn.writtenData)
		require.NoError(t, err)
		assert.Equal(t, dhcpv4.MessageTypeOffer, resp.MessageType())
	})

	t.Run("ignores non-PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		req := createBaseDHCPRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDiscover(mockConn, peer, req)

		assert.Nil(t, mockConn.writtenData)
	})

	t.Run("sets correct options in offer", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:       net.ParseIP("192.168.1.1"),
			SubnetMask:     net.ParseIP("255.255.255.0"),
			RangeStart:     net.ParseIP("192.168.1.100"),
			RangeEnd:       net.ParseIP("192.168.1.200"),
			LeaseTime:      time.Hour,
			Router:         net.ParseIP("192.168.1.1"),
			DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
			BootFilename:   "ipxe.efi",
			TFTPServerName: "pxeserver",
			TFTPServerIP:   net.ParseIP("192.168.1.1"),
		}
		server, err := NewDHCPServer(config, logging.DefaultLogger())
		require.NoError(t, err)

		mockConn := &mockPacketConn{}
		req := createPXEDiscoverRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}

		server.handleDiscover(mockConn, peer, req)

		resp, err := dhcpv4.FromBytes(mockConn.writtenData)
		require.NoError(t, err)

		assert.True(t, resp.YourIPAddr.Equal(net.ParseIP("192.168.1.100")))
		assert.True(t, resp.ServerIPAddr.Equal(net.ParseIP("192.168.1.1")))
	})
}

// TestDHCPServer_HandleRequest tests DHCP request handling.
func TestDHCPServer_HandleRequest(t *testing.T) {
	t.Run("sends ACK for PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		// First do discover to create lease
		discoverReq := createPXEDiscoverRequest(t)
		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}
		server.handleDiscover(mockConn, peer, discoverReq)

		// Now do request
		req := createPXERequestRequest(t, net.ParseIP("192.168.1.100"))
		server.handleRequest(mockConn, peer, req)

		assert.NotNil(t, mockConn.writtenData)
		resp, err := dhcpv4.FromBytes(mockConn.writtenData)
		require.NoError(t, err)
		assert.Equal(t, dhcpv4.MessageTypeAck, resp.MessageType())
	})

	t.Run("ignores non-PXE client", func(t *testing.T) {
		server := createTestDHCPServer(t)
		mockConn := &mockPacketConn{}

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, err := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		require.NoError(t, err)

		peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}
		server.handleRequest(mockConn, peer, req)

		assert.Nil(t, mockConn.writtenData)
	})
}

// TestDHCPServer_ThreadSafety tests concurrent access to leases.
func TestDHCPServer_ThreadSafety(t *testing.T) {
	server := createTestDHCPServer(t)

	const numGoroutines = 10
	const numOperations = 50

	done := make(chan struct{}, numGoroutines)

	// Concurrent IP assignments
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < numOperations; j++ {
				mac := generateMAC(id, j)
				_, _ = server.getOrAssignIP(mac)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify no race conditions occurred (test completes without panic)
}

// TestDHCPServer_LeaseExpiration tests that expired leases are properly handled.
func TestDHCPServer_LeaseExpiration(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.100"), // Only 1 IP
		LeaseTime:  10 * time.Millisecond,
	}
	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	// First client gets the IP
	ip1, err := server.getOrAssignIP(mac1)
	require.NoError(t, err)
	assert.NotNil(t, ip1)

	// Second client should fail (IP in use)
	_, err = server.getOrAssignIP(mac2)
	require.Error(t, err)

	// Wait for lease to expire
	time.Sleep(20 * time.Millisecond)

	// Now second client should succeed (expired lease cleaned up)
	ip2, err := server.getOrAssignIP(mac2)
	require.NoError(t, err)
	assert.NotNil(t, ip2)
	assert.True(t, ip1.Equal(ip2)) // Same IP recycled
}

// Helper functions

func createTestDHCPServer(t *testing.T) *DHCPServer {
	t.Helper()
	config := &DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		BroadcastIP:    net.ParseIP("192.168.1.255"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.200"),
		LeaseTime:      time.Hour,
		Router:         net.ParseIP("192.168.1.1"),
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
		TFTPServerName: "pxeserver",
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
		IPXEScript:     "http://192.168.1.1:8080/boot.ipxe",
	}
	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)
	return server
}

func createBaseDHCPRequest(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
	)
	require.NoError(t, err)
	return req
}

func createPXEDiscoverRequest(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
	)
	require.NoError(t, err)
	// Add PXE vendor class
	req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003001"))
	// Add client system architecture
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x07}))
	return req
}

func createPXERequestRequest(t *testing.T, requestedIP net.IP) *dhcpv4.DHCPv4 {
	t.Helper()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(requestedIP)),
	)
	require.NoError(t, err)
	// Add PXE vendor class
	req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003001"))
	// Add client system architecture
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x07}))
	return req
}

func generateMAC(id, seq int) net.HardwareAddr {
	return net.HardwareAddr{
		0x00, 0x11, 0x22,
		byte(id),
		byte(seq >> 8),
		byte(seq & 0xFF),
	}
}
