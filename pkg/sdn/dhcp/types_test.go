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

package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerConfig_Clone(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		var cfg *ServerConfig
		assert.Nil(t, cfg.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			IPAMBackend:          IPAMBackendMemory,
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Network: NetworkPublic,
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
					Options: DHCPOptions{
						LeaseTime:  12 * time.Hour,
						DomainName: "example.com",
					},
				},
			},
			IPAMConfig: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		}

		clone := cfg.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, cfg.DefaultLeaseDuration, clone.DefaultLeaseDuration)
		assert.Equal(t, cfg.IPAMBackend, clone.IPAMBackend)
		assert.Equal(t, len(cfg.Interfaces), len(clone.Interfaces))
		assert.Equal(t, cfg.Interfaces[0].Name, clone.Interfaces[0].Name)
		assert.Equal(t, cfg.IPAMConfig["key1"], clone.IPAMConfig["key1"])

		// Verify deep copy - modifying clone should not affect original
		clone.IPAMConfig["key1"] = "modified"
		assert.Equal(t, "value1", cfg.IPAMConfig["key1"])
	})

	t.Run("handles nil slices and maps", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			IPAMBackend:          IPAMBackendMemory,
		}

		clone := cfg.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.Interfaces)
		assert.Nil(t, clone.IPAMConfig)
	})
}

func TestServerConfig_Validate(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		var cfg *ServerConfig
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("no interfaces returns error", func(t *testing.T) {
		cfg := &ServerConfig{}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrNoInterfacesConfigured)
	})

	t.Run("invalid interface returns error", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{Name: ""}, // Invalid - empty name
			},
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("invalid IPAM backend returns error", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
			},
			IPAMBackend: "invalid",
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrIPAMBackendInvalid)
	})

	t.Run("valid config with memory backend", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
			},
			IPAMBackend: IPAMBackendMemory,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with quicbaas backend", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
			},
			IPAMBackend: IPAMBackendQuicBaaS,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with dht backend", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
			},
			IPAMBackend: IPAMBackendDHT,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config without backend", func(t *testing.T) {
		cfg := &ServerConfig{
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestInterfaceConfig_Clone(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		var cfg *InterfaceConfig
		assert.Nil(t, cfg.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Network: NetworkPublic,
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
			Options: DHCPOptions{
				LeaseTime:  12 * time.Hour,
				DomainName: "example.com",
				DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			},
		}

		clone := cfg.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, cfg.Name, clone.Name)
		assert.Equal(t, cfg.Network, clone.Network)
		assert.Equal(t, cfg.Address, clone.Address)
		assert.Equal(t, cfg.PoolID, clone.PoolID)
		assert.Equal(t, cfg.Options.LeaseTime, clone.Options.LeaseTime)
	})
}

func TestInterfaceConfig_Validate(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		var cfg *InterfaceConfig
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("empty name returns error", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("invalid address returns error", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:   "eth0",
			PoolID: "pool-1",
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("empty pool ID returns error", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Address: netip.MustParseAddr("192.168.1.1"),
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrPoolIDRequired)
	})

	t.Run("invalid network type returns error", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Network: "invalid",
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("valid config with public network", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Network: NetworkPublic,
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with private network", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Network: NetworkPrivate,
			Address: netip.MustParseAddr("10.0.0.1"),
			PoolID:  "pool-1",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config without network type", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestDHCPOptions_Clone(t *testing.T) {
	t.Run("nil options returns nil", func(t *testing.T) {
		var opts *DHCPOptions
		assert.Nil(t, opts.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		opts := &DHCPOptions{
			SubnetMask:   net.CIDRMask(24, 32),
			Router:       netip.MustParseAddr("192.168.1.1"),
			DNS:          []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
			DomainName:   "example.com",
			LeaseTime:    24 * time.Hour,
			RenewalTime:  12 * time.Hour,
			RebindTime:   20 * time.Hour,
			NTPServers:   []netip.Addr{netip.MustParseAddr("129.6.15.28")}, // NIST NTP server IP
			MTU:          1500,
			Hostname:     "host1",
			NextServer:   net.ParseIP("192.168.1.10"),
			BootFileName: "/pxelinux.0",
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, opts.SubnetMask, clone.SubnetMask)
		assert.Equal(t, opts.Router, clone.Router)
		assert.Equal(t, opts.DNS, clone.DNS)
		assert.Equal(t, opts.DomainName, clone.DomainName)
		assert.Equal(t, opts.LeaseTime, clone.LeaseTime)
		assert.Equal(t, opts.NextServer, clone.NextServer)
		assert.Equal(t, opts.BootFileName, clone.BootFileName)

		// Verify deep copy
		clone.DNS[0] = netip.MustParseAddr("1.1.1.1")
		assert.NotEqual(t, opts.DNS[0], clone.DNS[0])
	})
}

func TestDHCPOptions_Validate(t *testing.T) {
	t.Run("sets default lease time", func(t *testing.T) {
		opts := &DHCPOptions{}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, DefaultLeaseDuration, opts.LeaseTime)
	})

	t.Run("sets default renewal time", func(t *testing.T) {
		opts := &DHCPOptions{LeaseTime: 24 * time.Hour}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 12*time.Hour, opts.RenewalTime)
	})

	t.Run("sets default rebind time", func(t *testing.T) {
		opts := &DHCPOptions{LeaseTime: 24 * time.Hour}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 21*time.Hour, opts.RebindTime)
	})

	t.Run("preserves custom times", func(t *testing.T) {
		opts := &DHCPOptions{
			LeaseTime:   48 * time.Hour,
			RenewalTime: 20 * time.Hour,
			RebindTime:  40 * time.Hour,
		}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 48*time.Hour, opts.LeaseTime)
		assert.Equal(t, 20*time.Hour, opts.RenewalTime)
		assert.Equal(t, 40*time.Hour, opts.RebindTime)
	})
}

func TestLease_Clone(t *testing.T) {
	t.Run("nil lease returns nil", func(t *testing.T) {
		var l *Lease
		assert.Nil(t, l.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		now := time.Now()

		l := &Lease{
			IP:          netip.MustParseAddr("192.168.1.100"),
			MAC:         mac,
			Hostname:    "host1",
			PoolID:      "pool-1",
			Interface:   "eth0",
			ClientID:    []byte{0x01, 0x02, 0x03},
			VendorClass: "PXEClient",
			UserClass:   "iPXE",
			LeasedAt:    now,
			ExpiresAt:   now.Add(24 * time.Hour),
			RenewedAt:   now,
			State:       LeaseStateActive,
		}

		clone := l.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, l.IP, clone.IP)
		assert.Equal(t, l.MAC.String(), clone.MAC.String())
		assert.Equal(t, l.Hostname, clone.Hostname)
		assert.Equal(t, l.ClientID, clone.ClientID)
		assert.Equal(t, l.State, clone.State)

		// Verify deep copy
		clone.MAC[0] = 0xFF
		assert.NotEqual(t, l.MAC[0], clone.MAC[0])
	})
}

func TestLease_IsExpired(t *testing.T) {
	t.Run("zero expiry is not expired", func(t *testing.T) {
		l := &Lease{}
		assert.False(t, l.IsExpired())
	})

	t.Run("future expiry is not expired", func(t *testing.T) {
		l := &Lease{ExpiresAt: time.Now().Add(1 * time.Hour)}
		assert.False(t, l.IsExpired())
	})

	t.Run("past expiry is expired", func(t *testing.T) {
		l := &Lease{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		assert.True(t, l.IsExpired())
	})
}

func TestLease_IsActive(t *testing.T) {
	t.Run("active state and not expired is active", func(t *testing.T) {
		l := &Lease{
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.True(t, l.IsActive())
	})

	t.Run("active state but expired is not active", func(t *testing.T) {
		l := &Lease{
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		assert.False(t, l.IsActive())
	})

	t.Run("expired state is not active", func(t *testing.T) {
		l := &Lease{
			State:     LeaseStateExpired,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, l.IsActive())
	})

	t.Run("released state is not active", func(t *testing.T) {
		l := &Lease{
			State:     LeaseStateReleased,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, l.IsActive())
	})
}

func TestLease_TimeRemaining(t *testing.T) {
	t.Run("zero expiry returns zero", func(t *testing.T) {
		l := &Lease{}
		assert.Equal(t, time.Duration(0), l.TimeRemaining())
	})

	t.Run("future expiry returns positive duration", func(t *testing.T) {
		l := &Lease{ExpiresAt: time.Now().Add(1 * time.Hour)}
		remaining := l.TimeRemaining()
		assert.True(t, remaining > 0)
		assert.True(t, remaining <= 1*time.Hour)
	})

	t.Run("past expiry returns zero", func(t *testing.T) {
		l := &Lease{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		assert.Equal(t, time.Duration(0), l.TimeRemaining())
	})
}

func TestLeaseState_String(t *testing.T) {
	tests := []struct {
		state    LeaseState
		expected string
	}{
		{LeaseStateActive, "active"},
		{LeaseStateExpired, "expired"},
		{LeaseStateReleased, "released"},
		{LeaseStateDeclined, "declined"},
		{LeaseState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestLeaseState_IsValid(t *testing.T) {
	t.Run("valid states", func(t *testing.T) {
		assert.True(t, LeaseStateActive.IsValid())
		assert.True(t, LeaseStateExpired.IsValid())
		assert.True(t, LeaseStateReleased.IsValid())
		assert.True(t, LeaseStateDeclined.IsValid())
	})

	t.Run("invalid state", func(t *testing.T) {
		assert.False(t, LeaseState(99).IsValid())
	})
}

func TestServerStats_Clone(t *testing.T) {
	t.Run("nil stats returns nil", func(t *testing.T) {
		var s *ServerStats
		assert.Nil(t, s.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		s := &ServerStats{
			StartedAt:       time.Now(),
			PacketsReceived: 100,
			PacketsSent:     90,
			DiscoverCount:   30,
			OfferCount:      30,
			RequestCount:    25,
			AckCount:        25,
			NakCount:        5,
			ReleaseCount:    10,
			DeclineCount:    2,
			InformCount:     3,
			ErrorCount:      1,
			ActiveLeases:    20,
		}

		clone := s.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, s.PacketsReceived, clone.PacketsReceived)
		assert.Equal(t, s.PacketsSent, clone.PacketsSent)
		assert.Equal(t, s.DiscoverCount, clone.DiscoverCount)
		assert.Equal(t, s.ActiveLeases, clone.ActiveLeases)
	})
}

func TestPXEOptions_Clone(t *testing.T) {
	t.Run("nil options returns nil", func(t *testing.T) {
		var opts *PXEOptions
		assert.Nil(t, opts.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		opts := &PXEOptions{
			NextServer:   net.ParseIP("192.168.1.10"),
			BootFileName: "/pxelinux.0",
			TFTPRoot:     "/tftp",
			ArchitectureFilters: map[uint16]string{
				7: "/efi/bootx64.efi",
				0: "/bios/pxelinux.0",
			},
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, opts.NextServer, clone.NextServer)
		assert.Equal(t, opts.BootFileName, clone.BootFileName)
		assert.Equal(t, opts.ArchitectureFilters[7], clone.ArchitectureFilters[7])

		// Verify deep copy
		clone.ArchitectureFilters[7] = "modified"
		assert.NotEqual(t, opts.ArchitectureFilters[7], clone.ArchitectureFilters[7])
	})
}

func TestPXEOptions_Validate(t *testing.T) {
	t.Run("nil next server returns error", func(t *testing.T) {
		opts := &PXEOptions{BootFileName: "/pxelinux.0"}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidNextServer)
	})

	t.Run("unspecified next server returns error", func(t *testing.T) {
		opts := &PXEOptions{
			NextServer:   net.IPv4zero,
			BootFileName: "/pxelinux.0",
		}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidNextServer)
	})

	t.Run("empty boot file returns error", func(t *testing.T) {
		opts := &PXEOptions{NextServer: net.ParseIP("192.168.1.10")}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidBootFile)
	})

	t.Run("valid options", func(t *testing.T) {
		opts := &PXEOptions{
			NextServer:   net.ParseIP("192.168.1.10"),
			BootFileName: "/pxelinux.0",
		}
		err := opts.Validate()
		assert.NoError(t, err)
	})
}

func TestPXEOptions_GetBootFileForArch(t *testing.T) {
	opts := &PXEOptions{
		NextServer:   net.ParseIP("192.168.1.10"),
		BootFileName: "/default.0",
		ArchitectureFilters: map[uint16]string{
			7: "/efi/bootx64.efi",
			0: "/bios/pxelinux.0",
		},
	}

	t.Run("returns architecture-specific boot file", func(t *testing.T) {
		assert.Equal(t, "/efi/bootx64.efi", opts.GetBootFileForArch(7))
		assert.Equal(t, "/bios/pxelinux.0", opts.GetBootFileForArch(0))
	})

	t.Run("returns default for unknown architecture", func(t *testing.T) {
		assert.Equal(t, "/default.0", opts.GetBootFileForArch(99))
	})

	t.Run("returns default when no filters", func(t *testing.T) {
		opts2 := &PXEOptions{
			NextServer:   net.ParseIP("192.168.1.10"),
			BootFileName: "/default.0",
		}
		assert.Equal(t, "/default.0", opts2.GetBootFileForArch(7))
	})
}

func TestLeaseRequest_Clone(t *testing.T) {
	t.Run("nil request returns nil", func(t *testing.T) {
		var r *LeaseRequest
		assert.Nil(t, r.Clone())
	})

	t.Run("clones all fields", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		r := &LeaseRequest{
			MAC:           mac,
			PoolID:        "pool-1",
			Interface:     "eth0",
			Hostname:      "host1",
			RequestedIP:   netip.MustParseAddr("192.168.1.100"),
			LeaseDuration: 24 * time.Hour,
			ClientID:      []byte{0x01, 0x02, 0x03},
			VendorClass:   "PXEClient",
			UserClass:     "iPXE",
		}

		clone := r.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, r.MAC.String(), clone.MAC.String())
		assert.Equal(t, r.PoolID, clone.PoolID)
		assert.Equal(t, r.ClientID, clone.ClientID)

		// Verify deep copy
		clone.MAC[0] = 0xFF
		assert.NotEqual(t, r.MAC[0], clone.MAC[0])
	})
}

func TestLeaseRequest_Validate(t *testing.T) {
	t.Run("nil request returns error", func(t *testing.T) {
		var r *LeaseRequest
		err := r.Validate()
		assert.ErrorIs(t, err, ErrInvalidLeaseRequest)
	})

	t.Run("nil MAC returns error", func(t *testing.T) {
		r := &LeaseRequest{PoolID: "pool-1"}
		err := r.Validate()
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("empty MAC returns error", func(t *testing.T) {
		r := &LeaseRequest{
			MAC:    net.HardwareAddr{},
			PoolID: "pool-1",
		}
		err := r.Validate()
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("empty pool ID returns error", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		r := &LeaseRequest{MAC: mac}
		err := r.Validate()
		assert.ErrorIs(t, err, ErrPoolIDRequired)
	})

	t.Run("valid request", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		r := &LeaseRequest{
			MAC:    mac,
			PoolID: "pool-1",
		}
		err := r.Validate()
		assert.NoError(t, err)
	})
}

func TestConstants(t *testing.T) {
	t.Run("default durations are correct", func(t *testing.T) {
		assert.Equal(t, 24*time.Hour, DefaultLeaseDuration)
		assert.Equal(t, 12*time.Hour, DefaultRenewalTime)
		assert.Equal(t, 21*time.Hour, DefaultRebindingTime)
	})

	t.Run("IPAM backends are defined", func(t *testing.T) {
		assert.Equal(t, "memory", IPAMBackendMemory)
		assert.Equal(t, "quicbaas", IPAMBackendQuicBaaS)
		assert.Equal(t, "dht", IPAMBackendDHT)
	})

	t.Run("network types are defined", func(t *testing.T) {
		assert.Equal(t, "public", NetworkPublic)
		assert.Equal(t, "private", NetworkPrivate)
	})
}
