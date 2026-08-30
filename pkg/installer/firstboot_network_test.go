package installer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirstbootStaticAddress(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		netmask    string
		wantIP     string
		wantPrefix int
	}{
		{name: "cidr suffix wins", address: "198.18.1.140/24", netmask: "", wantIP: "198.18.1.140", wantPrefix: 24},
		{name: "cidr suffix ignores netmask", address: "198.18.1.140/28", netmask: "255.255.255.0", wantIP: "198.18.1.140", wantPrefix: 28},
		{name: "bare address with netmask", address: "198.18.1.140", netmask: "255.255.255.0", wantIP: "198.18.1.140", wantPrefix: 24},
		{name: "bare address with wide netmask", address: "10.1.2.3", netmask: "255.255.0.0", wantIP: "10.1.2.3", wantPrefix: 16},
		{name: "bare address defaults to /24", address: "198.18.1.140", netmask: "", wantIP: "198.18.1.140", wantPrefix: defaultStaticPrefixLen},
		{name: "host route", address: "198.18.1.140/32", netmask: "", wantIP: "198.18.1.140", wantPrefix: 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, prefix, err := firstbootStaticAddress(tt.address, tt.netmask)
			require.NoError(t, err)
			assert.Equal(t, tt.wantIP, ip)
			assert.Equal(t, tt.wantPrefix, prefix)
			assert.NotContains(t, ip, "/", "the bare address must never carry a prefix")
		})
	}
}

func TestFirstbootStaticAddress_Malformed(t *testing.T) {
	tests := []struct {
		name    string
		address string
		netmask string
	}{
		{name: "double prefix", address: "198.18.1.140/24/24"},
		{name: "empty prefix", address: "198.18.1.140/"},
		{name: "prefix too large", address: "198.18.1.140/33"},
		{name: "negative prefix", address: "198.18.1.140/-1"},
		{name: "non-numeric prefix", address: "198.18.1.140/24a"},
		{name: "not an address", address: "lab-node-2/24"},
		{name: "ipv6 address", address: "2001:db8::1/64"},
		{name: "empty address"},
		{name: "netmask not dotted-quad", address: "198.18.1.140", netmask: "24"},
		{name: "netmask not contiguous", address: "198.18.1.140", netmask: "255.0.255.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, prefix, err := firstbootStaticAddress(tt.address, tt.netmask)
			require.Error(t, err)
			var sae *StaticAddressError
			require.True(t, errors.As(err, &sae), "expected *StaticAddressError, got %T", err)
			assert.Equal(t, tt.address, sae.Address)
			assert.Equal(t, tt.netmask, sae.Netmask)
			assert.Contains(t, err.Error(), tt.address)
			assert.Empty(t, ip)
			assert.Zero(t, prefix)
		})
	}
}

func TestWriteFirstbootNetworkConfig_StaticCarriesPrefixOnce(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		netmask    string
		wantPrefix string
	}{
		{name: "cidr address", address: "198.18.1.140/24", wantPrefix: "24"},
		{name: "bare address with netmask", address: "198.18.1.140", netmask: "255.255.255.128", wantPrefix: "25"},
		{name: "bare address without netmask", address: "198.18.1.140", wantPrefix: "24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			efiDir := t.TempDir()
			inst := &installer{
				logger: createTestLogger(),
				config: &Config{
					OS: &OSConfig{Hostname: "lab-node-2"},
					Network: &NetworkConfig{
						Interfaces: []InterfaceConfig{{
							Name:        "eth0",
							Type:        "static",
							IPv4Address: tt.address,
							IPv4Netmask: tt.netmask,
							IPv4Gateway: "198.18.1.1",
						}},
						DNS: &DNSConfig{Nameservers: []string{"127.0.0.1", "198.18.1.1"}},
					},
				},
			}

			require.NoError(t, inst.writeFirstbootNetworkConfig(efiDir))

			raw, err := os.ReadFile(filepath.Join(efiDir, "network.conf"))
			require.NoError(t, err)
			content := string(raw)
			assert.Contains(t, content, "INTERFACE=eth0\n")
			assert.Contains(t, content, "TYPE=static\n")
			assert.Contains(t, content, "IPV4_ADDRESS=198.18.1.140\n")
			assert.Contains(t, content, "IPV4_PREFIX="+tt.wantPrefix+"\n")
			assert.Contains(t, content, "IPV4_NETMASK="+tt.netmask+"\n")
			assert.Contains(t, content, "IPV4_GATEWAY=198.18.1.1\n")
			assert.Contains(t, content, "DNS=\"127.0.0.1 198.18.1.1\"\n")
			assert.Contains(t, content, "HOSTNAME=lab-node-2\n")
			assert.NotContains(t, content, "IPV4_ADDRESS=198.18.1.140/", "the address line must be bare so the hook appends the prefix exactly once")
			assert.Equal(t, 1, strings.Count(content, "IPV4_ADDRESS="))
		})
	}
}

func TestWriteFirstbootNetworkConfig_MalformedStaticAddress(t *testing.T) {
	efiDir := t.TempDir()
	inst := &installer{
		logger: createTestLogger(),
		config: &Config{
			Network: &NetworkConfig{
				Interfaces: []InterfaceConfig{{
					Name:        "eth0",
					Type:        "static",
					IPv4Address: "198.18.1.140/24/24",
					IPv4Gateway: "198.18.1.1",
				}},
			},
		},
	}

	err := inst.writeFirstbootNetworkConfig(efiDir)
	require.Error(t, err)
	var sae *StaticAddressError
	assert.True(t, errors.As(err, &sae))
	_, statErr := os.Stat(filepath.Join(efiDir, "network.conf"))
	assert.True(t, os.IsNotExist(statErr), "a malformed address must not produce a network.conf")
}

func TestWriteFirstbootNetworkConfig_DHCPAndNoNetwork(t *testing.T) {
	t.Run("dhcp interface carries no address keys", func(t *testing.T) {
		efiDir := t.TempDir()
		inst := &installer{
			logger: createTestLogger(),
			config: &Config{
				Network: &NetworkConfig{
					Interfaces: []InterfaceConfig{{Name: "eth0", Type: "dhcp"}},
				},
			},
		}
		require.NoError(t, inst.writeFirstbootNetworkConfig(efiDir))
		raw, err := os.ReadFile(filepath.Join(efiDir, "network.conf"))
		require.NoError(t, err)
		assert.Contains(t, string(raw), "INTERFACE=eth0\nTYPE=dhcp\n")
		assert.NotContains(t, string(raw), "IPV4_")
	})

	t.Run("no network config writes nothing", func(t *testing.T) {
		efiDir := t.TempDir()
		inst := &installer{logger: createTestLogger(), config: &Config{}}
		require.NoError(t, inst.writeFirstbootNetworkConfig(efiDir))
		_, statErr := os.Stat(filepath.Join(efiDir, "network.conf"))
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("unwritable directory returns a typed error", func(t *testing.T) {
		inst := &installer{
			logger: createTestLogger(),
			config: &Config{
				Network: &NetworkConfig{
					Interfaces: []InterfaceConfig{{Name: "eth0", Type: "dhcp"}},
				},
			},
		}
		err := inst.writeFirstbootNetworkConfig(filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
		var we *WrappedError
		assert.True(t, errors.As(err, &we))
	})
}
