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
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg == nil {
		t.Fatal("DefaultServerConfig returned nil")
	}

	if cfg.HTTPPort != DefaultHTTPPort {
		t.Errorf("expected HTTPPort %d, got %d", DefaultHTTPPort, cfg.HTTPPort)
	}

	if cfg.TFTPPort != DefaultTFTPPort {
		t.Errorf("expected TFTPPort %d, got %d", DefaultTFTPPort, cfg.TFTPPort)
	}

	if cfg.LocalFilesDir == "" {
		t.Error("expected LocalFilesDir to be set")
	}

	if cfg.DHCPLeaseTime != DefaultLeaseTime {
		t.Errorf("expected DHCPLeaseTime %v, got %v", DefaultLeaseTime, cfg.DHCPLeaseTime)
	}

	if cfg.DHCPSubnetMask != DefaultSubnetMask {
		t.Errorf("expected DHCPSubnetMask %s, got %s", DefaultSubnetMask, cfg.DHCPSubnetMask)
	}

	if cfg.EnableDHCP {
		t.Error("expected DHCP to be disabled by default")
	}

	if len(cfg.BootEntries) != 0 {
		t.Errorf("expected no boot entries, got %d", len(cfg.BootEntries))
	}

	if cfg.BootFilename != "ipxe.efi" {
		t.Errorf("expected BootFilename 'ipxe.efi', got %s", cfg.BootFilename)
	}
}

func TestDefaultConfig(t *testing.T) {
	// DefaultConfig is an alias for DefaultServerConfig for backward compatibility
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Verify it returns the same configuration as DefaultServerConfig
	expected := DefaultServerConfig()
	if cfg.HTTPPort != expected.HTTPPort {
		t.Errorf("expected HTTPPort %d, got %d", expected.HTTPPort, cfg.HTTPPort)
	}
	if cfg.TFTPPort != expected.TFTPPort {
		t.Errorf("expected TFTPPort %d, got %d", expected.TFTPPort, cfg.TFTPPort)
	}
	if cfg.EnableDHCP != expected.EnableDHCP {
		t.Errorf("expected EnableDHCP %v, got %v", expected.EnableDHCP, cfg.EnableDHCP)
	}
}

func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *ServerConfig
		wantErr error
	}{
		{
			name: "valid config with DHCP disabled",
			cfg: &ServerConfig{
				HTTPPort: 8080,
				TFTPPort: 69,
				BootEntries: []BootEntry{
					{
						Name:        "ubuntu",
						Description: "Ubuntu 22.04",
						Kernel:      "vmlinuz",
						Initrd:      "initrd.img",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid config with DHCP enabled",
			cfg: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPSubnetMask: "255.255.255.0",
				DHCPLeaseTime:  1 * time.Hour,
				BootEntries: []BootEntry{
					{
						Name:        "ubuntu",
						Description: "Ubuntu 22.04",
						Kernel:      "vmlinuz",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid HTTP port - too low",
			cfg: &ServerConfig{
				HTTPPort: 0,
				TFTPPort: 69,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid HTTP port - too high",
			cfg: &ServerConfig{
				HTTPPort: 65536,
				TFTPPort: 69,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid TFTP port - negative",
			cfg: &ServerConfig{
				HTTPPort: 8080,
				TFTPPort: -1,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "no boot entries",
			cfg: &ServerConfig{
				HTTPPort:    8080,
				TFTPPort:    69,
				BootEntries: []BootEntry{},
			},
			wantErr: ErrNoBootEntries,
		},
		{
			name: "invalid boot entry - no name",
			cfg: &ServerConfig{
				HTTPPort: 8080,
				TFTPPort: 69,
				BootEntries: []BootEntry{
					{
						Description: "Test",
						Kernel:      "vmlinuz",
					},
				},
			},
			wantErr: ErrInvalidBootEntry,
		},
		{
			name: "invalid interface name",
			cfg: &ServerConfig{
				Interface: "nonexistent999",
				HTTPPort:  8080,
				TFTPPort:  69,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidInterface,
		},
		{
			name: "DHCP enabled but missing interface",
			cfg: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "DHCP enabled but missing range",
			cfg: &ServerConfig{
				HTTPPort:      8080,
				TFTPPort:      69,
				EnableDHCP:    true,
				DHCPInterface: "lo",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "vmlinuz"},
				},
			},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error containing %v, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestServerConfig_ValidateDHCP(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *ServerConfig
		wantErr error
	}{
		{
			name: "valid DHCP config",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPSubnetMask: "255.255.255.0",
				DHCPGateway:    "192.168.1.1",
				DHCPDNS:        []string{"8.8.8.8"},
				DHCPLeaseTime:  1 * time.Hour,
			},
			wantErr: nil,
		},
		{
			name: "missing interface",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid interface",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "nonexistent999",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
			},
			wantErr: ErrInvalidInterface,
		},
		{
			name: "missing range start",
			cfg: &ServerConfig{
				EnableDHCP:    true,
				DHCPInterface: "lo",
				DHCPRangeEnd:  "192.168.1.200",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid range start IP",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "invalid",
				DHCPRangeEnd:   "192.168.1.200",
			},
			wantErr: ErrInvalidIPRange,
		},
		{
			name: "invalid subnet mask",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPSubnetMask: "invalid",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid gateway",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPGateway:    "invalid",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid DNS",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPDNS:        []string{"invalid"},
			},
			wantErr: ErrInvalidConfig,
		},
		{
			// To4 of an IPv6 address is nil: it would drop option 3.
			name: "IPv6 gateway",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPGateway:    "fd00::1",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "bad DNS after a good one",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPDNS:        []string{"8.8.8.8", "fd00::53"},
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "zero lease time",
			cfg: &ServerConfig{
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "192.168.1.100",
				DHCPRangeEnd:   "192.168.1.200",
				DHCPLeaseTime:  0,
			},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateDHCP()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error containing %v, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestBootEntry_Validate(t *testing.T) {
	tests := []struct {
		name    string
		entry   BootEntry
		wantErr error
	}{
		{
			name: "valid entry with kernel and initrd",
			entry: BootEntry{
				Name:        "ubuntu",
				Description: "Ubuntu 22.04",
				Kernel:      "vmlinuz",
				Initrd:      "initrd.img",
			},
			wantErr: nil,
		},
		{
			name: "valid entry with ISO",
			entry: BootEntry{
				Name:        "ubuntu",
				Description: "Ubuntu 22.04",
				ISOURL:      "http://example.com/ubuntu.iso",
			},
			wantErr: nil,
		},
		{
			name: "valid entry with all fields",
			entry: BootEntry{
				Name:        "ubuntu",
				Description: "Ubuntu 22.04",
				ISOURL:      "http://example.com/ubuntu.iso",
				Kernel:      "vmlinuz",
				Initrd:      "initrd.img",
				Args:        "autoinstall",
				AutoInstall: "/configs/autoinstall.yaml",
			},
			wantErr: nil,
		},
		{
			name: "missing name",
			entry: BootEntry{
				Description: "Ubuntu 22.04",
				Kernel:      "vmlinuz",
			},
			wantErr: ErrInvalidBootEntry,
		},
		{
			name: "missing description",
			entry: BootEntry{
				Name:   "ubuntu",
				Kernel: "vmlinuz",
			},
			wantErr: ErrInvalidBootEntry,
		},
		{
			name: "missing all boot sources",
			entry: BootEntry{
				Name:        "ubuntu",
				Description: "Ubuntu 22.04",
			},
			wantErr: ErrInvalidBootEntry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error containing %v, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestServerConfig_GetServerIP(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr bool
	}{
		{
			name: "with explicit external URL IP",
			cfg: ServerConfig{
				ExternalURL: "http://192.168.1.100:8080",
			},
			wantErr: false,
		},
		{
			name: "with DHCP server IP",
			cfg: ServerConfig{
				DHCPServerIP: "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "with loopback interface",
			cfg: ServerConfig{
				Interface: "lo",
			},
			wantErr: true, // loopback is skipped in getInterfaceIP
		},
		{
			name:    "auto-detect default IP",
			cfg:     ServerConfig{},
			wantErr: false, // Should find at least one non-loopback interface
		},
		{
			name: "invalid interface",
			cfg: ServerConfig{
				Interface: "nonexistent999",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := tt.cfg.GetServerIP()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if ip == "" {
					t.Error("expected non-empty IP address")
				}
			}
		})
	}
}

func TestGetInterfaceIP(t *testing.T) {
	tests := []struct {
		name      string
		ifaceName string
		wantErr   error
	}{
		{
			name:      "loopback interface",
			ifaceName: "lo",
			wantErr:   ErrNoServerIP, // loopback is skipped
		},
		{
			name:      "nonexistent interface",
			ifaceName: "nonexistent999",
			wantErr:   ErrInvalidInterface,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := getInterfaceIP(tt.ifaceName)
			if tt.wantErr != nil {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ip == "" {
					t.Error("expected non-empty IP when no error")
				}
			}
		})
	}
}

func TestGetDefaultIP(t *testing.T) {
	// This test just ensures the function doesn't panic
	ip, err := getDefaultIP()

	// We should either get a valid IP or an error, but not both
	if err != nil && ip != "" {
		t.Error("got both error and IP")
	}

	// In most systems, there should be at least one non-loopback interface
	if err != nil && !errors.Is(err, ErrNoServerIP) {
		t.Errorf("unexpected error type: %v", err)
	}
}

func TestExtractIPFromURL(t *testing.T) {
	tests := []struct {
		name   string
		urlStr string
		want   string
	}{
		{
			name:   "HTTP URL with IP and port",
			urlStr: "http://192.168.1.100:8080",
			want:   "192.168.1.100",
		},
		{
			name:   "HTTPS URL with IP and port",
			urlStr: "https://10.0.0.1:443",
			want:   "10.0.0.1",
		},
		{
			name:   "IP without scheme",
			urlStr: "172.16.0.1:8080",
			want:   "172.16.0.1",
		},
		{
			name:   "IP without port",
			urlStr: "192.168.1.1",
			want:   "192.168.1.1",
		},
		{
			name:   "URL with path",
			urlStr: "http://192.168.1.100:8080/path/to/resource",
			want:   "192.168.1.100",
		},
		{
			name:   "hostname instead of IP",
			urlStr: "http://example.com:8080",
			want:   "",
		},
		{
			name:   "invalid URL",
			urlStr: "not-a-url",
			want:   "",
		},
		{
			name:   "empty string",
			urlStr: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPFromURL(tt.urlStr)
			if got != tt.want {
				t.Errorf("extractIPFromURL(%q) = %q, want %q", tt.urlStr, got, tt.want)
			}
		})
	}
}

func TestCalculateBroadcastIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		mask          string
		wantBroadcast string
	}{
		{
			name:          "typical class C network",
			ip:            "192.168.1.10",
			mask:          "255.255.255.0",
			wantBroadcast: "192.168.1.255",
		},
		{
			name:          "class B network",
			ip:            "172.16.10.20",
			mask:          "255.255.0.0",
			wantBroadcast: "172.16.255.255",
		},
		{
			name:          "custom subnet",
			ip:            "192.168.1.100",
			mask:          "255.255.255.128",
			wantBroadcast: "192.168.1.127",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netParseIP(tt.ip)
			mask := netParseIP(tt.mask)

			got := calculateBroadcastIP(ip, mask)
			if got.String() != tt.wantBroadcast {
				t.Errorf("calculateBroadcastIP(%s, %s) = %s, want %s",
					tt.ip, tt.mask, got.String(), tt.wantBroadcast)
			}
		})
	}
}

// Helper function for tests
func netParseIP(s string) []byte {
	ip := make([]byte, 4)
	var a, b, c, d int
	if n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d); n == 4 {
		ip[0], ip[1], ip[2], ip[3] = byte(a), byte(b), byte(c), byte(d)
	}
	return ip
}

func TestCalculateBroadcastIP_NilInputs(t *testing.T) {
	tests := []struct {
		name string
		ip   []byte
		mask []byte
	}{
		{
			name: "nil IP",
			ip:   nil,
			mask: []byte{255, 255, 255, 0},
		},
		{
			name: "nil mask",
			ip:   []byte{192, 168, 1, 10},
			mask: nil,
		},
		{
			name: "both nil",
			ip:   nil,
			mask: nil,
		},
		{
			name: "empty IP slice",
			ip:   []byte{},
			mask: []byte{255, 255, 255, 0},
		},
		{
			name: "IPv6 format IP (16 bytes, no valid IPv4)",
			ip:   make([]byte, 16),
			mask: []byte{255, 255, 255, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateBroadcastIP(tt.ip, tt.mask)
			if got != nil {
				t.Errorf("calculateBroadcastIP() expected nil, got %v", got)
			}
		})
	}
}

func TestGetInterfaceIP_EdgeCases(t *testing.T) {
	// Test with various interface edge cases
	tests := []struct {
		name      string
		ifaceName string
		wantErr   bool
	}{
		{
			name:      "empty interface name",
			ifaceName: "",
			wantErr:   true,
		},
		{
			name:      "interface with special characters",
			ifaceName: "eth0@veth123",
			wantErr:   true, // unlikely to exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getInterfaceIP(tt.ifaceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("getInterfaceIP(%q) error = %v, wantErr %v", tt.ifaceName, err, tt.wantErr)
			}
		})
	}
}

func TestExtractIPFromURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		urlStr string
		wantIP string
	}{
		{
			name:   "URL with path after IP",
			urlStr: "http://192.168.1.100/boot.ipxe",
			wantIP: "192.168.1.100",
		},
		{
			name:   "URL with port and path",
			urlStr: "http://10.0.0.1:8080/menu.ipxe",
			wantIP: "10.0.0.1",
		},
		{
			name:   "HTTPS URL",
			urlStr: "https://172.16.0.1:443/files/",
			wantIP: "172.16.0.1",
		},
		{
			name:   "hostname instead of IP",
			urlStr: "http://pxe.example.com:8080",
			wantIP: "",
		},
		{
			name:   "localhost hostname",
			urlStr: "http://localhost:8080",
			wantIP: "",
		},
		{
			name:   "empty string",
			urlStr: "",
			wantIP: "",
		},
		{
			name:   "just IP no scheme",
			urlStr: "192.168.1.1",
			wantIP: "192.168.1.1",
		},
		{
			name:   "IP with trailing slash",
			urlStr: "http://192.168.1.1/",
			wantIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPFromURL(tt.urlStr)
			if got != tt.wantIP {
				t.Errorf("extractIPFromURL(%q) = %q, want %q", tt.urlStr, got, tt.wantIP)
			}
		})
	}
}

func TestParseDHCPv4(t *testing.T) {
	ip, err := ParseDHCPv4("gateway", "192.0.2.1")
	if err != nil {
		t.Fatalf("ParseDHCPv4(192.0.2.1): %v", err)
	}
	if len(ip) != 4 || ip.String() != "192.0.2.1" {
		t.Errorf("got %v (len %d), want the four-byte form option 3 carries", ip, len(ip))
	}

	for _, bad := range []string{"", "router", "fd00::1", "192.0.2.256"} {
		_, err := ParseDHCPv4("dns", bad)
		var addrErr *DHCPAddressError
		if !errors.As(err, &addrErr) {
			t.Fatalf("ParseDHCPv4(%q): got %v, want a *DHCPAddressError", bad, err)
		}
		if addrErr.Option != "dns" || addrErr.Value != bad {
			t.Errorf("ParseDHCPv4(%q): got option %q value %q", bad, addrErr.Option, addrErr.Value)
		}
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseDHCPv4(%q): %v does not match ErrInvalidConfig", bad, err)
		}
	}
}
