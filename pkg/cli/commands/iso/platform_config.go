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

package iso

import (
	"fmt"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultServerPlatformConfigPath is the default path to the server platform config.
	DefaultServerPlatformConfigPath = "configs/platform/standalone/qemu.server.example.com.yaml"

	// DefaultClientPlatformConfigPath is the default path to the client platform config.
	DefaultClientPlatformConfigPath = "configs/platform/standalone/qemu.client.example.com.yaml"

	// platformTypeServer is the server platform type for ApplyNetworkConfig.
	platformTypeServer = "server"

	// platformTypeClient is the client platform type for ApplyNetworkConfig.
	platformTypeClient = "client"

	// platformTypeDHCP is the DHCP platform type for ApplyNetworkConfig (user-mode networking).
	platformTypeDHCP = "dhcp"

	// defaultPublicDNSPort is the default port for the platform public DNS server.
	defaultPublicDNSPort = 8053
)

// ReadServerPlatformConfig reads the server platform config file.
// The config should have all IPs and settings defined directly - no variable substitution.
// DNS zone records use macros like ${PRIVATE_IPv4} which are expanded at runtime
// by the DNS service using the dns.private-ipv4 and dns.public-ipv4 config values.
func ReadServerPlatformConfig(configPath string) ([]byte, error) {
	if configPath == "" {
		configPath = DefaultServerPlatformConfigPath
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, ErrPlatformConfigRead{Path: configPath, Reason: err.Error()}
	}

	return data, nil
}

// ReadClientPlatformConfig reads the client platform config file.
// The config should have all IPs and settings defined directly - no variable substitution.
func ReadClientPlatformConfig(configPath string) ([]byte, error) {
	if configPath == "" {
		configPath = DefaultClientPlatformConfigPath
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, ErrPlatformConfigRead{Path: configPath, Reason: err.Error()}
	}

	return data, nil
}

// WritePlatformConfig writes a platform config to a file.
func WritePlatformConfig(data []byte, path string) error {
	if err := os.WriteFile(path, data, 0644); err != nil {
		return ErrPlatformConfigWrite{Path: path, Reason: err.Error()}
	}
	return nil
}

// ApplyNetworkConfig modifies the platform config YAML to apply test network
// overrides. It updates the network.interfaces and network.dns sections based
// on the platform type (server, client, or dhcp).
//
// For server: sets static IP from netConfig.ServerIP with external DNS nameservers.
// For client: sets static IP from netConfig.ClientIP with upstream DNS pointing
// to the server's internal DNS on port 9053, plus search domains.
// For dhcp: sets DHCP interface with external DNS nameservers (used for
// user-mode networking where QEMU provides DHCP). netConfig may be nil for dhcp.
func ApplyNetworkConfig(platformData []byte, netConfig *testenv.NetworkConfig, platformType string, debug bool) ([]byte, error) {
	var config map[string]interface{}
	if err := yaml.Unmarshal(platformData, &config); err != nil {
		return nil, ErrPlatformConfigUnmarshal{Path: "<in-memory>", Reason: err.Error()}
	}

	// Set debug flag
	config["debug"] = debug

	// Build the network configuration based on platform type
	networkConfig, err := buildNetworkOverride(netConfig, platformType)
	if err != nil {
		return nil, err
	}
	config["network"] = networkConfig

	result, err := yaml.Marshal(config)
	if err != nil {
		return nil, ErrPlatformConfigMarshal{Reason: err.Error()}
	}

	return result, nil
}

// buildNetworkOverride constructs the network section map for a given platform type.
func buildNetworkOverride(netConfig *testenv.NetworkConfig, platformType string) (map[string]interface{}, error) {
	switch platformType {
	case platformTypeServer:
		if netConfig == nil {
			return nil, ErrNetworkConfigRequired{PlatformType: platformTypeServer}
		}
		return buildServerNetwork(netConfig), nil
	case platformTypeClient:
		if netConfig == nil {
			return nil, ErrNetworkConfigRequired{PlatformType: platformTypeClient}
		}
		return buildClientNetwork(netConfig), nil
	case platformTypeDHCP:
		return buildDHCPNetwork(), nil
	default:
		return nil, ErrUnsupportedPlatformType{PlatformType: platformType}
	}
}

// buildServerNetwork constructs the network override for a server platform.
func buildServerNetwork(netConfig *testenv.NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		"dns": map[string]interface{}{
			"nameservers": []string{"8.8.8.8", "8.8.4.4"},
		},
		"interfaces": []map[string]interface{}{
			{
				"name":         "eth0",
				"type":         "static",
				"ipv4-address": netConfig.ServerIP.String(),
				"ipv4-netmask": netConfig.SubnetMask(),
				"ipv4-gateway": netConfig.GatewayIP.String(),
				"auto-start":   true,
			},
		},
		"wait-online":  true,
		"wait-timeout": 30,
	}
}

// buildClientNetwork constructs the network override for a client platform.
func buildClientNetwork(netConfig *testenv.NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		"dns": map[string]interface{}{
			"upstream-dns":   fmt.Sprintf("%s#9053", netConfig.ServerIP.String()),
			"nameservers":    []string{"8.8.8.8", netConfig.ServerIP.String()},
			"search-domains": []string{netConfig.Domain},
		},
		"interfaces": []map[string]interface{}{
			{
				"name":         "eth0",
				"type":         "static",
				"ipv4-address": netConfig.ClientIP.String(),
				"ipv4-netmask": netConfig.SubnetMask(),
				"ipv4-gateway": netConfig.GatewayIP.String(),
				"auto-start":   true,
			},
		},
		"wait-online":  true,
		"wait-timeout": 30,
	}
}

// buildDHCPNetwork constructs the network override for DHCP (user-mode networking).
func buildDHCPNetwork() map[string]interface{} {
	return map[string]interface{}{
		"dns": map[string]interface{}{
			"nameservers": []string{"8.8.8.8", "8.8.4.4"},
		},
		"interfaces": []map[string]interface{}{
			{
				"name":       "eth0",
				"type":       "dhcp",
				"auto-start": true,
			},
		},
		"wait-online":  true,
		"wait-timeout": 30,
	}
}

// resolveBootstrapDNSServer determines the DNS server address for bootstrap
// operations. It checks the following sources in priority order:
//
//  1. The client platform config's dns.resolver.servers[0] (platform-wide default)
//  2. The client platform config's trust.bootstrap.dane.dns-server (scope-level override)
//  3. A fallback constructed from serverIP and the default public DNS port (8053)
//
// This allows the DNS server address to be centrally configured in the
// dns.resolver section rather than hardcoded per-service.
func resolveBootstrapDNSServer(clientConfigPath string, serverIP string) string {
	fallback := fmt.Sprintf("%s:%d", serverIP, defaultPublicDNSPort)

	configData, err := ReadClientPlatformConfig(clientConfigPath)
	if err != nil {
		return fallback
	}

	// Parse the resolver section from the dns config
	resolved := extractDNSServerFromConfig(configData)
	if resolved != "" {
		return resolved
	}

	return fallback
}

// dnsConfigFragment is a partial struct used to unmarshal the dns.resolver and
// trust.bootstrap.dane sections from a platform config YAML file.
type dnsConfigFragment struct {
	DNS *struct {
		Resolver *dns.ResolverConfig `yaml:"resolver"`
	} `yaml:"dns"`
	Trust *struct {
		Bootstrap *struct {
			DANE *struct {
				DNSServer string `yaml:"dns-server"`
			} `yaml:"dane"`
		} `yaml:"bootstrap"`
	} `yaml:"trust"`
}

// extractDNSServerFromConfig parses platform config YAML and extracts the DNS
// server address from the dns.resolver section or trust.bootstrap.dane.dns-server.
// extractDNSServerFromConfig returns an empty string if neither is configured.
// resolveServerHostname extracts the server's domain (hostname) from its platform
// config. This is needed for DANE TLSA lookups when the ServerURL uses an IP address,
// because TLSA records are published under the hostname, not the IP.
func resolveServerHostname(serverConfigPath string) string {
	configData, err := ReadServerPlatformConfig(serverConfigPath)
	if err != nil {
		return ""
	}
	var fragment struct {
		Domain string `yaml:"domain"`
	}
	if err := yaml.Unmarshal(configData, &fragment); err != nil {
		return ""
	}
	return fragment.Domain
}

func extractDNSServerFromConfig(configData []byte) string {
	var fragment dnsConfigFragment
	if err := yaml.Unmarshal(configData, &fragment); err != nil {
		return ""
	}

	// Priority 1: dns.resolver.servers[0]
	if fragment.DNS != nil && fragment.DNS.Resolver != nil {
		primary := fragment.DNS.Resolver.PrimaryServer()
		if primary != "" {
			return primary
		}
	}

	// Priority 2: trust.bootstrap.dane.dns-server
	if fragment.Trust != nil &&
		fragment.Trust.Bootstrap != nil &&
		fragment.Trust.Bootstrap.DANE != nil &&
		fragment.Trust.Bootstrap.DANE.DNSServer != "" {
		return fragment.Trust.Bootstrap.DANE.DNSServer
	}

	return ""
}
