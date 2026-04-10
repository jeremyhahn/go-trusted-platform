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

package testenv

import (
	"fmt"
	"net"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// ErrInvalidNetworkPhase is returned when a network phase configuration is invalid
type ErrInvalidNetworkPhase struct {
	Phase  string
	Reason string
}

func (e *ErrInvalidNetworkPhase) Error() string {
	return fmt.Sprintf("invalid network phase %s: %s", e.Phase, e.Reason)
}

// ErrMissingNetworkConfig is returned when a required network configuration is missing
type ErrMissingNetworkConfig struct {
	Phase string
}

func (e *ErrMissingNetworkConfig) Error() string {
	return fmt.Sprintf("missing network configuration for phase: %s", e.Phase)
}

// ErrInvalidIPAddress is returned when an IP address is invalid
type ErrInvalidIPAddress struct {
	Address string
	Reason  string
}

func (e *ErrInvalidIPAddress) Error() string {
	return fmt.Sprintf("invalid IP address %s: %s", e.Address, e.Reason)
}

// ProfileNetworkBuilder builds NetworkConfig from device profiles
type ProfileNetworkBuilder struct {
	serverProfile *deviceentities.DeviceProfile
	clientProfile *deviceentities.DeviceProfile
	baseConfig    *NetworkConfig
}

// NewProfileNetworkBuilder creates a builder with optional base config
func NewProfileNetworkBuilder(base *NetworkConfig) *ProfileNetworkBuilder {
	return &ProfileNetworkBuilder{
		baseConfig: base,
	}
}

// WithServerProfile sets the server device profile
func (b *ProfileNetworkBuilder) WithServerProfile(p *deviceentities.DeviceProfile) *ProfileNetworkBuilder {
	b.serverProfile = p
	return b
}

// WithClientProfile sets the client device profile
func (b *ProfileNetworkBuilder) WithClientProfile(p *deviceentities.DeviceProfile) *ProfileNetworkBuilder {
	b.clientProfile = p
	return b
}

// Build creates a NetworkConfig from the profiles
// Uses production network config from server profile and provisioning from client profile
func (b *ProfileNetworkBuilder) Build() (*NetworkConfig, error) {
	// Start with base config or create default
	cfg := b.baseConfig
	if cfg == nil {
		cfg = DefaultNetworkConfig()
	}

	// Extract server production network configuration
	if b.serverProfile != nil {
		prodNet := b.serverProfile.GetPostEnrollmentNetworkConfig()
		if prodNet != nil {
			serverIP, err := b.extractIPFromNetworkPhase(prodNet)
			if err != nil {
				return nil, fmt.Errorf("failed to extract server IP: %w", err)
			}
			cfg.ServerIP = serverIP

			// Extract subnet from server production network
			subnet, err := b.extractSubnetFromNetworkPhase(prodNet)
			if err != nil {
				return nil, fmt.Errorf("failed to extract server subnet: %w", err)
			}
			cfg.Subnet = subnet

			// Extract gateway if available
			if prodNet.Gateway != "" {
				gateway := net.ParseIP(prodNet.Gateway)
				if gateway == nil {
					return nil, &ErrInvalidIPAddress{
						Address: prodNet.Gateway,
						Reason:  "invalid gateway address",
					}
				}
				cfg.GatewayIP = gateway
			}
		} else {
			return nil, &ErrMissingNetworkConfig{Phase: "production (server)"}
		}
	}

	// Extract client provisioning network configuration
	if b.clientProfile != nil {
		provNet := b.clientProfile.GetEnrollmentNetworkConfig()
		if provNet != nil {
			clientIP, err := b.extractIPFromNetworkPhase(provNet)
			if err != nil {
				return nil, fmt.Errorf("failed to extract client IP: %w", err)
			}
			cfg.ClientIP = clientIP

			// If server profile wasn't provided, use client's subnet and gateway
			if b.serverProfile == nil {
				subnet, err := b.extractSubnetFromNetworkPhase(provNet)
				if err != nil {
					return nil, fmt.Errorf("failed to extract client subnet: %w", err)
				}
				cfg.Subnet = subnet

				// Also update server IP to be in the same subnet (first available IP after gateway)
				// Use gateway IP + 1 for server IP
				if provNet.Gateway != "" {
					gateway := net.ParseIP(provNet.Gateway)
					if gateway == nil {
						return nil, &ErrInvalidIPAddress{
							Address: provNet.Gateway,
							Reason:  "invalid gateway address",
						}
					}
					cfg.GatewayIP = gateway

					// Server IP is gateway IP + 1
					serverIP := make(net.IP, len(gateway))
					copy(serverIP, gateway)
					serverIP[len(serverIP)-1]++
					cfg.ServerIP = serverIP
				} else {
					// If no gateway specified, derive server IP from subnet
					serverIP := make(net.IP, len(subnet.IP))
					copy(serverIP, subnet.IP)
					// Network address + 2 (assuming +1 is gateway)
					serverIP[len(serverIP)-1] += 2
					cfg.ServerIP = serverIP
				}
			}
		} else {
			return nil, &ErrMissingNetworkConfig{Phase: "provisioning (client)"}
		}
	}

	// Validate the built configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid network configuration: %w", err)
	}

	return cfg, nil
}

// extractIPFromNetworkPhase extracts static IP or generates from DHCP pool
func (b *ProfileNetworkBuilder) extractIPFromNetworkPhase(phase *deviceentities.NetworkPhaseConfig) (net.IP, error) {
	if phase == nil {
		return nil, &ErrMissingNetworkConfig{Phase: "network phase is nil"}
	}

	// Prefer static IP if configured
	if phase.StaticIP != "" {
		ip := net.ParseIP(phase.StaticIP)
		if ip == nil {
			return nil, &ErrInvalidIPAddress{
				Address: phase.StaticIP,
				Reason:  "cannot parse static IP",
			}
		}
		return ip, nil
	}

	// If DHCP pool is configured, use the start of the range
	// In a real implementation, this would allocate from the pool
	if phase.DHCPPool != nil {
		if phase.DHCPPool.RangeStart != "" {
			ip := net.ParseIP(phase.DHCPPool.RangeStart)
			if ip == nil {
				return nil, &ErrInvalidIPAddress{
					Address: phase.DHCPPool.RangeStart,
					Reason:  "invalid DHCP pool range start",
				}
			}
			return ip, nil
		}
	}

	// Check legacy Subnet field (backward compatibility)
	if phase.Subnet != "" {
		_, subnet, err := net.ParseCIDR(phase.Subnet)
		if err != nil {
			return nil, &ErrInvalidIPAddress{
				Address: phase.Subnet,
				Reason:  fmt.Sprintf("invalid subnet CIDR: %v", err),
			}
		}
		// Generate first usable IP in subnet (network address + 1)
		ip := make(net.IP, len(subnet.IP))
		copy(ip, subnet.IP)
		ip[len(ip)-1]++
		return ip, nil
	}

	return nil, &ErrInvalidNetworkPhase{
		Phase:  "unknown",
		Reason: "no static IP, DHCP pool, or subnet configured",
	}
}

// extractSubnetFromNetworkPhase extracts subnet from network phase config
func (b *ProfileNetworkBuilder) extractSubnetFromNetworkPhase(phase *deviceentities.NetworkPhaseConfig) (*net.IPNet, error) {
	if phase == nil {
		return nil, &ErrMissingNetworkConfig{Phase: "network phase is nil"}
	}

	// Try DHCP pool network first
	if phase.DHCPPool != nil && phase.DHCPPool.Network != "" {
		_, subnet, err := net.ParseCIDR(phase.DHCPPool.Network)
		if err != nil {
			return nil, &ErrInvalidIPAddress{
				Address: phase.DHCPPool.Network,
				Reason:  fmt.Sprintf("invalid DHCP pool network: %v", err),
			}
		}
		return subnet, nil
	}

	// Try legacy Subnet field (backward compatibility)
	if phase.Subnet != "" {
		_, subnet, err := net.ParseCIDR(phase.Subnet)
		if err != nil {
			return nil, &ErrInvalidIPAddress{
				Address: phase.Subnet,
				Reason:  fmt.Sprintf("invalid subnet CIDR: %v", err),
			}
		}
		return subnet, nil
	}

	// If static IP is configured, try to infer subnet from it
	if phase.StaticIP != "" {
		ip := net.ParseIP(phase.StaticIP)
		if ip == nil {
			return nil, &ErrInvalidIPAddress{
				Address: phase.StaticIP,
				Reason:  "cannot parse static IP for subnet inference",
			}
		}
		// Default to /24 for IPv4 or /64 for IPv6
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(24, 32)
		} else {
			mask = net.CIDRMask(64, 128)
		}
		return &net.IPNet{
			IP:   ip.Mask(mask),
			Mask: mask,
		}, nil
	}

	return nil, &ErrInvalidNetworkPhase{
		Phase:  "unknown",
		Reason: "no DHCP pool network, subnet, or static IP configured",
	}
}
