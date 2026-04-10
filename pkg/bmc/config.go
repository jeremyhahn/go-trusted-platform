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

package bmc

import "fmt"

// Config holds baseboard management controller connection configuration.
type Config struct {
	Address       string   `yaml:"address" json:"address"`
	Port          int      `yaml:"port" json:"port"`
	Username      string   `yaml:"username" json:"username"`
	Password      string   `yaml:"password" json:"password" secret:"true"`
	Protocol      Protocol `yaml:"protocol" json:"protocol"`
	EncryptionKey string   `yaml:"encryption-key,omitempty" json:"encryption_key,omitempty" secret:"true"` // Hex-encoded KG key for IPMI 2.0 RAKP
	SkipTLSVerify bool     `yaml:"skip-tls-verify,omitempty" json:"skip_tls_verify,omitempty"`
	CACertPath    string   `yaml:"ca-cert-path,omitempty" json:"ca_cert_path,omitempty"` // Path to custom CA certificate PEM file
}

// DefaultConfig returns a Config with sensible defaults for IPMI.
func DefaultConfig() *Config {
	return &Config{
		Port:     623,
		Protocol: ProtocolIPMI,
	}
}

// DefaultRedfishConfig returns a Config with sensible defaults for Redfish.
func DefaultRedfishConfig() *Config {
	return &Config{
		Port:     443,
		Protocol: ProtocolRedfish,
	}
}

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if c.Address == "" {
		return ErrInvalidConfig{Field: "address", Reason: "address is required"}
	}
	if c.Port < 1 || c.Port > 65535 {
		return ErrInvalidConfig{Field: "port", Reason: "port must be between 1 and 65535"}
	}
	if !c.Protocol.IsValid() {
		return ErrInvalidConfig{Field: "protocol", Reason: "unsupported protocol"}
	}
	return nil
}

// Endpoint returns the address:port string for connecting to the BMC.
func (c *Config) Endpoint() string {
	return fmt.Sprintf("%s:%d", c.Address, c.Port)
}
