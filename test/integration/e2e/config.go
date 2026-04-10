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

//go:build integration
// +build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"fmt"
	"time"
)

// Test configuration constants
const (
	// Timeouts
	ServerBootTimeout      = 10 * time.Minute
	ClientBootTimeout      = 15 * time.Minute
	EnrollmentTimeout      = 10 * time.Minute
	NetworkTransitionWait  = 5 * time.Second
	HealthCheckInterval    = 5 * time.Second
	ServerReadyMaxAttempts = 120 // 10 minutes
	ClientReadyMaxAttempts = 180 // 15 minutes

	// Disk configuration
	DefaultDiskSize = "10G"
	DefaultMemoryMB = 4096
	DefaultCPUCores = 4

	// Network configuration - Provisioning VLAN
	ProvisioningVLAN     = 100
	ProvisioningBridge   = "br-prov"
	ProvisioningSubnet   = "10.100.0.0/24"
	ProvisioningGateway  = "10.100.0.1"
	ProvisioningServerIP = "10.100.0.10"
	ProvisioningDNSIP    = "10.100.0.10"

	// Network configuration - Production VLAN
	ProductionVLAN     = 200
	ProductionBridge   = "br-prod"
	ProductionSubnet   = "10.200.0.0/24"
	ProductionGateway  = "10.200.0.1"
	ProductionServerIP = "10.200.0.10"
	ProductionDNSIP    = "10.200.0.10"

	// Service ports
	ACMEServerPort = 8443
	DNSServerPort  = 9053

	// TPM attestation OIDs (TCG standard)
	OIDTPMManufacturer     = "2.23.133.2.1"
	OIDTPMModel            = "2.23.133.2.2"
	OIDTPMVersion          = "2.23.133.2.3"
	OIDTPMEKCertificate    = "2.23.133.8.1"
	OIDTPMPlatformCert     = "2.23.133.8.2"
	OIDTPMAIKCertificate   = "2.23.133.8.3"
	OIDTPMAttestationData  = "2.23.133.11.1"
	OIDTPMAttestationQuote = "2.23.133.11.2"
)

// TestConfig holds all configuration for the E2E test
type TestConfig struct {
	// Work directories
	WorkDir       string
	ServerWorkDir string
	ClientWorkDir string

	// Disk paths
	ServerDiskPath string
	ClientDiskPath string

	// ISO paths (optional - for full integration)
	ServerISO string
	ClientISO string

	// Resource allocation
	DiskSize string
	MemoryMB int
	CPUCores int

	// Network configuration
	ProvisioningNetwork NetworkConfig
	ProductionNetwork   NetworkConfig

	// Timeouts
	ServerBootTimeout time.Duration
	ClientBootTimeout time.Duration
	EnrollmentTimeout time.Duration
}

// NetworkConfig represents network phase configuration
type NetworkConfig struct {
	VLAN     uint16
	Bridge   string
	Subnet   string
	Gateway  string
	ServerIP string
	DNSIP    string
}

// DefaultTestConfig returns a default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		WorkDir:        "test-integration-e2e",
		ServerWorkDir:  "test-integration-e2e/server",
		ClientWorkDir:  "test-integration-e2e/client",
		ServerDiskPath: "test-integration-e2e/server-disk.qcow2",
		ClientDiskPath: "test-integration-e2e/client-disk.qcow2",
		DiskSize:       DefaultDiskSize,
		MemoryMB:       DefaultMemoryMB,
		CPUCores:       DefaultCPUCores,

		ProvisioningNetwork: NetworkConfig{
			VLAN:     ProvisioningVLAN,
			Bridge:   ProvisioningBridge,
			Subnet:   ProvisioningSubnet,
			Gateway:  ProvisioningGateway,
			ServerIP: ProvisioningServerIP,
			DNSIP:    ProvisioningDNSIP,
		},

		ProductionNetwork: NetworkConfig{
			VLAN:     ProductionVLAN,
			Bridge:   ProductionBridge,
			Subnet:   ProductionSubnet,
			Gateway:  ProductionGateway,
			ServerIP: ProductionServerIP,
			DNSIP:    ProductionDNSIP,
		},

		ServerBootTimeout: ServerBootTimeout,
		ClientBootTimeout: ClientBootTimeout,
		EnrollmentTimeout: EnrollmentTimeout,
	}
}

// Validate validates the test configuration
func (c *TestConfig) Validate() error {
	if c.WorkDir == "" {
		return fmt.Errorf("work directory is required")
	}
	if c.ServerDiskPath == "" {
		return fmt.Errorf("server disk path is required")
	}
	if c.ClientDiskPath == "" {
		return fmt.Errorf("client disk path is required")
	}
	if c.DiskSize == "" {
		return fmt.Errorf("disk size is required")
	}
	if c.MemoryMB <= 0 {
		return fmt.Errorf("memory must be positive")
	}
	if c.CPUCores <= 0 {
		return fmt.Errorf("CPU cores must be positive")
	}

	// Validate network configs
	if err := c.ProvisioningNetwork.Validate(); err != nil {
		return fmt.Errorf("invalid provisioning network: %w", err)
	}
	if err := c.ProductionNetwork.Validate(); err != nil {
		return fmt.Errorf("invalid production network: %w", err)
	}

	return nil
}

// Validate validates network configuration
func (n *NetworkConfig) Validate() error {
	if n.VLAN == 0 {
		return fmt.Errorf("VLAN is required")
	}
	if n.Bridge == "" {
		return fmt.Errorf("bridge name is required")
	}
	if n.Subnet == "" {
		return fmt.Errorf("subnet is required")
	}
	if n.Gateway == "" {
		return fmt.Errorf("gateway is required")
	}
	if n.ServerIP == "" {
		return fmt.Errorf("server IP is required")
	}
	return nil
}
