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

// Package pxe provides device provisioning orchestration with VLAN transition
// integration for the Trusted Platform.
//
// This package wraps the pkg/ipxe package and integrates it with the platform's
// VLAN transition system to provide secure, automated device provisioning. It
// implements a state machine for managing device lifecycle from discovery through
// enrollment and authorization.
//
// # UEFI Only
//
// This package supports UEFI Secure Boot exclusively. Legacy BIOS boot is not
// supported as it cannot meet trusted computing requirements. All devices must
// boot via UEFI with Secure Boot enabled to establish a chain of trust from
// firmware through the operating system.
//
// # Architecture
//
// The package integrates several existing platform components:
//
//	+----------------+     +------------------+     +------------------+
//	|    pkg/ipxe    |     | entities.Device  |     | Trusted Registry |
//	| (DHCP/TFTP/HTTP|     |    Profile       |     |  (QuicBaaS/OCI)  |
//	|    Servers)    |     +--------+---------+     +--------+---------+
//	+-------+--------+              |                        |
//	        |                       |                        |
//	        +----------+------------+------------------------+
//	                   |
//	           +-------+-------+
//	           |   pxe.Service |
//	           | (Orchestrator)|
//	           +-------+-------+
//	                   |
//	           +-------+-------+
//	           |  VLAN Manager |
//	           | (Transitions) |
//	           +---------------+
//
// # Device Provisioning States
//
// The provisioning state machine manages device lifecycle through these states:
//
//   - StateUnknown: Device has not been seen by the system
//   - StateDiscovered: Device detected via DHCP/PXE request (placed in quarantine VLAN)
//   - StateBooting: Device is booting iPXE firmware
//   - StateInstalling: Device is installing the operating system
//   - StateInstallComplete: OS installation finished (detected via webhook)
//   - StateEnrolling: Device is enrolling with the platform (IDevID/IAK provisioning)
//   - StateEnrolled: Device enrollment complete
//   - StateAuthorizing: Device is undergoing TPM attestation
//   - StateAuthorized: Device authorized for production (moved to production VLAN)
//
// State transitions trigger VLAN changes:
//
//	Discovered → Quarantine VLAN (isolated, restricted access)
//	Booting → Provisioning VLAN (access to PXE/TFTP/HTTP services)
//	Authorized → Production VLAN (full network access)
//
// # Type Reuse
//
// This package reuses existing platform types rather than defining new ones:
//
//   - installer.InstallConfig: OS installation configuration
//   - entities.DeviceProfile: Device profile with network phase configurations
//   - entities.NetworkPhaseConfig: VLAN and network settings per phase
//
// # Firmware Verification
//
// iPXE firmware downloaded from boot.ipxe.org is cryptographically verified
// before serving to clients. The package maintains a registry of known-good
// firmware hashes and validates firmware integrity on startup and during
// periodic checks.
//
// # ISO Registry
//
// Installation ISOs are stored in the platform's Trusted Registry, which is
// backed by QuicBaaS and OCI-compliant. This provides:
//
//   - Content-addressable storage with SHA-256 digests
//   - Signature verification for image authenticity
//   - Efficient distribution via OCI registry protocols
//   - Audit trail of all image operations
//
// # Multi-Protocol API
//
// The service is exposed through all platform protocols:
//
//	| Protocol | Transport | Port | Use Case                    |
//	|----------|-----------|------|-----------------------------|
//	| REST     | HTTP/HTTPS| 8443 | Web dashboard, external API |
//	| gRPC     | TCP       | 10443 | Service-to-service calls    |
//	| QUIC     | UDP       | 9444 | Low-latency operations      |
//	| MCP      | stdio/HTTP| 9445 | AI/LLM integration          |
//	| Unix     | Socket    | /run/platformd.sock | CLI, local IPC |
//
// # Event-Driven Architecture
//
// The package emits events for all state transitions, enabling:
//
//   - Real-time monitoring of provisioning progress
//   - Integration with external systems via webhooks
//   - Audit logging of device lifecycle events
//   - Custom automation workflows
//
// Supported events:
//
//   - DeviceDiscovered: New device detected
//   - DeviceBooting: Device started PXE boot
//   - InstallStarted: OS installation began
//   - InstallCompleted: OS installation finished
//   - EnrollmentStarted: Device enrollment initiated
//   - EnrollmentCompleted: Device enrolled successfully
//   - DeviceAuthorized: Device passed attestation
//   - VLANTransition: Device moved between VLANs
//
// # Webhook Support
//
// The package supports webhooks for install completion detection:
//
//	POST /api/v1/pxe/webhook/install-complete
//	{
//	    "device_id": "52:54:00:12:34:56",
//	    "status": "success",
//	    "timestamp": "2025-01-13T10:30:00Z"
//	}
//
// # Usage
//
// Create and start the PXE service:
//
//	import (
//	    "github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
//	    "github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
//	)
//
//	// Configure the underlying iPXE server
//	ipxeConfig := &ipxe.ServerConfig{
//	    Interface:     "eth0",
//	    HTTPPort:      8080,
//	    EnableDHCP:    true,
//	    DHCPRangeStart: "192.168.100.100",
//	    DHCPRangeEnd:   "192.168.100.200",
//	}
//
//	// Create PXE service with VLAN integration
//	service, err := pxe.NewService(
//	    pxe.WithIPXEConfig(ipxeConfig),
//	    pxe.WithVLANManager(vlanMgr),
//	    pxe.WithProfileStore(profileStore),
//	    pxe.WithRegistry(registry),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start the service. Start returns once the iPXE listeners have bound;
//	// the server runs until Stop or Close, not until ctx ends, and a
//	// stopped service can be started again.
//	ctx := context.Background()
//	if err := service.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Thread Safety
//
// The Service is safe for concurrent use. Internal state is protected by
// atomic operations and lock-free algorithms where possible.
//
// # References
//
//   - iPXE Documentation: https://ipxe.org/docs
//   - UEFI Specification: https://uefi.org/specs/UEFI/2.10/
//   - IEEE 802.1X: https://standards.ieee.org/ieee/802.1X/7345/
//   - TCG TPM 2.0 Specification: https://trustedcomputinggroup.org/
package pxe
