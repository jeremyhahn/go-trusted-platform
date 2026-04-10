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

// Package daemon implements the platformd daemon that manages the Trusted Platform.
//
// The daemon package provides the core runtime for the go-trusted-platform,
// exposing platform services through multiple protocols (Unix socket, gRPC, REST,
// QUIC, and MCP) for maximum interoperability across different client types.
//
// # Architecture
//
// The daemon follows a multi-protocol server architecture:
//
//	                    +------------------+
//	                    |     Daemon       |
//	                    |   (Lifecycle)    |
//	                    +--------+---------+
//	                             |
//	     +-----------+-----------+-----------+-----------+
//	     |           |           |           |           |
//	+----+----+ +----+----+ +----+----+ +----+----+ +----+----+
//	|  Unix   | |  gRPC   | |  REST   | |  QUIC   | |   MCP   |
//	| Socket  | | Server  | | Server  | | Server  | | Server  |
//	+---------+ +---------+ +---------+ +---------+ +---------+
//	     |           |           |           |           |
//	     +-----+-----+-----+-----+-----+-----+-----+-----+
//	                       |
//	               +-------+-------+
//	               |   Services    |
//	               | CA, IAM, KMS, |
//	               | Device, etc.  |
//	               +---------------+
//
// # Protocol Support
//
// The daemon supports five communication protocols:
//
//   - Unix Socket: High-performance local IPC for CLI and local services
//   - gRPC: High-performance RPC for service-to-service communication
//   - REST: HTTP/HTTPS for web clients and external integrations
//   - QUIC: Low-latency UDP-based transport for mobile and edge clients
//   - MCP: Model Context Protocol for AI/LLM integration
//
// # Services
//
// The daemon manages several core platform services:
//
// Certificate Authority (CA) Service:
//   - X.509 certificate issuance and management
//   - Certificate signing requests (CSR) processing
//   - Certificate revocation list (CRL) management
//   - OCSP responder functionality
//
// Identity and Access Management (IAM) Service:
//   - User, group, and role management
//   - Policy-based authorization (PEP)
//   - Multi-factor authentication (MFA)
//   - OAuth application management
//   - Session management
//   - Audit logging
//
// Key Management Service (KMS):
//   - Cryptographic key generation and storage
//   - Key wrapping and unwrapping
//   - Data key management
//   - TPM-backed key protection
//
// Device Service:
//   - Device registration and lifecycle
//   - TPM attestation
//   - IDevID/IAK certificate provisioning
//   - Device health monitoring
//
// Virtual TPM (vTPM) Service:
//   - Software TPM emulation for testing
//   - TPM quote generation
//   - PCR management
//
// # IAM Service Architecture
//
// The IAM subsystem integrates with QuicBaaS's IAM components:
//
//	+------------------+     +------------------+
//	| IAMGRPCService   |     |   IAMService     |
//	| (gRPC Protocol)  |     | (Unix Protocol)  |
//	+--------+---------+     +--------+---------+
//	         |                        |
//	         +------------+-----------+
//	                      |
//	         +------------+------------+
//	         |    QuicBaaS IAM         |
//	         | (TenantManager,         |
//	         |  IdentityStore,         |
//	         |  PolicyEngine,          |
//	         |  AppManager)            |
//	         +-------------------------+
//
// IAMService (iam_service.go):
//   - Wraps QuicBaaS IAM for Unix socket protocol
//   - Requires -tags iam build flag
//   - Manages service lifecycle (start/stop)
//   - Registers native opcode handlers
//
// IAMGRPCService (iam_grpc_service.go):
//   - Implements Platform IAM gRPC service
//   - Converts between platform and QuicBaaS protobuf types
//   - Handles pagination, validation, and error mapping
//
// QUICIAMService (quic_iam.go):
//   - Defines QUIC protocol interface for IAM
//   - Binary-encoded request/response types
//   - Opcode-based message routing
//
// # Configuration
//
// The daemon is configured via the Config struct:
//
//	config := &daemon.Config{
//	    Socket: daemon.SocketConfig{
//	        Path: "/run/platformd.sock",
//	        Permissions: 0660,
//	    },
//	    GRPC: daemon.GRPCConfig{
//	        Address: ":10443",
//	        TLS: &daemon.TLSConfig{...},
//	    },
//	    REST: daemon.RESTConfig{
//	        Address: ":8443",
//	        TLS: &daemon.TLSConfig{...},
//	    },
//	    QUIC: daemon.QUICConfig{
//	        Address: ":9444",
//	    },
//	    MCP: daemon.MCPConfig{
//	        Address: ":9445",
//	    },
//	}
//
// # Usage
//
// Basic daemon lifecycle:
//
//	// Create daemon
//	d, err := daemon.New(config, app)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start daemon
//	ctx := context.Background()
//	if err := d.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Wait for shutdown signal
//	<-ctx.Done()
//
//	// Stop daemon gracefully
//	if err := d.Stop(ctx); err != nil {
//	    log.Printf("shutdown error: %v", err)
//	}
//
// # Functional Options
//
// The daemon supports functional options for customization:
//
//	d, err := daemon.New(config, app,
//	    daemon.WithUnixServer(customUnixServer),
//	    daemon.WithGRPCServer(customGRPCServer),
//	    daemon.WithQUICServer(customQUICServer),
//	    daemon.WithRESTServer(customRESTServer),
//	    daemon.WithMCPServer(customMCPServer),
//	)
//
// # Health Monitoring
//
// The daemon integrates with the health registry for monitoring:
//
//	registry := d.HealthRegistry()
//	status := registry.GetStatus("iam")
//
// # Thread Safety
//
// The Daemon is safe for concurrent use. Internal state is protected by
// atomic operations and proper synchronization primitives.
//
// # Build Tags
//
// Some features require specific build tags:
//
//   - iam: Enable IAM service integration with QuicBaaS
//   - tpm: Enable hardware TPM support
//   - vtpm: Enable virtual TPM support
package daemon
