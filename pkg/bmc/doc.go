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

// Package bmc provides an abstraction layer for Baseboard Management Controller
// (BMC) operations using multiple protocol backends.
//
// The IPMI backend implements pure Go IPMI 2.0 RMCP+ transport with the full
// RAKP (Remote Authenticated Key Exchange Protocol) handshake, HMAC-SHA1/SHA256
// authentication, HMAC-SHA1-96/SHA256-128 integrity, and AES-CBC-128
// confidentiality for secure communication with modern BMCs.
//
// The Redfish backend implements the DMTF Redfish REST API over HTTPS with
// automatic service root discovery, vendor-agnostic collection enumeration,
// and support for power management, boot device configuration, sensor readings,
// system inventory, and virtual media operations.
//
// Use [NewDefaultClientFactory] to create clients that auto-select the protocol
// backend based on configuration, or use [NewIPMIClientFactory] and
// [NewRedfishClientFactory] for protocol-specific factories.
//
// The package provides power management, boot device configuration, sensor
// readings via SDR repository parsing (IPMI) or Thermal/Power resources (Redfish),
// system inventory via FRU data reading (IPMI) or System resources (Redfish),
// virtual media operations (Redfish only), and chassis status capabilities
// without requiring any external binaries or CGO dependencies.
package bmc
