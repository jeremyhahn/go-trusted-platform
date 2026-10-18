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

// Package ipxe provides integration tests for the iPXE boot services.
// These tests verify DHCP, TFTP, and HTTP server functionality in an
// isolated network environment suitable for PXE boot testing.
package ipxe

import (
	"net"
	"time"
)

// =============================================================================
// TFTP Options and Results
// =============================================================================

// TFTPDownloadResult contains the result of a TFTP file download.
type TFTPDownloadResult struct {
	// Filename is the downloaded filename.
	Filename string
	// Data is the file contents.
	Data []byte
	// Size is the file size in bytes.
	Size int64
	// TransferTime is the duration of the transfer.
	TransferTime time.Duration
}

// =============================================================================
// HTTP Options and Results
// =============================================================================

// HTTPBootScriptResult contains the result of fetching the boot script.
type HTTPBootScriptResult struct {
	// Script is the boot script content.
	Script string
	// ContentType is the HTTP content type.
	ContentType string
	// StatusCode is the HTTP status code.
	StatusCode int
}

// HTTPMenuScriptResult contains the result of fetching the menu script.
type HTTPMenuScriptResult struct {
	// Script is the menu script content.
	Script string
	// ContentType is the HTTP content type.
	ContentType string
	// StatusCode is the HTTP status code.
	StatusCode int
	// BootEntries are the parsed boot entries from the menu.
	BootEntries []string
}

// HTTPBootEntryResult contains the result of fetching a boot entry script.
type HTTPBootEntryResult struct {
	// EntryName is the name of the boot entry.
	EntryName string
	// Script is the boot entry script content.
	Script string
	// ContentType is the HTTP content type.
	ContentType string
	// StatusCode is the HTTP status code.
	StatusCode int
	// KernelURL is the kernel URL from the script.
	KernelURL string
	// InitrdURL is the initrd URL from the script.
	InitrdURL string
}

// HTTPHealthResult contains the result of the health check.
type HTTPHealthResult struct {
	// Status is the health status.
	Status string
	// StatusCode is the HTTP status code.
	StatusCode int
}

// =============================================================================
// Server Configuration
// =============================================================================

// TestServerConfig contains configuration for the iPXE test server.
type TestServerConfig struct {
	// ServerIP is the IP address of the PXE server.
	ServerIP net.IP
	// HTTPPort is the HTTP server port.
	HTTPPort int
	// TFTPPort is the TFTP server port.
	TFTPPort int
	// DHCPEnabled indicates if DHCP is enabled.
	DHCPEnabled bool
	// DHCPPort is the UDP port the DHCP server listens on.
	DHCPPort int
	// DHCPRangeStart is the start of the DHCP IP range.
	DHCPRangeStart net.IP
	// DHCPRangeEnd is the end of the DHCP IP range.
	DHCPRangeEnd net.IP
	// SubnetMask is the subnet mask.
	SubnetMask net.IPMask
	// Gateway is the default gateway.
	Gateway net.IP
	// BootEntries are the configured boot menu entries.
	BootEntries []BootEntryConfig
}

// BootEntryConfig contains configuration for a boot menu entry.
type BootEntryConfig struct {
	// Name is the entry identifier.
	Name string
	// Description is the human-readable description.
	Description string
	// ISOURL is the URL to the ISO file.
	ISOURL string
	// Kernel is the kernel path or URL.
	Kernel string
	// Initrd is the initrd path or URL.
	Initrd string
	// Args are the kernel arguments.
	Args string
}
