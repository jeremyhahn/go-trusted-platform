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
	"context"
	"net"
	"time"
)

// IPXECommands defines the central command set for iPXE integration testing.
// This interface abstracts the protocol-specific operations for testing
// DHCP, TFTP, and HTTP boot services.
type IPXECommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// DHCP Commands
	SendDHCPDiscover(ctx context.Context, opts DHCPDiscoverOptions) (*DHCPOfferResult, error)
	SendDHCPRequest(ctx context.Context, opts DHCPRequestOptions) (*DHCPAckResult, error)

	// TFTP Commands
	TFTPDownload(ctx context.Context, filename string) (*TFTPDownloadResult, error)
	TFTPList(ctx context.Context) (*TFTPListResult, error)

	// HTTP Commands
	HTTPGetBootScript(ctx context.Context) (*HTTPBootScriptResult, error)
	HTTPGetMenuScript(ctx context.Context) (*HTTPMenuScriptResult, error)
	HTTPGetBootEntry(ctx context.Context, entryName string) (*HTTPBootEntryResult, error)
	HTTPGetHealth(ctx context.Context) (*HTTPHealthResult, error)
	HTTPGetFile(ctx context.Context, path string) (*HTTPFileResult, error)
}

// =============================================================================
// DHCP Options and Results
// =============================================================================

// DHCPDiscoverOptions contains options for sending a DHCP DISCOVER packet.
type DHCPDiscoverOptions struct {
	// ClientMAC is the MAC address of the client.
	ClientMAC net.HardwareAddr
	// ClientArch is the client architecture (0x0007 = EFI x64).
	ClientArch uint16
	// IsPXEClient indicates if the client is a PXE client.
	IsPXEClient bool
	// IsIPXEClient indicates if the client is already running iPXE.
	IsIPXEClient bool
	// VendorClass is the vendor class identifier (e.g., "PXEClient").
	VendorClass string
}

// DHCPOfferResult contains the result of a DHCP DISCOVER request.
type DHCPOfferResult struct {
	// YourIP is the offered IP address.
	YourIP net.IP
	// ServerIP is the DHCP server IP.
	ServerIP net.IP
	// SubnetMask is the subnet mask.
	SubnetMask net.IPMask
	// Router is the default gateway.
	Router net.IP
	// DNS is the DNS server.
	DNS net.IP
	// LeaseTime is the offered lease duration.
	LeaseTime time.Duration
	// BootFilename is the boot filename (for non-iPXE clients).
	BootFilename string
	// TFTPServerName is the TFTP server hostname.
	TFTPServerName string
	// TransactionID is the DHCP transaction ID.
	TransactionID uint32
}

// DHCPRequestOptions contains options for sending a DHCP REQUEST packet.
type DHCPRequestOptions struct {
	// ClientMAC is the MAC address of the client.
	ClientMAC net.HardwareAddr
	// RequestedIP is the IP address being requested.
	RequestedIP net.IP
	// ServerIP is the DHCP server IP.
	ServerIP net.IP
	// TransactionID is the DHCP transaction ID from the OFFER.
	TransactionID uint32
	// ClientArch is the client architecture.
	ClientArch uint16
	// IsPXEClient indicates if the client is a PXE client.
	IsPXEClient bool
	// IsIPXEClient indicates if the client is already running iPXE.
	IsIPXEClient bool
}

// DHCPAckResult contains the result of a DHCP REQUEST.
type DHCPAckResult struct {
	// YourIP is the confirmed IP address.
	YourIP net.IP
	// ServerIP is the DHCP server IP.
	ServerIP net.IP
	// SubnetMask is the subnet mask.
	SubnetMask net.IPMask
	// Router is the default gateway.
	Router net.IP
	// DNS is the DNS server.
	DNS net.IP
	// LeaseTime is the confirmed lease duration.
	LeaseTime time.Duration
	// BootFilename is the boot filename.
	BootFilename string
	// TFTPServerName is the TFTP server hostname.
	TFTPServerName string
	// TFTPServerIP is the TFTP server IP.
	TFTPServerIP net.IP
}

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

// TFTPListResult contains the result of listing available TFTP files.
type TFTPListResult struct {
	// Files is the list of available firmware files.
	Files []TFTPFileInfo
}

// TFTPFileInfo contains information about a TFTP file.
type TFTPFileInfo struct {
	// Filename is the name of the file.
	Filename string
	// Size is the file size in bytes.
	Size int64
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

// HTTPFileResult contains the result of fetching a file.
type HTTPFileResult struct {
	// Path is the file path.
	Path string
	// Data is the file contents.
	Data []byte
	// Size is the file size.
	Size int64
	// ContentType is the HTTP content type.
	ContentType string
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
