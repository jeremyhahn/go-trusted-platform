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

package pxe

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vlan"
)

const (
	// DefaultQuarantineVLAN is the default VLAN for quarantined devices.
	// Sourced from the canonical pkg/sdn/vlan defaults (reference-network.md).
	DefaultQuarantineVLAN = vlan.DefaultQuarantine

	// DefaultProvisioningVLAN is the default VLAN for devices during provisioning.
	// Sourced from the canonical pkg/sdn/vlan defaults (reference-network.md).
	DefaultProvisioningVLAN = vlan.DefaultProvisioning

	// DefaultTrustedVLAN is the default VLAN for trusted (enrolled+authorized) devices.
	// Sourced from the canonical pkg/sdn/vlan defaults (reference-network.md).
	DefaultTrustedVLAN = vlan.DefaultTrusted

	// DefaultStorageVLAN is the default VLAN for storage zone devices.
	// Sourced from the canonical pkg/sdn/vlan defaults (reference-network.md).
	DefaultStorageVLAN = vlan.DefaultStorage

	// DefaultManagementVLAN is the default VLAN for the management zone.
	// Sourced from the canonical pkg/sdn/vlan defaults (reference-network.md).
	DefaultManagementVLAN = vlan.DefaultManagement

	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3

	// DefaultInstallTimeout is the default timeout for OS installation.
	DefaultInstallTimeout = 30 * time.Minute

	// DefaultEnrollmentTimeout is the default timeout for device enrollment.
	DefaultEnrollmentTimeout = 5 * time.Minute

	// DefaultWebhookPath is the default path for install completion webhooks.
	DefaultWebhookPath = "/api/v1/pxe/webhook/complete"

	// DefaultISORef is the default ISO registry reference.
	DefaultISORef = "iso/platform:latest"

	// DefaultUpstreamFirmwareURL is the default URL for upstream iPXE firmware.
	DefaultUpstreamFirmwareURL = "https://boot.ipxe.org/ipxe.efi"

	// FirmwareSourceUpstream indicates firmware is fetched from upstream.
	FirmwareSourceUpstream = "upstream"

	// FirmwareSourceCustom indicates firmware is loaded from a custom path.
	FirmwareSourceCustom = "custom"

	// FirmwareSourceEmbedded indicates firmware is embedded in the binary.
	FirmwareSourceEmbedded = "embedded"

	// MinVLANID is the minimum valid VLAN ID per IEEE 802.1Q.
	MinVLANID = vlan.MinVLAN

	// MaxVLANID is the maximum valid VLAN ID per IEEE 802.1Q.
	MaxVLANID = vlan.MaxVLAN
)

// ServiceConfig holds all configuration for the PXE provisioning service.
type ServiceConfig struct {
	// IPXEConfig is the underlying iPXE server configuration.
	IPXEConfig *ipxe.ServerConfig

	// BridgeName is the OVS bridge name for VLAN management.
	BridgeName string

	// QuarantineVLAN is the VLAN ID for quarantined devices (default: 202).
	QuarantineVLAN uint16

	// ProvisioningVLAN is the VLAN ID for devices during provisioning (default: 201).
	ProvisioningVLAN uint16

	// Firmware contains UEFI firmware verification configuration.
	Firmware *FirmwareConfig

	// RegistryAddr is the ISO registry endpoint address.
	RegistryAddr string

	// DefaultISORef is the default ISO registry reference (default: "iso/platform:latest").
	DefaultISORef string

	// ACMEServerIPs are the IP addresses of ACME servers accessible during provisioning.
	ACMEServerIPs []net.IP

	// DNSServerIPs are the IP addresses of DNS servers accessible during provisioning.
	DNSServerIPs []net.IP

	// MaxRetries is the maximum number of retry attempts (default: 3).
	MaxRetries int

	// InstallTimeout is the timeout for OS installation (default: 30m).
	InstallTimeout time.Duration

	// EnrollmentTimeout is the timeout for device enrollment (default: 5m).
	EnrollmentTimeout time.Duration

	// EnableAutoQuarantine enables automatic quarantine on security events (default: true).
	EnableAutoQuarantine bool

	// WebhookEnabled enables the install completion webhook endpoint.
	WebhookEnabled bool

	// WebhookPath is the URL path for install completion webhooks (default: "/api/v1/pxe/webhook/complete").
	WebhookPath string

	// WebhookSecret is the HMAC secret for webhook authentication.
	WebhookSecret string
}

// FirmwareConfig holds configuration for UEFI firmware verification.
type FirmwareConfig struct {
	// Source specifies the firmware source: "upstream", "custom", or "embedded".
	Source string

	// UpstreamURL is the URL for fetching upstream firmware (default: "https://boot.ipxe.org/ipxe.efi").
	UpstreamURL string

	// ExpectedDigest is the expected SHA256 digest of verified firmware (required for upstream source).
	ExpectedDigest string

	// CustomPath is the filesystem path for custom firmware (required for custom source).
	CustomPath string

	// RequireSecureBoot indicates whether UEFI Secure Boot is required (default: true).
	RequireSecureBoot bool
}

// DefaultServiceConfig returns a ServiceConfig with sensible defaults.
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		IPXEConfig:           ipxe.DefaultServerConfig(),
		BridgeName:           "",
		QuarantineVLAN:       DefaultQuarantineVLAN,
		ProvisioningVLAN:     DefaultProvisioningVLAN,
		Firmware:             DefaultFirmwareConfig(),
		RegistryAddr:         "",
		DefaultISORef:        DefaultISORef,
		ACMEServerIPs:        nil,
		DNSServerIPs:         nil,
		MaxRetries:           DefaultMaxRetries,
		InstallTimeout:       DefaultInstallTimeout,
		EnrollmentTimeout:    DefaultEnrollmentTimeout,
		EnableAutoQuarantine: true,
		WebhookEnabled:       false,
		WebhookPath:          DefaultWebhookPath,
		WebhookSecret:        "",
	}
}

// DefaultFirmwareConfig returns a FirmwareConfig with sensible defaults.
func DefaultFirmwareConfig() *FirmwareConfig {
	return &FirmwareConfig{
		Source:            FirmwareSourceEmbedded,
		UpstreamURL:       DefaultUpstreamFirmwareURL,
		ExpectedDigest:    "",
		CustomPath:        "",
		RequireSecureBoot: true,
	}
}

// Validate validates the ServiceConfig and returns an error if invalid.
func (c *ServiceConfig) Validate() error {
	// IPXEConfig must be set
	if c.IPXEConfig == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "IPXEConfig is required"}}
	}

	// BridgeName must not be empty
	if c.BridgeName == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "BridgeName is required"}}
	}

	// Validate VLAN IDs are in valid range (1-4094)
	if c.QuarantineVLAN < MinVLANID || c.QuarantineVLAN > MaxVLANID {
		return &SentinelCauseError{Sentinel: ErrInvalidVLAN, Cause: &MessageError{Msg: fmt.Sprintf("QuarantineVLAN must be between %d and %d, got %d", MinVLANID, MaxVLANID, c.QuarantineVLAN)}}
	}

	if c.ProvisioningVLAN < MinVLANID || c.ProvisioningVLAN > MaxVLANID {
		return &SentinelCauseError{Sentinel: ErrInvalidVLAN, Cause: &MessageError{Msg: fmt.Sprintf("ProvisioningVLAN must be between %d and %d, got %d", MinVLANID, MaxVLANID, c.ProvisioningVLAN)}}
	}

	// QuarantineVLAN must not equal ProvisioningVLAN
	if c.QuarantineVLAN == c.ProvisioningVLAN {
		return &SentinelCauseError{Sentinel: ErrInvalidVLAN, Cause: &MessageError{Msg: "QuarantineVLAN and ProvisioningVLAN must be different"}}
	}

	// Validate firmware config if present
	if c.Firmware != nil {
		if err := c.Firmware.Validate(); err != nil {
			return &WrappedError{Msg: "firmware config", Err: err}
		}
	}

	// Validate timeouts are positive
	if c.InstallTimeout <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidTimeout, Cause: &MessageError{Msg: "InstallTimeout must be positive"}}
	}

	if c.EnrollmentTimeout <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidTimeout, Cause: &MessageError{Msg: "EnrollmentTimeout must be positive"}}
	}

	// Validate MaxRetries is non-negative
	if c.MaxRetries < 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "MaxRetries must be non-negative"}}
	}

	// Validate webhook secret if webhook is enabled
	if c.WebhookEnabled && c.WebhookSecret == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "WebhookSecret is required when WebhookEnabled is true"}}
	}

	return nil
}

// Validate validates the FirmwareConfig and returns an error if invalid.
func (f *FirmwareConfig) Validate() error {
	switch f.Source {
	case FirmwareSourceUpstream:
		// ExpectedDigest is required for upstream source
		if f.ExpectedDigest == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidFirmwareConfig, Cause: &MessageError{Msg: "ExpectedDigest is required for upstream firmware source"}}
		}

		// UpstreamURL should be set (defaults to DefaultUpstreamFirmwareURL)
		if f.UpstreamURL == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidFirmwareConfig, Cause: &MessageError{Msg: "UpstreamURL is required for upstream firmware source"}}
		}

	case FirmwareSourceCustom:
		// CustomPath must exist for custom source
		if f.CustomPath == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidFirmwareConfig, Cause: &MessageError{Msg: "CustomPath is required for custom firmware source"}}
		}

		// Verify the custom path exists
		if _, err := os.Stat(f.CustomPath); os.IsNotExist(err) {
			return &SentinelCauseError{Sentinel: ErrFirmwareNotFound, Cause: &MessageError{Msg: fmt.Sprintf("CustomPath does not exist: %s", f.CustomPath)}}
		}

	case FirmwareSourceEmbedded:
		// No additional validation required for embedded source

	case "":
		return &SentinelCauseError{Sentinel: ErrInvalidFirmwareConfig, Cause: &MessageError{Msg: "Source is required"}}

	default:
		return &SentinelCauseError{Sentinel: ErrInvalidFirmwareConfig, Cause: &MessageError{Msg: fmt.Sprintf("unknown firmware source: %s", f.Source)}}
	}

	return nil
}
