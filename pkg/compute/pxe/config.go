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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3

	// DefaultInstallTimeout is the default timeout for OS installation.
	DefaultInstallTimeout = 30 * time.Minute

	// DefaultEnrollmentTimeout is the default timeout for device enrollment.
	DefaultEnrollmentTimeout = 5 * time.Minute

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
	MinVLANID uint16 = 1

	// MaxVLANID is the maximum valid VLAN ID per IEEE 802.1Q.
	MaxVLANID uint16 = netplan.MaxVLAN
)

// ServiceConfig holds all configuration for the PXE provisioning service.
type ServiceConfig struct {
	// IPXEConfig is the underlying iPXE server configuration.
	IPXEConfig *ipxe.ServerConfig

	// BridgeName is the OVS bridge name for VLAN management.
	BridgeName string

	// QuarantineVLAN is the VLAN ID of the quarantine zone, from the
	// network plan (NewServiceConfig).
	QuarantineVLAN uint16

	// ProvisioningVLAN is the VLAN ID of the provisioning zone, from the
	// network plan (NewServiceConfig).
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

	// WebhookEnabled mounts the install-completion webhook,
	// POST /api/v1/pxe/webhook/complete (default: false). When false the
	// route is not served at all. When true it is served WITHOUT
	// authentication -- see WebhookSecret and #238.
	WebhookEnabled bool

	// WebhookSecret is reserved for authenticating install-completion
	// webhooks. It is NOT CURRENTLY USED.
	//
	// Setting it protects nothing today: no code reads this field beyond the
	// validation below, and POST /api/v1/pxe/webhook/complete authenticates
	// nobody -- the handler identifies the device by a MAC address taken from
	// the request body, and MACs are not secrets. Configuring a value here
	// must not be read as evidence the endpoint is authenticated.
	//
	// The field is retained rather than removed because what a booting node
	// should present -- an HMAC over the body using this secret, IDevID over
	// mTLS, or a provisioning-session token -- is an open architecture
	// decision. See #238.
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

// NewServiceConfig returns a ServiceConfig with sensible defaults and the
// quarantine and provisioning VLANs of the network plan. There is no VLAN
// default: a nil plan is ErrNetworkPlanRequired.
func NewServiceConfig(plan *netplan.Plan) (*ServiceConfig, error) {
	if plan == nil {
		return nil, ErrNetworkPlanRequired{}
	}
	quarantine, err := plan.MustZone(zone.ZoneQuarantine)
	if err != nil {
		return nil, &WrappedError{Msg: "quarantine zone", Err: err}
	}
	provisioning, err := plan.MustZone(zone.ZoneProvisioning)
	if err != nil {
		return nil, &WrappedError{Msg: "provisioning zone", Err: err}
	}
	return &ServiceConfig{
		IPXEConfig:           ipxe.DefaultServerConfig(),
		BridgeName:           "",
		QuarantineVLAN:       quarantine.VLAN,
		ProvisioningVLAN:     provisioning.VLAN,
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
		WebhookSecret:        "",
	}, nil
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

	// Require WebhookSecret when webhooks are enabled.
	//
	// This requirement is currently a placeholder, and the message says so.
	// Demanding a credential the platform never checks tells an operator the
	// endpoint is protected when it is not -- a false assurance is worse than
	// an obviously open endpoint, because it stops the reader looking. The
	// requirement is kept so that configurations already carrying a secret
	// stay valid for whatever #238 decides.
	if c.WebhookEnabled && c.WebhookSecret == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{
			Msg: "WebhookSecret is required when WebhookEnabled is true. " +
				"NOTE: this secret is not yet enforced -- the install-completion " +
				"webhook currently authenticates no caller and identifies the device " +
				"by a MAC address from the request body. Setting it does not protect " +
				"the endpoint (see #238)"}}
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
