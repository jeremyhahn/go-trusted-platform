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

package fido2

import "time"

// Config holds FIDO2 configuration
type Config struct {
	// Timeout for device operations
	Timeout time.Duration `yaml:"timeout" json:"timeout" mapstructure:"timeout"`

	// UserPresenceTimeout for waiting for user interaction
	UserPresenceTimeout time.Duration `yaml:"user-presence-timeout" json:"user_presence_timeout" mapstructure:"user-presence-timeout"`

	// RetryCount for device operations
	RetryCount int `yaml:"retry-count" json:"retry_count" mapstructure:"retry-count"`

	// RetryDelay between retries
	RetryDelay time.Duration `yaml:"retry-delay" json:"retry_delay" mapstructure:"retry-delay"`

	// Debug enables debug logging
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`

	// DevicePath specifies a specific device to use (optional)
	DevicePath string `yaml:"device-path,omitempty" json:"device_path,omitempty" mapstructure:"device-path"`

	// RelyingPartyID default RP ID for LUKS operations
	RelyingPartyID string `yaml:"relying-party-id" json:"relying_party_id" mapstructure:"relying-party-id"`

	// RelyingPartyName default RP name
	RelyingPartyName string `yaml:"relying-party-name" json:"relying_party_name" mapstructure:"relying-party-name"`

	// RequireUserVerification requires UV for operations
	RequireUserVerification bool `yaml:"require-user-verification" json:"require_user_verification" mapstructure:"require-user-verification"`

	// AllowedVendors limits devices to specific vendor IDs
	AllowedVendors []uint16 `yaml:"allowed-vendors,omitempty" json:"allowed_vendors,omitempty" mapstructure:"allowed-vendors"`

	// AllowedProducts limits devices to specific product IDs
	AllowedProducts []uint16 `yaml:"allowed-products,omitempty" json:"allowed_products,omitempty" mapstructure:"allowed-products"`

	// WorkaroundCanoKey enables workaround for CanoKey CBOR truncation bug
	WorkaroundCanoKey bool `yaml:"workaround-canokey" json:"workaround_canokey" mapstructure:"workaround-canokey"`
}

// DefaultConfig returns the default FIDO2 configuration
var DefaultConfig = Config{
	Timeout:                 DefaultTimeout,
	UserPresenceTimeout:     DefaultUserPresenceTimeout,
	RetryCount:              DefaultRetryCount,
	RetryDelay:              DefaultRetryDelay,
	Debug:                   false,
	RelyingPartyID:          "luks-unlock",
	RelyingPartyName:        "LUKS Disk Encryption",
	RequireUserVerification: false,
	WorkaroundCanoKey:       true,
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.UserPresenceTimeout <= 0 {
		c.UserPresenceTimeout = DefaultUserPresenceTimeout
	}
	if c.RetryCount < 0 {
		c.RetryCount = DefaultRetryCount
	}
	if c.RetryDelay < 0 {
		c.RetryDelay = DefaultRetryDelay
	}
	if c.RelyingPartyID == "" {
		c.RelyingPartyID = "luks-unlock"
	}
	if c.RelyingPartyName == "" {
		c.RelyingPartyName = "LUKS Disk Encryption"
	}
	return nil
}
