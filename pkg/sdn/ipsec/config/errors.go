// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package config

import "errors"

var (
	// ErrRequired is returned when a mandatory field is empty.
	ErrRequired = errors.New("ipsec: field is required")
	// ErrInvalidAddress is returned when an address is not a single
	// unicast IP address.
	ErrInvalidAddress = errors.New("ipsec: not a unicast IP address")
	// ErrDuplicatePeer is returned when a static peer is listed twice or
	// equals the local address.
	ErrDuplicatePeer = errors.New("ipsec: duplicate peer")
	// ErrFamilyMismatch is returned when a peer's address family differs
	// from the local address's: a transport SA joins two addresses of one
	// family.
	ErrFamilyMismatch = errors.New("ipsec: peer address family differs from the local address")
	// ErrInvalidInterface is returned when an interface name is not a valid
	// Linux interface name.
	ErrInvalidInterface = errors.New("ipsec: interface name is invalid")
	// ErrRelativePath is returned when a filesystem path is not absolute.
	ErrRelativePath = errors.New("ipsec: path must be absolute")
	// ErrInvalidHandle is returned when a token key handle is not a hex
	// CKA_ID.
	ErrInvalidHandle = errors.New("ipsec: token handle must be a hex CKA_ID")
	// ErrInvalidModule is returned when a token module is not a pkcs11
	// module name from strongswan.conf.
	ErrInvalidModule = errors.New("ipsec: token module must be a strongswan.conf pkcs11 module name")
	// ErrReplayWindowTooSmall is returned when the replay window is below
	// MinReplayWindow.
	ErrReplayWindowTooSmall = errors.New("ipsec: replay window below the minimum")
	// ErrLifetimeTooShort is returned when the certificate lifetime is
	// shorter than OutageFactor times the tolerated control-plane outage.
	ErrLifetimeTooShort = errors.New("ipsec: certificate lifetime shorter than 3x the tolerated control-plane outage")
	// ErrNegativeDuration is returned when a duration is negative.
	ErrNegativeDuration = errors.New("ipsec: duration must not be negative")
	// ErrInvalidRate is returned when a rate limit has a burst below its
	// rate.
	ErrInvalidRate = errors.New("ipsec: burst must be at least the rate")
	// ErrNotEnabled is returned when a controller is built from an absent
	// or disabled section.
	ErrNotEnabled = errors.New("ipsec: overlay IPsec is not enabled")
)

// ConfigError names the overlay.ipsec field that failed validation.
type ConfigError struct {
	// Field is the YAML path below overlay.ipsec ("local-address",
	// "static-peers[2]", "token.handle", ...).
	Field string
	// Err is the rule it broke.
	Err error
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "overlay.ipsec." + e.Field + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *ConfigError) Unwrap() error { return e.Err }
