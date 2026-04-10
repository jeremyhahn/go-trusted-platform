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

// Package attestation provides attestation-gated DNS update support.
package attestation

import (
	"time"
)

// AttestationToken represents a validated TPM attestation token.
type AttestationToken struct {
	// Version of the token format
	Version int `json:"version"`

	// Issued timestamp
	Issued time.Time `json:"issued"`

	// Expires timestamp
	Expires time.Time `json:"expires"`

	// DeviceID is the unique device identifier
	DeviceID string `json:"device_id"`

	// EKFingerprint is the SHA-256 hash of the Endorsement Key certificate
	EKFingerprint string `json:"ek_fingerprint"`

	// PCRDigest is the SHA-256 hash of the quoted PCR values
	PCRDigest string `json:"pcr_digest"`

	// AllowedOperations lists permitted DNS operations (A, AAAA, TXT, PTR, etc.)
	AllowedOperations []string `json:"allowed_operations"`

	// AllowedZones lists zones this token can modify
	AllowedZones []string `json:"allowed_zones"`

	// Signature is the token signature
	Signature string `json:"signature"`
}

// IsExpired returns true if the token has expired.
func (t *AttestationToken) IsExpired() bool {
	return time.Now().After(t.Expires)
}

// IsValidFor checks if the token allows the given operation on the zone.
func (t *AttestationToken) IsValidFor(operation, zone string) bool {
	if t.IsExpired() {
		return false
	}

	// Check allowed operations
	opAllowed := false
	for _, op := range t.AllowedOperations {
		if op == operation || op == "*" {
			opAllowed = true
			break
		}
	}
	if !opAllowed {
		return false
	}

	// Check allowed zones
	for _, z := range t.AllowedZones {
		if z == zone || z == "*" {
			return true
		}
	}
	return false
}

// ZoneAttestationConfig defines attestation requirements for a zone.
type ZoneAttestationConfig struct {
	// Required indicates whether attestation is required for updates
	Required bool `yaml:"required" json:"required" mapstructure:"required"`

	// MaxAge is the maximum age of attestation evidence
	MaxAge time.Duration `yaml:"max-age" json:"max_age" mapstructure:"max_age"`

	// PCRPolicy is the name of the PCR policy to apply
	PCRPolicy string `yaml:"pcr-policy" json:"pcr_policy" mapstructure:"pcr_policy"`

	// AllowedEKCerts lists paths to allowed EK certificate CAs
	AllowedEKCerts []string `yaml:"allowed-ek-certs" json:"allowed_ek_certs" mapstructure:"allowed_ek_certs"`

	// Fallback defines behavior when attestation service is unavailable
	// Options: "deny", "allow-with-warning", "cached-quote"
	Fallback string `yaml:"fallback" json:"fallback" mapstructure:"fallback"`
}

// FallbackMode constants define behavior when attestation service is unavailable.
const (
	FallbackDeny             = "deny"
	FallbackAllowWithWarning = "allow-with-warning"
	FallbackCachedQuote      = "cached-quote"
)

// DefaultZoneAttestationConfig returns the default attestation configuration.
func DefaultZoneAttestationConfig() *ZoneAttestationConfig {
	return &ZoneAttestationConfig{
		Required:  true,
		MaxAge:    5 * time.Minute,
		PCRPolicy: "standard-boot",
		Fallback:  FallbackDeny,
	}
}
