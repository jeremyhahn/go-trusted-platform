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

package bmc

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// Config holds baseboard management controller connection configuration.
type Config struct {
	Address       string   `yaml:"address" json:"address"`
	Port          int      `yaml:"port" json:"port"`
	Username      string   `yaml:"username" json:"username"`
	Password      string   `yaml:"password" json:"password" secret:"true"`
	Protocol      Protocol `yaml:"protocol" json:"protocol"`
	EncryptionKey string   `yaml:"encryption-key,omitempty" json:"encryption_key,omitempty" secret:"true"` // Hex-encoded KG key for IPMI 2.0 RAKP

	// SOLPayloadInstance overrides the IPMI 2.0 SOL payload instance the
	// Console session activates against. Most BMCs route serial-console
	// bytes to instance 0x01 (the IPMI default); a few — notably
	// Supermicro X10SDV-TP8F — route to 0x02. The platform's quirk
	// registry supplies the correct instance for known boards
	// automatically; this field is the explicit operator override for
	// new hardware before a quirk is added.
	//
	// Zero (the YAML default) means "consult the quirk registry, fall
	// back to 0x01". Permitted values: 0x01 - 0x0F per IPMI 2.0
	// Table 24-2.
	SOLPayloadInstance byte `yaml:"sol-payload-instance,omitempty" json:"sol_payload_instance,omitempty"`

	// Certificate is the BMC web-server TLS identity when ACME-based
	// issuance is configured for this BMC. Uses the common.Identity
	// type so operators get the identical YAML surface across every
	// ACME-managed identity (webservice TLS, BMC TLS, etc.).
	//
	// When nil, BMC TLS management is disabled. When non-nil, Key
	// must also be set, and Certificate.ACME.Challenge
	// MUST equal "dns-01" — BMCs sit on isolated management VLANs
	// unreachable from ACME servers, so http-01 validation cannot
	// succeed.
	Certificate *common.Identity `yaml:"certificate,omitempty" json:"certificate,omitempty" mapstructure:"certificate"`

	// Key describes the key algorithm and storage for the BMC TLS
	// cert. Same shape as webservice's Key (common.KeyConfig).
	Key *common.KeyConfig `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key"`

	// Backend pins the CertificateManager backend for this BMC's TLS
	// cert deployment. Empty or "auto" lets AutoCertManager probe the
	// vendor and pick the recommended backend. Explicit values
	// "redfish" or "smc-cgi" bypass the probe.
	Backend CertBackend `yaml:"backend,omitempty" json:"backend,omitempty" mapstructure:"backend"`

	// AllowCGIFallback enables the AutoCertManager to select the
	// Supermicro ATEN CGI cert upload backend in auto mode. Default
	// false — gated until hardware validation clears (task #9).
	AllowCGIFallback bool `yaml:"allow_cgi_fallback,omitempty" json:"allow_cgi_fallback,omitempty"`

	// TLS is the runtime TLS provider injected by the daemon after config
	// loading. It is never serialized; callers that load Config from YAML
	// must inject a provider separately. When non-nil, BuildTLSConfig
	// delegates to it exclusively. When nil, system roots with TLS 1.2+
	// minimum are used — connections to BMCs presenting self-signed or
	// private-CA certificates will fail, which is the correct secure
	// default; operators must configure a TLSProvider.
	TLS TLSProvider `yaml:"-" json:"-"`

	// Enrollment controls which optional steps the BMC enrollment ceremony
	// performs for this BMC. Nil selects DefaultEnrollmentConfig.
	Enrollment *EnrollmentConfig `yaml:"enrollment,omitempty" json:"enrollment,omitempty" mapstructure:"enrollment"`
}

// effectiveEnrollment returns the enrollment configuration in effect for
// this BMC: the explicit Enrollment when set, otherwise the package default.
func (c *Config) effectiveEnrollment() *EnrollmentConfig {
	if c.Enrollment != nil {
		return c.Enrollment
	}
	return DefaultEnrollmentConfig()
}

// DefaultConfig returns a Config with sensible defaults for IPMI.
func DefaultConfig() *Config {
	return &Config{
		Port:     623,
		Protocol: ProtocolIPMI,
	}
}

// DefaultRedfishConfig returns a Config with sensible defaults for Redfish.
func DefaultRedfishConfig() *Config {
	return &Config{
		Port:     443,
		Protocol: ProtocolRedfish,
	}
}

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if c.Address == "" {
		return ErrInvalidConfig{Field: "address", Reason: "address is required"}
	}
	if c.Port < 1 || c.Port > 65535 {
		return ErrInvalidConfig{Field: "port", Reason: "port must be between 1 and 65535"}
	}
	if !c.Protocol.IsValid() {
		return ErrInvalidConfig{Field: "protocol", Reason: "unsupported protocol"}
	}
	if err := c.validateCertBlock(); err != nil {
		return err
	}
	return nil
}

// validateCertBlock enforces the Certificate+Key+Backend invariants
// described in the Config.Certificate godoc.
func (c *Config) validateCertBlock() error {
	hasCert := c.Certificate != nil
	hasKey := c.Key != nil
	if hasCert != hasKey {
		return ErrInvalidConfig{
			Field:  "certificate/key",
			Reason: "certificate and key must both be set or both be absent",
		}
	}
	if !hasCert {
		// No cert management configured — Backend must also be empty
		// so the config accurately reflects "TLS management disabled".
		if c.Backend != "" {
			return ErrInvalidConfig{
				Field:  "backend",
				Reason: "backend is only valid when certificate and key are configured",
			}
		}
		return nil
	}
	if c.Backend != "" && !c.Backend.IsValid() {
		return ErrInvalidConfig{
			Field:  "backend",
			Reason: "unrecognized cert backend: " + string(c.Backend),
		}
	}
	if c.Certificate.ACME == nil || c.Certificate.ACME.Challenge == "" {
		return ErrInvalidConfig{
			Field:  "certificate.acme.challenge",
			Reason: "ACME challenge is required when certificate is configured",
		}
	}
	if c.Certificate.ACME.Challenge != "dns-01" {
		return ErrInvalidConfig{
			Field: "certificate.acme.challenge",
			Reason: fmt.Sprintf(
				"BMC cert issuance requires challenge=dns-01 (got %q); BMCs sit on isolated management VLANs unreachable from ACME servers, so http-01 cannot succeed",
				c.Certificate.ACME.Challenge),
		}
	}
	return nil
}

// Endpoint returns the address:port string for connecting to the BMC.
func (c *Config) Endpoint() string {
	return fmt.Sprintf("%s:%d", c.Address, c.Port)
}
