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

package v1

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

type Config struct {
	Name         string            `yaml:"name" json:"name" mapstructure:"name"`
	ACME         *ACMEConfig       `yaml:"acme" json:"acme" mapstructure:"acme"`
	Certificate  Identity          `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	Home         string            `yaml:"home" json:"home" mapstructure:"home"`
	Index        string            `yaml:"index" json:"index" mapstructure:"index"`
	JWT          JWT               `yaml:"jwt" json:"jwt" mapstructure:"jwt"`
	Key          *common.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Port         int               `yaml:"port" json:"port" mapstructure:"port"`
	Proxy        *ProxyConfig      `yaml:"proxy" json:"proxy" mapstructure:"proxy"`
	RewriteRules []*RewriteRule    `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
	TLSPort      int               `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	VirtualHosts *[]VirtualHost    `yaml:"virtual-hosts" json:"virtual_hosts" mapstructure:"virtual-hosts"`
	WebAuthn     *WebAuthn         `yaml:"webauthn" json:"webauthn" mapstructure:"webauthn"`
	CORS         *CORSConfig       `yaml:"cors" json:"cors" mapstructure:"cors"`
}

// ACMEConfig contains ACME server configuration for a webservice (YAML config)
type ACMEConfig struct {
	// Enabled indicates whether the ACME server is enabled for this webservice
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// DirectoryURL is the ACME directory endpoint URL for this webservice
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`
	// TermsOfService is the URL to the terms of service
	TermsOfService string `yaml:"terms-of-service" json:"terms_of_service" mapstructure:"terms-of-service"`
	// Challenges is the list of supported challenge types
	Challenges []string `yaml:"challenges" json:"challenges" mapstructure:"challenges"`
	// ExternalAccountRequired indicates whether external account binding is required
	ExternalAccountRequired bool `yaml:"external-account-required" json:"external_account_required" mapstructure:"external-account-required"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed-origins" json:"allowed_origins" mapstructure:"allowed-origins"`
	AllowedMethods   []string `yaml:"allowed-methods" json:"allowed_methods" mapstructure:"allowed-methods"`
	AllowedHeaders   []string `yaml:"allowed-headers" json:"allowed_headers" mapstructure:"allowed-headers"`
	AllowCredentials bool     `yaml:"allow-credentials" json:"allow_credentials" mapstructure:"allow-credentials"`
}

// ACMEIdentityConfig defines ACME-related configuration for an identity.
// Aliased from pkg/common so infrastructure packages (pkg/bmc) can use
// the same shape without importing webservice.
type ACMEIdentityConfig = common.ACMEIdentityConfig

// Identity is the webservice alias for common.Identity — the canonical
// ACME-managed TLS cert identity type shared across the platform.
type Identity = common.Identity

type JWT struct {
	Expiration int64  `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Issuer     string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
}

type ProxyConfig struct {
	Backends []string `yaml:"backends" json:"backends" mapstructure:"backends"`
}

type RewriteRule struct {
	Pattern string `yaml:"pattern" json:"pattern" mapstructure:"pattern"`
	Target  string `yaml:"target" json:"target" mapstructure:"target"`
}

type VirtualHost struct {
	Certificate  *Identity         `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	CORS         *CORSConfig       `yaml:"cors" json:"cors" mapstructure:"cors"`
	Home         string            `yaml:"home" json:"home" mapstructure:"home"`
	Hosts        []string          `yaml:"hosts" json:"hosts" mapstructure:"hosts"`
	Index        string            `yaml:"index" json:"index" mapstructure:"index"`
	Key          *common.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Proxy        *ProxyConfig      `yaml:"proxy" json:"proxy" mapstructure:"proxy"`
	RewriteRules []*RewriteRule    `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
}

type WebAuthn struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}
