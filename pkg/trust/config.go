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

// Package trust provides the platform-wide trust resolver. It maps a trust
// class (default, bmc, internal) and a peer endpoint onto a verified
// *tls.Config, *x509.CertPool, or raw CA bundle PEM by delegating to the
// canonical xkms generic resolver via the QuicBaaS SDK re-export.
//
// This package owns only:
//   - The three platform class constants (default, bmc, internal).
//   - Per-class strategy allowlists, including TOFU for default and bmc.
//   - platform-ca → provider-ca normalization before handing config to
//     the generic resolver.
//   - Type aliases so existing call sites keep compiling unchanged.
//
// Strategy dispatch, caching, install, and all per-strategy fetch logic
// live in go-xkms pkg/trust/resolver, reached through the QuicBaaS SDK
// re-export per the SDK-consumption invariant in CLAUDE.md.
package trust

import (
	"os"
	"strings"
	"time"

	xkmsresolver "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/resolver"
)

// Class identifies a trust scope. Each class carries its own strategy
// chain and per-strategy configuration.
type Class string

const (
	// ClassDefault is the trust class for the platform's own control
	// plane endpoints (CA bundle fetch at first boot, ACME directory,
	// webservice provisioning).
	ClassDefault Class = "default"

	// ClassBMC is the trust class for baseboard management controllers
	// (Redfish, IPMI-over-TLS, vendor CGI endpoints).
	ClassBMC Class = "bmc"

	// ClassInternal is the trust class for intra-platform services that
	// present platform-CA-issued certificates (attestation push, SDN
	// reporter, mTLS webservice clients).
	ClassInternal Class = "internal"
)

// Strategy identifies a single trust-establishment method within a
// class's ordered chain.
//
// The generic resolver (go-xkms/pkg/trust/resolver) recognises the string
// values directly; the platform-ca constant is normalised to provider-ca
// before being passed to the generic resolver.
type Strategy = xkmsresolver.Strategy

const (
	// StrategyDANE verifies the peer via DNSSEC-validated TLSA records
	// per RFC 7671.
	StrategyDANE = xkmsresolver.StrategyDANE

	// StrategyNoise fetches the CA bundle over a Noise_NK channel
	// authenticated by the server's static public key.
	StrategyNoise = xkmsresolver.StrategyNoise

	// StrategySPKI verifies the peer leaf certificate against a pinned
	// SHA-256 SubjectPublicKeyInfo digest (hex encoded).
	StrategySPKI = xkmsresolver.StrategySPKI

	// StrategyEmbedded trusts the operating system trust store. The ISO
	// build embeds the platform CA bundle into the image, so no network
	// fetch is performed.
	StrategyEmbedded = xkmsresolver.StrategyEmbedded

	// StrategyCAFile trusts a CA bundle PEM file on local disk.
	StrategyCAFile = xkmsresolver.StrategyCAFile

	// StrategyPlatformCA trusts the platform's own certificate authority
	// bundle, supplied by an injected CABundleProvider. In the platform
	// YAML this strategy is spelled "platform-ca"; the resolver
	// normalises it to "provider-ca" before delegating to the generic
	// resolver.
	StrategyPlatformCA Strategy = "platform-ca"

	// StrategyTOFU fetches a CA bundle from the scope's ServerURL over a
	// channel pinned on first use: the BUNDLE SERVER's leaf SPKI pin is
	// captured and persisted via the injected TOFUPinStore, and later
	// connections to that server verify the stored pin.
	//
	// It is NOT endpoint pinning. The resolver's tofu path discards the
	// caller's endpoint entirely, so tofu cannot verify an arbitrary TLS
	// server — which is why it is not allowed for ClassBMC (#83). To pin
	// an endpoint's own certificate, use StrategySPKI. Endpoint-pinning
	// tofu is requested upstream as go-xkms#139.
	//
	// Requires WithTOFUPinStore at construction time. TOFU is never an
	// implicit fallback — it must be listed explicitly in the strategies
	// chain.
	StrategyTOFU = xkmsresolver.StrategyTOFU
)

// allowedStrategies defines which strategies each class may use. The
// chains are intentionally narrow: internal services are always
// platform-CA verified; BMC endpoints never speak Noise.
var allowedStrategies = map[Class]map[Strategy]bool{
	ClassDefault: {
		StrategyDANE:     true,
		StrategyNoise:    true,
		StrategySPKI:     true,
		StrategyEmbedded: true,
		StrategyTOFU:     true,
	},
	ClassBMC: {
		StrategyDANE:   true,
		StrategySPKI:   true,
		StrategyCAFile: true,
		// StrategyTOFU is deliberately ABSENT — see #83. TOFU in this
		// stack is a CA-bundle FETCH pinned on first contact, not
		// endpoint pinning: the resolver's tofu path discards the
		// caller's endpoint and fetches a bundle from ServerURL. A BMC
		// serves Redfish, never a CA bundle, so tofu can never verify
		// one — with or without a ServerURL. Endpoint pinning for a BMC
		// is the spki strategy (bmc_spki_pin). Restore this entry when
		// upstream grows an endpoint-pinning tofu (go-xkms#139).
	},
	ClassInternal: {
		StrategyPlatformCA: true,
	},
}

// Config is the top-level `trust:` configuration. Each class is optional;
// an unconfigured class fails resolution with ErrClassNotConfigured.
//
// The YAML schema is deliberately flat (default:, bmc:, internal: at the
// top level) to remain backward compatible with existing operator configs
// and templates. Internally, Config.ToGeneric() projects these fields into
// the generic resolver's Scopes map with platform-ca → provider-ca
// normalisation.
type Config struct {
	Default  *ScopeConfig `yaml:"default,omitempty" json:"default,omitempty" mapstructure:"default"`
	BMC      *ScopeConfig `yaml:"bmc,omitempty" json:"bmc,omitempty" mapstructure:"bmc"`
	Internal *ScopeConfig `yaml:"internal,omitempty" json:"internal,omitempty" mapstructure:"internal"`
}

// ScopeConfig configures a single trust class: the ordered strategy chain
// plus per-strategy inputs.
type ScopeConfig struct {
	// Strategies is the ordered fallback chain. The resolver tries each
	// strategy in turn and returns the first success.
	Strategies []Strategy `yaml:"strategies" json:"strategies" mapstructure:"strategies"`

	// ServerURL is the CA bundle server URL (e.g.
	// "https://cp.example.com:8443") — the server a bundle is fetched
	// FROM, not the endpoint being verified.
	//
	// Required by the bundle-fetch strategies (noise, tofu, and the
	// dane/spki bundle paths used by CABundlePEM). It is NOT consulted
	// when dane or spki verify a caller-supplied endpoint on the TLS
	// path: those build an endpoint-level verifier from the endpoint
	// itself. A non-empty endpoint never populates ServerURL — the
	// substitution runs the other way, ServerURL standing in when a
	// caller passes an empty endpoint.
	ServerURL string `yaml:"server-url" json:"server_url" mapstructure:"server-url"`

	// Hostname is the DNS name under which TLSA records are published.
	// Required for DANE when ServerURL (or the caller's endpoint) uses
	// an IP address, because TLSA records live under the hostname (e.g.
	// _8443._tcp.cp.example.com), not the IP.
	Hostname string `yaml:"hostname" json:"hostname" mapstructure:"hostname"`

	// BundlePath overrides the CA bundle REST endpoint path used by the
	// fetch strategies. Empty selects the library default.
	BundlePath string `yaml:"bundle-path" json:"bundle_path" mapstructure:"bundle-path"`

	// PerMethodTimeout caps each individual strategy attempt.
	PerMethodTimeout time.Duration `yaml:"per-method-timeout" json:"per_method_timeout" mapstructure:"per-method-timeout"`

	// InstallToSystemTrust requests that a fetched CA bundle be installed
	// into the OS trust store after a successful fetch.
	InstallToSystemTrust bool `yaml:"install-to-system-trust" json:"install_to_system_trust" mapstructure:"install-to-system-trust"`

	// DANE carries DANE/TLSA resolver options.
	DANE *DANEConfig `yaml:"dane,omitempty" json:"dane,omitempty" mapstructure:"dane"`

	// Noise carries Noise_NK client options.
	Noise *NoiseConfig `yaml:"noise,omitempty" json:"noise,omitempty" mapstructure:"noise"`

	// SPKI carries the SPKI pin options.
	SPKI *SPKIConfig `yaml:"spki,omitempty" json:"spki,omitempty" mapstructure:"spki"`

	// CAFile is the CA bundle PEM path for the ca-file strategy.
	CAFile string `yaml:"ca-file,omitempty" json:"ca_file,omitempty" mapstructure:"ca-file"`
}

// DANEConfig configures the DANE/TLSA resolver used by the dane strategy.
// An empty DNSServer selects the system resolver from /etc/resolv.conf;
// DNSSEC AD validation is always required.
type DANEConfig = xkmsresolver.DANEConfig

// NoiseConfig configures the Noise_NK client used by the noise strategy.
type NoiseConfig = xkmsresolver.NoiseConfig

// SPKIConfig configures the SPKI pin used by the spki strategy.
//
// Either Pin (the hex-encoded SHA-256 of the server SPKI) or PinFile (a
// path on disk holding the same value) must be set. PinFile is the form
// the autoinstall flow writes during install
// (/etc/trusted-platform/bootstrap-spki-pin); direct Pin is used when an
// operator hand-curates the deploy YAML.
type SPKIConfig = xkmsresolver.SPKIConfig

// DefaultConfig returns a Config with the default class configured for the
// standard fetch chain (dane, noise, spki) and a conservative per-method
// timeout.
//
// TOFU is intentionally excluded from the programmatic default; add it
// explicitly in YAML templates where the operator can read the comment
// explaining trust-on-first-use semantics.
func DefaultConfig() *Config {
	return &Config{
		Default: &ScopeConfig{
			Strategies:       []Strategy{StrategyDANE, StrategyNoise, StrategySPKI},
			PerMethodTimeout: 5 * time.Second,
		},
	}
}

// Scope returns the ScopeConfig for the given class, or nil when the
// class is not configured.
func (c *Config) Scope(class Class) *ScopeConfig {
	scopes := map[Class]*ScopeConfig{
		ClassDefault:  c.Default,
		ClassBMC:      c.BMC,
		ClassInternal: c.Internal,
	}
	return scopes[class]
}

// Validate checks every configured class for invalid strategy chains and
// missing per-strategy inputs. SPKI pin files are resolved into the Pin
// field as a side effect. Platform-level validation covers class
// allowlists and platform-ca normalisation checks; structural validation
// of the generic fields is delegated to the generic resolver via
// ToGeneric().Validate().
func (c *Config) Validate() error {
	for _, class := range []Class{ClassDefault, ClassBMC, ClassInternal} {
		scope := c.Scope(class)
		if scope == nil {
			continue
		}
		if err := scope.validateClass(class); err != nil {
			return err
		}
	}
	return nil
}

// ToGeneric projects this platform Config into the generic xkms resolver
// Config. It normalises platform-ca → provider-ca in every strategy list
// and maps the three class-named fields into the Scopes map.
func (c *Config) ToGeneric() *xkmsresolver.Config {
	scopes := make(map[string]*xkmsresolver.ScopeConfig, 3)
	for _, class := range []Class{ClassDefault, ClassBMC, ClassInternal} {
		scope := c.Scope(class)
		if scope == nil {
			continue
		}
		scopes[string(class)] = scope.toGeneric()
	}
	return &xkmsresolver.Config{Scopes: scopes}
}

// toGeneric converts a ScopeConfig to the generic xkms ScopeConfig,
// normalising platform-ca → provider-ca in the strategy list.
func (s *ScopeConfig) toGeneric() *xkmsresolver.ScopeConfig {
	strategies := make([]xkmsresolver.Strategy, len(s.Strategies))
	for i, start := range s.Strategies {
		if start == StrategyPlatformCA {
			strategies[i] = xkmsresolver.StrategyProviderCA
		} else {
			strategies[i] = start
		}
	}

	generic := &xkmsresolver.ScopeConfig{
		Strategies:           strategies,
		ServerURL:            s.ServerURL,
		Hostname:             s.Hostname,
		BundlePath:           s.BundlePath,
		PerMethodTimeout:     s.PerMethodTimeout,
		InstallToSystemTrust: s.InstallToSystemTrust,
		CAFile:               s.CAFile,
	}
	if s.DANE != nil {
		generic.DANE = s.DANE
	}
	if s.Noise != nil {
		generic.Noise = s.Noise
	}
	if s.SPKI != nil {
		generic.SPKI = s.SPKI
	}
	return generic
}

// validateClass checks a single scope against the given class's allowed
// strategy set and per-strategy requirements. SPKI pin files are resolved
// into the Pin field as a side effect.
func (s *ScopeConfig) validateClass(class Class) error {
	if len(s.Strategies) == 0 {
		return &ErrInvalidConfig{
			Class:  class,
			Field:  "strategies",
			Reason: "at least one strategy is required",
		}
	}

	allowed := allowedStrategies[class]
	for _, strategy := range s.Strategies {
		if !allowed[strategy] {
			return &ErrStrategyNotAllowed{Class: class, Strategy: strategy}
		}
	}

	// Validation is structural: a strategy whose inputs are entirely absent
	// is permitted (the resolver records a per-strategy attempt failure at
	// runtime and falls through). A partially supplied per-strategy config
	// is a hard validation error.
	if s.HasStrategy(StrategyNoise) && s.Noise != nil {
		if s.Noise.ServerStaticKey == "" {
			return &ErrInvalidConfig{
				Class:  class,
				Field:  "noise.server-static-key",
				Reason: "server static key is required for the noise strategy",
			}
		}
		if s.Noise.ServerAddr == "" {
			return &ErrInvalidConfig{
				Class:  class,
				Field:  "noise.server-addr",
				Reason: "server address is required for the noise strategy",
			}
		}
	}

	if s.HasStrategy(StrategySPKI) && s.SPKI != nil {
		// Resolve PinFile into Pin if Pin is unset. The autoinstall flow
		// writes /etc/trusted-platform/bootstrap-spki-pin; this
		// reconciliation lets the YAML reference the file path instead of
		// duplicating the value. A scope without any pin is still valid here
		// because a PinStore may supply per-endpoint pins at resolution time.
		if s.SPKI.Pin == "" && s.SPKI.PinFile != "" {
			data, err := os.ReadFile(s.SPKI.PinFile)
			if err != nil {
				return &ErrInvalidConfig{
					Class:  class,
					Field:  "spki.pin-file",
					Reason: "could not read pin file: " + err.Error(),
				}
			}
			s.SPKI.Pin = strings.TrimSpace(string(data))
		}
	}

	if s.PerMethodTimeout < 0 {
		return &ErrInvalidConfig{
			Class:  class,
			Field:  "per-method-timeout",
			Reason: "timeout must not be negative",
		}
	}

	return nil
}

// StrategyAllowedForClass reports whether class permits strategy. It is the
// single query point for the allowlist, so callers do not re-derive it and
// drift from it — see #83, where a caller assumed tofu was usable for
// ClassBMC and short-circuited before validation could say otherwise.
func StrategyAllowedForClass(class Class, strategy Strategy) bool {
	return allowedStrategies[class][strategy]
}

// HasStrategy reports whether the scope's chain contains the given strategy.
func (s *ScopeConfig) HasStrategy(strategy Strategy) bool {
	for _, candidate := range s.Strategies {
		if candidate == strategy {
			return true
		}
	}
	return false
}
