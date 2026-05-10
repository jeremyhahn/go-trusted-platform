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

package bootstrap

import (
	"os"
	"strings"
	"time"
)

// Bootstrap strategy constants define the supported trust bootstrap methods.
const (
	StrategyDANE     = "dane"
	StrategyNoise    = "noise"
	StrategySPKI     = "spki"
	StrategyEmbedded = "embedded"
	StrategyAuto     = "auto"
)

// Config is the top-level bootstrap configuration.
type Config struct {
	Noise *NoiseServerConfig `yaml:"noise" json:"noise" mapstructure:"noise"`
}

// NoiseServerConfig configures the Noise_NK bootstrap server.
type NoiseServerConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	ListenAddr     string        `yaml:"listen-addr" json:"listen_addr" mapstructure:"listen-addr"`
	MaxConnections int           `yaml:"max-connections" json:"max_connections" mapstructure:"max-connections"`
	ReadTimeout    time.Duration `yaml:"read-timeout" json:"read_timeout" mapstructure:"read-timeout"`
	WriteTimeout   time.Duration `yaml:"write-timeout" json:"write_timeout" mapstructure:"write-timeout"`
}

// ClientConfig configures client-side trust bootstrap.
type ClientConfig struct {
	Strategy  string `yaml:"strategy" json:"strategy" mapstructure:"strategy"`
	ServerURL string `yaml:"server-url" json:"server_url" mapstructure:"server-url"`
	// Hostname is the server hostname for DANE TLSA lookups. Required when
	// ServerURL uses an IP address, because TLSA records are published under
	// the hostname (e.g., _8443._tcp.server.example.com), not the IP.
	Hostname             string             `yaml:"hostname" json:"hostname" mapstructure:"hostname"`
	DNSServer            string             `yaml:"dns-server" json:"dns_server" mapstructure:"dns-server"`
	BundlePath           string             `yaml:"bundle-path" json:"bundle_path" mapstructure:"bundle-path"`
	PerMethodTimeout     time.Duration      `yaml:"per-method-timeout" json:"per_method_timeout" mapstructure:"per-method-timeout"`
	InstallToSystemTrust bool               `yaml:"install-to-system-trust" json:"install_to_system_trust" mapstructure:"install-to-system-trust"`
	Noise                *ClientNoiseConfig `yaml:"noise" json:"noise" mapstructure:"noise"`
	SPKI                 *ClientSPKIConfig  `yaml:"spki" json:"spki" mapstructure:"spki"`
}

// ClientNoiseConfig configures Noise_NK client bootstrap.
type ClientNoiseConfig struct {
	ServerAddr      string `yaml:"server-addr" json:"server_addr" mapstructure:"server-addr"`
	ServerStaticKey string `yaml:"server-static-key" json:"server_static_key" mapstructure:"server-static-key"`
}

// ClientSPKIConfig configures SPKI-pinned TLS client bootstrap.
//
// Either Pin (the literal base64-std SHA-256 of the server SPKI) or
// PinFile (a path on disk holding the same value) must be set. PinFile
// is the form the autoinstall flow writes during install:
// /etc/trusted-platform/bootstrap-spki-pin. Direct Pin is used when an
// operator hand-curates the deploy YAML.
type ClientSPKIConfig struct {
	Pin string `yaml:"pin" json:"pin" mapstructure:"pin"`
	// PinFile is an absolute path to a file containing the
	// base64-std SHA-256 SPKI pin (whitespace tolerated, single
	// pin per file). Resolved by Validate so callers see Pin
	// populated regardless of which form the YAML used.
	PinFile string `yaml:"pin-file" json:"pin_file" mapstructure:"pin-file"`
}

// DefaultConfig returns a Config with sensible defaults for the bootstrap server.
func DefaultConfig() *Config {
	return &Config{
		Noise: &NoiseServerConfig{
			Enabled:        false,
			ListenAddr:     ":9999",
			MaxConnections: 100,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
		},
	}
}

// DefaultClientConfig returns a ClientConfig with sensible defaults for bootstrap clients.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Strategy:             StrategyAuto,
		PerMethodTimeout:     5 * time.Second,
		InstallToSystemTrust: false,
	}
}

// Validate checks the ClientConfig for invalid field combinations and returns
// an error if the configuration is not valid.
func (c *ClientConfig) Validate() error {
	if c.Strategy == "" {
		return &ErrInvalidConfig{
			Field:  "strategy",
			Reason: "strategy is required",
		}
	}

	switch c.Strategy {
	case StrategyDANE, StrategyNoise, StrategySPKI, StrategyEmbedded, StrategyAuto:
	default:
		return &ErrStrategyNotSupported{Strategy: c.Strategy}
	}

	if c.Strategy == StrategyNoise {
		if c.Noise == nil {
			return &ErrInvalidConfig{
				Field:  "noise",
				Reason: "noise configuration is required for noise strategy",
			}
		}
		if c.Noise.ServerStaticKey == "" {
			return &ErrInvalidConfig{
				Field:  "noise.server-static-key",
				Reason: "server static key is required for noise strategy",
			}
		}
		if c.Noise.ServerAddr == "" {
			return &ErrInvalidConfig{
				Field:  "noise.server-addr",
				Reason: "server address is required for noise strategy",
			}
		}
	}

	if c.Strategy == StrategySPKI {
		if c.SPKI == nil {
			return &ErrInvalidConfig{
				Field:  "spki",
				Reason: "SPKI configuration is required for spki strategy",
			}
		}
		// Resolve PinFile into Pin if Pin is unset. The autoinstall
		// flow writes /etc/trusted-platform/bootstrap-spki-pin; this
		// reconciliation lets the YAML reference the file path
		// instead of duplicating the value.
		if c.SPKI.Pin == "" && c.SPKI.PinFile != "" {
			data, err := os.ReadFile(c.SPKI.PinFile)
			if err != nil {
				return &ErrInvalidConfig{
					Field:  "spki.pin-file",
					Reason: "could not read pin file: " + err.Error(),
				}
			}
			c.SPKI.Pin = strings.TrimSpace(string(data))
		}
		if c.SPKI.Pin == "" {
			return &ErrInvalidConfig{
				Field:  "spki.pin",
				Reason: "SPKI pin is required for spki strategy (set spki.pin or spki.pin-file)",
			}
		}
	}

	if c.Strategy == StrategyDANE {
		if c.DNSServer == "" {
			return &ErrInvalidConfig{
				Field:  "dns-server",
				Reason: "DNS server is required for dane strategy (set bootstrap-client.dns-server or dns.resolver.servers)",
			}
		}
	}

	if c.PerMethodTimeout < 0 {
		return &ErrInvalidConfig{
			Field:  "per-method-timeout",
			Reason: "timeout must not be negative",
		}
	}

	return nil
}
