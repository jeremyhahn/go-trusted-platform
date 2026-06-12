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
	"time"
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
