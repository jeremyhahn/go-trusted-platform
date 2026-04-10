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

package baremetal

import "time"

// Config holds tunable parameters for the bare metal provisioning service.
type Config struct {
	InstallTimeout time.Duration `yaml:"install-timeout" json:"install_timeout"`
	PowerOnDelay   time.Duration `yaml:"power-on-delay" json:"power_on_delay"`
}

// DefaultConfig returns a Config with production-appropriate defaults.
func DefaultConfig() *Config {
	return &Config{
		InstallTimeout: 30 * time.Minute,
		PowerOnDelay:   5 * time.Second,
	}
}
