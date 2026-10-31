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

package nbd

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

func TestConfigValidate(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)

	if cfg := testConfig(t, bundle); cfg.Validate() != nil {
		t.Fatalf("valid config rejected: %v", cfg.Validate())
	}

	tests := []struct {
		field  string
		mutate func(*Config)
	}{
		{"Certificate", func(c *Config) { c.Certificate = tls.Certificate{} }},
		{"Certificate", func(c *Config) { c.Certificate.PrivateKey = nil }},
		{"Anchor", func(c *Config) { c.Anchor = nil }},
		{"Identities", func(c *Config) { c.Identities = nil }},
		{"Identities", func(c *Config) { c.Identities = []string{"../escape"} }},
		{"Volumes", func(c *Config) { c.Volumes = nil }},
		{"VolumeSize", func(c *Config) { c.VolumeSize = 0 }},
		{"VolumeSize", func(c *Config) { c.VolumeSize = 1000 }},
		{"HandshakeTimeout", func(c *Config) { c.HandshakeTimeout = -1 }},
	}
	for _, tc := range tests {
		cfg := testConfig(t, bundle)
		tc.mutate(&cfg)
		var invalid ErrInvalidConfig
		if err := cfg.Validate(); !errors.As(err, &invalid) || invalid.Field != tc.field {
			t.Errorf("Validate = %v, want ErrInvalidConfig for %s", err, tc.field)
		}
	}
}

func TestValidIdentity(t *testing.T) {
	valid := []string{"node-01", "pi4.rack-2.example", "A1", strings.Repeat("a", 63)}
	for _, identity := range valid {
		if !validIdentity(identity) {
			t.Errorf("validIdentity(%q) = false", identity)
		}
	}

	invalid := []string{
		"", ".", "..", "../x", "a/b", "-node", "node-", "a..b", "node_01",
		strings.Repeat("a", 64),
		strings.Repeat("a.", 127) + "ab",
	}
	for _, identity := range invalid {
		if validIdentity(identity) {
			t.Errorf("validIdentity(%q) = true", identity)
		}
	}
}
