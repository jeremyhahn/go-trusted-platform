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

package main

import (
	"log/slog"
	"testing"
)

// TestLoadConfig_Defaults verifies loadConfig picks up defaults for
// all vBMC settings when no VBMC_* env vars are set. Ensures a fresh
// container boot binds the expected HTTPS + IPMI ports.
func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env that would override defaults.
	for _, k := range []string{
		"VBMC_HTTPS_ADDR", "VBMC_VENDOR", "VBMC_CN", "VBMC_LOG_LEVEL",
		"VBMC_IPMI_ADDR", "VBMC_IPMI_USER", "VBMC_IPMI_PASSWORD",
	} {
		t.Setenv(k, "")
	}
	c := loadConfig()
	if c.httpsAddr != ":8443" {
		t.Errorf("httpsAddr = %q, want :8443", c.httpsAddr)
	}
	if c.vendor != "Supermicro" {
		t.Errorf("vendor = %q, want Supermicro", c.vendor)
	}
	if c.cn != "vbmc.example.internal" {
		t.Errorf("cn = %q", c.cn)
	}
	if c.logLevel != slog.LevelInfo {
		t.Errorf("logLevel = %v, want Info", c.logLevel)
	}
	if c.ipmiAddr != ":6230" {
		t.Errorf("ipmiAddr = %q, want :6230", c.ipmiAddr)
	}
	if c.ipmiUser != "ADMIN" {
		t.Errorf("ipmiUser = %q, want ADMIN", c.ipmiUser)
	}
	if c.ipmiPassword != "ADMIN" {
		t.Errorf("ipmiPassword = %q, want ADMIN", c.ipmiPassword)
	}
}

// TestLoadConfig_Overrides verifies every vBMC env var can be
// overridden. Asserts the IPMI fields in particular are wired.
func TestLoadConfig_Overrides(t *testing.T) {
	t.Setenv("VBMC_HTTPS_ADDR", ":28443")
	t.Setenv("VBMC_VENDOR", "Dell")
	t.Setenv("VBMC_CN", "custom.example")
	t.Setenv("VBMC_LOG_LEVEL", "debug")
	t.Setenv("VBMC_IPMI_ADDR", ":16230")
	t.Setenv("VBMC_IPMI_USER", "root")
	t.Setenv("VBMC_IPMI_PASSWORD", "s3cret")

	c := loadConfig()
	if c.httpsAddr != ":28443" {
		t.Errorf("httpsAddr = %q", c.httpsAddr)
	}
	if c.vendor != "Dell" {
		t.Errorf("vendor = %q", c.vendor)
	}
	if c.cn != "custom.example" {
		t.Errorf("cn = %q", c.cn)
	}
	if c.logLevel != slog.LevelDebug {
		t.Errorf("logLevel = %v, want Debug", c.logLevel)
	}
	if c.ipmiAddr != ":16230" {
		t.Errorf("ipmiAddr = %q", c.ipmiAddr)
	}
	if c.ipmiUser != "root" {
		t.Errorf("ipmiUser = %q", c.ipmiUser)
	}
	if c.ipmiPassword != "s3cret" {
		t.Errorf("ipmiPassword = %q", c.ipmiPassword)
	}
}

// TestLoadConfig_LogLevels covers each branch of the VBMC_LOG_LEVEL
// switch.
func TestLoadConfig_LogLevels(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":       slog.LevelDebug,
		"info":        slog.LevelInfo,
		"warn":        slog.LevelWarn,
		"error":       slog.LevelError,
		"garbage-val": slog.LevelInfo,
		"":            slog.LevelInfo,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Setenv("VBMC_LOG_LEVEL", in)
			c := loadConfig()
			if c.logLevel != want {
				t.Errorf("VBMC_LOG_LEVEL=%q -> %v, want %v", in, c.logLevel, want)
			}
		})
	}
}

// TestGetenv covers the tiny getenv helper.
func TestGetenv(t *testing.T) {
	t.Setenv("VBMC_TEST_KEY", "")
	if got := getenv("VBMC_TEST_KEY", "default"); got != "default" {
		t.Errorf("getenv unset = %q, want default", got)
	}
	t.Setenv("VBMC_TEST_KEY", "value")
	if got := getenv("VBMC_TEST_KEY", "default"); got != "value" {
		t.Errorf("getenv set = %q, want value", got)
	}
}
