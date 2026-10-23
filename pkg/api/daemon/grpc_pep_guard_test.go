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

package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// pepGuardConfig is the combination the embedded SDK cannot serve: gRPC TCP
// on, mTLS off, platform tokens off, IAM validation on, embedded quicbaas.
func pepGuardConfig() *Config {
	config := DefaultConfig()
	config.App = &app.App{QuicBaaSConfig: &quicbaas.Config{Transport: quicbaas.TransportEmbedded}}
	config.EnableGRPCTCP = true
	config.EnableMTLS = false
	config.PlatformToken.Enabled = false
	config.SkipIAMValidation = false
	return config
}

func TestValidateGRPCAuthorization_RejectsEmbeddedPEPPath(t *testing.T) {
	cases := map[string]func(*Config){
		"explicit embedded transport": func(*Config) {},
		"absent quicbaas section is the embedded default": func(c *Config) {
			c.App.QuicBaaSConfig = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := pepGuardConfig()
			mutate(config)

			err := config.validateGRPCAuthorization()
			var want ErrEmbeddedPEPUnavailable
			if !errors.As(err, &want) {
				t.Fatalf("error is %T (%v), want ErrEmbeddedPEPUnavailable", err, err)
			}
			if want.Transport != transportGRPCTCP {
				t.Errorf("Transport = %q, want %q", want.Transport, transportGRPCTCP)
			}
			for _, remedy := range []string{"platform-token", "--enable-mtls"} {
				if !strings.Contains(err.Error(), remedy) {
					t.Errorf("error %q does not name the %s alternative", err, remedy)
				}
			}
		})
	}
}

func TestValidateGRPCAuthorization_AcceptsWorkingModes(t *testing.T) {
	cases := map[string]func(*Config){
		"mTLS enabled":            func(c *Config) { c.EnableMTLS = true },
		"platform tokens enabled": func(c *Config) { c.PlatformToken.Enabled = true },
		"remote quicbaas transport": func(c *Config) {
			c.App.QuicBaaSConfig.Transport = quicbaas.TransportGRPC
		},
		"gRPC TCP disabled":              func(c *Config) { c.EnableGRPCTCP = false },
		"testing-only IAM opt-out":       func(c *Config) { c.SkipIAMValidation = true },
		"no App leaves it to IAM wiring": func(c *Config) { c.App = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := pepGuardConfig()
			mutate(config)
			if err := config.validateGRPCAuthorization(); err != nil {
				t.Fatalf("validateGRPCAuthorization() = %v, want nil", err)
			}
		})
	}
}

func TestNew_RefusesEmbeddedPEPPathAtStartup(t *testing.T) {
	d, err := New(pepGuardConfig())
	var want ErrEmbeddedPEPUnavailable
	if !errors.As(err, &want) {
		t.Fatalf("New() error is %T (%v), want ErrEmbeddedPEPUnavailable", err, err)
	}
	if d != nil {
		t.Error("New() returned a daemon alongside the refusal")
	}
}
