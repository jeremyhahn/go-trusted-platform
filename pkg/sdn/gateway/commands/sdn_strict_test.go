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

package commands

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

func strictServeViper(t *testing.T, doc string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBufferString(doc)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	return v
}

// TestLoadServeConfig_SDNStrict decodes a current sdn section.
func TestLoadServeConfig_SDNStrict(t *testing.T) {
	cfg, err := LoadServeConfig(strictServeViper(t, "sdn:\n  enabled: true\n  environment: {id: 4}\n"))
	if err != nil {
		t.Fatalf("LoadServeConfig: %v", err)
	}
	if cfg.SDN == nil || cfg.SDN.Environment == nil || cfg.SDN.Environment.ID != 4 {
		t.Fatalf("sdn section not decoded: %+v", cfg.SDN)
	}
}

// TestLoadServeConfig_SDNStaleKeysRefused refuses keys the sdn schema no
// longer has, as platformd does.
func TestLoadServeConfig_SDNStaleKeysRefused(t *testing.T) {
	_, err := LoadServeConfig(strictServeViper(t, "sdn:\n  enabled: true\n  networks: []\n  transit: {vlan: 10}\n"))
	var section *ErrConfigSection
	if !errors.As(err, &section) || section.Section != "sdn" {
		t.Fatalf("want ErrConfigSection for sdn, got %v", err)
	}
	var unknown *config.ErrUnknownConfigKeys
	if !errors.As(err, &unknown) || len(unknown.Keys) != 2 {
		t.Fatalf("want two unknown keys, got %v", err)
	}
}

// TestLoadServeConfig_ProxyRequiredRolesRefused refuses a proxy route that
// still names the removed required-roles (#926), and names the field.
func TestLoadServeConfig_ProxyRequiredRolesRefused(t *testing.T) {
	doc := "proxy:\n  enabled: true\n  routes:\n    - id: web\n      path-prefix: /\n      pool: web\n      auth: {mode: token, required-roles: [admin]}\n"
	_, err := LoadServeConfig(strictServeViper(t, doc))
	var section *ErrConfigSection
	if !errors.As(err, &section) || section.Section != "proxy" {
		t.Fatalf("want ErrConfigSection for proxy, got %v", err)
	}
	var unknown *config.ErrUnknownConfigKeys
	if !errors.As(err, &unknown) || len(unknown.Keys) != 1 || unknown.Keys[0].Path != "proxy.routes[0].auth.required-roles" {
		t.Fatalf("want the one unknown key proxy.routes[0].auth.required-roles, got %v", err)
	}
}

// TestLoadServeConfig_ProxyStrict decodes a current proxy route, with its
// required scopes, through the strict path.
func TestLoadServeConfig_ProxyStrict(t *testing.T) {
	doc := "proxy:\n  enabled: true\n  routes:\n    - id: web\n      path-prefix: /\n      pool: web\n      auth: {mode: token, required-scopes: [\"proxy:read\"], attestation-max-age: 5m}\n"
	cfg, err := LoadServeConfig(strictServeViper(t, doc))
	if err != nil {
		t.Fatalf("LoadServeConfig: %v", err)
	}
	if cfg.Proxy == nil || len(cfg.Proxy.Routes) != 1 || cfg.Proxy.Routes[0].Auth.RequiredScopes[0] != "proxy:read" {
		t.Fatalf("proxy section not decoded: %+v", cfg.Proxy)
	}
}
