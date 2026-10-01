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
