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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestApplySection_InMemory(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	type target struct {
		Daemon struct {
			SocketGroup string `mapstructure:"socket_group"`
		} `mapstructure:"daemon"`
	}
	var tgt target

	sections, err := ApplySection(&tgt, "daemon", map[string]string{"socket_group": "trusted"}, false)
	if err != nil {
		t.Fatalf("ApplySection() error: %v", err)
	}
	if viper.GetString("daemon.socket_group") != "trusted" {
		t.Fatalf("viper value = %q, want trusted", viper.GetString("daemon.socket_group"))
	}
	if tgt.Daemon.SocketGroup != "trusted" {
		t.Fatalf("target not decoded: %+v", tgt)
	}
	if len(sections) == 0 {
		t.Fatalf("expected at least one section returned")
	}
}

func TestApplySection_NilTargetSucceeds(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	if _, err := ApplySection(nil, "daemon", map[string]string{"k": "v"}, false); err != nil {
		t.Fatalf("ApplySection(nil target) error: %v", err)
	}
	if viper.GetString("daemon.k") != "v" {
		t.Fatalf("viper value not set")
	}
}

func TestApplySection_Persist(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("daemon:\n  socket_group: original\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}

	if _, err := ApplySection(nil, "daemon", map[string]string{"socket_group": "changed"}, true); err != nil {
		t.Fatalf("ApplySection(persist) error: %v", err)
	}

	// The change must be durable: reading the file back shows the new value.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !contains(string(data), "changed") {
		t.Fatalf("persisted config missing new value: %s", data)
	}
}

func TestApplySection_Errors(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	if _, err := ApplySection(nil, "", map[string]string{"k": "v"}, false); err == nil {
		t.Fatal("expected error for empty section")
	} else {
		var e ErrApplySectionFailed
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrApplySectionFailed, got %T", err)
		}
	}

	if _, err := ApplySection(nil, "daemon", map[string]string{"": "v"}, false); err == nil {
		t.Fatal("expected error for empty key")
	}

	// Persist with no active config file must fail rather than silently drop.
	viper.Reset()
	if _, err := ApplySection(nil, "daemon", map[string]string{"k": "v"}, true); err == nil {
		t.Fatal("expected error persisting with no config file")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
