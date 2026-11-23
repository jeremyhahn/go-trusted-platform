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
	"gopkg.in/yaml.v3"
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

// writeDNSConfig writes a config file with dns.default-ttl 60, points
// Viper at it and reads it. It returns the path and the original bytes.
func writeDNSConfig(t *testing.T) (string, []byte) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	orig := []byte("dns:\n  default-ttl: 60\n")
	if err := os.WriteFile(cfgPath, orig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}
	return cfgPath, orig
}

func TestApplySection_InvalidValueChangesNothing(t *testing.T) {
	const badValue = "not-a-number-7f3a"
	defer viper.Reset()
	for _, persist := range []bool{true, false} {
		viper.Reset()
		cfgPath, orig := writeDNSConfig(t)

		var tgt struct {
			DNS struct {
				DefaultTTL int `mapstructure:"default-ttl"`
			} `mapstructure:"dns"`
		}
		_, err := ApplySection(&tgt, "dns", map[string]string{"default-ttl": badValue}, persist)
		if err == nil {
			t.Fatalf("persist=%v: ApplySection with an undecodable value returned nil", persist)
		}
		if !errors.As(err, &ErrInvalidSectionValue{}) {
			t.Fatalf("persist=%v: error %v is not ErrInvalidSectionValue", persist, err)
		}
		if contains(err.Error(), badValue) {
			t.Fatalf("persist=%v: error message leaks the value: %q", persist, err.Error())
		}
		data, rerr := os.ReadFile(cfgPath)
		if rerr != nil {
			t.Fatalf("read back: %v", rerr)
		}
		if string(data) != string(orig) {
			t.Fatalf("persist=%v: config file changed: %q", persist, data)
		}
		if got := viper.GetInt("dns.default-ttl"); got != 60 {
			t.Fatalf("persist=%v: live dns.default-ttl = %d, want 60", persist, got)
		}
	}
}

func TestApplySection_ReloadUndoesInMemoryApply(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	writeDNSConfig(t)

	if _, err := ApplySection(nil, "dns", map[string]string{"default-ttl": "120"}, false); err != nil {
		t.Fatalf("ApplySection: %v", err)
	}
	if got := viper.GetInt("dns.default-ttl"); got != 120 {
		t.Fatalf("after apply dns.default-ttl = %d, want 120", got)
	}
	if _, err := ReloadFromDisk(nil); err != nil {
		t.Fatalf("ReloadFromDisk: %v", err)
	}
	if got := viper.GetInt("dns.default-ttl"); got != 60 {
		t.Fatalf("after reload dns.default-ttl = %d, want 60", got)
	}
}

func TestApplySection_RollbackUndoesApplyAndKeepsStartupOverride(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	writeDNSConfig(t)
	// Stands in for a startup flag bound as an override.
	viper.Set("debug", true)

	store := newTestStore(t)
	snap, err := CaptureCurrent(store, "pre-update", "tester")
	if err != nil {
		t.Fatalf("CaptureCurrent: %v", err)
	}
	if _, err := ApplySection(nil, "dns", map[string]string{"default-ttl": "120"}, false); err != nil {
		t.Fatalf("ApplySection: %v", err)
	}
	if got := viper.GetInt("dns.default-ttl"); got != 120 {
		t.Fatalf("after apply dns.default-ttl = %d, want 120", got)
	}
	if _, err := RollbackTo(store, snap.ID, "tester", nil); err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if got := viper.GetInt("dns.default-ttl"); got != 60 {
		t.Fatalf("after rollback dns.default-ttl = %d, want 60", got)
	}
	if !viper.GetBool("debug") {
		t.Fatalf("after rollback the startup override debug=true was lost")
	}
}

// A persisted section update writes the config file's own keys plus the
// section, not Viper's merged settings: startup overrides, defaults and
// environment values stay in memory only.
func TestApplySection_PersistWritesOnlyTheFileLayer(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	cfgPath, _ := writeDNSConfig(t)

	viper.Set("debug", true)
	viper.SetDefault("tenant-id", "default")
	t.Setenv("W2047_PROBE_SECRET", "env-only-value-9c1e")
	if err := viper.BindEnv("probe.secret", "W2047_PROBE_SECRET"); err != nil {
		t.Fatalf("bind env: %v", err)
	}

	if _, err := ApplySection(nil, "dns", map[string]string{"default-ttl": "120"}, true); err != nil {
		t.Fatalf("ApplySection: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse written file: %v", err)
	}
	for _, k := range []string{"debug", "tenant-id", "probe"} {
		if _, ok := doc[k]; ok {
			t.Errorf("persisted file carries %q, which never came from the file:\n%s", k, raw)
		}
	}
	if len(doc) != 1 {
		t.Errorf("persisted file top-level keys = %v, want only dns", doc)
	}
	if contains(string(raw), "env-only-value-9c1e") {
		t.Errorf("persisted file carries the environment value:\n%s", raw)
	}
	dns, _ := doc["dns"].(map[string]interface{})
	switch v := dns["default-ttl"].(type) {
	case int:
		if v != 120 {
			t.Errorf("dns.default-ttl = %d, want 120", v)
		}
	case string:
		if v != "120" {
			t.Errorf("dns.default-ttl = %q, want 120", v)
		}
	default:
		t.Errorf("dns.default-ttl = %#v, want 120", v)
	}

	if !viper.GetBool("debug") {
		t.Errorf("live debug override lost")
	}
	if got := viper.GetString("tenant-id"); got != "default" {
		t.Errorf("live tenant-id = %q, want default", got)
	}
	if got := viper.GetString("probe.secret"); got != "env-only-value-9c1e" {
		t.Errorf("live probe.secret = %q, want the env value", got)
	}
	if got := viper.GetInt("dns.default-ttl"); got != 120 {
		t.Errorf("live dns.default-ttl = %d, want 120", got)
	}
}

// A persisted section update keeps the file's other sections.
func TestApplySection_PersistKeepsOtherFileSections(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	orig := []byte("dns:\n  default-ttl: 60\ndaemon:\n  socket_group: original\n")
	if err := os.WriteFile(cfgPath, orig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}

	if _, err := ApplySection(nil, "dns", map[string]string{"default-ttl": "120"}, true); err != nil {
		t.Fatalf("ApplySection: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var doc struct {
		DNS    map[string]interface{} `yaml:"dns"`
		Daemon map[string]interface{} `yaml:"daemon"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse written file: %v", err)
	}
	if got := doc.Daemon["socket_group"]; got != "original" {
		t.Errorf("daemon.socket_group = %#v, want original:\n%s", got, raw)
	}
	if got := doc.DNS["default-ttl"]; got != 120 && got != "120" {
		t.Errorf("dns.default-ttl = %#v, want 120:\n%s", got, raw)
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
