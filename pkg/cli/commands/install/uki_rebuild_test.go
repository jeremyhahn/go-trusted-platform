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

package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestIsFileURI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"file:///etc/secure-boot/DB.key", true},
		{"FILE:///etc/secure-boot/DB.key", true},
		{"kms://platform/secureboot/db", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isFileURI(c.uri); got != c.want {
			t.Errorf("isFileURI(%q) = %v, want %v", c.uri, got, c.want)
		}
	}
}

func TestNewUKIRebuildCommand_Flags(t *testing.T) {
	cmd := newUKIRebuildCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	if cmd.Use != "uki-rebuild" {
		t.Errorf("Use = %q, want uki-rebuild", cmd.Use)
	}
	for _, name := range []string{"kver", "config", "uki"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected --%s flag", name)
		}
	}
}

func TestLoadUKIRebuildConfig_NotFound(t *testing.T) {
	// Neutralise the host fallbacks so the test never reads a real
	// /etc/platformd config.
	orig := ukiRebuildConfigFallbacks
	ukiRebuildConfigFallbacks = []string{filepath.Join(t.TempDir(), "nope.yaml")}
	t.Cleanup(func() { ukiRebuildConfigFallbacks = orig })

	_, err := loadUKIRebuildConfig(getInstallLogger(false, false), filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected ErrUKIRebuildConfigNotFound, got nil")
	}
	var nf ErrUKIRebuildConfigNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrUKIRebuildConfigNotFound, got %T: %v", err, err)
	}
}

func TestRunUKIRebuild_DisabledSecureBootNoop(t *testing.T) {
	// A config without a secure-boot section yields SecureBoot == nil, so the
	// verb logs "nothing to re-sign" and returns nil without touching the ESP or
	// connecting to a daemon.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("os:\n  hostname: test\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := runUKIRebuild(&cli.CommonFlags{}, &ukiRebuildFlags{config: cfgPath})
	if err != nil {
		t.Fatalf("runUKIRebuild with Secure Boot disabled should be a no-op, got: %v", err)
	}
}
