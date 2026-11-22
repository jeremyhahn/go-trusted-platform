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

package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformConfigDir_DefaultsToTheInTreeTemplates(t *testing.T) {
	t.Setenv("PLATFORM_CONFIG_DIR", "")
	dir, set := PlatformConfigDir()
	if dir != "configs/platform" || set {
		t.Errorf("PlatformConfigDir() = %q, %v; want %q, false", dir, set, "configs/platform")
	}
}

func TestPlatformConfigDir_ReadsTheEnvironment(t *testing.T) {
	want := t.TempDir()
	t.Setenv("PLATFORM_CONFIG_DIR", want)
	dir, set := PlatformConfigDir()
	if dir != want || !set {
		t.Errorf("PlatformConfigDir() = %q, %v; want %q, true", dir, set, want)
	}
}

func TestPlatformTemplatePath_JoinsUnderTemplates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLATFORM_CONFIG_DIR", dir)
	if got, want := PlatformTemplatePath("single-node", "default.yaml"), filepath.Join(dir, "templates", "single-node", "default.yaml"); got != want {
		t.Errorf("set: PlatformTemplatePath = %q, want %q", got, want)
	}
	t.Setenv("PLATFORM_CONFIG_DIR", "")
	if got, want := PlatformTemplatePath("single-node", "default.yaml"), filepath.Join("configs", "platform", "templates", "single-node", "default.yaml"); got != want {
		t.Errorf("unset: PlatformTemplatePath = %q, want %q", got, want)
	}
}

func TestErrPlatformTemplateMissing_NamesTheVariable(t *testing.T) {
	msg := ErrPlatformTemplateMissing{Path: "x/y.yaml"}.Error()
	if !strings.Contains(msg, "PLATFORM_CONFIG_DIR") || !strings.Contains(msg, "x/y.yaml") {
		t.Errorf("Error() = %q, want it to name PLATFORM_CONFIG_DIR and x/y.yaml", msg)
	}
}
