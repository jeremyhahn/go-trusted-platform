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
	"fmt"
	"os"
	"path/filepath"
)

// PlatformConfigDirEnv names the environment variable that points the CLI
// at a platform config root: a checkout of the private platform-configs
// repository, laid out like the in-tree configs/platform (a templates/
// tree). The default and role templates of `iso create` and
// `diskimage create` come from under it.
const PlatformConfigDirEnv = "PLATFORM_CONFIG_DIR"

// DefaultPlatformConfigDir is the platform config root used when
// PLATFORM_CONFIG_DIR is unset: the in-tree templates, which carry public
// example values only.
const DefaultPlatformConfigDir = "configs/platform"

// PlatformConfigDir returns the platform config root and whether
// PLATFORM_CONFIG_DIR set it. An empty value counts as unset and yields the
// in-tree public templates (DefaultPlatformConfigDir).
func PlatformConfigDir() (dir string, set bool) {
	if dir := os.Getenv(PlatformConfigDirEnv); dir != "" {
		return dir, true
	}
	return DefaultPlatformConfigDir, false
}

// PlatformTemplatePath joins elem under the templates/ tree of the platform
// config root (see PlatformConfigDir).
func PlatformTemplatePath(elem ...string) string {
	dir, _ := PlatformConfigDir()
	return filepath.Join(append([]string{dir, "templates"}, elem...)...)
}

// ErrPlatformTemplateMissing is returned when PLATFORM_CONFIG_DIR is set and
// the template a command needs is not under it. The command fails closed
// rather than fall back to the in-tree public templates.
type ErrPlatformTemplateMissing struct {
	Path string
}

func (e ErrPlatformTemplateMissing) Error() string {
	return fmt.Sprintf("platform template %s not found under %s", e.Path, PlatformConfigDirEnv)
}
