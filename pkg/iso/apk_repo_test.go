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

package iso

import (
	"reflect"
	"strings"
	"testing"
)

// TestAlpineReleaseBranch covers the version -> branch derivation, including
// the empty-version case that lets the autoinstall script fall back to
// /etc/alpine-release at runtime.
func TestAlpineReleaseBranch(t *testing.T) {
	cases := []struct {
		name    string
		version string
		want    string
	}{
		{"full version", "3.22.2", "v3.22"},
		{"major minor only", "3.22", "v3.22"},
		{"single component", "3", "v3"},
		{"empty version", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := alpineReleaseBranch(tc.version); got != tc.want {
				t.Fatalf("alpineReleaseBranch(%q) = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}

// TestApkRepositoryLines exercises all three auto-detect branches the
// autoinstall script bakes in: local CD (offline), configured mirror, and
// the public-mirror fallback. The branch order matters — cdrom must win even
// when a mirror is also supplied, because vmedia installs are offline.
func TestApkRepositoryLines(t *testing.T) {
	cases := []struct {
		name         string
		cdromPresent bool
		mirror       string
		branch       string
		want         []string
	}{
		{
			name:         "cdrom present wins over mirror",
			cdromPresent: true,
			mirror:       "http://198.51.100.11:8080",
			branch:       "v3.22",
			want:         []string{"/media/cdrom/apks", "/media/cdrom/apks-prefetch"},
		},
		{
			name:         "configured mirror",
			cdromPresent: false,
			mirror:       "http://198.51.100.11:8080",
			branch:       "v3.22",
			want: []string{
				"http://198.51.100.11:8080/v3.22/main",
				"http://198.51.100.11:8080/v3.22/community",
			},
		},
		{
			name:         "configured mirror with trailing slash is trimmed",
			cdromPresent: false,
			mirror:       "http://198.51.100.11:8080/",
			branch:       "v3.22",
			want: []string{
				"http://198.51.100.11:8080/v3.22/main",
				"http://198.51.100.11:8080/v3.22/community",
			},
		},
		{
			name:         "public fallback when no cdrom and no mirror",
			cdromPresent: false,
			mirror:       "",
			branch:       "v3.22",
			want: []string{
				PublicAlpineMirror + "/v3.22/main",
				PublicAlpineMirror + "/v3.22/community",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := apkRepositoryLines(tc.cdromPresent, tc.mirror, tc.branch)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("apkRepositoryLines(%v, %q, %q) = %v, want %v",
					tc.cdromPresent, tc.mirror, tc.branch, got, tc.want)
			}
		})
	}
}

// TestBuildAutoinstallScriptRepoDetect asserts the generated autoinstall
// script carries the three-way repo auto-detect and the build-time branch,
// so a regression that re-hardcodes /media/cdrom can't slip through.
func TestBuildAutoinstallScriptRepoDetect(t *testing.T) {
	c := &Customizer{config: &PlatformISOConfig{
		Alpine: AlpineConfig{Version: "3.22.2"},
	}}
	script := c.buildAutoinstallScript()

	wantFragments := []string{
		`ALPINE_BRANCH="v3.22"`,
		`grep '^platform_apk_mirror='`,
		`if [ -d /media/cdrom/apks ]; then`,
		`elif [ -n "$APK_MIRROR" ]; then`,
		`$APK_MIRROR/$ALPINE_BRANCH/main`,
		`$PUBLIC_APK_MIRROR/$ALPINE_BRANCH/main`,
		`apk update $APK_ALLOW_UNTRUSTED`,
	}
	for _, frag := range wantFragments {
		if !strings.Contains(script, frag) {
			t.Errorf("autoinstall script missing fragment %q", frag)
		}
	}
}
