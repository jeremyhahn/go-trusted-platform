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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsPackage checks if a package is present in the slice
func containsPackage(packages []string, pkg string) bool {
	for _, p := range packages {
		if p == pkg {
			return true
		}
	}
	return false
}

func TestCollectRequiredPackages(t *testing.T) {
	tests := []struct {
		name           string
		config         *PreFetchConfig
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "base config returns base packages",
			config: &PreFetchConfig{
				FIPS:          false,
				FilesystemLVM: false,
				EnableFIDO2:   false,
				IMAEnabled:    false,
			},
			wantContains: []string{
				"alpine-base",
				"e2fsprogs",
				"dosfstools",
				"device-mapper",
				"device-mapper-udev",
				"dracut",
				"dracut-modules-network",
				"musl-fts",
				"binutils",
				"systemd-efistub",
				"kmod",
				"gcompat",
				"libc6-compat",
				"ca-certificates",
				"linux-lts",
			},
			wantNotContain: []string{
				"lvm2",
				"lvm2-openrc",
				"libfido2",
				"fido2",
				"coreutils",
				"ima-evm-utils",
				"keyutils",
				"attr",
				"audit",
				"audit-openrc",
			},
		},
		{
			name: "with FIPS excludes linux-lts kernel",
			config: &PreFetchConfig{
				FIPS:          true,
				FilesystemLVM: false,
				EnableFIDO2:   false,
				IMAEnabled:    false,
			},
			wantContains: []string{
				"alpine-base",
				"e2fsprogs",
				"dosfstools",
			},
			wantNotContain: []string{
				"linux-lts",
			},
		},
		{
			name: "with FilesystemLVM includes lvm2 packages",
			config: &PreFetchConfig{
				FIPS:          false,
				FilesystemLVM: true,
				EnableFIDO2:   false,
				IMAEnabled:    false,
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"lvm2",
				"lvm2-openrc",
			},
			wantNotContain: []string{
				"libfido2",
				"ima-evm-utils",
			},
		},
		{
			name: "with EnableFIDO2 includes FIDO2 packages",
			config: &PreFetchConfig{
				FIPS:          false,
				FilesystemLVM: false,
				EnableFIDO2:   true,
				IMAEnabled:    false,
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"libfido2",
				"fido2",
				"coreutils",
			},
			wantNotContain: []string{
				"lvm2",
				"ima-evm-utils",
			},
		},
		{
			name: "with IMAEnabled includes IMA packages",
			config: &PreFetchConfig{
				FIPS:            false,
				FilesystemLVM:   false,
				EnableFIDO2:     false,
				IMAEnabled:      true,
				IMAAuditEnabled: false,
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"ima-evm-utils",
				"keyutils",
				"attr",
			},
			wantNotContain: []string{
				"audit",
				"audit-openrc",
				"libfido2",
			},
		},
		{
			name: "with IMAEnabled and IMAAuditEnabled includes audit packages",
			config: &PreFetchConfig{
				FIPS:            false,
				FilesystemLVM:   false,
				EnableFIDO2:     false,
				IMAEnabled:      true,
				IMAAuditEnabled: true,
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"ima-evm-utils",
				"keyutils",
				"attr",
				"audit",
				"audit-openrc",
			},
			wantNotContain: []string{
				"libfido2",
				"lvm2",
			},
		},
		{
			name: "IMAAuditEnabled without IMAEnabled does not include audit packages",
			config: &PreFetchConfig{
				FIPS:            false,
				FilesystemLVM:   false,
				EnableFIDO2:     false,
				IMAEnabled:      false,
				IMAAuditEnabled: true,
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
			},
			wantNotContain: []string{
				"ima-evm-utils",
				"audit",
				"audit-openrc",
			},
		},
		{
			name: "ExtraPackages are included",
			config: &PreFetchConfig{
				FIPS:          false,
				FilesystemLVM: false,
				EnableFIDO2:   false,
				IMAEnabled:    false,
				ExtraPackages: []string{"nginx", "openssl", "curl"},
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"nginx",
				"openssl",
				"curl",
			},
			wantNotContain: []string{
				"lvm2",
			},
		},
		{
			name: "all features enabled",
			config: &PreFetchConfig{
				FIPS:            false,
				FilesystemLVM:   true,
				EnableFIDO2:     true,
				IMAEnabled:      true,
				IMAAuditEnabled: true,
				ExtraPackages:   []string{"custom-pkg"},
			},
			wantContains: []string{
				"alpine-base",
				"linux-lts",
				"lvm2",
				"lvm2-openrc",
				"libfido2",
				"fido2",
				"coreutils",
				"ima-evm-utils",
				"keyutils",
				"attr",
				"audit",
				"audit-openrc",
				"custom-pkg",
			},
			wantNotContain: []string{},
		},
		{
			name: "FIPS with all other features enabled",
			config: &PreFetchConfig{
				FIPS:            true,
				FilesystemLVM:   true,
				EnableFIDO2:     true,
				IMAEnabled:      true,
				IMAAuditEnabled: true,
			},
			wantContains: []string{
				"alpine-base",
				"lvm2",
				"libfido2",
				"ima-evm-utils",
				"audit",
			},
			wantNotContain: []string{
				"linux-lts",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages := CollectRequiredPackages(tt.config)

			for _, pkg := range tt.wantContains {
				if !containsPackage(packages, pkg) {
					t.Errorf("expected %s to be in packages, got: %v", pkg, packages)
				}
			}

			for _, pkg := range tt.wantNotContain {
				if containsPackage(packages, pkg) {
					t.Errorf("expected %s to NOT be in packages, got: %v", pkg, packages)
				}
			}
		})
	}
}

func TestCollectRequiredPackages_Deduplication(t *testing.T) {
	// Test that ExtraPackages that duplicate base packages are not filtered
	// (the function doesn't deduplicate - this tests current behavior)
	config := &PreFetchConfig{
		FIPS:          false,
		FilesystemLVM: false,
		EnableFIDO2:   false,
		IMAEnabled:    false,
		ExtraPackages: []string{"alpine-base", "e2fsprogs"},
	}

	packages := CollectRequiredPackages(config)

	// Count occurrences of alpine-base
	count := 0
	for _, p := range packages {
		if p == "alpine-base" {
			count++
		}
	}

	// Current behavior: duplicates are allowed
	assert.Equal(t, 2, count, "expected alpine-base to appear twice (base + extra)")
}

func TestPreFetchConfig(t *testing.T) {
	t.Run("zero value config", func(t *testing.T) {
		config := &PreFetchConfig{}
		assert.Empty(t, config.Mirror)
		assert.Empty(t, config.Version)
		assert.Empty(t, config.Architecture)
		assert.Empty(t, config.WorkDir)
		assert.Empty(t, config.ISODir)
		assert.False(t, config.FIPS)
		assert.False(t, config.EnableFIDO2)
		assert.False(t, config.FilesystemLVM)
		assert.False(t, config.IMAEnabled)
		assert.False(t, config.IMAAuditEnabled)
		assert.Nil(t, config.ExtraPackages)
	})

	t.Run("fully populated config", func(t *testing.T) {
		config := &PreFetchConfig{
			Mirror:          "https://dl-cdn.alpinelinux.org/alpine",
			Version:         "3.22.2",
			Architecture:    "x86_64",
			WorkDir:         "/tmp/work",
			ISODir:          "/tmp/iso",
			FIPS:            true,
			EnableFIDO2:     true,
			FilesystemLVM:   true,
			IMAEnabled:      true,
			IMAAuditEnabled: true,
			ExtraPackages:   []string{"pkg1", "pkg2"},
		}

		assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine", config.Mirror)
		assert.Equal(t, "3.22.2", config.Version)
		assert.Equal(t, "x86_64", config.Architecture)
		assert.Equal(t, "/tmp/work", config.WorkDir)
		assert.Equal(t, "/tmp/iso", config.ISODir)
		assert.True(t, config.FIPS)
		assert.True(t, config.EnableFIDO2)
		assert.True(t, config.FilesystemLVM)
		assert.True(t, config.IMAEnabled)
		assert.True(t, config.IMAAuditEnabled)
		assert.Equal(t, []string{"pkg1", "pkg2"}, config.ExtraPackages)
	})
}

func TestNewPreFetchBuilder(t *testing.T) {
	t.Run("with valid config and logger", func(t *testing.T) {
		logger := logging.DefaultLogger()
		config := &PreFetchConfig{
			Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
			Version:      "3.22.2",
			Architecture: "x86_64",
			WorkDir:      "/tmp/work",
			ISODir:       "/tmp/iso",
		}

		builder := NewPreFetchBuilder(config, logger)

		require.NotNil(t, builder)
		assert.Equal(t, config, builder.config)
		assert.NotNil(t, builder.logger)
		assert.NotNil(t, builder.apkManager)
		assert.NotNil(t, builder.packageIndex)
		assert.Len(t, builder.packageIndex, 0)
	})

	t.Run("with nil logger", func(t *testing.T) {
		config := &PreFetchConfig{
			Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
			Version:      "3.22.2",
			Architecture: "x86_64",
			WorkDir:      "/tmp/work",
		}

		// The implementation uses nil logger directly
		builder := NewPreFetchBuilder(config, nil)

		require.NotNil(t, builder)
		assert.Equal(t, config, builder.config)
		assert.Nil(t, builder.logger) // Current behavior: nil logger is stored
		assert.NotNil(t, builder.apkManager)
		assert.NotNil(t, builder.packageIndex)
	})

	t.Run("with minimal config", func(t *testing.T) {
		config := &PreFetchConfig{}
		logger := logging.DefaultLogger()

		builder := NewPreFetchBuilder(config, logger)

		require.NotNil(t, builder)
		assert.Equal(t, config, builder.config)
		assert.NotNil(t, builder.apkManager)
	})

	t.Run("package index is initialized empty", func(t *testing.T) {
		config := &PreFetchConfig{
			Mirror:       "https://example.com",
			Version:      "3.22",
			Architecture: "aarch64",
		}
		logger := logging.DefaultLogger()

		builder := NewPreFetchBuilder(config, logger)

		assert.NotNil(t, builder.packageIndex)
		assert.Len(t, builder.packageIndex, 0)
	})
}

func TestErrPreFetchFailed(t *testing.T) {
	t.Run("Error with underlying error", func(t *testing.T) {
		underlyingErr := errors.New("network timeout")
		err := &ErrPreFetchFailed{
			Operation: "download",
			Reason:    "failed to connect to mirror",
			Err:       underlyingErr,
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "pre-fetch")
		assert.Contains(t, errorMsg, "download")
		assert.Contains(t, errorMsg, "failed to connect to mirror")
		assert.Contains(t, errorMsg, "network timeout")
		assert.Equal(t, "pre-fetch download failed: failed to connect to mirror: network timeout", errorMsg)
	})

	t.Run("Error without underlying error", func(t *testing.T) {
		err := &ErrPreFetchFailed{
			Operation: "validate",
			Reason:    "invalid configuration",
			Err:       nil,
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "pre-fetch")
		assert.Contains(t, errorMsg, "validate")
		assert.Contains(t, errorMsg, "invalid configuration")
		// Without underlying error, message has exactly 1 colon (format: "pre-fetch X failed: Y")
		assert.Equal(t, 1, strings.Count(errorMsg, ":"), "expected exactly 1 colon in error without underlying error")
		assert.Equal(t, "pre-fetch validate failed: invalid configuration", errorMsg)
	})

	t.Run("Unwrap returns underlying error", func(t *testing.T) {
		underlyingErr := errors.New("disk full")
		err := &ErrPreFetchFailed{
			Operation: "write",
			Reason:    "cannot save package",
			Err:       underlyingErr,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, underlyingErr, unwrapped)
		assert.True(t, errors.Is(err, underlyingErr))
	})

	t.Run("Unwrap returns nil when no underlying error", func(t *testing.T) {
		err := &ErrPreFetchFailed{
			Operation: "cleanup",
			Reason:    "nothing to clean",
			Err:       nil,
		}

		unwrapped := err.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error with empty operation", func(t *testing.T) {
		err := &ErrPreFetchFailed{
			Operation: "",
			Reason:    "some reason",
			Err:       nil,
		}

		errorMsg := err.Error()
		assert.Equal(t, "pre-fetch  failed: some reason", errorMsg)
	})

	t.Run("error with empty reason", func(t *testing.T) {
		err := &ErrPreFetchFailed{
			Operation: "test",
			Reason:    "",
			Err:       nil,
		}

		errorMsg := err.Error()
		assert.Equal(t, "pre-fetch test failed: ", errorMsg)
	})
}

func TestErrPackageNotFound(t *testing.T) {
	t.Run("Error returns formatted message", func(t *testing.T) {
		err := &ErrPackageNotFound{
			Package: "nonexistent-pkg",
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "package not found")
		assert.Contains(t, errorMsg, "nonexistent-pkg")
		assert.Equal(t, "package not found: nonexistent-pkg", errorMsg)
	})

	t.Run("Error with empty package name", func(t *testing.T) {
		err := &ErrPackageNotFound{
			Package: "",
		}

		errorMsg := err.Error()
		assert.Equal(t, "package not found: ", errorMsg)
	})

	t.Run("Error with package containing special characters", func(t *testing.T) {
		err := &ErrPackageNotFound{
			Package: "pkg-with-dash_and_underscore",
		}

		errorMsg := err.Error()
		assert.Equal(t, "package not found: pkg-with-dash_and_underscore", errorMsg)
	})
}

func TestErrAPKINDEXFailed(t *testing.T) {
	t.Run("Error with underlying error", func(t *testing.T) {
		underlyingErr := errors.New("gzip: invalid header")
		err := &ErrAPKINDEXFailed{
			Repository: "main",
			Err:        underlyingErr,
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "APKINDEX operation failed")
		assert.Contains(t, errorMsg, "main")
		assert.Contains(t, errorMsg, "gzip: invalid header")
		assert.Equal(t, "APKINDEX operation failed for repository main: gzip: invalid header", errorMsg)
	})

	t.Run("Error without underlying error", func(t *testing.T) {
		err := &ErrAPKINDEXFailed{
			Repository: "community",
			Err:        nil,
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "APKINDEX operation failed")
		assert.Contains(t, errorMsg, "community")
		// Without underlying error, message has exactly 0 colons
		assert.Equal(t, 0, strings.Count(errorMsg, ":"), "expected no colons in error without underlying error")
		assert.Equal(t, "APKINDEX operation failed for repository community", errorMsg)
	})

	t.Run("Unwrap returns underlying error", func(t *testing.T) {
		underlyingErr := errors.New("HTTP 404")
		err := &ErrAPKINDEXFailed{
			Repository: "testing",
			Err:        underlyingErr,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, underlyingErr, unwrapped)
		assert.True(t, errors.Is(err, underlyingErr))
	})

	t.Run("Unwrap returns nil when no underlying error", func(t *testing.T) {
		err := &ErrAPKINDEXFailed{
			Repository: "edge",
			Err:        nil,
		}

		unwrapped := err.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error with URL-like repository", func(t *testing.T) {
		err := &ErrAPKINDEXFailed{
			Repository: "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64",
			Err:        errors.New("connection refused"),
		}

		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64")
		assert.Contains(t, errorMsg, "connection refused")
	})
}

func TestContainsPackage(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
		pkg      string
		want     bool
	}{
		{
			name:     "package exists",
			packages: []string{"alpine-base", "e2fsprogs", "linux-lts"},
			pkg:      "e2fsprogs",
			want:     true,
		},
		{
			name:     "package does not exist",
			packages: []string{"alpine-base", "e2fsprogs", "linux-lts"},
			pkg:      "nonexistent",
			want:     false,
		},
		{
			name:     "empty package list",
			packages: []string{},
			pkg:      "any-pkg",
			want:     false,
		},
		{
			name:     "nil package list",
			packages: nil,
			pkg:      "any-pkg",
			want:     false,
		},
		{
			name:     "empty search string",
			packages: []string{"alpine-base", "e2fsprogs"},
			pkg:      "",
			want:     false,
		},
		{
			name:     "exact match required",
			packages: []string{"alpine-base", "e2fsprogs"},
			pkg:      "alpine",
			want:     false,
		},
		{
			name:     "case sensitive",
			packages: []string{"Alpine-Base", "E2FSPROGS"},
			pkg:      "alpine-base",
			want:     false,
		},
		{
			name:     "first element",
			packages: []string{"first-pkg", "second-pkg", "third-pkg"},
			pkg:      "first-pkg",
			want:     true,
		},
		{
			name:     "last element",
			packages: []string{"first-pkg", "second-pkg", "third-pkg"},
			pkg:      "third-pkg",
			want:     true,
		},
		{
			name:     "single element match",
			packages: []string{"only-pkg"},
			pkg:      "only-pkg",
			want:     true,
		},
		{
			name:     "single element no match",
			packages: []string{"only-pkg"},
			pkg:      "other-pkg",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsPackage(tt.packages, tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStripVersionConstraint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no version constraint",
			input: "alpine-base",
			want:  "alpine-base",
		},
		{
			name:  "greater than or equal",
			input: "foo>=1.0",
			want:  "foo",
		},
		{
			name:  "less than",
			input: "bar<2.0",
			want:  "bar",
		},
		{
			name:  "equals",
			input: "baz=1.2.3",
			want:  "baz",
		},
		{
			name:  "tilde constraint",
			input: "pkg~1.0",
			want:  "pkg",
		},
		{
			name:  "negation returns empty",
			input: "!negated-pkg",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "complex version",
			input: "openssl>=3.0.0-r1",
			want:  "openssl",
		},
		{
			name:  "package with dash before constraint",
			input: "foo-bar>=1.0",
			want:  "foo-bar",
		},
		{
			name:  "only constraint chars",
			input: ">=",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripVersionConstraint(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApkPackageEntry(t *testing.T) {
	t.Run("zero value", func(t *testing.T) {
		entry := &apkPackageEntry{}
		assert.Empty(t, entry.Name)
		assert.Empty(t, entry.Version)
		assert.Empty(t, entry.Architecture)
		assert.Zero(t, entry.Size)
		assert.Empty(t, entry.Checksum)
		assert.Nil(t, entry.Dependencies)
		assert.Nil(t, entry.Provides)
	})

	t.Run("fully populated", func(t *testing.T) {
		entry := &apkPackageEntry{
			Name:         "test-package",
			Version:      "1.2.3-r0",
			Architecture: "x86_64",
			Size:         12345,
			Checksum:     "Q1abc123=",
			Dependencies: []string{"dep1", "dep2"},
			Provides:     []string{"provides1"},
		}

		assert.Equal(t, "test-package", entry.Name)
		assert.Equal(t, "1.2.3-r0", entry.Version)
		assert.Equal(t, "x86_64", entry.Architecture)
		assert.Equal(t, int64(12345), entry.Size)
		assert.Equal(t, "Q1abc123=", entry.Checksum)
		assert.Equal(t, []string{"dep1", "dep2"}, entry.Dependencies)
		assert.Equal(t, []string{"provides1"}, entry.Provides)
	})
}

func TestCollectRequiredPackages_PackageOrder(t *testing.T) {
	// Test that base packages come before optional packages
	config := &PreFetchConfig{
		FIPS:          false,
		FilesystemLVM: true,
		EnableFIDO2:   true,
		IMAEnabled:    true,
		ExtraPackages: []string{"extra-pkg"},
	}

	packages := CollectRequiredPackages(config)

	// Find indices
	alpineBaseIdx := -1
	lvm2Idx := -1
	libfido2Idx := -1
	imaIdx := -1
	extraIdx := -1

	for i, p := range packages {
		switch p {
		case "alpine-base":
			alpineBaseIdx = i
		case "lvm2":
			lvm2Idx = i
		case "libfido2":
			libfido2Idx = i
		case "ima-evm-utils":
			imaIdx = i
		case "extra-pkg":
			extraIdx = i
		}
	}

	// Verify base packages come before feature packages
	assert.Less(t, alpineBaseIdx, lvm2Idx, "alpine-base should come before lvm2")
	assert.Less(t, alpineBaseIdx, libfido2Idx, "alpine-base should come before libfido2")
	assert.Less(t, alpineBaseIdx, imaIdx, "alpine-base should come before ima-evm-utils")

	// Extra packages come at the end
	assert.Greater(t, extraIdx, imaIdx, "extra packages should come after IMA packages")
}

func TestCollectRequiredPackages_EmptyExtraPackages(t *testing.T) {
	config1 := &PreFetchConfig{
		FIPS:          false,
		FilesystemLVM: false,
		EnableFIDO2:   false,
		IMAEnabled:    false,
		ExtraPackages: nil,
	}

	config2 := &PreFetchConfig{
		FIPS:          false,
		FilesystemLVM: false,
		EnableFIDO2:   false,
		IMAEnabled:    false,
		ExtraPackages: []string{},
	}

	packages1 := CollectRequiredPackages(config1)
	packages2 := CollectRequiredPackages(config2)

	// Both should produce the same result
	assert.Equal(t, packages1, packages2)
}

func TestPreFetchBuilderFields(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.20",
		Architecture: "aarch64",
		WorkDir:      "/custom/work",
		ISODir:       "/custom/iso",
	}
	logger := logging.DefaultLogger()

	builder := NewPreFetchBuilder(config, logger)

	// Verify all fields are properly set
	assert.Same(t, config, builder.config)
	assert.Same(t, logger, builder.logger)
	assert.NotNil(t, builder.apkManager)
	assert.NotNil(t, builder.packageIndex)

	// Package index should be empty map, not nil
	assert.Empty(t, builder.packageIndex)

	// Test that we can add to package index
	builder.packageIndex["test-pkg"] = &apkPackageEntry{Name: "test-pkg"}
	assert.Len(t, builder.packageIndex, 1)
}

func TestFindPackage(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()
	builder := NewPreFetchBuilder(config, logger)

	// Populate the package index
	builder.packageIndex["alpine-base"] = &apkPackageEntry{
		Name:     "alpine-base",
		Version:  "3.22.0-r0",
		Provides: []string{},
	}
	builder.packageIndex["busybox"] = &apkPackageEntry{
		Name:     "busybox",
		Version:  "1.36.0-r0",
		Provides: []string{"sh", "ash"},
	}

	t.Run("direct lookup exists", func(t *testing.T) {
		pkg := builder.findPackage("alpine-base")
		require.NotNil(t, pkg)
		assert.Equal(t, "alpine-base", pkg.Name)
	})

	t.Run("direct lookup not found", func(t *testing.T) {
		pkg := builder.findPackage("nonexistent")
		assert.Nil(t, pkg)
	})

	t.Run("find by provides", func(t *testing.T) {
		pkg := builder.findPackage("sh")
		require.NotNil(t, pkg)
		assert.Equal(t, "busybox", pkg.Name)
	})

	t.Run("find by provides - second provide", func(t *testing.T) {
		pkg := builder.findPackage("ash")
		require.NotNil(t, pkg)
		assert.Equal(t, "busybox", pkg.Name)
	})

	t.Run("empty package name", func(t *testing.T) {
		pkg := builder.findPackage("")
		assert.Nil(t, pkg)
	})
}

func TestResolveAllDependencies(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()
	builder := NewPreFetchBuilder(config, logger)

	// Setup a small dependency graph:
	// app -> lib1 -> lib2
	// app -> lib3
	builder.packageIndex["app"] = &apkPackageEntry{
		Name:         "app",
		Version:      "1.0",
		Dependencies: []string{"lib1", "lib3"},
	}
	builder.packageIndex["lib1"] = &apkPackageEntry{
		Name:         "lib1",
		Version:      "1.0",
		Dependencies: []string{"lib2"},
	}
	builder.packageIndex["lib2"] = &apkPackageEntry{
		Name:         "lib2",
		Version:      "1.0",
		Dependencies: []string{},
	}
	builder.packageIndex["lib3"] = &apkPackageEntry{
		Name:         "lib3",
		Version:      "1.0",
		Dependencies: []string{},
	}

	t.Run("resolve single package with dependencies", func(t *testing.T) {
		packages, err := builder.resolveAllDependencies([]string{"app"})
		require.NoError(t, err)

		// Should include app, lib1, lib2, lib3
		assert.Len(t, packages, 4)
		assert.True(t, containsPackage(packages, "app"))
		assert.True(t, containsPackage(packages, "lib1"))
		assert.True(t, containsPackage(packages, "lib2"))
		assert.True(t, containsPackage(packages, "lib3"))
	})

	t.Run("resolve package with no dependencies", func(t *testing.T) {
		packages, err := builder.resolveAllDependencies([]string{"lib2"})
		require.NoError(t, err)

		assert.Len(t, packages, 1)
		assert.True(t, containsPackage(packages, "lib2"))
	})

	t.Run("resolve multiple packages", func(t *testing.T) {
		packages, err := builder.resolveAllDependencies([]string{"lib2", "lib3"})
		require.NoError(t, err)

		assert.Len(t, packages, 2)
		assert.True(t, containsPackage(packages, "lib2"))
		assert.True(t, containsPackage(packages, "lib3"))
	})

	t.Run("resolve empty list", func(t *testing.T) {
		packages, err := builder.resolveAllDependencies([]string{})
		require.NoError(t, err)
		assert.Len(t, packages, 0)
	})

	t.Run("resolve with missing package skips it", func(t *testing.T) {
		packages, err := builder.resolveAllDependencies([]string{"nonexistent", "lib2"})
		require.NoError(t, err)

		// Should still include lib2
		assert.True(t, containsPackage(packages, "lib2"))
	})
}

func TestResolveAllDependencies_CircularDependency(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()
	builder := NewPreFetchBuilder(config, logger)

	// Create a circular dependency: pkgA -> pkgB -> pkgA
	builder.packageIndex["pkgA"] = &apkPackageEntry{
		Name:         "pkgA",
		Version:      "1.0",
		Dependencies: []string{"pkgB"},
	}
	builder.packageIndex["pkgB"] = &apkPackageEntry{
		Name:         "pkgB",
		Version:      "1.0",
		Dependencies: []string{"pkgA"},
	}

	packages, err := builder.resolveAllDependencies([]string{"pkgA"})
	require.NoError(t, err, "should handle circular dependencies without error")

	// Both packages should be resolved
	assert.Len(t, packages, 2)
	assert.True(t, containsPackage(packages, "pkgA"))
	assert.True(t, containsPackage(packages, "pkgB"))
}

func TestResolveAllDependencies_ResultIsSorted(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()
	builder := NewPreFetchBuilder(config, logger)

	// Add packages in non-alphabetical order
	builder.packageIndex["zebra"] = &apkPackageEntry{Name: "zebra", Version: "1.0"}
	builder.packageIndex["apple"] = &apkPackageEntry{Name: "apple", Version: "1.0"}
	builder.packageIndex["mango"] = &apkPackageEntry{Name: "mango", Version: "1.0"}

	packages, err := builder.resolveAllDependencies([]string{"zebra", "apple", "mango"})
	require.NoError(t, err)

	// Result should be sorted
	assert.Equal(t, []string{"apple", "mango", "zebra"}, packages)
}
