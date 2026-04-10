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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAPKINDEXContent(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()

	t.Run("parse single package entry", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		input := `P:alpine-base
V:3.22.0-r0
A:x86_64
S:12345
C:Q1abc123=
D:musl>=1.2 busybox>=1.36
p:base

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		pkg, ok := builder.packageIndex["alpine-base"]
		require.True(t, ok, "alpine-base should be in package index")
		assert.Equal(t, "alpine-base", pkg.Name)
		assert.Equal(t, "3.22.0-r0", pkg.Version)
		assert.Equal(t, "x86_64", pkg.Architecture)
		assert.Equal(t, int64(12345), pkg.Size)
		assert.Equal(t, "Q1abc123=", pkg.Checksum)
		assert.Contains(t, pkg.Dependencies, "musl")
		assert.Contains(t, pkg.Dependencies, "busybox")
		assert.Contains(t, pkg.Provides, "base")
	})

	t.Run("parse multiple package entries", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		input := `P:pkg-a
V:1.0-r0
A:x86_64

P:pkg-b
V:2.0-r1
A:x86_64
D:pkg-a

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		assert.Len(t, builder.packageIndex, 2)

		pkgA := builder.packageIndex["pkg-a"]
		require.NotNil(t, pkgA)
		assert.Equal(t, "1.0-r0", pkgA.Version)

		pkgB := builder.packageIndex["pkg-b"]
		require.NotNil(t, pkgB)
		assert.Equal(t, "2.0-r1", pkgB.Version)
		assert.Contains(t, pkgB.Dependencies, "pkg-a")
	})

	t.Run("skip negated dependencies", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		input := `P:test-pkg
V:1.0
D:gooddep !baddep anothergood

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		pkg := builder.packageIndex["test-pkg"]
		require.NotNil(t, pkg)
		assert.Contains(t, pkg.Dependencies, "gooddep")
		assert.Contains(t, pkg.Dependencies, "anothergood")
		for _, dep := range pkg.Dependencies {
			assert.False(t, strings.HasPrefix(dep, "!"), "negated dependency should be excluded")
		}
	})

	t.Run("empty input produces empty index", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		err := builder.parseAPKINDEXContent(strings.NewReader(""))
		require.NoError(t, err)
		assert.Len(t, builder.packageIndex, 0)
	})

	t.Run("handle entry without trailing empty line", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		// No trailing empty line - the last entry is handled by the final check
		input := `P:last-pkg
V:1.0-r0
A:x86_64`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		pkg := builder.packageIndex["last-pkg"]
		require.NotNil(t, pkg)
		assert.Equal(t, "1.0-r0", pkg.Version)
	})

	t.Run("skip short lines", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		// Lines with length < 2 should be skipped
		input := `P:test-pkg
V:1.0
x

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		pkg := builder.packageIndex["test-pkg"]
		require.NotNil(t, pkg)
		assert.Equal(t, "1.0", pkg.Version)
	})

	t.Run("skip entry without name", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		// Entry with no P: field should be skipped
		input := `V:1.0
A:x86_64

P:real-pkg
V:2.0

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		// Only the named entry should be in the index
		assert.Len(t, builder.packageIndex, 1)
		assert.NotNil(t, builder.packageIndex["real-pkg"])
	})

	t.Run("parse provides field", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)

		input := `P:busybox
V:1.36.0-r0
p:sh ash cmd:sh cmd:ash

`
		err := builder.parseAPKINDEXContent(strings.NewReader(input))
		require.NoError(t, err)

		pkg := builder.packageIndex["busybox"]
		require.NotNil(t, pkg)
		assert.Contains(t, pkg.Provides, "sh")
		assert.Contains(t, pkg.Provides, "ash")
	})
}

func TestParsePKGINFO(t *testing.T) {
	config := &PreFetchConfig{
		Mirror:       "https://test.example.com",
		Version:      "3.22",
		Architecture: "x86_64",
	}
	logger := logging.DefaultLogger()

	t.Run("parse complete PKGINFO", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		input := `# Generated by abuild
pkgname = alpine-base
pkgver = 3.22.0-r0
arch = x86_64
depend = musl>=1.2
depend = busybox>=1.36
provides = base
`
		err := builder.parsePKGINFO(strings.NewReader(input), entry)
		require.NoError(t, err)

		assert.Equal(t, "alpine-base", entry.Name)
		assert.Equal(t, "3.22.0-r0", entry.Version)
		assert.Equal(t, "x86_64", entry.Architecture)
		assert.Len(t, entry.Dependencies, 2)
		assert.Contains(t, entry.Dependencies, "musl")
		assert.Contains(t, entry.Dependencies, "busybox")
		assert.Contains(t, entry.Provides, "base")
	})

	t.Run("skip comments and empty lines", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		input := `# This is a comment
# Another comment

pkgname = test-pkg
pkgver = 1.0

# Final comment
`
		err := builder.parsePKGINFO(strings.NewReader(input), entry)
		require.NoError(t, err)

		assert.Equal(t, "test-pkg", entry.Name)
		assert.Equal(t, "1.0", entry.Version)
	})

	t.Run("skip lines without separator", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		input := `pkgname = good-pkg
badline
pkgver = 1.0
`
		err := builder.parsePKGINFO(strings.NewReader(input), entry)
		require.NoError(t, err)

		assert.Equal(t, "good-pkg", entry.Name)
		assert.Equal(t, "1.0", entry.Version)
	})

	t.Run("skip negated dependencies", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		input := `pkgname = test-pkg
depend = gooddep
depend = !baddep
`
		err := builder.parsePKGINFO(strings.NewReader(input), entry)
		require.NoError(t, err)

		assert.Len(t, entry.Dependencies, 1)
		assert.Contains(t, entry.Dependencies, "gooddep")
	})

	t.Run("handle version constraints in dependencies", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		input := `pkgname = test-pkg
depend = musl>=1.2.0
depend = openssl>=3.0.0-r1
provides = ssl>=3.0
`
		err := builder.parsePKGINFO(strings.NewReader(input), entry)
		require.NoError(t, err)

		assert.Contains(t, entry.Dependencies, "musl")
		assert.Contains(t, entry.Dependencies, "openssl")
		assert.Contains(t, entry.Provides, "ssl")
	})

	t.Run("empty input", func(t *testing.T) {
		builder := NewPreFetchBuilder(config, logger)
		entry := &apkPackageEntry{}

		err := builder.parsePKGINFO(strings.NewReader(""), entry)
		require.NoError(t, err)

		assert.Empty(t, entry.Name)
		assert.Empty(t, entry.Version)
	})
}
