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

package jwt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTestDataDirIsOutsideTheSourceTree is the regression guard for #273.
//
// These tests generate real RSA private keys through a file-backed keystore.
// The directory holding them used to be "./testdata", inside the package, and
// because it is not gitignored an interrupted run left untracked key material
// in the working tree — one `git add -A` away from being committed.
//
// Asserting the directory is outside the package is the check that actually
// prevents a regression: reverting to a relative path is a one-character
// change that nothing else would notice, because the normal path cleans up
// after itself and looks fine.
func TestTestDataDirIsOutsideTheSourceTree(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, testDataDir, "setup must have created a test data directory")

	pkgDir, err := os.Getwd()
	require.NoError(t, err)

	// Resolve to an absolute path FIRST. filepath.Rel errors when given one
	// absolute and one relative path, and an earlier version of this test
	// treated that error as "cannot tell, so pass" — which made it blind to
	// exactly the regression it exists to catch, since "./testdata" is
	// relative. Mutation testing found that; do not reintroduce an error
	// path that returns without asserting.
	abs, err := filepath.Abs(testDataDir)
	require.NoError(t, err)

	rel, err := filepath.Rel(pkgDir, abs)
	require.NoError(t, err, "could not compare %s against the package directory", abs)

	assert.True(t, strings.HasPrefix(rel, ".."),
		"key material must not be written inside the package directory: %s resolves to %s",
		testDataDir, rel)
}

// TestSourceTreeHasNoTestdataDirectory asserts the specific path that caused
// #273 is not recreated. It is separate from the check above because a future
// change could move testDataDir correctly and still leave a stray ./testdata
// behind from some other code path.
func TestSourceTreeHasNoTestdataDirectory(t *testing.T) {
	t.Parallel()
	_, err := os.Stat("testdata")
	assert.True(t, os.IsNotExist(err),
		"./testdata must not exist in the package directory; these tests write key material and it is not gitignored")
}
