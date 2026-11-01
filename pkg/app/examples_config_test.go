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

package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// examplesDir is the repository's examples/ tree, relative to this package.
const examplesDir = "../../examples"

// loadExampleConfig decodes one platform config document the way the yaml
// loaders do: unknown keys in the strict sections are refused, then the
// document is decoded into App (a duplicate key fails the decode).
func loadExampleConfig(doc []byte) error {
	if err := CheckPlatformConfigYAML(doc); err != nil {
		return err
	}
	var platform App
	return config.DecodeYAML(doc, &platform)
}

// exampleConfigPaths returns every config.yaml under root.
func exampleConfigPaths(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "config.yaml" {
			paths = append(paths, path)
		}
		return nil
	})
	require.NoError(t, err)
	return paths
}

// TestExampleConfigsLoad decodes every examples/**/config.yaml with the
// platform config loader, so a shipped example with a duplicate or unknown
// key fails the build (#1172).
func TestExampleConfigsLoad(t *testing.T) {
	paths := exampleConfigPaths(t, examplesDir)
	require.NotEmpty(t, paths, "no config.yaml found under %s", examplesDir)

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			doc, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, loadExampleConfig(doc))
		})
	}
}

// TestLoadExampleConfigRefusesBadDocuments proves the loader the examples
// test relies on rejects the defects it is there to catch.
func TestLoadExampleConfigRefusesBadDocuments(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{
			name: "duplicate key",
			doc:  "tpm:\n  platform-pcr-bank: sha256\n  platform-pcr-bank: sha256\n",
		},
		{
			name: "unknown key in a strict section",
			doc:  "sdn:\n  no-such-key: true\n",
		},
		{
			name: "malformed yaml",
			doc:  "tpm: [\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, loadExampleConfig([]byte(tt.doc)))
		})
	}
}
