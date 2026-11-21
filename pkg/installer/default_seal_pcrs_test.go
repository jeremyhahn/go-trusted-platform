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

package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestDefaultSealPCRs pins the SPEC default seal PCR selection (7 and 11,
// docs/SPEC.md installer row) on every path that fills it in when a TPM
// seal is enabled and no PCRs are given: the generator, a profile and the
// loader.
func TestDefaultSealPCRs(t *testing.T) {
	want := []uint{7, 11}

	t.Run("constant", func(t *testing.T) {
		assert.Equal(t, want, DefaultSealPCRs)
	})

	t.Run("generator", func(t *testing.T) {
		data, err := GenerateInstallConfig(&Config{
			Disk:             &DiskConfig{Device: "/dev/sda"},
			OS:               &OSConfig{OS: OSAlpine, Version: "3.22.2"},
			EnableTPMSealing: true,
		})
		require.NoError(t, err)
		var cfg InstallConfig
		require.NoError(t, yaml.Unmarshal(data, &cfg))
		assert.Equal(t, want, cfg.Security.TPM.SealPCRs)
	})

	t.Run("profile", func(t *testing.T) {
		const name ProfileName = "seal-pcrs-default-test"
		builtInProfiles[name] = []byte("security:\n  tpm:\n    enabled: true\n")
		t.Cleanup(func() { delete(builtInProfiles, name) })
		cfg, err := GetProfile(string(name))
		require.NoError(t, err)
		assert.Equal(t, want, cfg.PCRs)
	})

	t.Run("loader", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		yamlContent := "version: \"1.0\"\ndisk:\n  device: /dev/sda\nos:\n  name: alpine\n  version: \"3.22.2\"\nsecurity:\n  tpm:\n    enabled: true\n"
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0600))
		cfg, err := LoadInstallConfig(path)
		require.NoError(t, err)
		assert.Equal(t, want, cfg.PCRs)

		// The loaded config gets its own copy: changing it leaves the
		// package default alone.
		cfg.PCRs[0] = 99
		assert.Equal(t, want, DefaultSealPCRs)
	})
}
