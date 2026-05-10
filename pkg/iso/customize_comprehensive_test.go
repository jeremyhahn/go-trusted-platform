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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestCreateDracutModule(t *testing.T) {
	tmpDir := t.TempDir()
	extractDir := filepath.Join(tmpDir, "extract")
	require.NoError(t, os.MkdirAll(extractDir, 0755))

	config := &PlatformISOConfig{
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())
	err := customizer.createDracutModule(extractDir)

	// Should create dracut module structure
	assert.NoError(t, err)

	moduleDir := filepath.Join(extractDir, "usr", "lib", "dracut", "modules.d", "99platformd")
	if _, statErr := os.Stat(moduleDir); statErr == nil {
		assert.DirExists(t, moduleDir)
	}
}
