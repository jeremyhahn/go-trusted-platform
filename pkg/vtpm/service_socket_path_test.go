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

package vtpm

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A running swtpm may listen in a short temp directory, so the socket path
// reported for a running vTPM is the instance's, not the bundle default.
func TestGetTPMSocketPath_RunningInstanceReportsItsSocket(t *testing.T) {
	service, err := NewService(createTestConfig(t), nil, &mockCA{})
	require.NoError(t, err)

	service.instances["bundle-1"] = &runningInstance{socketPath: "/tmp/swtpm-123/swtpm.sock"}

	assert.Equal(t, "/tmp/swtpm-123/swtpm.sock", service.GetTPMSocketPath("bundle-1"))
}

func TestGetTPMSocketPath_StoppedBundleReportsBundleDefault(t *testing.T) {
	config := createTestConfig(t)
	service, err := NewService(config, nil, &mockCA{})
	require.NoError(t, err)

	want := filepath.Join(config.BundlePath("bundle-2"), "tpm", "swtpm.sock")
	assert.Equal(t, want, service.GetTPMSocketPath("bundle-2"))
}
