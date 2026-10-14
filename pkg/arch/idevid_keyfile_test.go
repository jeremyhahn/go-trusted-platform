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

package arch

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// deviceIdentityMarkers are what a script on the installed image would carry
// to activate or heartbeat the device itself: the endpoints, and a file
// holding the IDevID private key.
var deviceIdentityMarkers = []string{
	"/api/v1/device/activate",
	"/api/v1/device/heartbeat",
	"idevid.key",
}

// TestImageConfigsLeaveDeviceIdentityToPlatformd asserts that no file under
// configs/os activates or heartbeats the device. platformd does both with the
// TPM-resident IDevID; the trusted-platform-network script duplicated the
// activation with a PEM key file nothing writes, and was removed (#149).
func TestImageConfigsLeaveDeviceIdentityToPlatformd(t *testing.T) {
	osDir := filepath.Join(repoRoot(t), "configs", "os")

	var findings []string
	walkErr := filepath.WalkDir(osDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, marker := range deviceIdentityMarkers {
			if strings.Contains(string(data), marker) {
				findings = append(findings, filepath.Base(path)+": "+marker)
			}
		}
		return nil
	})
	require.NoError(t, walkErr)
	require.Empty(t, findings,
		"these configs/os files activate or heartbeat the device; platformd does that "+
			"with the TPM-resident IDevID (pkg/app FetchProfileAndActivate, StartDeviceHeartbeat):\n%s",
		strings.Join(findings, "\n"))
}
