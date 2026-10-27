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

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// enrollingPlatformConfig is a unified platform configuration that selects
// ACME device enrollment.
const enrollingPlatformConfig = `acme:
  client:
    directory: https://cp.example:8443/acme/directory
    enrollment:
      challenge: enroll-01
`

// loadPlatform loads a unified platform configuration the way the install
// command does.
func loadPlatform(t *testing.T, yaml string) *app.App {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "platform.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0o600))
	cmd := newSystemCommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
	config, platform, err := loadConfig(getInstallLogger(false, false), cmd, &systemFlags{config: configPath})
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotNil(t, platform)
	return platform
}

// The enroller the install command supplies is the platform App itself, so
// a diskless-nbd install enrols through App.EnrollIdentity, not a copy.
func TestIdentityEnroller_IsThePlatformsEnrollIdentity(t *testing.T) {
	platform := loadPlatform(t, enrollingPlatformConfig)

	enroller := identityEnroller(platform)

	require.NotNil(t, enroller)
	assert.Same(t, platform, enroller)
}

// Without a platform configuration (an install configured by flags) there
// is no enroller, and the installer refuses a diskless-nbd install.
func TestIdentityEnroller_NoPlatformConfigurationNoEnroller(t *testing.T) {
	assert.Nil(t, identityEnroller(nil))

	cmd := newSystemCommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
	flags := &systemFlags{config: filepath.Join(t.TempDir(), "absent.yaml"), disk: "/dev/sda"}
	_, platform, err := loadConfig(getInstallLogger(false, false), cmd, flags)
	require.NoError(t, err)
	assert.Nil(t, platform)
}

// An enrollment that cannot run fails with its typed error before it builds
// a client or touches anything; the installer then refuses the install
// before any disk is touched (installer TestInstall_EnrollmentFailureTouchesNoDisk).
func TestIdentityEnroller_FailureKeepsItsTypedError(t *testing.T) {
	platform := loadPlatform(t, enrollingPlatformConfig)

	idevid, err := identityEnroller(platform).EnrollIdentity(context.Background())

	assert.Nil(t, idevid)
	var unavailable app.ErrEnrollmentUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "an open TPM", unavailable.Missing)
	assert.Nil(t, platform.ACMEClient, "no enrollment client was built")
}
