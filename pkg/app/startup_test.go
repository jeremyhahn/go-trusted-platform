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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitLogger_CreatesLogFile(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "log")
	app := &App{LogDir: logDir}

	require.NoError(t, app.initLogger())

	require.NotNil(t, app.Logger)
	info, err := os.Stat(filepath.Join(logDir, logFileName()))
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
}

func TestInitLogger_Errors(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0600))
	logPathIsADir := filepath.Join(dir, "log")
	require.NoError(t, os.MkdirAll(filepath.Join(logPathIsADir, logFileName()), 0700))

	tests := []struct {
		name     string
		logDir   string
		wantType error
	}{
		{name: "empty log dir", logDir: "", wantType: LogDirInvalidError{}},
		{name: "log dir under a file", logDir: filepath.Join(notADir, "log"), wantType: LogDirCreateError{}},
		{name: "log file path is a directory", logDir: logPathIsADir, wantType: LogFileOpenError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{LogDir: tt.logDir}

			err := app.initLogger()

			assertErrorType(t, err, tt.wantType)
			assert.Nil(t, app.Logger, "no logger may be installed when its file cannot be opened")
		})
	}
}

func TestResolveHostname(t *testing.T) {
	t.Run("unset reads the OS hostname", func(t *testing.T) {
		app := &App{}

		require.NoError(t, app.resolveHostname(func() (string, error) { return "node-01", nil }))

		assert.Equal(t, "node-01", app.Hostname)
	})
	t.Run("configured hostname is kept", func(t *testing.T) {
		app := &App{Hostname: "configured"}
		called := false

		require.NoError(t, app.resolveHostname(func() (string, error) { called = true; return "os", nil }))

		assert.Equal(t, "configured", app.Hostname)
		assert.False(t, called, "a configured hostname must not consult the OS")
	})
}

func TestResolveHostname_Error(t *testing.T) {
	app := &App{}
	cause := fakeOpError{op: "hostname"}

	err := app.resolveHostname(func() (string, error) { return "", cause })

	var target HostnameError
	require.ErrorAs(t, err, &target)
	assert.ErrorIs(t, err, cause)
	assert.Empty(t, app.Hostname)
}

// useTestConfigDir runs a TestConfigWithStorage test in its own working
// directory, and restores the package globals it changes.
func useTestConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	saved := Name
	t.Cleanup(func() {
		Name = saved
		viper.Reset()
	})
	return dir
}

func TestTestConfigWithStorage(t *testing.T) {
	dir := useTestConfigDir(t)

	app, err := TestConfigWithStorage(nil)

	require.NoError(t, err)
	assert.Equal(t, "trusted-data/log", app.LogDir)
	assert.Equal(t, "trusted-data/etc", app.ConfigDir)
	assert.FileExists(t, filepath.Join(dir, "trusted-data", "log", "trusted-platform.log"))
	assert.FileExists(t, filepath.Join(dir, "trusted-data", "etc", "config.yaml"))
}

func TestTestConfigWithStorage_Errors(t *testing.T) {
	tests := []struct {
		name     string
		block    string
		wantType error
	}{
		{name: "log directory", block: "trusted-data", wantType: LogDirCreateError{}},
		{name: "config directory", block: filepath.Join("trusted-data", "etc"), wantType: TestConfigError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := useTestConfigDir(t)
			// A regular file where a directory must go makes MkdirAll fail,
			// even for root.
			blocked := filepath.Join(dir, tt.block)
			require.NoError(t, os.MkdirAll(filepath.Dir(blocked), 0700))
			require.NoError(t, os.WriteFile(blocked, nil, 0600))

			app, err := TestConfigWithStorage(nil)

			assert.Nil(t, app)
			assertErrorType(t, err, tt.wantType)
		})
	}
}

func TestStartupErrors_Messages(t *testing.T) {
	cause := fakeOpError{op: "cause"}
	tests := []struct {
		err  error
		want []string
	}{
		{HostnameError{Cause: cause}, []string{"hostname"}},
		{TestConfigError{Step: "marshal", Cause: cause}, []string{"test config: marshal:"}},
		{TestConfigError{Step: "write config", Path: "/c/config.yaml", Cause: cause},
			[]string{"write config", `"/c/config.yaml"`}},
	}
	for _, tt := range tests {
		msg := tt.err.Error()
		for _, want := range tt.want {
			assert.Contains(t, msg, want)
		}
		assert.Contains(t, msg, cause.Error())
		assert.ErrorIs(t, tt.err, cause, "%T must unwrap to its cause", tt.err)
	}
}
