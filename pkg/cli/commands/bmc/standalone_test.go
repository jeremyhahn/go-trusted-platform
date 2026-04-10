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

package bmc

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// withMockBMCClient swaps the package-level newBMCClient hook for the
// duration of a test. The returned restore function MUST be deferred.
func withMockBMCClient(t *testing.T, mock *bmc.MockClient) func() {
	t.Helper()
	prev := newBMCClient
	newBMCClient = func(_ *bmc.Config, _ *slog.Logger) (bmc.Client, error) {
		return mock, nil
	}
	return func() { newBMCClient = prev }
}

func TestLoadStandalonePassword_Inline(t *testing.T) {
	pw, err := loadStandalonePassword(&standaloneBMCFlags{password: "secret"})
	require.NoError(t, err)
	assert.Equal(t, "secret", pw)
}

func TestLoadStandalonePassword_FileHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	require.NoError(t, os.WriteFile(path, []byte("topsecret\n"), 0o600))

	pw, err := loadStandalonePassword(&standaloneBMCFlags{passwordFile: path})
	require.NoError(t, err)
	assert.Equal(t, "topsecret", pw)
}

func TestLoadStandalonePassword_TrailingWhitespaceTrimmed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	require.NoError(t, os.WriteFile(path, []byte("hunter2\r\n  \t"), 0o600))

	pw, err := loadStandalonePassword(&standaloneBMCFlags{passwordFile: path})
	require.NoError(t, err)
	assert.Equal(t, "hunter2", pw)
}

func TestLoadStandalonePassword_BothFlagsConflict(t *testing.T) {
	_, err := loadStandalonePassword(&standaloneBMCFlags{password: "x", passwordFile: "/tmp/y"})
	var conflict ErrBMCFlagConflict
	require.ErrorAs(t, err, &conflict)
}

func TestLoadStandalonePassword_NeitherFlagSet(t *testing.T) {
	_, err := loadStandalonePassword(&standaloneBMCFlags{})
	var missing ErrBMCMissingCredential
	require.ErrorAs(t, err, &missing)
}

func TestLoadStandalonePassword_InsecureFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

	_, err := loadStandalonePassword(&standaloneBMCFlags{passwordFile: path})
	var insecure ErrBMCInsecurePasswordFile
	require.ErrorAs(t, err, &insecure)
	assert.Equal(t, path, insecure.Path)
}

func TestLoadStandalonePassword_FileMissing(t *testing.T) {
	_, err := loadStandalonePassword(&standaloneBMCFlags{passwordFile: "/nonexistent/definitely-not-here"})
	var unread ErrBMCPasswordFileUnreadable
	require.ErrorAs(t, err, &unread)
}

func TestCheckModeConflict(t *testing.T) {
	tests := []struct {
		name       string
		standalone standaloneBMCFlags
		daemon     bmcFlags
		wantErr    error
	}{
		{
			name:       "neither set",
			standalone: standaloneBMCFlags{},
			daemon:     bmcFlags{},
			wantErr:    ErrBMCNoMode{},
		},
		{
			name:       "both set",
			standalone: standaloneBMCFlags{host: "1.2.3.4"},
			daemon:     bmcFlags{serverURL: "https://x", profileID: "p"},
			wantErr:    ErrBMCFlagConflict{Fields: []string{"--bmc-host", "--server-url/--profile-id"}},
		},
		{
			name:       "standalone only",
			standalone: standaloneBMCFlags{host: "1.2.3.4"},
		},
		{
			name:   "daemon only",
			daemon: bmcFlags{serverURL: "https://x", profileID: "p"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkModeConflict(&tc.standalone, &tc.daemon)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr.Error())
		})
	}
}

func TestNewStandaloneClient_InvalidProtocol(t *testing.T) {
	_, err := newStandaloneClient(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: "telnet",
	}, slog.Default())
	var invalid ErrBMCInvalidProtocol
	require.ErrorAs(t, err, &invalid)
}

func TestNewStandaloneClient_MissingUser(t *testing.T) {
	_, err := newStandaloneClient(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		password: "secret",
		protocol: string(bmc.ProtocolIPMI),
	}, slog.Default())
	var missing ErrBMCMissingCredential
	require.ErrorAs(t, err, &missing)
}

func TestNewStandaloneClient_ExplicitIPMIDefaultsPort(t *testing.T) {
	mock := bmc.NewMockClient()
	defer withMockBMCClient(t, mock)()

	client, err := newStandaloneClient(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: string(bmc.ProtocolIPMI),
	}, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestResolveBMCClient_NoMode(t *testing.T) {
	_, err := resolveBMCClient(context.Background(), &standaloneBMCFlags{}, slog.Default())
	require.Error(t, err)
	var nomode ErrBMCNoMode
	assert.ErrorAs(t, err, &nomode)
}

// TestErrBMCFlagConflictMessage exercises the error string formatting so that
// regressions in the user-facing message are caught.
func TestErrBMCFlagConflictMessage(t *testing.T) {
	err := ErrBMCFlagConflict{Fields: []string{"--a", "--b"}}
	assert.Contains(t, err.Error(), "--a")
	assert.Contains(t, err.Error(), "--b")
}

// TestErrBMCPasswordFileUnreadableUnwrap ensures Unwrap returns the underlying
// error so callers can use errors.Is/As against os.PathError.
func TestErrBMCPasswordFileUnreadableUnwrap(t *testing.T) {
	cause := errors.New("boom")
	err := ErrBMCPasswordFileUnreadable{Path: "/x", Cause: cause}
	assert.ErrorIs(t, err, cause)
}
