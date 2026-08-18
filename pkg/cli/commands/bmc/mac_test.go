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
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// withStubbedHostMACDiscovery swaps the package-level discoverHostMACs
// hook for the duration of a test so no BMC or network is touched.
func withStubbedHostMACDiscovery(t *testing.T, fn func(context.Context, *bmc.Config, *slog.Logger) ([]string, error)) {
	t.Helper()
	prev := discoverHostMACs
	discoverHostMACs = fn
	t.Cleanup(func() { discoverHostMACs = prev })
}

func execMACCommand(t *testing.T, getFlags func() *cli.CommonFlags, args ...string) error {
	t.Helper()
	cmd := newMACCommand(getFlags)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestMACCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newMACCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "mac", cmd.Use)

	// Same standalone flag set as system-info's --bmc-host mode.
	for _, flagName := range []string{"bmc-host", "bmc-port", "bmc-user", "bmc-pass", "bmc-pass-file", "bmc-protocol"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}

	// Standalone-only: no daemon-mode flags.
	for _, flagName := range []string{"server-url", "profile-id"} {
		assert.Nil(t, cmd.Flag(flagName), "flag %s should not exist on a standalone-only command", flagName)
	}
}

func TestMACCommand_Run(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		stub    func(context.Context, *bmc.Config, *slog.Logger) ([]string, error)
		wantErr error
		verify  func(t *testing.T, cfg *bmc.Config)
	}{
		{
			name: "happy path over explicit IPMI",
			args: []string{
				"--bmc-host", "192.0.2.10",
				"--bmc-user", "admin",
				"--bmc-pass", "secret",
				"--bmc-protocol", "ipmi",
			},
			stub: func(_ context.Context, _ *bmc.Config, _ *slog.Logger) ([]string, error) {
				return []string{"00:25:90:5e:02:aa"}, nil
			},
			verify: func(t *testing.T, cfg *bmc.Config) {
				assert.Equal(t, "192.0.2.10", cfg.Address)
				assert.Equal(t, bmc.ProtocolIPMI, cfg.Protocol)
				assert.Equal(t, 623, cfg.Port, "IPMI protocol should default to port 623")
				assert.Equal(t, "admin", cfg.Username)
			},
		},
		{
			name: "explicit --bmc-port overrides the protocol default",
			args: []string{
				"--bmc-host", "192.0.2.10",
				"--bmc-user", "admin",
				"--bmc-pass", "secret",
				"--bmc-protocol", "ipmi",
				"--bmc-port", "6230",
			},
			stub: func(_ context.Context, _ *bmc.Config, _ *slog.Logger) ([]string, error) {
				return []string{"00:25:90:5e:02:aa"}, nil
			},
			verify: func(t *testing.T, cfg *bmc.Config) {
				assert.Equal(t, 6230, cfg.Port)
			},
		},
		{
			name:    "missing --bmc-host returns ErrBMCStandaloneRequired",
			args:    []string{"--bmc-user", "admin", "--bmc-pass", "secret"},
			wantErr: ErrBMCStandaloneRequired{Command: "mac"},
		},
		{
			name: "missing --bmc-user returns ErrBMCMissingCredential",
			args: []string{
				"--bmc-host", "192.0.2.10",
				"--bmc-pass", "secret",
				"--bmc-protocol", "ipmi",
			},
			wantErr: ErrBMCMissingCredential{Field: "username (set --bmc-user)"},
		},
		{
			name: "invalid protocol returns ErrBMCInvalidProtocol",
			args: []string{
				"--bmc-host", "192.0.2.10",
				"--bmc-user", "admin",
				"--bmc-pass", "secret",
				"--bmc-protocol", "telnet",
			},
			wantErr: ErrBMCInvalidProtocol{Value: "telnet"},
		},
		{
			name: "discovery failure is propagated",
			args: []string{
				"--bmc-host", "192.0.2.10",
				"--bmc-user", "admin",
				"--bmc-pass", "secret",
				"--bmc-protocol", "ipmi",
			},
			stub: func(_ context.Context, _ *bmc.Config, _ *slog.Logger) ([]string, error) {
				return nil, bmc.ErrMACDiscoveryUnsupported{Protocol: bmc.ProtocolIPMI}
			},
			wantErr: bmc.ErrMACDiscoveryUnsupported{Protocol: bmc.ProtocolIPMI},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotConfig *bmc.Config
			stub := tc.stub
			if stub == nil {
				stub = func(_ context.Context, _ *bmc.Config, _ *slog.Logger) ([]string, error) {
					t.Fatal("discoverHostMACs must not be invoked on this path")
					return nil, nil
				}
			}
			withStubbedHostMACDiscovery(t, func(ctx context.Context, cfg *bmc.Config, logger *slog.Logger) ([]string, error) {
				gotConfig = cfg
				return stub(ctx, cfg, logger)
			})

			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
			}
			err := execMACCommand(t, getFlags, tc.args...)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gotConfig, "expected discovery to receive the standalone config")
			if tc.verify != nil {
				tc.verify(t, gotConfig)
			}
		})
	}
}

func TestErrBMCStandaloneRequiredMessage(t *testing.T) {
	err := ErrBMCStandaloneRequired{Command: "mac"}
	assert.Equal(t, "bmc: mac is a standalone-only command; set --bmc-host", err.Error())
}
