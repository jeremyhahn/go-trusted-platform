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

//go:build integration

package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestCreateTestConfigPointsQuicBaaSAtPlatformd pins the context the CA
// suite's platformctl runs under: the quicbaas client the kms verbs open
// must dial platformd's gRPC listener, which serves quicbaas.kms.v1, over
// the harness TLS, and not the /run/quicbaas.sock default nothing in the
// devcontainer serves.
func TestCreateTestConfigPointsQuicBaaSAtPlatformd(t *testing.T) {
	t.Setenv(helpers.EnvCACert, "/certs/ca.crt")
	adapter := &CLIAdapter{socketPath: "/run/platformd-it.sock", grpcEndpoint: "127.0.0.1:10443"}
	require.NoError(t, adapter.createTestConfig())
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(adapter.configDir)) })

	config, err := cli.LoadConfig(adapter.configPath)
	require.NoError(t, err)
	context, err := config.GetContext(helpers.CLIContextName)
	require.NoError(t, err)

	require.Equal(t, adapter.socketPath, context.Local.SocketPath)
	require.Equal(t, adapter.grpcEndpoint, context.ResolveQuicBaaSAddr())
	require.NotEqual(t, cli.DefaultQuicBaaSSocketPath, context.ResolveQuicBaaSAddr())
	require.Equal(t, "grpc", context.ResolveQuicBaaSTransport())
	require.Equal(t, "/certs/ca.crt", context.Local.QuicBaaSCACert)
}

// TestCreateTestConfigReportsUnwritableTempDir checks a temp directory that
// cannot be created fails with the typed error and leaves no config path.
func TestCreateTestConfigReportsUnwritableTempDir(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	adapter := &CLIAdapter{socketPath: "/run/platformd-it.sock", grpcEndpoint: "127.0.0.1:10443"}

	err := adapter.createTestConfig()

	var target ErrCLIConfigCreationFailed
	require.ErrorAs(t, err, &target)
	require.Empty(t, adapter.configPath)
}
