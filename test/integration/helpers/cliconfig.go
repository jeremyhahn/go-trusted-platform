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

package helpers

import (
	"os"
	"path/filepath"
)

// CLIContextName is the platformctl context WriteLocalCLIConfig defines and
// selects.
const CLIContextName = "integration-test"

// WriteLocalCLIConfig writes a platformctl config file into dir whose current
// context dials platformd's Unix socket at socketPath (and its gRPC listener
// at grpcAddr), and returns the file's path. Pass it with --config.
//
// Without one, platformctl uses its built-in "local" context and dials
// /run/platformd.sock -- the production path, which the devcontainer harness
// never creates. That is how the tenant CLI adapter reported "failed to
// connect via unix to /run/platformd.sock" for every call (#730).
func WriteLocalCLIConfig(dir, socketPath, grpcAddr string) (string, error) {
	content := "current_context: " + CLIContextName + "\n" +
		"contexts:\n" +
		"  - name: " + CLIContextName + "\n" +
		"    type: local\n" +
		"    local:\n" +
		"      socket_path: " + socketPath + "\n" +
		"      grpc_addr: " + grpcAddr + "\n"
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
