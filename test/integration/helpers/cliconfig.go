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
	"errors"
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
//
// The context's quicbaas connection (the verbs that open Client.QuicBaaS(),
// such as `kms key csr`, `dek` and `secrets`) also goes to platformd: the
// devcontainer runs no quicbaasd, and platformd serves the quicbaas.kms.v1
// services itself (docs/kms/cli.md §3). It goes to grpcAddr with the harness
// TLS files, not to socketPath: the quicbaas SDK requires TLS on every
// transport, and platformd's Unix socket is plaintext with peer credentials.
func WriteLocalCLIConfig(dir, socketPath, grpcAddr string) (string, error) {
	content := "current_context: " + CLIContextName + "\n" +
		"contexts:\n" +
		"  - name: " + CLIContextName + "\n" +
		"    type: local\n" +
		"    local:\n" +
		"      socket_path: " + socketPath + "\n" +
		"      grpc_addr: " + grpcAddr + "\n"
	if grpcAddr != "" {
		content += "      quicbaas_addr: " + grpcAddr + "\n" +
			"      quicbaas_transport: grpc\n" +
			localContextFileLine("quicbaas_ca_cert", os.Getenv(EnvCACert)) +
			localContextFileLine("quicbaas_client_cert", os.Getenv(EnvClientCert)) +
			localContextFileLine("quicbaas_client_key", os.Getenv(EnvClientKey))
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// localContextFileLine renders one local-context file field, or nothing when
// the harness did not set the file.
func localContextFileLine(key, path string) string {
	if path == "" {
		return ""
	}
	return "      " + key + ": " + path + "\n"
}

// WriteTempLocalCLIConfig writes the WriteLocalCLIConfig file into a new
// temporary directory and returns the directory, which the caller removes on
// teardown, and the file's path. Pass the path with --config: platformctl has
// no --socket flag, so a CLI adapter that tried to name the harness socket on
// the command line had every command rejected before it dialled (#540).
func WriteTempLocalCLIConfig(socketPath, grpcAddr string) (dir, path string, err error) {
	dir, err = os.MkdirTemp("", "platformctl-config-*")
	if err != nil {
		return "", "", err
	}
	path, err = WriteLocalCLIConfig(dir, socketPath, grpcAddr)
	if err != nil {
		return "", "", errors.Join(err, os.RemoveAll(dir))
	}
	return dir, path, nil
}
