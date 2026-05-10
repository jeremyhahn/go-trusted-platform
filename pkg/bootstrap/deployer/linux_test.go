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

package deployer

import (
	"strings"
	"testing"
)

// All commands run remotely over SSH so every interpolated value is
// shell-quoted (single quotes). Tests verify the unquoted prefix and
// the quoted occurrences so the substring assertions remain stable
// against safer-quoting refactors.

func TestLinuxDeployer_GenerateRunCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "ghcr.io/org/bootstrap:latest",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)

	if !strings.HasPrefix(cmd, "'docker' run -d --name") {
		t.Errorf("expected command to start with quoted 'docker' run -d, got: %s", cmd)
	}
	if !strings.Contains(cmd, "'"+DefaultContainerName+"'") {
		t.Errorf("expected quoted container name %q in command, got: %s", DefaultContainerName, cmd)
	}
	if !strings.Contains(cmd, "--net=host") {
		t.Error("expected '--net=host' in command")
	}
	if !strings.Contains(cmd, "'"+DefaultRemoteDataDir+"':/data") {
		t.Errorf("expected quoted volume mount %q:/data in command, got: %s", DefaultRemoteDataDir, cmd)
	}
	if !strings.Contains(cmd, "'"+config.ContainerImage+"'") {
		t.Errorf("expected quoted container image in command, got: %s", cmd)
	}
}

func TestLinuxDeployer_GenerateRunCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
		ContainerImage:   "ghcr.io/org/bootstrap:v1.0",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)

	if !strings.HasPrefix(cmd, "'podman' run -d") {
		t.Errorf("expected command to start with 'podman' run -d, got: %s", cmd)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)

	if !strings.Contains(cmd, "'docker' rm -f '"+DefaultContainerName+"'") {
		t.Errorf("expected quoted 'docker' rm -f with container name in command, got: %s", cmd)
	}
	if !strings.Contains(cmd, "rm -rf '"+DefaultRemoteDataDir+"'") {
		t.Errorf("expected 'rm -rf %q' in command, got: %s", DefaultRemoteDataDir, cmd)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)

	if !strings.HasPrefix(cmd, "'podman' rm -f") {
		t.Errorf("expected command to start with 'podman' rm -f, got: %s", cmd)
	}
}

func TestLinuxDeployer_DataDirOverride(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "img:v1",
		DataDir:          "/var/lib/trusted-bootstrap",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)
	if !strings.Contains(cmd, "'/var/lib/trusted-bootstrap':/data") {
		t.Errorf("expected DataDir override honoured, got: %s", cmd)
	}

	teardown := GenerateTeardownCommand(config)
	if !strings.Contains(teardown, "rm -rf '/var/lib/trusted-bootstrap'") {
		t.Errorf("expected DataDir honoured in teardown, got: %s", teardown)
	}
}

func TestDeployConfig_ApplyDefaults_DataDirAndContainerName(t *testing.T) {
	c := &DeployConfig{}
	c.ApplyDefaults()
	if c.DataDir != DefaultRemoteDataDir {
		t.Errorf("expected DataDir default %q, got %q", DefaultRemoteDataDir, c.DataDir)
	}
	if c.ContainerName != DefaultContainerName {
		t.Errorf("expected ContainerName default %q, got %q", DefaultContainerName, c.ContainerName)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":        "'plain'",
		"with space":   "'with space'",
		"with'quote":   `'with'\''quote'`,
		"":             "''",
		"a'b'c":        `'a'\''b'\''c'`,
		"--flag=value": "'--flag=value'",
	}
	for in, want := range cases {
		got := shellQuote(in)
		if got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsMissingAssetError(t *testing.T) {
	missing := []string{
		"Error response from daemon: Could not find the file /data/vmlinuz in container",
		"Error: No such file or directory",
		"error: stat /data/foo: no such file",
		"Error: path /data/x does not exist in container abc",
	}
	for _, s := range missing {
		if !isMissingAssetError(s) {
			t.Errorf("expected missing-asset signal in %q", s)
		}
	}
	notMissing := []string{
		"docker: connection refused",
		"runtime crashed",
		"",
	}
	for _, s := range notMissing {
		if isMissingAssetError(s) {
			t.Errorf("did not expect missing-asset signal in %q", s)
		}
	}
}
