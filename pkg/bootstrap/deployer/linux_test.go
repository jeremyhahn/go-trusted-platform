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

func TestLinuxDeployer_GenerateRunCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "ghcr.io/org/bootstrap:latest",
	}

	cmd := GenerateRunCommand(config)

	if !strings.Contains(cmd, "docker run -d") {
		t.Error("expected 'docker run -d' in command")
	}
	if !strings.Contains(cmd, "--name "+DefaultContainerName) {
		t.Errorf("expected container name %s in command", DefaultContainerName)
	}
	if !strings.Contains(cmd, "--net=host") {
		t.Error("expected '--net=host' in command")
	}
	if !strings.Contains(cmd, DefaultRemoteDataDir+":/data") {
		t.Errorf("expected volume mount with %s:/data", DefaultRemoteDataDir)
	}
	if !strings.Contains(cmd, config.ContainerImage) {
		t.Error("expected container image in command")
	}
}

func TestLinuxDeployer_GenerateRunCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
		ContainerImage:   "ghcr.io/org/bootstrap:v1.0",
	}

	cmd := GenerateRunCommand(config)

	if !strings.HasPrefix(cmd, "podman run -d") {
		t.Error("expected command to start with 'podman run -d'")
	}
}

func TestLinuxDeployer_GenerateTeardownCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
	}

	cmd := GenerateTeardownCommand(config)

	if !strings.Contains(cmd, "docker rm -f "+DefaultContainerName) {
		t.Error("expected 'docker rm -f' with container name in command")
	}
	if !strings.Contains(cmd, "rm -rf "+DefaultRemoteDataDir) {
		t.Errorf("expected 'rm -rf %s' in command", DefaultRemoteDataDir)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
	}

	cmd := GenerateTeardownCommand(config)

	if !strings.HasPrefix(cmd, "podman rm -f") {
		t.Error("expected command to start with 'podman rm -f'")
	}
}
