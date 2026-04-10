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
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// LinuxDeployer deploys the bootstrap container to a Linux host via SSH.
type LinuxDeployer struct {
	logger *slog.Logger
}

// Deploy connects to the Linux host via SSH, copies the manifest and configs,
// pulls the container image, and runs the bootstrap container.
func (d *LinuxDeployer) Deploy(ctx context.Context, config *DeployConfig) (*DeployResult, error) {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	d.logger.Info("connected to deploy target",
		slog.String("host", config.Host),
		slog.Int("port", config.Port))

	// Create remote data directory.
	mkdirCmd := fmt.Sprintf("mkdir -p %s/configs", DefaultRemoteDataDir)
	if _, err := client.Run(ctx, mkdirCmd); err != nil {
		return nil, err
	}

	// Copy manifest file.
	remotManifest := fmt.Sprintf("%s/manifest.yaml", DefaultRemoteDataDir)
	if err := client.CopyFile(ctx, config.ManifestPath, remotManifest); err != nil {
		return nil, err
	}
	d.logger.Info("copied manifest", slog.String("remote_path", remotManifest))

	// Pull the container image.
	pullCmd := fmt.Sprintf("%s pull %s", config.ContainerRuntime, config.ContainerImage)
	if _, err := client.Run(ctx, pullCmd); err != nil {
		return nil, err
	}
	d.logger.Info("pulled container image", slog.String("image", config.ContainerImage))

	// Run the container.
	runCmd := GenerateRunCommand(config)
	output, err := client.Run(ctx, runCmd)
	if err != nil {
		return nil, err
	}

	containerID := strings.TrimSpace(output)
	d.logger.Info("started bootstrap container",
		slog.String("container_id", containerID),
		slog.String("host", config.Host))

	return &DeployResult{
		ContainerID: containerID,
		Host:        config.Host,
		Running:     true,
	}, nil
}

// Verify checks that the bootstrap container is running on the target host.
func (d *LinuxDeployer) Verify(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return err
	}

	inspectCmd := fmt.Sprintf("%s inspect --format '{{.State.Running}}' %s",
		config.ContainerRuntime, DefaultContainerName)
	output, err := client.Run(ctx, inspectCmd)
	if err != nil {
		return ErrContainerNotRunning{ContainerID: DefaultContainerName, Host: config.Host}
	}

	if strings.TrimSpace(output) != "true" {
		return ErrContainerNotRunning{ContainerID: DefaultContainerName, Host: config.Host}
	}

	d.logger.Info("container verified running",
		slog.String("host", config.Host),
		slog.String("container", DefaultContainerName))
	return nil
}

// Teardown stops and removes the bootstrap container and data from the target host.
func (d *LinuxDeployer) Teardown(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return err
	}

	teardownCmd := GenerateTeardownCommand(config)
	if _, err := client.Run(ctx, teardownCmd); err != nil {
		d.logger.Warn("teardown command returned error",
			slog.String("error", err.Error()))
	}

	d.logger.Info("teardown complete",
		slog.String("host", config.Host),
		slog.String("container", DefaultContainerName))
	return nil
}

// GenerateRunCommand builds the container run command string.
func GenerateRunCommand(config *DeployConfig) string {
	return fmt.Sprintf(
		"%s run -d --name %s --net=host -v %s:/data %s",
		config.ContainerRuntime,
		DefaultContainerName,
		DefaultRemoteDataDir,
		config.ContainerImage,
	)
}

// GenerateTeardownCommand builds the container teardown command string.
func GenerateTeardownCommand(config *DeployConfig) string {
	return fmt.Sprintf(
		"%s rm -f %s && rm -rf %s",
		config.ContainerRuntime,
		DefaultContainerName,
		DefaultRemoteDataDir,
	)
}
