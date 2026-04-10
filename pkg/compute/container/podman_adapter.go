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

package container

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
)

// EmbeddedPodmanAdapter adapts the embedded podman.PodmanManager to
// the PodmanBackend interface used by the Container Orchestrator.
// This provides a bridge between the embedded OCI runtime and the
// higher-level orchestration layer.
type EmbeddedPodmanAdapter struct {
	manager podman.PodmanManager
}

// NewEmbeddedPodmanAdapter creates a new adapter for the embedded podman runtime.
func NewEmbeddedPodmanAdapter(manager podman.PodmanManager) *EmbeddedPodmanAdapter {
	return &EmbeddedPodmanAdapter{
		manager: manager,
	}
}

// Connect initializes the embedded runtime.
// This is called Connect for interface compatibility, but uses Initialize internally.
func (a *EmbeddedPodmanAdapter) Connect(ctx context.Context) error {
	return a.manager.Initialize(ctx)
}

// PullImage pulls a container image from a registry.
func (a *EmbeddedPodmanAdapter) PullImage(ctx context.Context, imageRef string) error {
	return a.manager.PullImage(ctx, imageRef)
}

// ListImages returns all images.
func (a *EmbeddedPodmanAdapter) ListImages(ctx context.Context) ([]*PodmanImage, error) {
	images, err := a.manager.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*PodmanImage, 0, len(images))
	for _, img := range images {
		result = append(result, convertToPodmanImage(img))
	}
	return result, nil
}

// InspectImage returns detailed information about an image.
func (a *EmbeddedPodmanAdapter) InspectImage(ctx context.Context, imageRef string) (*PodmanImage, error) {
	img, err := a.manager.InspectImage(ctx, imageRef)
	if err != nil {
		return nil, err
	}
	return convertToPodmanImage(img), nil
}

// CreateContainer creates a new container.
func (a *EmbeddedPodmanAdapter) CreateContainer(ctx context.Context, config *PodmanContainerConfig) (*PodmanContainer, error) {
	podmanConfig := convertFromPodmanContainerConfig(config)
	container, err := a.manager.CreateContainer(ctx, podmanConfig)
	if err != nil {
		return nil, err
	}
	return convertToPodmanContainer(container), nil
}

// StartContainer starts a container.
func (a *EmbeddedPodmanAdapter) StartContainer(ctx context.Context, id string) error {
	return a.manager.StartContainer(ctx, id)
}

// StopContainer stops a running container.
func (a *EmbeddedPodmanAdapter) StopContainer(ctx context.Context, id string, timeout *int) error {
	return a.manager.StopContainer(ctx, id, timeout)
}

// RemoveContainer removes a container.
func (a *EmbeddedPodmanAdapter) RemoveContainer(ctx context.Context, id string, force bool) error {
	return a.manager.RemoveContainer(ctx, id, force)
}

// InspectContainer returns detailed information about a container.
func (a *EmbeddedPodmanAdapter) InspectContainer(ctx context.Context, id string) (*PodmanContainer, error) {
	container, err := a.manager.InspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	return convertToPodmanContainer(container), nil
}

// ListContainers returns all containers.
func (a *EmbeddedPodmanAdapter) ListContainers(ctx context.Context, all bool) ([]*PodmanContainer, error) {
	containers, err := a.manager.ListContainers(ctx, all)
	if err != nil {
		return nil, err
	}

	result := make([]*PodmanContainer, 0, len(containers))
	for _, c := range containers {
		result = append(result, convertToPodmanContainer(c))
	}
	return result, nil
}

// GetContainerLogs retrieves logs from a container.
func (a *EmbeddedPodmanAdapter) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*PodmanContainerLogs, error) {
	logs, err := a.manager.GetContainerLogs(ctx, id, follow, since)
	if err != nil {
		return nil, err
	}
	return convertToPodmanContainerLogs(logs), nil
}

// Close closes the embedded runtime.
func (a *EmbeddedPodmanAdapter) Close() error {
	return a.manager.Close()
}

// convertToPodmanImage converts podman.Image to PodmanImage
func convertToPodmanImage(img *podman.Image) *PodmanImage {
	if img == nil {
		return nil
	}
	return &PodmanImage{
		ID:           img.ID,
		Names:        img.Names,
		Digest:       img.Digest,
		Size:         img.Size,
		Created:      img.Created,
		Labels:       img.Labels,
		Architecture: img.Architecture,
		OS:           img.OS,
	}
}

// convertToPodmanContainer converts podman.Container to PodmanContainer
func convertToPodmanContainer(c *podman.Container) *PodmanContainer {
	if c == nil {
		return nil
	}
	pc := &PodmanContainer{
		ID:          c.ID,
		Name:        c.Name,
		Image:       c.Image,
		ImageDigest: c.ImageDigest,
		State:       string(c.State),
		CreatedAt:   c.CreatedAt,
		ExitCode:    c.ExitCode,
		Labels:      c.Labels,
		PID:         c.PID,
		Command:     c.Command,
		NetworkMode: c.NetworkMode,
	}
	if c.StartedAt != nil {
		pc.StartedAt = c.StartedAt
	}
	if c.FinishedAt != nil {
		pc.FinishedAt = c.FinishedAt
	}
	return pc
}

// convertFromPodmanContainerConfig converts PodmanContainerConfig to podman.ContainerConfig
func convertFromPodmanContainerConfig(config *PodmanContainerConfig) *podman.ContainerConfig {
	if config == nil {
		return nil
	}

	defaultTimeout := 10
	cc := &podman.ContainerConfig{
		Name:        config.Name,
		Image:       config.Image,
		Command:     config.Command,
		Environment: config.Environment,
		Labels:      config.Labels,
		NetworkMode: config.NetworkMode,
		User:        config.User,
		WorkDir:     config.WorkDir,
		Hostname:    config.Hostname,
		Privileged:  config.Privileged,
		ReadOnly:    config.ReadOnly,
		StopTimeout: &defaultTimeout,
		CapAdd:      config.CapAdd,
		CapDrop:     config.CapDrop,
		TPMAccess:   config.TPMAccess,
	}

	if config.StopTimeout != nil {
		cc.StopTimeout = config.StopTimeout
	}

	// Convert mounts
	for _, m := range config.Mounts {
		cc.Mounts = append(cc.Mounts, podman.Mount{
			Source:   m.Source,
			Target:   m.Target,
			Type:     m.Type,
			ReadOnly: m.ReadOnly,
			Options:  m.Options,
		})
	}

	// Convert ports
	for _, p := range config.Ports {
		cc.Ports = append(cc.Ports, podman.PortMapping{
			HostIP:        p.HostIP,
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	return cc
}

// convertToPodmanContainerLogs converts podman.ContainerLogs to PodmanContainerLogs
func convertToPodmanContainerLogs(logs *podman.ContainerLogs) *PodmanContainerLogs {
	if logs == nil {
		return nil
	}
	return &PodmanContainerLogs{
		ContainerID: logs.ContainerID,
		Stdout:      logs.Stdout,
		Stderr:      logs.Stderr,
		Since:       logs.Since,
		Until:       logs.Until,
	}
}

// Ensure EmbeddedPodmanAdapter implements PodmanBackend
var _ PodmanBackend = (*EmbeddedPodmanAdapter)(nil)
