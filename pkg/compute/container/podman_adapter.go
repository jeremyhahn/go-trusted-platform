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
	"strconv"
	"strings"
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
	podmanConfig, err := convertFromPodmanContainerConfig(config)
	if err != nil {
		return nil, err
	}
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

// WaitContainer blocks until the container exits and returns its exit code.
func (a *EmbeddedPodmanAdapter) WaitContainer(ctx context.Context, id string) (int, error) {
	return a.manager.WaitContainer(ctx, id)
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

// backendNetworkModes maps a platform network mode onto the network mode the
// podman backend understands. An SDN container is launched on the runtime's
// own bridge and then attached to the OVS bridge by the network manager, so
// the backend is told "bridge" while the measured launch configuration keeps
// naming "sdn" — the platform mode is what the operator approved, and the
// backend mode is a function of it.
var backendNetworkModes = map[string]string{
	NetworkModeBridge.String(): "bridge",
	NetworkModeHost.String():   "host",
	NetworkModeNone.String():   "none",
	NetworkModeSDN.String():    "bridge",
}

// backendNetworkMode resolves the backend network mode for a platform mode,
// defaulting to the bridge every unrecognized mode falls back to.
func backendNetworkMode(mode string) string {
	if mapped, ok := backendNetworkModes[mode]; ok {
		return mapped
	}
	return "bridge"
}

// convertFromPodmanContainerConfig converts a container's effective launch
// configuration into the embedded podman backend's container configuration.
//
// This is the backend projection of the single derivation, and the counterpart
// of podmanRunArgs: whatever it hands the backend, a generated systemd unit or
// rc script must apply too, or the two supervisors would run different
// containers from one measurement.
//
// TPMAccess is derived from the launch configuration's mount list rather than
// carried alongside it, so the host TPM cannot be requested from the backend
// without appearing in the measured configuration. See
// PodmanContainerConfig.GrantsTPMDevice.
//
// It returns an error only for a resource limit whose value is not a quantity
// the runtime can apply; the launch then fails rather than silently starting an
// unconstrained container.
func convertFromPodmanContainerConfig(config *PodmanContainerConfig) (*podman.ContainerConfig, error) {
	if config == nil {
		return nil, nil
	}

	resources, err := backendResources(config.Resources)
	if err != nil {
		return nil, err
	}

	defaultTimeout := defaultStopTimeoutSeconds
	cc := &podman.ContainerConfig{
		Name:        config.Name,
		Image:       config.Image,
		Command:     config.Command,
		Environment: config.Environment,
		Labels:      config.Labels,
		NetworkMode: backendNetworkMode(config.NetworkMode),
		User:        config.User,
		WorkDir:     config.WorkDir,
		Hostname:    config.Hostname,
		Privileged:  config.Privileged,
		ReadOnly:    config.ReadOnly,
		StopTimeout: &defaultTimeout,
		CapAdd:      config.CapAdd,
		CapDrop:     config.CapDrop,
		TPMAccess:   config.GrantsTPMDevice(),
		Resources:   resources,
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

	return cc, nil
}

// backendResources projects the declared resource limits onto the quantities
// the embedded runtime applies to the container's cgroup.
//
// The launch configuration carries the limits as the operator declared them —
// "512M", "1.5" — because that is what a podman command line takes; the OCI
// runtime needs bytes and a CFS quota. Converting here, at the backend
// boundary, keeps one declaration behind both launch paths, exactly as
// backendNetworkMode does for the network mode.
//
// A zero ResourceConfig yields no limits at all rather than an empty limit set,
// so a container that declared none is launched exactly as it was before.
func backendResources(r ResourceConfig) (*podman.ResourceLimits, error) {
	if r == (ResourceConfig{}) {
		return nil, nil
	}

	limits := &podman.ResourceLimits{
		CPUShares: r.CPUShares,
		PidsLimit: r.PidsLimit,
	}

	memoryFields := []struct {
		name  string
		value string
		out   *int64
	}{
		{name: "memory_limit", value: r.MemoryLimit, out: &limits.MemoryLimit},
		{name: "memory_reservation", value: r.MemoryReservation, out: &limits.MemoryReservation},
		{name: "memory_swap", value: r.MemorySwap, out: &limits.MemorySwap},
	}
	for _, field := range memoryFields {
		bytes, err := parseMemoryBytes(field.name, field.value)
		if err != nil {
			return nil, err
		}
		*field.out = bytes
	}

	if r.CPULimit != "" {
		cpus, err := strconv.ParseFloat(strings.TrimSpace(r.CPULimit), 64)
		if err != nil || cpus < 0 {
			return nil, &ResourceValueError{Field: "cpu_limit", Value: r.CPULimit}
		}
		// podman's --cpus is a fraction of one CFS period; the runtime enforces
		// it as that quota, so both forms are derived here from the one value.
		limits.CPUs = cpus
		limits.CPUPeriod = cpuQuotaPeriodMicroseconds
		limits.CPUQuota = int64(cpus * cpuQuotaPeriodMicroseconds)
	}

	return limits, nil
}

// memoryUnitBytes maps the size suffixes a declared memory limit may carry onto
// their multipliers. They are binary multiples, as the container runtimes treat
// them.
var memoryUnitBytes = map[string]int64{
	"":   1,
	"B":  1,
	"K":  1 << 10,
	"KB": 1 << 10,
	"M":  1 << 20,
	"MB": 1 << 20,
	"G":  1 << 30,
	"GB": 1 << 30,
	"T":  1 << 40,
	"TB": 1 << 40,
}

// parseMemoryBytes converts a declared memory quantity to bytes. An empty
// value means "no limit" and yields zero, which the runtime treats as unset.
func parseMemoryBytes(field, value string) (int64, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	if trimmed == "" {
		return 0, nil
	}

	digits := strings.TrimRight(trimmed, "BKMGT")
	unit := trimmed[len(digits):]
	multiplier, ok := memoryUnitBytes[unit]
	if !ok || digits == "" {
		return 0, &ResourceValueError{Field: field, Value: value}
	}

	quantity, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || quantity < 0 || quantity > (1<<62)/multiplier {
		return 0, &ResourceValueError{Field: field, Value: value}
	}
	return quantity * multiplier, nil
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
