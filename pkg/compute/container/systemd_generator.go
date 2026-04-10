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
	"fmt"
	"strings"
)

// SystemdGenerator generates systemd unit files for container services.
// It creates properly formatted unit files with all necessary sections
// for managing containers as systemd services.
type SystemdGenerator struct {
	// podmanPath is the path to the podman binary
	podmanPath string
}

// NewSystemdGenerator creates a new SystemdGenerator with default settings
func NewSystemdGenerator() *SystemdGenerator {
	return &SystemdGenerator{
		podmanPath: "/usr/bin/podman",
	}
}

// SystemdGeneratorOption configures a SystemdGenerator
type SystemdGeneratorOption func(*SystemdGenerator)

// WithPodmanPath sets a custom path to the podman binary
func WithPodmanPath(path string) SystemdGeneratorOption {
	return func(g *SystemdGenerator) {
		g.podmanPath = path
	}
}

// NewSystemdGeneratorWithOptions creates a new SystemdGenerator with options
func NewSystemdGeneratorWithOptions(opts ...SystemdGeneratorOption) *SystemdGenerator {
	g := NewSystemdGenerator()
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Generate generates a systemd unit file for the given container specification.
// The generated unit file includes:
// - Description and documentation
// - After/Wants dependencies
// - ExecStartPre for image pull
// - ExecStart for container run
// - ExecStop for container stop
// - Restart policy
// - Resource limits (CPUQuota, MemoryMax)
func (g *SystemdGenerator) Generate(spec *OrchestratorContainerSpec) string {
	var builder strings.Builder

	// Write [Unit] section
	g.writeUnitSection(&builder, spec.Name, &spec.Service)

	// Write [Service] section
	g.writeServiceSection(&builder, spec.Name, spec.Image, spec.Network.GetNetworkMode().String(),
		spec.Privileged, spec.Env, spec.Labels, spec.Ports, spec.Mounts, &spec.Resources, &spec.Service, spec.Command)

	// Write [Install] section
	g.writeInstallSection(&builder)

	return builder.String()
}

// GenerateFromContainerConfig generates a systemd unit file for a ContainerConfig.
func (g *SystemdGenerator) GenerateFromContainerConfig(container *ContainerConfig) string {
	var builder strings.Builder

	// Write [Unit] section
	g.writeUnitSection(&builder, container.Name, &container.Service)

	// Write [Service] section
	g.writeServiceSection(&builder, container.Name, container.Image, container.Network.GetNetworkMode().String(),
		container.Privileged, container.Env, container.Labels, container.Ports, container.Mounts,
		&container.Resources, &container.Service, container.Command)

	// Write [Install] section
	g.writeInstallSection(&builder)

	return builder.String()
}

// writeUnitSection writes the [Unit] section of the systemd unit file
func (g *SystemdGenerator) writeUnitSection(builder *strings.Builder, name string, service *ServiceConfig) {
	builder.WriteString("[Unit]\n")
	fmt.Fprintf(builder, "Description=Container %s managed by go-trusted-platform\n", name)
	builder.WriteString("Documentation=https://github.com/jeremyhahn/go-trusted-platform\n")

	// Build After dependencies
	afterDeps := []string{"network-online.target"}
	if service != nil && service.Standalone != nil {
		afterDeps = append(afterDeps, service.Standalone.After...)
	}
	if len(afterDeps) > 0 {
		fmt.Fprintf(builder, "After=%s\n", strings.Join(afterDeps, " "))
	}

	// Build Wants dependencies
	wantsDeps := []string{"network-online.target"}
	if service != nil && service.Standalone != nil {
		wantsDeps = append(wantsDeps, service.Standalone.Wants...)
	}
	if len(wantsDeps) > 0 {
		fmt.Fprintf(builder, "Wants=%s\n", strings.Join(wantsDeps, " "))
	}

	builder.WriteString("\n")
}

// writeServiceSection writes the [Service] section of the systemd unit file
func (g *SystemdGenerator) writeServiceSection(builder *strings.Builder, name, image, networkMode string,
	privileged bool, env, labels map[string]string, ports []PortMapping, mounts []MountConfig,
	resources *ResourceConfig, service *ServiceConfig, command []string) {

	builder.WriteString("[Service]\n")
	builder.WriteString("Type=simple\n")
	builder.WriteString("Restart=on-failure\n")
	builder.WriteString("RestartSec=5\n")

	// Override restart policy if specified
	restartPolicy := g.getRestartPolicy(service)
	if restartPolicy != "" {
		fmt.Fprintf(builder, "Restart=%s\n", restartPolicy)
	}

	// ExecStartPre - pull the image
	fmt.Fprintf(builder, "ExecStartPre=-%s pull %s\n", g.podmanPath, image)

	// ExecStartPre - remove any existing container with the same name
	fmt.Fprintf(builder, "ExecStartPre=-%s rm -f %s\n", g.podmanPath, name)

	// ExecStart - run the container
	runCmd := g.buildRunCommand(name, image, networkMode, privileged, env, labels, ports, mounts, resources, command)
	fmt.Fprintf(builder, "ExecStart=%s\n", runCmd)

	// ExecStop - stop the container
	fmt.Fprintf(builder, "ExecStop=%s stop -t 10 %s\n", g.podmanPath, name)

	// ExecStopPost - remove the container after stop
	fmt.Fprintf(builder, "ExecStopPost=-%s rm -f %s\n", g.podmanPath, name)

	// Resource limits
	g.writeResourceLimits(builder, service)

	builder.WriteString("\n")
}

// writeInstallSection writes the [Install] section of the systemd unit file
func (g *SystemdGenerator) writeInstallSection(builder *strings.Builder) {
	builder.WriteString("[Install]\n")
	builder.WriteString("WantedBy=multi-user.target\n")
}

// buildRunCommand builds the podman run command for the container
func (g *SystemdGenerator) buildRunCommand(name, image, networkMode string, privileged bool,
	env, labels map[string]string, ports []PortMapping, mounts []MountConfig,
	resources *ResourceConfig, command []string) string {

	var parts []string

	parts = append(parts, g.podmanPath, "run")

	// Container name
	parts = append(parts, "--name", name)

	// Remove container when it exits (handled by ExecStopPost, but good practice)
	parts = append(parts, "--rm")

	// Network mode
	if networkMode != "" && networkMode != "bridge" {
		parts = append(parts, "--network", networkMode)
	}

	// Privileged mode
	if privileged {
		parts = append(parts, "--privileged")
	}

	// Environment variables
	for key, value := range env {
		parts = append(parts, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Labels
	for key, value := range labels {
		parts = append(parts, "--label", fmt.Sprintf("%s=%s", key, value))
	}

	// Port mappings
	for _, port := range ports {
		portSpec := fmt.Sprintf("%d:%d", port.HostPort, port.ContainerPort)
		if port.HostIP != "" {
			portSpec = fmt.Sprintf("%s:%s", port.HostIP, portSpec)
		}
		if port.Protocol != "" && port.Protocol != "tcp" {
			portSpec = fmt.Sprintf("%s/%s", portSpec, port.Protocol)
		}
		parts = append(parts, "-p", portSpec)
	}

	// Volume mounts
	for _, m := range mounts {
		mountSpec := fmt.Sprintf("%s:%s", m.Source, m.Target)
		if m.ReadOnly {
			mountSpec += ":ro"
		}
		parts = append(parts, "-v", mountSpec)
	}

	// Resource limits from container config
	if resources != nil {
		if resources.MemoryLimit != "" {
			parts = append(parts, "--memory", resources.MemoryLimit)
		}
		if resources.CPULimit != "" {
			parts = append(parts, "--cpus", resources.CPULimit)
		}
	}

	// Image
	parts = append(parts, image)

	// Command
	parts = append(parts, command...)

	return strings.Join(parts, " ")
}

// writeResourceLimits writes systemd resource limit directives
func (g *SystemdGenerator) writeResourceLimits(builder *strings.Builder, service *ServiceConfig) {
	if service == nil || service.Standalone == nil {
		return
	}

	cfg := service.Standalone

	// CPUQuota - e.g., "200%" for 2 CPUs
	if cfg.CPUQuota != "" {
		fmt.Fprintf(builder, "CPUQuota=%s\n", cfg.CPUQuota)
	}

	// MemoryMax - e.g., "4G", "512M"
	if cfg.MemoryMax != "" {
		fmt.Fprintf(builder, "MemoryMax=%s\n", cfg.MemoryMax)
	}
}

// getRestartPolicy maps container restart policy to systemd restart policy
func (g *SystemdGenerator) getRestartPolicy(service *ServiceConfig) string {
	// Check standalone config first
	if service != nil && service.Standalone != nil {
		restart := service.Standalone.Restart
		switch strings.ToLower(restart) {
		case "always":
			return "always"
		case "on-failure":
			return "on-failure"
		case "no", "never":
			return "no"
		case "unless-stopped":
			return "always" // Closest equivalent in systemd
		}
	}

	// Default to on-failure
	return "on-failure"
}

// GenerateSystemdUnit is a convenience function that generates a systemd unit
// file for the given container specification.
func GenerateSystemdUnit(spec *OrchestratorContainerSpec) string {
	g := NewSystemdGenerator()
	return g.Generate(spec)
}
