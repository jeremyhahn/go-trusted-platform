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
//
// The unit starts the container's effective launch configuration — the same
// value newLaunchConfig derives for the embedded path and AttestationSpec
// measures — so a standalone container is the container that was measured. The
// specification is read only to derive that value; the unit's own supervision
// settings (dependencies, restart policy, cgroup limits) come from
// spec.Service.
func (g *SystemdGenerator) Generate(spec *OrchestratorContainerSpec) string {
	if spec == nil {
		return ""
	}
	return g.generate(newLaunchConfig(spec), &spec.Service)
}

// GenerateFromContainerConfig generates a systemd unit file for a
// ContainerConfig, through the same single derivation as Generate.
func (g *SystemdGenerator) GenerateFromContainerConfig(container *ContainerConfig) string {
	if container == nil {
		return ""
	}
	return g.generate(newLaunchConfig(container.ToOrchestratorContainerSpec()), &container.Service)
}

// generate writes the unit file for an effective launch configuration.
func (g *SystemdGenerator) generate(launch *PodmanContainerConfig, service *ServiceConfig) string {
	var builder strings.Builder

	g.writeUnitSection(&builder, launch.Name, service)
	g.writeServiceSection(&builder, launch, service)
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

// writeServiceSection writes the [Service] section of the systemd unit file.
//
// ExecStart is the launch configuration rendered by podmanRunArgs, the same
// rendering the OpenRC script runs, so the two supervisors start identical
// containers.
func (g *SystemdGenerator) writeServiceSection(builder *strings.Builder, launch *PodmanContainerConfig, service *ServiceConfig) {
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
	fmt.Fprintf(builder, "ExecStartPre=-%s pull %s\n",
		systemdExecArg(g.podmanPath), systemdExecArg(launch.Image))

	// ExecStartPre - remove any existing container with the same name
	fmt.Fprintf(builder, "ExecStartPre=-%s rm -f %s\n",
		systemdExecArg(g.podmanPath), systemdExecArg(launch.Name))

	// ExecStart - run the measured launch configuration
	fmt.Fprintf(builder, "ExecStart=%s\n",
		systemdExecCommand(g.podmanPath, append([]string{"run"}, podmanRunArgs(launch)...)))

	// ExecStop - stop the container on the launch configuration's schedule
	fmt.Fprintf(builder, "ExecStop=%s stop -t %d %s\n",
		systemdExecArg(g.podmanPath), effectiveStopTimeout(launch), systemdExecArg(launch.Name))

	// ExecStopPost - remove the container after stop
	fmt.Fprintf(builder, "ExecStopPost=-%s rm -f %s\n",
		systemdExecArg(g.podmanPath), systemdExecArg(launch.Name))

	// Resource limits
	g.writeResourceLimits(builder, service)

	builder.WriteString("\n")
}

// writeInstallSection writes the [Install] section of the systemd unit file
func (g *SystemdGenerator) writeInstallSection(builder *strings.Builder) {
	builder.WriteString("[Install]\n")
	builder.WriteString("WantedBy=multi-user.target\n")
}

// writeResourceLimits writes systemd resource limit directives.
//
// These are the supervisor's own cgroup settings from the standalone service
// configuration, not the container's declared limits: the latter are part of the
// launch configuration and are applied by podman itself, on every launch path.
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
