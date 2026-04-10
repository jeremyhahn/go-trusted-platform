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
	"strings"
	"testing"
)

// TestNewSystemdGenerator tests the constructor
func TestNewSystemdGenerator(t *testing.T) {
	g := NewSystemdGenerator()

	if g == nil {
		t.Fatal("NewSystemdGenerator() returned nil")
	}

	if g.podmanPath != "/usr/bin/podman" {
		t.Errorf("podmanPath = %q, want %q", g.podmanPath, "/usr/bin/podman")
	}
}

// TestNewSystemdGeneratorWithOptions tests the constructor with options
func TestNewSystemdGeneratorWithOptions(t *testing.T) {
	customPath := "/custom/podman"
	g := NewSystemdGeneratorWithOptions(
		WithPodmanPath(customPath),
	)

	if g == nil {
		t.Fatal("NewSystemdGeneratorWithOptions() returned nil")
	}

	if g.podmanPath != customPath {
		t.Errorf("podmanPath = %q, want %q", g.podmanPath, customPath)
	}
}

// TestSystemdGenerator_Generate tests generating a systemd unit file
func TestSystemdGenerator_Generate(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:  "test-container",
		Image: "docker.io/library/nginx:latest",
	}

	result := g.Generate(spec)

	// Verify sections
	if !strings.Contains(result, "[Unit]") {
		t.Error("Generated unit file missing [Unit] section")
	}
	if !strings.Contains(result, "[Service]") {
		t.Error("Generated unit file missing [Service] section")
	}
	if !strings.Contains(result, "[Install]") {
		t.Error("Generated unit file missing [Install] section")
	}

	// Verify description
	if !strings.Contains(result, "Description=Container test-container managed by go-trusted-platform") {
		t.Error("Generated unit file missing description")
	}

	// Verify documentation
	if !strings.Contains(result, "Documentation=https://github.com/jeremyhahn/go-trusted-platform") {
		t.Error("Generated unit file missing documentation")
	}

	// Verify ExecStartPre pull
	if !strings.Contains(result, "ExecStartPre=-/usr/bin/podman pull docker.io/library/nginx:latest") {
		t.Error("Generated unit file missing image pull command")
	}

	// Verify ExecStart
	if !strings.Contains(result, "ExecStart=/usr/bin/podman run") {
		t.Error("Generated unit file missing ExecStart")
	}

	// Verify ExecStop
	if !strings.Contains(result, "ExecStop=/usr/bin/podman stop -t 10 test-container") {
		t.Error("Generated unit file missing ExecStop")
	}

	// Verify WantedBy
	if !strings.Contains(result, "WantedBy=multi-user.target") {
		t.Error("Generated unit file missing WantedBy")
	}
}

// TestSystemdGenerator_GenerateWithFullConfig tests with all options
func TestSystemdGenerator_GenerateWithFullConfig(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:       "full-test",
		Image:      "myregistry.io/myapp:v1.0",
		Command:    []string{"/app/start.sh"},
		Privileged: true,
		Env: map[string]string{
			"APP_ENV":   "production",
			"LOG_LEVEL": "debug",
		},
		Labels: map[string]string{
			"app": "myapp",
		},
		Ports: []PortMapping{
			{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			{HostPort: 9090, ContainerPort: 90, Protocol: "udp"},
			{HostIP: "127.0.0.1", HostPort: 3000, ContainerPort: 3000},
		},
		Mounts: []MountConfig{
			{Source: "/host/data", Target: "/data"},
			{Source: "/host/config", Target: "/config", ReadOnly: true},
		},
		Network: ContainerNetworkConfig{
			Mode: NetworkModeHost,
		},
		Resources: ResourceConfig{
			MemoryLimit: "2G",
			CPULimit:    "2",
		},
		Service: ServiceConfig{
			Mode: ServiceModeStandalone,
			Standalone: &StandaloneConfig{
				Restart:   "always",
				CPUQuota:  "200%",
				MemoryMax: "4G",
				After:     []string{"network.target", "database.service"},
				Wants:     []string{"logging.service"},
			},
		},
	}

	result := g.Generate(spec)

	// Verify privileged flag
	if !strings.Contains(result, "--privileged") {
		t.Error("Generated unit file missing --privileged flag")
	}

	// Verify environment variables
	if !strings.Contains(result, "-e APP_ENV=production") {
		t.Error("Generated unit file missing environment variable")
	}

	// Verify labels
	if !strings.Contains(result, "--label app=myapp") {
		t.Error("Generated unit file missing label")
	}

	// Verify port mappings
	if !strings.Contains(result, "-p 8080:80") {
		t.Error("Generated unit file missing TCP port mapping")
	}
	if !strings.Contains(result, "-p 9090:90/udp") {
		t.Error("Generated unit file missing UDP port mapping")
	}
	if !strings.Contains(result, "-p 127.0.0.1:3000:3000") {
		t.Error("Generated unit file missing IP-specific port mapping")
	}

	// Verify volume mounts
	if !strings.Contains(result, "-v /host/data:/data") {
		t.Error("Generated unit file missing volume mount")
	}
	if !strings.Contains(result, "-v /host/config:/config:ro") {
		t.Error("Generated unit file missing read-only volume mount")
	}

	// Verify network mode
	if !strings.Contains(result, "--network host") {
		t.Error("Generated unit file missing network mode")
	}

	// Verify resource limits
	if !strings.Contains(result, "--memory 2G") {
		t.Error("Generated unit file missing memory limit")
	}
	if !strings.Contains(result, "--cpus 2") {
		t.Error("Generated unit file missing CPU limit")
	}

	// Verify systemd resource limits
	if !strings.Contains(result, "CPUQuota=200%") {
		t.Error("Generated unit file missing CPUQuota")
	}
	if !strings.Contains(result, "MemoryMax=4G") {
		t.Error("Generated unit file missing MemoryMax")
	}

	// Verify dependencies
	if !strings.Contains(result, "After=network-online.target network.target database.service") {
		t.Error("Generated unit file missing After dependencies")
	}
	if !strings.Contains(result, "Wants=network-online.target logging.service") {
		t.Error("Generated unit file missing Wants dependencies")
	}

	// Verify restart policy
	if !strings.Contains(result, "Restart=always") {
		t.Error("Generated unit file missing restart policy")
	}

	// Verify command
	if !strings.Contains(result, "/app/start.sh") {
		t.Error("Generated unit file missing command")
	}
}

// TestSystemdGenerator_RestartPolicies tests different restart policies
func TestSystemdGenerator_RestartPolicies(t *testing.T) {
	g := NewSystemdGenerator()

	tests := []struct {
		name           string
		restart        string
		expectedPolicy string
	}{
		{"always", "always", "Restart=always"},
		{"on-failure", "on-failure", "Restart=on-failure"},
		{"no", "no", "Restart=no"},
		{"never", "never", "Restart=no"},
		{"unless-stopped", "unless-stopped", "Restart=always"},
		{"empty", "", "Restart=on-failure"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &OrchestratorContainerSpec{
				Name:  "restart-test",
				Image: "test:latest",
				Service: ServiceConfig{
					Mode: ServiceModeStandalone,
					Standalone: &StandaloneConfig{
						Restart: tt.restart,
					},
				},
			}

			result := g.Generate(spec)
			if !strings.Contains(result, tt.expectedPolicy) {
				t.Errorf("Generated unit file should contain %q for restart=%q", tt.expectedPolicy, tt.restart)
			}
		})
	}
}

// TestSystemdGenerator_GenerateFromContainerConfig tests ContainerConfig
func TestSystemdGenerator_GenerateFromContainerConfig(t *testing.T) {
	g := NewSystemdGenerator()

	config := &ContainerConfig{
		Name:  "config-test",
		Image: "nginx:alpine",
		Ports: []PortMapping{
			{HostPort: 80, ContainerPort: 80},
		},
	}

	result := g.GenerateFromContainerConfig(config)

	if !strings.Contains(result, "Container config-test") {
		t.Error("Generated unit file missing container name")
	}
	if !strings.Contains(result, "nginx:alpine") {
		t.Error("Generated unit file missing image")
	}
	if !strings.Contains(result, "-p 80:80") {
		t.Error("Generated unit file missing port mapping")
	}
}

// TestGenerateSystemdUnit tests the convenience function
func TestGenerateSystemdUnit(t *testing.T) {
	spec := &OrchestratorContainerSpec{
		Name:  "convenience-test",
		Image: "test:latest",
	}

	result := GenerateSystemdUnit(spec)

	if result == "" {
		t.Error("GenerateSystemdUnit() returned empty string")
	}
	if !strings.Contains(result, "[Unit]") {
		t.Error("GenerateSystemdUnit() missing [Unit] section")
	}
}

// TestSystemdGenerator_EmptyMounts tests handling empty mounts
func TestSystemdGenerator_EmptyMounts(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:   "no-mounts",
		Image:  "test:latest",
		Mounts: nil,
	}

	result := g.Generate(spec)

	// Should not contain -v flag
	if strings.Contains(result, " -v ") {
		t.Error("Generated unit file should not contain -v flag when no mounts")
	}
}

// TestSystemdGenerator_EmptyPorts tests handling empty ports
func TestSystemdGenerator_EmptyPorts(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:  "no-ports",
		Image: "test:latest",
		Ports: nil,
	}

	result := g.Generate(spec)

	// Should not contain -p flag
	if strings.Contains(result, " -p ") {
		t.Error("Generated unit file should not contain -p flag when no ports")
	}
}

// TestSystemdGenerator_ContainsRm tests that --rm is included
func TestSystemdGenerator_ContainsRm(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:  "rm-test",
		Image: "test:latest",
	}

	result := g.Generate(spec)

	if !strings.Contains(result, "--rm") {
		t.Error("Generated unit file should contain --rm flag")
	}
}

// TestSystemdGenerator_ExecStartPreCleanup tests cleanup command
func TestSystemdGenerator_ExecStartPreCleanup(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:  "cleanup-test",
		Image: "test:latest",
	}

	result := g.Generate(spec)

	// Should have cleanup command to remove existing container
	if !strings.Contains(result, "ExecStartPre=-/usr/bin/podman rm -f cleanup-test") {
		t.Error("Generated unit file should contain container cleanup command")
	}
}

// TestSystemdGenerator_ExecStopPost tests post-stop cleanup
func TestSystemdGenerator_ExecStopPost(t *testing.T) {
	g := NewSystemdGenerator()

	spec := &OrchestratorContainerSpec{
		Name:  "poststop-test",
		Image: "test:latest",
	}

	result := g.Generate(spec)

	// Should have ExecStopPost cleanup
	if !strings.Contains(result, "ExecStopPost=-/usr/bin/podman rm -f poststop-test") {
		t.Error("Generated unit file should contain ExecStopPost cleanup command")
	}
}
