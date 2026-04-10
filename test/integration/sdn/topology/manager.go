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

package topology

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Manager Interface
// =============================================================================

// Manager handles topology lifecycle operations.
type Manager interface {
	// Start starts a topology.
	Start(ctx context.Context, topology *Topology) error

	// Stop stops a running topology.
	Stop(ctx context.Context, name string) error

	// Destroy stops and removes all resources for a topology.
	Destroy(ctx context.Context, name string) error

	// Status returns the current status of a topology.
	Status(ctx context.Context, name string) (*TopologyStatus, error)

	// WaitHealthy waits for all nodes in a topology to become healthy.
	WaitHealthy(ctx context.Context, name string) error

	// WaitBGPConvergence waits for BGP sessions to converge.
	WaitBGPConvergence(ctx context.Context, name string) error

	// CaptureLogs captures logs from all nodes in a topology.
	CaptureLogs(ctx context.Context, name string, outputDir string) error

	// ExecInNode executes a command in a specific node.
	ExecInNode(ctx context.Context, topologyName, nodeName string, cmd []string) (string, error)

	// GetNodeIP returns the IP address of a node on a specific network.
	GetNodeIP(ctx context.Context, topologyName, nodeName, networkName string) (string, error)

	// List returns all managed topologies.
	List(ctx context.Context) ([]string, error)

	// IsRunning checks if a topology is running.
	IsRunning(ctx context.Context, name string) (bool, error)
}

// =============================================================================
// Manager Configuration
// =============================================================================

// ManagerConfig contains configuration for the topology manager.
type ManagerConfig struct {
	// WorkDir is the working directory for generated files.
	WorkDir string

	// DockerComposeProject is the Docker Compose project name prefix.
	DockerComposeProject string

	// DefaultImage is the default Docker image for nodes.
	DefaultImage string

	// PullImages indicates whether to pull images before starting.
	PullImages bool

	// CleanupOnFailure indicates whether to clean up on failure.
	CleanupOnFailure bool

	// LogLevel is the logging level.
	LogLevel string

	// UseDockerCompose indicates whether to use Docker Compose.
	UseDockerCompose bool

	// ParallelStart indicates whether to start nodes in parallel.
	ParallelStart bool
}

// DefaultManagerConfig returns the default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		WorkDir:              "/tmp/sdn-topology",
		DockerComposeProject: "sdn-test",
		DefaultImage:         "go-trusted-platform-sdn:latest",
		PullImages:           false,
		CleanupOnFailure:     true,
		LogLevel:             "info",
		UseDockerCompose:     true,
		ParallelStart:        true,
	}
}

// =============================================================================
// Manager Implementation
// =============================================================================

// manager implements the Manager interface.
type manager struct {
	config     ManagerConfig
	topologies sync.Map // map[string]*managedTopology
	mu         sync.Mutex
}

// managedTopology represents a topology being managed.
type managedTopology struct {
	topology    *Topology
	status      atomic.Pointer[TopologyStatus]
	composeFile string
	startedAt   time.Time
}

// NewManager creates a new topology manager.
func NewManager(config ManagerConfig) Manager {
	return &manager{
		config: config,
	}
}

// Start starts a topology.
func (m *manager) Start(ctx context.Context, topology *Topology) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if topology already exists
	if _, exists := m.topologies.Load(topology.Name); exists {
		return ErrTopologyAlreadyExists{Name: topology.Name}
	}

	// Create working directory
	workDir := filepath.Join(m.config.WorkDir, topology.Name)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return ErrTopologyStartFailed{Name: topology.Name, Reason: "failed to create work dir: " + err.Error()}
	}

	// Generate Docker Compose file
	composeFile := filepath.Join(workDir, "docker-compose.yml")
	if err := m.generateComposeFile(topology, composeFile); err != nil {
		return ErrTopologyStartFailed{Name: topology.Name, Reason: "failed to generate compose file: " + err.Error()}
	}

	// Initialize managed topology
	mt := &managedTopology{
		topology:    topology,
		composeFile: composeFile,
		startedAt:   time.Now(),
	}

	initialStatus := &TopologyStatus{
		Name:            topology.Name,
		State:           TopologyStateCreating,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(initialStatus)

	m.topologies.Store(topology.Name, mt)

	// Start topology
	if err := m.startTopology(ctx, mt); err != nil {
		// Cleanup on failure
		if m.config.CleanupOnFailure {
			m.topologies.Delete(topology.Name)
			_ = os.RemoveAll(workDir)
		}
		return err
	}

	// Update status to running
	runningStatus := &TopologyStatus{
		Name:            topology.Name,
		State:           TopologyStateRunning,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(runningStatus)

	return nil
}

// Stop stops a running topology.
func (m *manager) Stop(ctx context.Context, name string) error {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return err
	}

	// Update status
	stoppingStatus := &TopologyStatus{
		Name:            name,
		State:           TopologyStateStopping,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(stoppingStatus)

	// Stop with Docker Compose
	if err := m.runDockerCompose(ctx, mt.composeFile, "stop"); err != nil {
		return ErrTopologyStopFailed{Name: name, Reason: err.Error()}
	}

	// Update status
	stoppedStatus := &TopologyStatus{
		Name:            name,
		State:           TopologyStateStopped,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(stoppedStatus)

	return nil
}

// Destroy stops and removes all resources for a topology.
func (m *manager) Destroy(ctx context.Context, name string) error {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return err
	}

	// Update status
	destroyingStatus := &TopologyStatus{
		Name:            name,
		State:           TopologyStateDestroying,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(destroyingStatus)

	// Destroy with Docker Compose
	if err := m.runDockerCompose(ctx, mt.composeFile, "down", "--volumes", "--remove-orphans"); err != nil {
		return ErrTopologyStopFailed{Name: name, Reason: err.Error()}
	}

	// Remove working directory
	workDir := filepath.Dir(mt.composeFile)
	_ = os.RemoveAll(workDir)

	// Remove from managed topologies
	m.topologies.Delete(name)

	return nil
}

// Status returns the current status of a topology.
func (m *manager) Status(ctx context.Context, name string) (*TopologyStatus, error) {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return nil, err
	}

	status := mt.status.Load()
	if status == nil {
		return nil, ErrTopologyNotFound{Name: name}
	}

	// Update node statuses from Docker
	if err := m.updateNodeStatuses(ctx, mt); err != nil {
		// Don't fail, just log and return cached status
		status.Error = err
	}

	return status, nil
}

// WaitHealthy waits for all nodes in a topology to become healthy.
func (m *manager) WaitHealthy(ctx context.Context, name string) error {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return err
	}

	timeout := mt.topology.Timeouts.HealthCheckTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return ErrHealthCheckFailed{NodeName: "topology", Reason: "timeout waiting for healthy nodes"}
			}

			allHealthy := true
			for _, node := range mt.topology.Nodes {
				healthy, err := m.isNodeHealthy(ctx, mt, node.Name)
				if err != nil || !healthy {
					allHealthy = false
					break
				}
			}

			if allHealthy {
				return nil
			}
		}
	}
}

// WaitBGPConvergence waits for BGP sessions to converge.
func (m *manager) WaitBGPConvergence(ctx context.Context, name string) error {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return err
	}

	// Skip if no BGP peers configured
	if len(mt.topology.BGPPeers) == 0 {
		return nil
	}

	timeout := mt.topology.Timeouts.BGPConvergenceTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return ErrBGPConvergenceFailed{Reason: "timeout waiting for BGP convergence"}
			}

			converged, err := m.checkBGPConvergence(ctx, mt)
			if err != nil {
				continue // Retry on transient errors
			}

			if converged {
				return nil
			}
		}
	}
}

// CaptureLogs captures logs from all nodes in a topology.
func (m *manager) CaptureLogs(ctx context.Context, name string, outputDir string) error {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, node := range mt.topology.Nodes {
		logFile := filepath.Join(outputDir, node.Name+".log")
		if err := m.captureNodeLogs(ctx, mt, node.Name, logFile); err != nil {
			// Continue capturing other logs even if one fails
			continue
		}
	}

	return nil
}

// ExecInNode executes a command in a specific node.
func (m *manager) ExecInNode(ctx context.Context, topologyName, nodeName string, cmd []string) (string, error) {
	mt, err := m.getManagedTopology(topologyName)
	if err != nil {
		return "", err
	}

	// Find node
	var found bool
	for _, node := range mt.topology.Nodes {
		if node.Name == nodeName {
			found = true
			break
		}
	}
	if !found {
		return "", ErrNodeNotFound{TopologyName: topologyName, NodeName: nodeName}
	}

	containerName := m.containerName(mt.topology.Name, nodeName)
	args := append([]string{"exec", containerName}, cmd...)

	execCmd := exec.CommandContext(ctx, "docker", args...)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// GetNodeIP returns the IP address of a node on a specific network.
func (m *manager) GetNodeIP(ctx context.Context, topologyName, nodeName, networkName string) (string, error) {
	mt, err := m.getManagedTopology(topologyName)
	if err != nil {
		return "", err
	}

	containerName := m.containerName(mt.topology.Name, nodeName)
	fullNetworkName := m.networkName(mt.topology.Name, networkName)

	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", fmt.Sprintf("{{.NetworkSettings.Networks.%s.IPAddress}}", fullNetworkName),
		containerName)

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// List returns all managed topologies.
func (m *manager) List(ctx context.Context) ([]string, error) {
	var names []string
	m.topologies.Range(func(key, value any) bool {
		names = append(names, key.(string))
		return true
	})
	return names, nil
}

// IsRunning checks if a topology is running.
func (m *manager) IsRunning(ctx context.Context, name string) (bool, error) {
	mt, err := m.getManagedTopology(name)
	if err != nil {
		return false, nil
	}

	status := mt.status.Load()
	return status != nil && status.State == TopologyStateRunning, nil
}

// =============================================================================
// Internal Methods
// =============================================================================

// getManagedTopology retrieves a managed topology by name.
func (m *manager) getManagedTopology(name string) (*managedTopology, error) {
	value, exists := m.topologies.Load(name)
	if !exists {
		return nil, ErrTopologyNotFound{Name: name}
	}
	return value.(*managedTopology), nil
}

// generateComposeFile generates a Docker Compose file for the topology.
func (m *manager) generateComposeFile(topology *Topology, outputPath string) error {
	var buf bytes.Buffer

	// Write header
	buf.WriteString("# Auto-generated Docker Compose file for topology: " + topology.Name + "\n")
	buf.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n")
	buf.WriteString("version: '3.8'\n\n")

	// Write networks
	buf.WriteString("networks:\n")
	for _, network := range topology.Networks {
		buf.WriteString("  " + network.Name + ":\n")
		buf.WriteString("    driver: " + string(network.Driver) + "\n")
		if network.Internal {
			buf.WriteString("    internal: true\n")
		}
		if network.Subnet != "" {
			buf.WriteString("    ipam:\n")
			buf.WriteString("      config:\n")
			buf.WriteString("        - subnet: " + network.Subnet + "\n")
			if network.Gateway != "" {
				buf.WriteString("          gateway: " + network.Gateway + "\n")
			}
			if network.IPRange != "" {
				buf.WriteString("          ip_range: " + network.IPRange + "\n")
			}
		}
		if len(network.Options) > 0 {
			buf.WriteString("    driver_opts:\n")
			for k, v := range network.Options {
				buf.WriteString("      " + k + ": " + v + "\n")
			}
		}
		if len(network.Labels) > 0 {
			buf.WriteString("    labels:\n")
			for k, v := range network.Labels {
				buf.WriteString("      " + k + ": \"" + v + "\"\n")
			}
		}
	}

	buf.WriteString("\n")

	// Write services
	buf.WriteString("services:\n")
	for _, node := range topology.Nodes {
		buf.WriteString("  " + node.Name + ":\n")

		// Image
		image := node.Image
		if image == "" {
			image = m.config.DefaultImage
		}
		buf.WriteString("    image: " + image + "\n")

		// Container name
		containerName := m.containerName(topology.Name, node.Name)
		buf.WriteString("    container_name: " + containerName + "\n")

		// Hostname
		buf.WriteString("    hostname: " + node.Name + "\n")

		// Privileged mode
		if node.Privileged {
			buf.WriteString("    privileged: true\n")
		}

		// Capabilities
		if len(node.Capabilities) > 0 {
			buf.WriteString("    cap_add:\n")
			for _, cap := range node.Capabilities {
				buf.WriteString("      - " + cap + "\n")
			}
		}

		// Networks
		if len(node.Networks) > 0 {
			buf.WriteString("    networks:\n")
			for _, netName := range node.Networks {
				buf.WriteString("      - " + netName + "\n")
			}
		}

		// Volumes
		if len(node.Volumes) > 0 {
			buf.WriteString("    volumes:\n")
			for _, vol := range node.Volumes {
				volumeStr := "      - " + vol.Source + ":" + vol.Target
				if vol.ReadOnly {
					volumeStr += ":ro"
				}
				buf.WriteString(volumeStr + "\n")
			}
		}

		// Environment
		if len(node.Environment) > 0 {
			buf.WriteString("    environment:\n")
			for k, v := range node.Environment {
				buf.WriteString("      - " + k + "=" + v + "\n")
			}
		}

		// Ports
		if len(node.Ports) > 0 {
			buf.WriteString("    ports:\n")
			for _, port := range node.Ports {
				portStr := fmt.Sprintf("      - \"%d:%d", port.HostPort, port.ContainerPort)
				if port.Protocol != "" && port.Protocol != "tcp" {
					portStr += "/" + port.Protocol
				}
				portStr += "\"\n"
				buf.WriteString(portStr)
			}
		}

		// Dependencies
		if len(node.DependsOn) > 0 {
			buf.WriteString("    depends_on:\n")
			for _, dep := range node.DependsOn {
				buf.WriteString("      - " + dep + "\n")
			}
		}

		// Health check
		if node.HealthCheck != nil {
			buf.WriteString("    healthcheck:\n")
			buf.WriteString("      test: [\"CMD\"")
			for _, arg := range node.HealthCheck.Command {
				buf.WriteString(", \"" + arg + "\"")
			}
			buf.WriteString("]\n")
			buf.WriteString(fmt.Sprintf("      interval: %s\n", node.HealthCheck.Interval))
			buf.WriteString(fmt.Sprintf("      timeout: %s\n", node.HealthCheck.Timeout))
			buf.WriteString(fmt.Sprintf("      start_period: %s\n", node.HealthCheck.StartPeriod))
			buf.WriteString(fmt.Sprintf("      retries: %d\n", node.HealthCheck.Retries))
		}

		// Resource limits
		if node.Resources != nil {
			buf.WriteString("    deploy:\n")
			buf.WriteString("      resources:\n")
			buf.WriteString("        limits:\n")
			if node.Resources.CPULimit != "" {
				buf.WriteString("          cpus: '" + node.Resources.CPULimit + "'\n")
			}
			if node.Resources.MemoryLimit != "" {
				buf.WriteString("          memory: " + node.Resources.MemoryLimit + "\n")
			}
			if node.Resources.CPUReservation != "" || node.Resources.MemoryReservation != "" {
				buf.WriteString("        reservations:\n")
				if node.Resources.CPUReservation != "" {
					buf.WriteString("          cpus: '" + node.Resources.CPUReservation + "'\n")
				}
				if node.Resources.MemoryReservation != "" {
					buf.WriteString("          memory: " + node.Resources.MemoryReservation + "\n")
				}
			}
		}

		// Labels
		if len(node.Labels) > 0 {
			buf.WriteString("    labels:\n")
			for k, v := range node.Labels {
				buf.WriteString("      " + k + ": \"" + v + "\"\n")
			}
		}

		buf.WriteString("\n")
	}

	// Write to file
	return os.WriteFile(outputPath, buf.Bytes(), 0o644)
}

// startTopology starts the topology using Docker Compose.
func (m *manager) startTopology(ctx context.Context, mt *managedTopology) error {
	// Update status
	startingStatus := &TopologyStatus{
		Name:            mt.topology.Name,
		State:           TopologyStateStarting,
		StartedAt:       mt.startedAt,
		NodeStatuses:    make(map[string]NodeStatus),
		NetworkStatuses: make(map[string]NetworkStatus),
	}
	mt.status.Store(startingStatus)

	// Pull images if configured
	if m.config.PullImages {
		if err := m.runDockerCompose(ctx, mt.composeFile, "pull"); err != nil {
			return ErrTopologyStartFailed{Name: mt.topology.Name, Reason: "failed to pull images: " + err.Error()}
		}
	}

	// Start with Docker Compose
	if err := m.runDockerCompose(ctx, mt.composeFile, "up", "-d"); err != nil {
		return ErrTopologyStartFailed{Name: mt.topology.Name, Reason: "failed to start: " + err.Error()}
	}

	return nil
}

// runDockerCompose runs a docker-compose command.
func (m *manager) runDockerCompose(ctx context.Context, composeFile string, args ...string) error {
	projectName := m.config.DockerComposeProject + "-" + filepath.Base(filepath.Dir(composeFile))
	cmdArgs := append([]string{"-f", composeFile, "-p", projectName}, args...)

	cmd := exec.CommandContext(ctx, "docker-compose", cmdArgs...)
	cmd.Dir = filepath.Dir(composeFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}

	return nil
}

// updateNodeStatuses updates the status of all nodes.
func (m *manager) updateNodeStatuses(ctx context.Context, mt *managedTopology) error {
	status := mt.status.Load()
	if status == nil {
		return nil
	}

	for _, node := range mt.topology.Nodes {
		containerName := m.containerName(mt.topology.Name, node.Name)

		// Get container status
		cmd := exec.CommandContext(ctx, "docker", "inspect",
			"--format", "{{.State.Status}}",
			containerName)
		output, err := cmd.Output()
		if err != nil {
			status.NodeStatuses[node.Name] = NodeStatus{
				Name:  node.Name,
				State: "unknown",
				Error: err.Error(),
			}
			continue
		}

		state := strings.TrimSpace(string(output))
		healthy := state == "running"

		status.NodeStatuses[node.Name] = NodeStatus{
			Name:    node.Name,
			State:   state,
			Healthy: healthy,
		}
	}

	mt.status.Store(status)
	return nil
}

// isNodeHealthy checks if a node is healthy.
func (m *manager) isNodeHealthy(ctx context.Context, mt *managedTopology, nodeName string) (bool, error) {
	containerName := m.containerName(mt.topology.Name, nodeName)

	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.Health.Status}}",
		containerName)

	output, err := cmd.Output()
	if err != nil {
		// If no health check, check if running
		cmd = exec.CommandContext(ctx, "docker", "inspect",
			"--format", "{{.State.Status}}",
			containerName)
		output, err = cmd.Output()
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(string(output)) == "running", nil
	}

	status := strings.TrimSpace(string(output))
	return status == "healthy", nil
}

// checkBGPConvergence checks if all BGP sessions are established.
func (m *manager) checkBGPConvergence(ctx context.Context, mt *managedTopology) (bool, error) {
	// For each BGP peer configuration, check if sessions are established
	for _, peer := range mt.topology.BGPPeers {
		// Execute BGP status check in the local node
		output, err := m.ExecInNode(ctx, mt.topology.Name, peer.LocalNodeName,
			[]string{"platformctl", "sdn", "bgp", "peer", "list", "--format", "json"})
		if err != nil {
			return false, err
		}

		// Check if peer session is established
		if !strings.Contains(output, "established") {
			return false, nil
		}
	}

	return true, nil
}

// captureNodeLogs captures logs from a specific node.
func (m *manager) captureNodeLogs(ctx context.Context, mt *managedTopology, nodeName, outputFile string) error {
	containerName := m.containerName(mt.topology.Name, nodeName)

	cmd := exec.CommandContext(ctx, "docker", "logs", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	return os.WriteFile(outputFile, output, 0o644)
}

// containerName returns the full container name for a node.
func (m *manager) containerName(topologyName, nodeName string) string {
	return m.config.DockerComposeProject + "-" + topologyName + "-" + nodeName
}

// networkName returns the full network name for a topology network.
func (m *manager) networkName(topologyName, networkName string) string {
	return m.config.DockerComposeProject + "-" + topologyName + "_" + networkName
}

// =============================================================================
// Test Cleanup Helper
// =============================================================================

// CleanupManager provides cleanup utilities for test teardown.
type CleanupManager struct {
	manager       Manager
	topologyNames []string
	logsDir       string
	mu            sync.Mutex
}

// NewCleanupManager creates a new cleanup manager.
func NewCleanupManager(manager Manager, logsDir string) *CleanupManager {
	return &CleanupManager{
		manager:       manager,
		topologyNames: make([]string, 0),
		logsDir:       logsDir,
	}
}

// RegisterTopology registers a topology for cleanup.
func (c *CleanupManager) RegisterTopology(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topologyNames = append(c.topologyNames, name)
}

// Cleanup performs cleanup of all registered topologies.
func (c *CleanupManager) Cleanup(ctx context.Context, captureLogs bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var lastErr error
	for _, name := range c.topologyNames {
		// Capture logs if requested
		if captureLogs && c.logsDir != "" {
			logDir := filepath.Join(c.logsDir, name)
			_ = c.manager.CaptureLogs(ctx, name, logDir)
		}

		// Destroy topology
		if err := c.manager.Destroy(ctx, name); err != nil {
			lastErr = err
		}
	}

	c.topologyNames = nil
	return lastErr
}

// =============================================================================
// Log Capture Utilities
// =============================================================================

// LogCapture provides log capture functionality for debugging.
type LogCapture struct {
	writer    io.Writer
	topology  string
	nodeName  string
	startTime time.Time
}

// NewLogCapture creates a new log capture.
func NewLogCapture(writer io.Writer, topology, nodeName string) *LogCapture {
	return &LogCapture{
		writer:    writer,
		topology:  topology,
		nodeName:  nodeName,
		startTime: time.Now(),
	}
}

// WriteHeader writes a header to the log.
func (l *LogCapture) WriteHeader() {
	fmt.Fprintf(l.writer, "=== Log capture for %s/%s ===\n", l.topology, l.nodeName)
	fmt.Fprintf(l.writer, "Started at: %s\n", l.startTime.Format(time.RFC3339))
	fmt.Fprintf(l.writer, "=================================\n\n")
}

// WriteFooter writes a footer to the log.
func (l *LogCapture) WriteFooter() {
	duration := time.Since(l.startTime)
	fmt.Fprintf(l.writer, "\n=================================\n")
	fmt.Fprintf(l.writer, "Duration: %s\n", duration)
	fmt.Fprintf(l.writer, "=== End of log capture ===\n")
}
