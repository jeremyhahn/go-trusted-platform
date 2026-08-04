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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServiceStatus represents the status of a service
type ServiceStatus string

const (
	// ServiceStatusRunning indicates the service is running
	ServiceStatusRunning ServiceStatus = "running"

	// ServiceStatusStopped indicates the service is stopped
	ServiceStatusStopped ServiceStatus = "stopped"

	// ServiceStatusFailed indicates the service has failed
	ServiceStatusFailed ServiceStatus = "failed"

	// ServiceStatusUnknown indicates the service status is unknown
	ServiceStatusUnknown ServiceStatus = "unknown"
)

// String returns the string representation of ServiceStatus
func (s ServiceStatus) String() string {
	return string(s)
}

// IsRunning returns true if the service is running
func (s ServiceStatus) IsRunning() bool {
	return s == ServiceStatusRunning
}

// CommandExecutor defines the interface for executing system commands
type CommandExecutor interface {
	// Run executes a command and returns its output and error
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// FileWriter defines the interface for writing files
type FileWriter interface {
	// WriteFile writes data to a file with the given permissions
	WriteFile(path string, data []byte, perm os.FileMode) error

	// RemoveFile removes a file
	RemoveFile(path string) error

	// FileExists checks if a file exists
	FileExists(path string) bool
}

// ServiceManager handles service file generation and lifecycle management
// for containers running as standalone services.
type ServiceManager struct {
	// systemdDir is the directory for systemd unit files
	systemdDir string

	// rcDir is the directory for OpenRC init scripts
	rcDir string

	// detector is used to detect the init system
	detector *InitSystemDetector

	// executor executes system commands
	executor CommandExecutor

	// writer handles file operations
	writer FileWriter

	// systemdGenerator generates systemd unit files
	systemdGenerator *SystemdGenerator

	// rcGenerator generates OpenRC init scripts
	rcGenerator *RCGenerator
}

// ServiceManagerOption configures a ServiceManager
type ServiceManagerOption func(*ServiceManager)

// WithCommandExecutor sets a custom command executor
func WithCommandExecutor(executor CommandExecutor) ServiceManagerOption {
	return func(m *ServiceManager) {
		m.executor = executor
	}
}

// WithFileWriter sets a custom file writer
func WithFileWriter(writer FileWriter) ServiceManagerOption {
	return func(m *ServiceManager) {
		m.writer = writer
	}
}

// WithInitSystemDetector sets a custom init system detector
func WithInitSystemDetector(detector *InitSystemDetector) ServiceManagerOption {
	return func(m *ServiceManager) {
		m.detector = detector
	}
}

// NewServiceManager creates a new ServiceManager
func NewServiceManager(systemdDir, rcDir string, opts ...ServiceManagerOption) *ServiceManager {
	m := &ServiceManager{
		systemdDir:       systemdDir,
		rcDir:            rcDir,
		detector:         NewInitSystemDetector(),
		executor:         &defaultCommandExecutor{},
		writer:           &defaultFileWriter{},
		systemdGenerator: NewSystemdGenerator(),
		rcGenerator:      NewRCGenerator(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// EnsureService creates or updates the service file for a container.
// For embedded mode containers, this is a no-op.
func (m *ServiceManager) EnsureService(ctx context.Context, container *ContainerConfig) error {
	if container == nil {
		return ErrNilContainerConfig
	}

	if container.Name == "" {
		return ErrEmptyContainerName
	}

	// Check if this is standalone mode
	if container.Service.GetMode() != ServiceModeStandalone {
		return nil // Embedded mode - nothing to do
	}

	// Determine init system
	initSystem := m.determineInitSystem(container)

	switch initSystem {
	case InitSystemSystemd:
		return m.ensureSystemdService(ctx, container)
	case InitSystemRC:
		return m.ensureRCService(ctx, container)
	default:
		return ErrUnsupportedInitSystem
	}
}

// RemoveService removes the service file for a container
func (m *ServiceManager) RemoveService(ctx context.Context, containerName string) error {
	if containerName == "" {
		return ErrEmptyContainerName
	}

	// Try to remove both systemd and rc services
	// This handles cases where the init system changed
	var lastErr error

	// Remove systemd service
	systemdPath := m.getSystemdServicePath(containerName)
	if m.writer.FileExists(systemdPath) {
		// Stop the service first (ignore error - service might not be running)
		_, _ = m.executor.Run(ctx, "systemctl", "stop", m.getSystemdServiceName(containerName))

		// Disable the service (ignore error - service might not be enabled)
		_, _ = m.executor.Run(ctx, "systemctl", "disable", m.getSystemdServiceName(containerName))

		// Remove the file
		if err := m.writer.RemoveFile(systemdPath); err != nil {
			lastErr = &WrappedError{Msg: "failed to remove systemd service file", Err: err}
		}

		// Reload systemd daemon
		if _, err := m.executor.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			lastErr = &WrappedError{Msg: "failed to reload systemd daemon", Err: err}
		}
	}

	// Remove rc service
	rcPath := m.getRCServicePath(containerName)
	if m.writer.FileExists(rcPath) {
		// Stop the service first (ignore error - service might not be running)
		_, _ = m.executor.Run(ctx, "rc-service", containerName, "stop")

		// Remove from default runlevel (ignore error - might not be in runlevel)
		_, _ = m.executor.Run(ctx, "rc-update", "del", m.getRCServiceName(containerName), "default")

		// Remove the file
		if err := m.writer.RemoveFile(rcPath); err != nil {
			lastErr = &WrappedError{Msg: "failed to remove rc service file", Err: err}
		}
	}

	return lastErr
}

// StartService starts the service for a container
func (m *ServiceManager) StartService(ctx context.Context, containerName string) error {
	if containerName == "" {
		return ErrEmptyContainerName
	}

	initSystem := m.detector.DetectAtRuntime()

	switch initSystem {
	case InitSystemSystemd:
		_, err := m.executor.Run(ctx, "systemctl", "start", m.getSystemdServiceName(containerName))
		return err
	case InitSystemRC:
		_, err := m.executor.Run(ctx, "rc-service", m.getRCServiceName(containerName), "start")
		return err
	default:
		return ErrUnsupportedInitSystem
	}
}

// StopService stops the service for a container
func (m *ServiceManager) StopService(ctx context.Context, containerName string) error {
	if containerName == "" {
		return ErrEmptyContainerName
	}

	initSystem := m.detector.DetectAtRuntime()

	switch initSystem {
	case InitSystemSystemd:
		_, err := m.executor.Run(ctx, "systemctl", "stop", m.getSystemdServiceName(containerName))
		return err
	case InitSystemRC:
		_, err := m.executor.Run(ctx, "rc-service", m.getRCServiceName(containerName), "stop")
		return err
	default:
		return ErrUnsupportedInitSystem
	}
}

// ServiceStatus returns the status of the service for a container
func (m *ServiceManager) ServiceStatus(ctx context.Context, containerName string) (ServiceStatus, error) {
	if containerName == "" {
		return ServiceStatusUnknown, ErrEmptyContainerName
	}

	initSystem := m.detector.DetectAtRuntime()

	switch initSystem {
	case InitSystemSystemd:
		return m.getSystemdServiceStatus(ctx, containerName)
	case InitSystemRC:
		return m.getRCServiceStatus(ctx, containerName)
	default:
		return ServiceStatusUnknown, ErrUnsupportedInitSystem
	}
}

// determineInitSystem determines which init system to use for the container
func (m *ServiceManager) determineInitSystem(container *ContainerConfig) InitSystem {
	// Check for explicit override
	if container.Service.Standalone != nil {
		if override := container.Service.Standalone.InitSystemOverride; override != "" {
			switch strings.ToLower(override) {
			case "systemd":
				return InitSystemSystemd
			case "rc", "openrc":
				return InitSystemRC
			}
		}
	}

	// Use runtime detection
	return m.detector.DetectAtRuntime()
}

// ensureSystemdService creates or updates a systemd service file
func (m *ServiceManager) ensureSystemdService(ctx context.Context, container *ContainerConfig) error {
	// Generate unit file content
	unitContent := m.systemdGenerator.GenerateFromContainerConfig(container)

	// Determine service path
	servicePath := m.getSystemdServicePath(container.Name)
	if container.Service.Standalone != nil {
		if customPath := container.Service.Standalone.ServicePath; customPath != "" {
			servicePath = customPath
		}
	}

	// Write the service file
	if err := m.writer.WriteFile(servicePath, []byte(unitContent), 0644); err != nil {
		return &WrappedError{Msg: "failed to write systemd service file", Err: err}
	}

	// Reload systemd daemon
	if _, err := m.executor.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return &WrappedError{Msg: "failed to reload systemd daemon", Err: err}
	}

	// Enable the service
	if _, err := m.executor.Run(ctx, "systemctl", "enable", m.getSystemdServiceName(container.Name)); err != nil {
		return &WrappedError{Msg: "failed to enable systemd service", Err: err}
	}

	return nil
}

// ensureRCService creates or updates an OpenRC service script
func (m *ServiceManager) ensureRCService(ctx context.Context, container *ContainerConfig) error {
	// Generate script content
	scriptContent := m.rcGenerator.GenerateFromContainerConfig(container)

	// Determine service path
	servicePath := m.getRCServicePath(container.Name)
	if container.Service.Standalone != nil {
		if customPath := container.Service.Standalone.ServicePath; customPath != "" {
			servicePath = customPath
		}
	}

	// Write the service script (executable)
	if err := m.writer.WriteFile(servicePath, []byte(scriptContent), 0755); err != nil {
		return &WrappedError{Msg: "failed to write rc service script", Err: err}
	}

	// Add to default runlevel
	if _, err := m.executor.Run(ctx, "rc-update", "add", m.getRCServiceName(container.Name), "default"); err != nil {
		return &WrappedError{Msg: "failed to add rc service to default runlevel", Err: err}
	}

	return nil
}

// getSystemdServicePath returns the path to the systemd service file
func (m *ServiceManager) getSystemdServicePath(containerName string) string {
	return filepath.Join(m.systemdDir, fmt.Sprintf("container-%s.service", containerName))
}

// getRCServicePath returns the path to the OpenRC service script
func (m *ServiceManager) getRCServicePath(containerName string) string {
	return filepath.Join(m.rcDir, fmt.Sprintf("container-%s", containerName))
}

// getSystemdServiceName returns the systemd service name
func (m *ServiceManager) getSystemdServiceName(containerName string) string {
	return fmt.Sprintf("container-%s.service", containerName)
}

// getRCServiceName returns the OpenRC service name
func (m *ServiceManager) getRCServiceName(containerName string) string {
	return fmt.Sprintf("container-%s", containerName)
}

// getSystemdServiceStatus gets the status of a systemd service
func (m *ServiceManager) getSystemdServiceStatus(ctx context.Context, containerName string) (ServiceStatus, error) {
	output, err := m.executor.Run(ctx, "systemctl", "is-active", m.getSystemdServiceName(containerName))
	if err != nil {
		// is-active returns non-zero for inactive/failed services
		outputStr := strings.TrimSpace(string(output))
		switch outputStr {
		case "inactive":
			return ServiceStatusStopped, nil
		case "failed":
			return ServiceStatusFailed, nil
		default:
			return ServiceStatusUnknown, nil
		}
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "active" {
		return ServiceStatusRunning, nil
	}

	return ServiceStatusUnknown, nil
}

// getRCServiceStatus gets the status of an OpenRC service
func (m *ServiceManager) getRCServiceStatus(ctx context.Context, containerName string) (ServiceStatus, error) {
	output, err := m.executor.Run(ctx, "rc-service", m.getRCServiceName(containerName), "status")
	if err != nil {
		// status returns non-zero for stopped services
		return ServiceStatusStopped, nil
	}

	outputStr := strings.ToLower(string(output))
	if strings.Contains(outputStr, "started") || strings.Contains(outputStr, "running") {
		return ServiceStatusRunning, nil
	}
	if strings.Contains(outputStr, "stopped") {
		return ServiceStatusStopped, nil
	}
	if strings.Contains(outputStr, "crashed") || strings.Contains(outputStr, "failed") {
		return ServiceStatusFailed, nil
	}

	return ServiceStatusUnknown, nil
}

// defaultCommandExecutor implements CommandExecutor using os/exec
type defaultCommandExecutor struct{}

func (e *defaultCommandExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Import is deferred to avoid pulling in os/exec at package level
	// This implementation would use exec.CommandContext in production
	return nil, &MessageError{Msg: "command execution not implemented in default executor"}
}

// defaultFileWriter implements FileWriter using os package
type defaultFileWriter struct{}

func (w *defaultFileWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (w *defaultFileWriter) RemoveFile(path string) error {
	return os.Remove(path)
}

func (w *defaultFileWriter) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
