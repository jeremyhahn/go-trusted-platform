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
	"errors"
	"os"
	"testing"
)

// TestServiceStatus_String tests the String method
func TestServiceStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   ServiceStatus
		expected string
	}{
		{
			name:     "running",
			status:   ServiceStatusRunning,
			expected: "running",
		},
		{
			name:     "stopped",
			status:   ServiceStatusStopped,
			expected: "stopped",
		},
		{
			name:     "failed",
			status:   ServiceStatusFailed,
			expected: "failed",
		},
		{
			name:     "unknown",
			status:   ServiceStatusUnknown,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.status.String(); result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestServiceStatus_IsRunning tests the IsRunning method
func TestServiceStatus_IsRunning(t *testing.T) {
	tests := []struct {
		name     string
		status   ServiceStatus
		expected bool
	}{
		{
			name:     "running is running",
			status:   ServiceStatusRunning,
			expected: true,
		},
		{
			name:     "stopped is not running",
			status:   ServiceStatusStopped,
			expected: false,
		},
		{
			name:     "failed is not running",
			status:   ServiceStatusFailed,
			expected: false,
		},
		{
			name:     "unknown is not running",
			status:   ServiceStatusUnknown,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.status.IsRunning(); result != tt.expected {
				t.Errorf("IsRunning() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// mockCommandExecutor implements CommandExecutor for testing
type mockCommandExecutor struct {
	runFunc func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (m *mockCommandExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m.runFunc != nil {
		return m.runFunc(ctx, name, args...)
	}
	return nil, nil
}

// mockFileWriter implements FileWriter for testing
type mockFileWriter struct {
	writeFileFunc  func(path string, data []byte, perm os.FileMode) error
	removeFileFunc func(path string) error
	fileExistsFunc func(path string) bool
	writtenFiles   map[string][]byte
	removedFiles   []string
}

func newMockFileWriter() *mockFileWriter {
	return &mockFileWriter{
		writtenFiles: make(map[string][]byte),
		removedFiles: []string{},
	}
}

func (m *mockFileWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	if m.writeFileFunc != nil {
		return m.writeFileFunc(path, data, perm)
	}
	m.writtenFiles[path] = data
	return nil
}

func (m *mockFileWriter) RemoveFile(path string) error {
	if m.removeFileFunc != nil {
		return m.removeFileFunc(path)
	}
	m.removedFiles = append(m.removedFiles, path)
	return nil
}

func (m *mockFileWriter) FileExists(path string) bool {
	if m.fileExistsFunc != nil {
		return m.fileExistsFunc(path)
	}
	_, exists := m.writtenFiles[path]
	return exists
}

// TestNewServiceManager tests the constructor
func TestNewServiceManager(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	if m == nil {
		t.Fatal("NewServiceManager() returned nil")
	}

	if m.systemdDir != "/etc/systemd/system" {
		t.Errorf("systemdDir = %q, want %q", m.systemdDir, "/etc/systemd/system")
	}

	if m.rcDir != "/etc/init.d" {
		t.Errorf("rcDir = %q, want %q", m.rcDir, "/etc/init.d")
	}

	if m.detector == nil {
		t.Error("detector should not be nil")
	}

	if m.systemdGenerator == nil {
		t.Error("systemdGenerator should not be nil")
	}

	if m.rcGenerator == nil {
		t.Error("rcGenerator should not be nil")
	}
}

// TestNewServiceManager_WithOptions tests the constructor with options
func TestNewServiceManager_WithOptions(t *testing.T) {
	mockExec := &mockCommandExecutor{}
	mockWriter := newMockFileWriter()
	mockDetector := NewInitSystemDetector()

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
		WithInitSystemDetector(mockDetector),
	)

	if m == nil {
		t.Fatal("NewServiceManager() returned nil")
	}
}

// TestServiceManager_EnsureService_NilConfig tests error handling for nil config
func TestServiceManager_EnsureService_NilConfig(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	err := m.EnsureService(context.Background(), nil)
	if !errors.Is(err, ErrNilContainerConfig) {
		t.Errorf("EnsureService(nil) = %v, want %v", err, ErrNilContainerConfig)
	}
}

// TestServiceManager_EnsureService_EmptyName tests error handling for empty name
func TestServiceManager_EnsureService_EmptyName(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	config := &ContainerConfig{
		Name: "",
	}

	err := m.EnsureService(context.Background(), config)
	if !errors.Is(err, ErrEmptyContainerName) {
		t.Errorf("EnsureService(empty name) = %v, want %v", err, ErrEmptyContainerName)
	}
}

// TestServiceManager_EnsureService_EmbeddedMode tests embedded mode (no-op)
func TestServiceManager_EnsureService_EmbeddedMode(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	config := &ContainerConfig{
		Name:  "test",
		Image: "test:latest",
		Service: ServiceConfig{
			Mode: ServiceModeEmbedded,
		},
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService(embedded) = %v, want nil", err)
	}
}

// TestServiceManager_EnsureService_DefaultMode tests default mode (embedded, no-op)
func TestServiceManager_EnsureService_DefaultMode(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	config := &ContainerConfig{
		Name:  "test",
		Image: "test:latest",
		// Service.Mode defaults to embedded when empty
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService(default mode) = %v, want nil", err)
	}
}

// TestServiceManager_EnsureService_StandaloneSystemd tests standalone mode with systemd
func TestServiceManager_EnsureService_StandaloneSystemd(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil // Success
		},
	}
	mockWriter := newMockFileWriter()

	// Mock systemd detection
	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil // systemd running
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
		WithInitSystemDetector(mockDetector),
	)

	config := &ContainerConfig{
		Name:  "myapp",
		Image: "myapp:latest",
		Service: ServiceConfig{
			Mode: ServiceModeStandalone,
		},
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService() = %v, want nil", err)
	}

	// Verify service file was written
	expectedPath := "/etc/systemd/system/container-myapp.service"
	if _, exists := mockWriter.writtenFiles[expectedPath]; !exists {
		t.Errorf("Service file not written to %s", expectedPath)
	}
}

// TestServiceManager_EnsureService_StandaloneRC tests standalone mode with OpenRC
func TestServiceManager_EnsureService_StandaloneRC(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil // Success
		},
	}
	mockWriter := newMockFileWriter()

	// Mock OpenRC detection
	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/sbin/openrc" {
			return nil, nil // OpenRC exists
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
		WithInitSystemDetector(mockDetector),
	)

	config := &ContainerConfig{
		Name:  "myapp",
		Image: "myapp:latest",
		Service: ServiceConfig{
			Mode: ServiceModeStandalone,
		},
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService() = %v, want nil", err)
	}

	// Verify service file was written
	expectedPath := "/etc/init.d/container-myapp"
	if _, exists := mockWriter.writtenFiles[expectedPath]; !exists {
		t.Errorf("Service file not written to %s", expectedPath)
	}
}

// TestServiceManager_EnsureService_InitSystemOverride tests init system override
func TestServiceManager_EnsureService_InitSystemOverride(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	mockWriter := newMockFileWriter()

	// Mock systemd detection (but we'll override to rc)
	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
		WithInitSystemDetector(mockDetector),
	)

	config := &ContainerConfig{
		Name:  "myapp",
		Image: "myapp:latest",
		Service: ServiceConfig{
			Mode: ServiceModeStandalone,
			Standalone: &StandaloneConfig{
				InitSystemOverride: "rc", // Override to RC
			},
		},
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService() = %v, want nil", err)
	}

	// Verify RC script was written (not systemd)
	expectedPath := "/etc/init.d/container-myapp"
	if _, exists := mockWriter.writtenFiles[expectedPath]; !exists {
		t.Errorf("RC script not written to %s despite override", expectedPath)
	}
}

// TestServiceManager_RemoveService_EmptyName tests error handling
func TestServiceManager_RemoveService_EmptyName(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	err := m.RemoveService(context.Background(), "")
	if !errors.Is(err, ErrEmptyContainerName) {
		t.Errorf("RemoveService('') = %v, want %v", err, ErrEmptyContainerName)
	}
}

// TestServiceManager_RemoveService tests removing a service
func TestServiceManager_RemoveService(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	mockWriter := newMockFileWriter()
	mockWriter.writtenFiles["/etc/systemd/system/container-myapp.service"] = []byte("content")

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
	)

	err := m.RemoveService(context.Background(), "myapp")
	if err != nil {
		t.Errorf("RemoveService() = %v, want nil", err)
	}

	// Verify file was removed
	found := false
	for _, path := range mockWriter.removedFiles {
		if path == "/etc/systemd/system/container-myapp.service" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Service file was not removed")
	}
}

// TestServiceManager_StartService_EmptyName tests error handling
func TestServiceManager_StartService_EmptyName(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	err := m.StartService(context.Background(), "")
	if !errors.Is(err, ErrEmptyContainerName) {
		t.Errorf("StartService('') = %v, want %v", err, ErrEmptyContainerName)
	}
}

// TestServiceManager_StartService_Systemd tests starting a systemd service
func TestServiceManager_StartService_Systemd(t *testing.T) {
	commandsCalled := []string{}
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandsCalled = append(commandsCalled, name)
			return nil, nil
		},
	}

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithInitSystemDetector(mockDetector),
	)

	err := m.StartService(context.Background(), "myapp")
	if err != nil {
		t.Errorf("StartService() = %v, want nil", err)
	}

	// Verify systemctl was called
	found := false
	for _, cmd := range commandsCalled {
		if cmd == "systemctl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("systemctl was not called")
	}
}

// TestServiceManager_StopService_EmptyName tests error handling
func TestServiceManager_StopService_EmptyName(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	err := m.StopService(context.Background(), "")
	if !errors.Is(err, ErrEmptyContainerName) {
		t.Errorf("StopService('') = %v, want %v", err, ErrEmptyContainerName)
	}
}

// TestServiceManager_StopService_Systemd tests stopping a systemd service
func TestServiceManager_StopService_Systemd(t *testing.T) {
	commandsCalled := []string{}
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandsCalled = append(commandsCalled, name)
			return nil, nil
		},
	}

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithInitSystemDetector(mockDetector),
	)

	err := m.StopService(context.Background(), "myapp")
	if err != nil {
		t.Errorf("StopService() = %v, want nil", err)
	}

	// Verify systemctl was called
	found := false
	for _, cmd := range commandsCalled {
		if cmd == "systemctl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("systemctl was not called")
	}
}

// TestServiceManager_ServiceStatus_EmptyName tests error handling
func TestServiceManager_ServiceStatus_EmptyName(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	status, err := m.ServiceStatus(context.Background(), "")
	if !errors.Is(err, ErrEmptyContainerName) {
		t.Errorf("ServiceStatus('') error = %v, want %v", err, ErrEmptyContainerName)
	}
	if status != ServiceStatusUnknown {
		t.Errorf("ServiceStatus('') = %v, want %v", status, ServiceStatusUnknown)
	}
}

// TestServiceManager_ServiceStatus_Running tests running status
func TestServiceManager_ServiceStatus_Running(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("active"), nil
		},
	}

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithInitSystemDetector(mockDetector),
	)

	status, err := m.ServiceStatus(context.Background(), "myapp")
	if err != nil {
		t.Errorf("ServiceStatus() error = %v, want nil", err)
	}
	if status != ServiceStatusRunning {
		t.Errorf("ServiceStatus() = %v, want %v", status, ServiceStatusRunning)
	}
}

// TestServiceManager_ServiceStatus_Stopped tests stopped status
func TestServiceManager_ServiceStatus_Stopped(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("inactive"), errors.New("exit code 3")
		},
	}

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithInitSystemDetector(mockDetector),
	)

	status, err := m.ServiceStatus(context.Background(), "myapp")
	if err != nil {
		t.Errorf("ServiceStatus() error = %v, want nil", err)
	}
	if status != ServiceStatusStopped {
		t.Errorf("ServiceStatus() = %v, want %v", status, ServiceStatusStopped)
	}
}

// TestServiceManager_ServiceStatus_Failed tests failed status
func TestServiceManager_ServiceStatus_Failed(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("failed"), errors.New("exit code 1")
		},
	}

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithInitSystemDetector(mockDetector),
	)

	status, err := m.ServiceStatus(context.Background(), "myapp")
	if err != nil {
		t.Errorf("ServiceStatus() error = %v, want nil", err)
	}
	if status != ServiceStatusFailed {
		t.Errorf("ServiceStatus() = %v, want %v", status, ServiceStatusFailed)
	}
}

// TestServiceManager_ServicePaths tests path generation
func TestServiceManager_ServicePaths(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	// Test systemd path
	systemdPath := m.getSystemdServicePath("myapp")
	expectedSystemd := "/etc/systemd/system/container-myapp.service"
	if systemdPath != expectedSystemd {
		t.Errorf("getSystemdServicePath() = %q, want %q", systemdPath, expectedSystemd)
	}

	// Test rc path
	rcPath := m.getRCServicePath("myapp")
	expectedRC := "/etc/init.d/container-myapp"
	if rcPath != expectedRC {
		t.Errorf("getRCServicePath() = %q, want %q", rcPath, expectedRC)
	}
}

// TestServiceManager_ServiceNames tests service name generation
func TestServiceManager_ServiceNames(t *testing.T) {
	m := NewServiceManager("/etc/systemd/system", "/etc/init.d")

	// Test systemd name
	systemdName := m.getSystemdServiceName("myapp")
	expectedSystemd := "container-myapp.service"
	if systemdName != expectedSystemd {
		t.Errorf("getSystemdServiceName() = %q, want %q", systemdName, expectedSystemd)
	}

	// Test rc name
	rcName := m.getRCServiceName("myapp")
	expectedRC := "container-myapp"
	if rcName != expectedRC {
		t.Errorf("getRCServiceName() = %q, want %q", rcName, expectedRC)
	}
}

// TestServiceManager_CustomServicePath tests custom service path
func TestServiceManager_CustomServicePath(t *testing.T) {
	mockExec := &mockCommandExecutor{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	mockWriter := newMockFileWriter()

	mockStatFunc := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	mockDetector := NewInitSystemDetectorWithOptions(WithOSStatFunc(mockStatFunc))

	m := NewServiceManager("/etc/systemd/system", "/etc/init.d",
		WithCommandExecutor(mockExec),
		WithFileWriter(mockWriter),
		WithInitSystemDetector(mockDetector),
	)

	config := &ContainerConfig{
		Name:  "myapp",
		Image: "myapp:latest",
		Service: ServiceConfig{
			Mode: ServiceModeStandalone,
			Standalone: &StandaloneConfig{
				ServicePath: "/custom/path/myapp.service",
			},
		},
	}

	err := m.EnsureService(context.Background(), config)
	if err != nil {
		t.Errorf("EnsureService() = %v, want nil", err)
	}

	// Verify file was written to custom path
	if _, exists := mockWriter.writtenFiles["/custom/path/myapp.service"]; !exists {
		t.Error("Service file not written to custom path")
	}
}

// TestDefaultFileWriter tests the default file writer implementation.
func TestDefaultFileWriter(t *testing.T) {
	w := &defaultFileWriter{}

	t.Run("file exists with non-existent file", func(t *testing.T) {
		exists := w.FileExists("/non/existent/path/12345")
		if exists {
			t.Error("expected FileExists to return false for non-existent file")
		}
	})
}

// TestDefaultCommandExecutor tests the default command executor.
func TestDefaultCommandExecutor(t *testing.T) {
	e := &defaultCommandExecutor{}

	t.Run("run returns error", func(t *testing.T) {
		_, err := e.Run(context.Background(), "echo", "test")
		if err == nil {
			t.Error("expected error from default executor")
		}
	})
}

// TestDefaultFileWriterWriteAndRemove tests write and remove operations.
func TestDefaultFileWriterWriteAndRemove(t *testing.T) {
	w := &defaultFileWriter{}
	testFile := "/tmp/go_test_service_writer_" + t.Name()

	t.Run("write file", func(t *testing.T) {
		err := w.WriteFile(testFile, []byte("test content"), 0644)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		defer os.Remove(testFile)

		if !w.FileExists(testFile) {
			t.Error("expected file to exist after write")
		}
	})

	t.Run("remove file", func(t *testing.T) {
		// Create file first
		w.WriteFile(testFile, []byte("test"), 0644)

		err := w.RemoveFile(testFile)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		if w.FileExists(testFile) {
			t.Error("expected file to not exist after remove")
		}
	})

	t.Run("remove non-existent file", func(t *testing.T) {
		err := w.RemoveFile("/non/existent/file/path/12345")
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})
}
