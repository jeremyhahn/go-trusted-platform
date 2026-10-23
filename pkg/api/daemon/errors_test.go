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

package daemon

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrDaemonNotRunning(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDaemonNotRunning
		expected string
	}{
		{
			name:     "error message",
			err:      ErrDaemonNotRunning{},
			expected: "daemon is not running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("ErrDaemonNotRunning.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrDaemonAlreadyRunning(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDaemonAlreadyRunning
		expected string
	}{
		{
			name:     "error message",
			err:      ErrDaemonAlreadyRunning{},
			expected: "daemon is already running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("ErrDaemonAlreadyRunning.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrServiceNotFound(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		expected    string
	}{
		{
			name:        "tpm service",
			serviceName: "tpm",
			expected:    "service not found: tpm",
		},
		{
			name:        "unknown service",
			serviceName: "unknown",
			expected:    "service not found: unknown",
		},
		{
			name:        "empty service name",
			serviceName: "",
			expected:    "service not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceNotFound{ServiceName: tt.serviceName}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrServiceNotFound.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrServiceAlreadyRunning(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		expected    string
	}{
		{
			name:        "tpm service",
			serviceName: "tpm",
			expected:    "service already running: tpm",
		},
		{
			name:        "webservice",
			serviceName: "webservice",
			expected:    "service already running: webservice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceAlreadyRunning{ServiceName: tt.serviceName}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrServiceAlreadyRunning.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrServiceNotRunning(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		expected    string
	}{
		{
			name:        "dns service",
			serviceName: "dns",
			expected:    "service is not running: dns",
		},
		{
			name:        "acme service",
			serviceName: "acme",
			expected:    "service is not running: acme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceNotRunning{ServiceName: tt.serviceName}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrServiceNotRunning.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrConfigNotFound(t *testing.T) {
	tests := []struct {
		name      string
		configKey string
		expected  string
	}{
		{
			name:      "socket config",
			configKey: "socket_path",
			expected:  "configuration not found: socket_path",
		},
		{
			name:      "timeout config",
			configKey: "shutdown_timeout",
			expected:  "configuration not found: shutdown_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrConfigNotFound{ConfigKey: tt.configKey}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrConfigNotFound.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "empty socket path",
			reason:   "socket path cannot be empty",
			expected: "invalid configuration: socket path cannot be empty",
		},
		{
			name:     "negative timeout",
			reason:   "shutdown timeout must be positive",
			expected: "invalid configuration: shutdown timeout must be positive",
		},
		{
			name:     "service timeout",
			reason:   "service tpm timeout must be positive",
			expected: "invalid configuration: service tpm timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidConfig{Reason: tt.reason}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrInvalidConfig.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrProvisionFailed(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "tpm init failed",
			reason:   "TPM initialization failed",
			expected: "provisioning failed: TPM initialization failed",
		},
		{
			name:     "disk error",
			reason:   "disk I/O error",
			expected: "provisioning failed: disk I/O error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrProvisionFailed{Reason: tt.reason}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrProvisionFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrShutdownFailed(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "service stop timeout",
			reason:   "service failed to stop within timeout",
			expected: "shutdown failed: service failed to stop within timeout",
		},
		{
			name:     "socket close error",
			reason:   "failed to close socket",
			expected: "shutdown failed: failed to close socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrShutdownFailed{Reason: tt.reason}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrShutdownFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidServiceType(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		expected    string
	}{
		{
			name:        "unknown service",
			serviceType: "unknown",
			expected:    "invalid service type: unknown",
		},
		{
			name:        "empty type",
			serviceType: "",
			expected:    "invalid service type: ",
		},
		{
			name:        "invalid type",
			serviceType: "invalid-service-123",
			expected:    "invalid service type: invalid-service-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidServiceType{Type: tt.serviceType}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrInvalidServiceType.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrHealthRegistryNotConfigured(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrHealthRegistryNotConfigured
		expected string
	}{
		{
			name:     "error message",
			err:      ErrHealthRegistryNotConfigured{},
			expected: "health registry not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("ErrHealthRegistryNotConfigured.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrHealthCheckFailed(t *testing.T) {
	tests := []struct {
		name      string
		component string
		reason    string
		expected  string
	}{
		{
			name:      "database check failed",
			component: "database",
			reason:    "connection timeout",
			expected:  "health check failed for database: connection timeout",
		},
		{
			name:      "service check failed",
			component: "kms",
			reason:    "service not responding",
			expected:  "health check failed for kms: service not responding",
		},
		{
			name:      "empty component",
			component: "",
			reason:    "unknown failure",
			expected:  "health check failed for : unknown failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrHealthCheckFailed{Component: tt.component, Reason: tt.reason}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrHealthCheckFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrDatabaseNotAvailable(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "not initialized",
			reason:   "database not initialized",
			expected: "database not available: database not initialized",
		},
		{
			name:     "connection refused",
			reason:   "connection refused",
			expected: "database not available: connection refused",
		},
		{
			name:     "empty reason",
			reason:   "",
			expected: "database not available: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDatabaseNotAvailable{Reason: tt.reason}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrDatabaseNotAvailable.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrUnsupportedRecordType(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrUnsupportedRecordType
		expected string
	}{
		{
			name:     "error message",
			err:      ErrUnsupportedRecordType{},
			expected: "unsupported DNS record type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("ErrUnsupportedRecordType.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrDNSServiceNotAvailable(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDNSServiceNotAvailable
		expected string
	}{
		{
			name:     "error message",
			err:      ErrDNSServiceNotAvailable{},
			expected: "DNS service not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("ErrDNSServiceNotAvailable.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrServiceNotAvailable(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		expected    string
	}{
		{
			name:        "kms service",
			serviceName: "kms",
			expected:    "service not available: kms",
		},
		{
			name:        "dns service",
			serviceName: "dns",
			expected:    "service not available: dns",
		},
		{
			name:        "empty service",
			serviceName: "",
			expected:    "service not available: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceNotAvailable{Service: tt.serviceName}
			got := err.Error()
			if got != tt.expected {
				t.Errorf("ErrServiceNotAvailable.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestErrorClasses_GRPCStatus pins the class the MCP server encodes into its
// JSON-RPC code for the errors MCP tools return: a missing service is
// Unavailable and a malformed device ID is InvalidArgument, wrapped or not.
func TestErrorClasses_GRPCStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"service not available", ErrServiceNotAvailable{Service: "device"}, codes.Unavailable},
		{"invalid device id", ErrInvalidDeviceID{ID: "abc"}, codes.InvalidArgument},
		{"wrapped service not available", fmt.Errorf("device_get: %w", ErrServiceNotAvailable{Service: "device"}), codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := status.Code(tt.err); got != tt.want {
				t.Errorf("status.Code(%v) = %s, want %s", tt.err, got, tt.want)
			}
		})
	}
}

// TestErrorClasses_UnclassifiedStaysUnknown keeps an error without a class
// out of the table, so the MCP server answers it with InternalError.
func TestErrorClasses_UnclassifiedStaysUnknown(t *testing.T) {
	if got := status.Code(ErrServiceAlreadyRunning{ServiceName: "dns"}); got != codes.Unknown {
		t.Errorf("status.Code(ErrServiceAlreadyRunning) = %s, want Unknown", got)
	}
}
