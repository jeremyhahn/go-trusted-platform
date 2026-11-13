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

package platform

import (
	"strings"
	"testing"
)

func TestErrServiceNotFound(t *testing.T) {
	err := ErrServiceNotFound{ServiceName: "test-service"}
	msg := err.Error()

	if !strings.Contains(msg, "test-service") {
		t.Errorf("expected error message to contain service name, got: %s", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("expected error message to contain 'not found', got: %s", msg)
	}
}

func TestErrServiceAlreadyRunning(t *testing.T) {
	err := ErrServiceAlreadyRunning{ServiceName: "test-service"}
	msg := err.Error()

	if !strings.Contains(msg, "test-service") {
		t.Errorf("expected error message to contain service name, got: %s", msg)
	}
	if !strings.Contains(msg, "already running") {
		t.Errorf("expected error message to contain 'already running', got: %s", msg)
	}
}

func TestErrServiceNotRunning(t *testing.T) {
	err := ErrServiceNotRunning{ServiceName: "test-service"}
	msg := err.Error()

	if !strings.Contains(msg, "test-service") {
		t.Errorf("expected error message to contain service name, got: %s", msg)
	}
	if !strings.Contains(msg, "not running") {
		t.Errorf("expected error message to contain 'not running', got: %s", msg)
	}
}

func TestErrServiceStartFailed(t *testing.T) {
	err := ErrServiceStartFailed{ServiceName: "test-service", Reason: "connection refused"}
	msg := err.Error()

	if !strings.Contains(msg, "test-service") {
		t.Errorf("expected error message to contain service name, got: %s", msg)
	}
	if !strings.Contains(msg, "failed to start") {
		t.Errorf("expected error message to contain 'failed to start', got: %s", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("expected error message to contain reason, got: %s", msg)
	}
}

func TestErrServiceStopFailed(t *testing.T) {
	err := ErrServiceStopFailed{ServiceName: "test-service", Reason: "timeout"}
	msg := err.Error()

	if !strings.Contains(msg, "test-service") {
		t.Errorf("expected error message to contain service name, got: %s", msg)
	}
	if !strings.Contains(msg, "failed to stop") {
		t.Errorf("expected error message to contain 'failed to stop', got: %s", msg)
	}
	if !strings.Contains(msg, "timeout") {
		t.Errorf("expected error message to contain reason, got: %s", msg)
	}
}

func TestErrHealthRegistryNotConfigured(t *testing.T) {
	err := ErrHealthRegistryNotConfigured{}
	msg := err.Error()

	if !strings.Contains(msg, "health registry") {
		t.Errorf("expected error message to contain 'health registry', got: %s", msg)
	}
	if !strings.Contains(msg, "not configured") {
		t.Errorf("expected error message to contain 'not configured', got: %s", msg)
	}
}

func TestErrServiceRegistryNotConfigured(t *testing.T) {
	err := ErrServiceRegistryNotConfigured{}
	msg := err.Error()

	if !strings.Contains(msg, "service registry") {
		t.Errorf("expected error message to contain 'service registry', got: %s", msg)
	}
	if !strings.Contains(msg, "not configured") {
		t.Errorf("expected error message to contain 'not configured', got: %s", msg)
	}
}

func TestErrDaemonConfigNotConfigured(t *testing.T) {
	err := ErrDaemonConfigNotConfigured{}
	msg := err.Error()

	if !strings.Contains(msg, "daemon config") {
		t.Errorf("expected error message to contain 'daemon config', got: %s", msg)
	}
	if !strings.Contains(msg, "not configured") {
		t.Errorf("expected error message to contain 'not configured', got: %s", msg)
	}
}
