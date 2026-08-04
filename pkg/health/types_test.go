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

package health

import (
	"encoding/json"
	"testing"
	"time"
)

// TestHealthStatusValues guards the wire values of the status constants.
// StatusHealthy/StatusDegraded/StatusUnhealthy alias the shared quicbaas SDK
// health statuses; StatusUnknown is a platform-local extension. All four must
// keep their historical string values because they appear verbatim in the
// platform REST and gRPC health API payloads.
func TestHealthStatusValues(t *testing.T) {
	tests := []struct {
		name   string
		status HealthStatus
		want   string
	}{
		{"healthy", StatusHealthy, "healthy"},
		{"degraded", StatusDegraded, "degraded"},
		{"unhealthy", StatusUnhealthy, "unhealthy"},
		{"unknown", StatusUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.want {
				t.Errorf("status = %q, want %q", string(tt.status), tt.want)
			}
		})
	}
}

// TestHealthStatusJSON verifies statuses marshal to and unmarshal from their
// plain string wire representation.
func TestHealthStatusJSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(StatusDegraded)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		if string(data) != `"degraded"` {
			t.Errorf("Marshal() = %s, want %q", data, `"degraded"`)
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		var s HealthStatus
		if err := json.Unmarshal([]byte(`"unhealthy"`), &s); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if s != StatusUnhealthy {
			t.Errorf("Unmarshal() = %q, want %q", s, StatusUnhealthy)
		}
	})

	t.Run("unmarshal invalid JSON", func(t *testing.T) {
		var s HealthStatus
		if err := json.Unmarshal([]byte(`{`), &s); err == nil {
			t.Error("Unmarshal() expected error for invalid JSON")
		}
	})
}

// TestComponentHealthJSON verifies the ComponentHealth wire shape.
func TestComponentHealthJSON(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		in := ComponentHealth{
			Name:        "quicbaas",
			Status:      StatusHealthy,
			Message:     "ok",
			LastChecked: time.Unix(1700000000, 0).UTC(),
			Duration:    5 * time.Millisecond,
			Details:     map[string]any{"response_time_ms": 5.0},
		}
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		var out ComponentHealth
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if out.Name != in.Name || out.Status != in.Status || out.Duration != in.Duration {
			t.Errorf("round trip mismatch: got %+v, want %+v", out, in)
		}
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		data, err := json.Marshal(ComponentHealth{Name: "x", Status: StatusUnknown})
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if _, ok := m["message"]; ok {
			t.Error("expected message to be omitted when empty")
		}
		if _, ok := m["details"]; ok {
			t.Error("expected details to be omitted when empty")
		}
	})
}

func TestDefaultRegistryConfig(t *testing.T) {
	cfg := DefaultRegistryConfig()
	if cfg.MaxCheckers != 100 {
		t.Errorf("MaxCheckers = %d, want 100", cfg.MaxCheckers)
	}
	if cfg.DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", cfg.DefaultTimeout)
	}
}
