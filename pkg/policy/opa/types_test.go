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

package opa

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluationResult(t *testing.T) {
	t.Run("creation and fields", func(t *testing.T) {
		now := time.Now()
		result := &EvaluationResult{
			Allowed:    true,
			Reason:     "all checks passed",
			PolicyName: "test-policy",
			Timestamp:  now,
			Input: map[string]interface{}{
				"user": "admin",
			},
			Violations: []Violation{},
			Duration:   100 * time.Millisecond,
		}

		assert.True(t, result.Allowed)
		assert.Equal(t, "all checks passed", result.Reason)
		assert.Equal(t, "test-policy", result.PolicyName)
		assert.Equal(t, now, result.Timestamp)
		assert.Equal(t, "admin", result.Input["user"])
		assert.Empty(t, result.Violations)
		assert.Equal(t, 100*time.Millisecond, result.Duration)
	})

	t.Run("JSON serialization", func(t *testing.T) {
		result := &EvaluationResult{
			Allowed:    false,
			Reason:     "policy violation",
			PolicyName: "security-policy",
			Timestamp:  time.Now(),
			Violations: []Violation{
				{Rule: "rule1", Message: "violation 1"},
			},
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var decoded EvaluationResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, result.Allowed, decoded.Allowed)
		assert.Equal(t, result.Reason, decoded.Reason)
		assert.Equal(t, result.PolicyName, decoded.PolicyName)
		assert.Len(t, decoded.Violations, 1)
	})

	t.Run("with bindings", func(t *testing.T) {
		result := &EvaluationResult{
			Allowed:    true,
			PolicyName: "test-policy",
			Bindings: map[string]interface{}{
				"role":        "admin",
				"permissions": []string{"read", "write"},
			},
		}

		assert.Equal(t, "admin", result.Bindings["role"])
	})
}

func TestViolation(t *testing.T) {
	t.Run("creation and fields", func(t *testing.T) {
		violation := Violation{
			Rule:     "pcr-validation",
			Message:  "PCR values do not match",
			Severity: SeverityError,
			Details: map[string]interface{}{
				"expected": "abc123",
				"actual":   "def456",
			},
		}

		assert.Equal(t, "pcr-validation", violation.Rule)
		assert.Equal(t, "PCR values do not match", violation.Message)
		assert.Equal(t, SeverityError, violation.Severity)
		assert.Equal(t, "abc123", violation.Details["expected"])
	})

	t.Run("JSON serialization", func(t *testing.T) {
		violation := Violation{
			Rule:     "test-rule",
			Message:  "test message",
			Severity: SeverityWarning,
		}

		data, err := json.Marshal(violation)
		require.NoError(t, err)

		var decoded Violation
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, violation.Rule, decoded.Rule)
		assert.Equal(t, violation.Message, decoded.Message)
		assert.Equal(t, violation.Severity, decoded.Severity)
	})
}

func TestViolationSeverity(t *testing.T) {
	t.Run("severity values", func(t *testing.T) {
		assert.Equal(t, ViolationSeverity("info"), SeverityInfo)
		assert.Equal(t, ViolationSeverity("warning"), SeverityWarning)
		assert.Equal(t, ViolationSeverity("error"), SeverityError)
		assert.Equal(t, ViolationSeverity("critical"), SeverityCritical)
	})

	t.Run("string conversion", func(t *testing.T) {
		assert.Equal(t, "info", string(SeverityInfo))
		assert.Equal(t, "warning", string(SeverityWarning))
		assert.Equal(t, "error", string(SeverityError))
		assert.Equal(t, "critical", string(SeverityCritical))
	})
}

func TestPolicyBundle(t *testing.T) {
	t.Run("creation and fields", func(t *testing.T) {
		now := time.Now()
		bundle := &PolicyBundle{
			Name:     "host-policy",
			Version:  "1.0.0",
			Content:  "package test\ndefault allow = false",
			LoadedAt: now,
			Package:  "data.test",
			Path:     "/etc/policies/host.rego",
			Checksum: "abc123def456",
		}

		assert.Equal(t, "host-policy", bundle.Name)
		assert.Equal(t, "1.0.0", bundle.Version)
		assert.Contains(t, bundle.Content, "package test")
		assert.Equal(t, now, bundle.LoadedAt)
		assert.Equal(t, "data.test", bundle.Package)
		assert.Equal(t, "/etc/policies/host.rego", bundle.Path)
		assert.Equal(t, "abc123def456", bundle.Checksum)
	})

	t.Run("JSON serialization", func(t *testing.T) {
		bundle := &PolicyBundle{
			Name:    "test-policy",
			Version: "2.0.0",
			Content: "package test",
		}

		data, err := json.Marshal(bundle)
		require.NoError(t, err)

		var decoded PolicyBundle
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, bundle.Name, decoded.Name)
		assert.Equal(t, bundle.Version, decoded.Version)
		assert.Equal(t, bundle.Content, decoded.Content)
	})
}

func TestPolicyChangeEvent(t *testing.T) {
	t.Run("creation for new policy", func(t *testing.T) {
		event := PolicyChangeEvent{
			Name:      "new-policy",
			Content:   []byte("package test"),
			Deleted:   false,
			Timestamp: time.Now(),
		}

		assert.Equal(t, "new-policy", event.Name)
		assert.Equal(t, []byte("package test"), event.Content)
		assert.False(t, event.Deleted)
	})

	t.Run("creation for deleted policy", func(t *testing.T) {
		event := PolicyChangeEvent{
			Name:      "deleted-policy",
			Content:   nil,
			Deleted:   true,
			Timestamp: time.Now(),
		}

		assert.Equal(t, "deleted-policy", event.Name)
		assert.Nil(t, event.Content)
		assert.True(t, event.Deleted)
	})
}

func TestDecisionLog(t *testing.T) {
	t.Run("creation and fields", func(t *testing.T) {
		result := &EvaluationResult{
			Allowed:    true,
			PolicyName: "test-policy",
		}

		log := DecisionLog{
			ID:         "decision-001",
			Timestamp:  time.Now(),
			PolicyName: "test-policy",
			Input: map[string]interface{}{
				"user": "admin",
			},
			Result:    result,
			RequestID: "req-123",
			Source:    "api-server",
		}

		assert.Equal(t, "decision-001", log.ID)
		assert.Equal(t, "test-policy", log.PolicyName)
		assert.Equal(t, "admin", log.Input["user"])
		assert.Equal(t, result, log.Result)
		assert.Equal(t, "req-123", log.RequestID)
		assert.Equal(t, "api-server", log.Source)
	})

	t.Run("JSON serialization", func(t *testing.T) {
		log := DecisionLog{
			ID:         "decision-002",
			Timestamp:  time.Now(),
			PolicyName: "security-policy",
			Input:      map[string]interface{}{"key": "value"},
			Result: &EvaluationResult{
				Allowed: false,
			},
		}

		data, err := json.Marshal(log)
		require.NoError(t, err)

		var decoded DecisionLog
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, log.ID, decoded.ID)
		assert.Equal(t, log.PolicyName, decoded.PolicyName)
	})
}

func TestEngineStats(t *testing.T) {
	t.Run("creation and fields", func(t *testing.T) {
		now := time.Now()
		stats := EngineStats{
			PolicyCount:           5,
			EvaluationCount:       1000,
			AllowedCount:          800,
			DeniedCount:           200,
			ErrorCount:            10,
			AverageEvaluationTime: 5 * time.Millisecond,
			LastEvaluationTime:    now,
			InitializedAt:         now.Add(-24 * time.Hour),
		}

		assert.Equal(t, 5, stats.PolicyCount)
		assert.Equal(t, int64(1000), stats.EvaluationCount)
		assert.Equal(t, int64(800), stats.AllowedCount)
		assert.Equal(t, int64(200), stats.DeniedCount)
		assert.Equal(t, int64(10), stats.ErrorCount)
		assert.Equal(t, 5*time.Millisecond, stats.AverageEvaluationTime)
	})

	t.Run("JSON serialization", func(t *testing.T) {
		stats := EngineStats{
			PolicyCount:     3,
			EvaluationCount: 500,
			AllowedCount:    400,
			DeniedCount:     100,
		}

		data, err := json.Marshal(stats)
		require.NoError(t, err)

		var decoded EngineStats
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, stats.PolicyCount, decoded.PolicyCount)
		assert.Equal(t, stats.EvaluationCount, decoded.EvaluationCount)
	})

	t.Run("zero values", func(t *testing.T) {
		stats := EngineStats{}
		assert.Equal(t, 0, stats.PolicyCount)
		assert.Equal(t, int64(0), stats.EvaluationCount)
		assert.True(t, stats.LastEvaluationTime.IsZero())
		assert.True(t, stats.InitializedAt.IsZero())
	})
}
