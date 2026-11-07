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
}

func TestViolation(t *testing.T) {
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
}

func TestPolicyBundle(t *testing.T) {
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

func TestDecisionLog(t *testing.T) {
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
}
