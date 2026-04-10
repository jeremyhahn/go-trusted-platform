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
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// PolicyEngine defines the interface for policy evaluation engines.
type PolicyEngine interface {
	// Initialize prepares the engine with the given configuration.
	Initialize(ctx context.Context, config *config.PolicyConfig) error

	// LoadPolicy loads a policy with the given name and content.
	LoadPolicy(ctx context.Context, name string, content []byte) error

	// UnloadPolicy removes a loaded policy by name.
	UnloadPolicy(ctx context.Context, name string) error

	// Evaluate evaluates a policy against the provided input.
	Evaluate(ctx context.Context, policyName string, input map[string]interface{}) (*EvaluationResult, error)

	// EvaluateWithData evaluates a policy with additional data context.
	EvaluateWithData(ctx context.Context, policyName string, input map[string]interface{}, data map[string]interface{}) (*EvaluationResult, error)

	// ListPolicies returns all loaded policies.
	ListPolicies() []*PolicyBundle

	// GetPolicy returns a specific policy by name.
	GetPolicy(name string) (*PolicyBundle, error)

	// Reload reloads all policies from the configured directory.
	Reload(ctx context.Context) error

	// Close releases resources held by the engine.
	Close() error

	// IsInitialized returns whether the engine has been initialized.
	IsInitialized() bool
}

// PolicyWatcher defines the interface for watching policy file changes.
type PolicyWatcher interface {
	// Start begins watching for policy file changes.
	Start(ctx context.Context) error

	// Stop stops watching for policy file changes.
	Stop() error

	// OnPolicyChange registers a callback for policy change events.
	OnPolicyChange(callback func(name string, content []byte, deleted bool))

	// IsRunning returns whether the watcher is currently running.
	IsRunning() bool
}

// EvaluationResult represents the result of a policy evaluation.
type EvaluationResult struct {
	// Allowed indicates whether the policy allows the action.
	Allowed bool `json:"allowed"`

	// Reason provides a human-readable explanation of the decision.
	Reason string `json:"reason,omitempty"`

	// PolicyName is the name of the policy that was evaluated.
	PolicyName string `json:"policy_name"`

	// Timestamp is when the evaluation occurred.
	Timestamp time.Time `json:"timestamp"`

	// Input is the input that was evaluated.
	Input map[string]interface{} `json:"input,omitempty"`

	// Violations contains any policy violations found.
	Violations []Violation `json:"violations,omitempty"`

	// Duration is how long the evaluation took.
	Duration time.Duration `json:"duration"`

	// Bindings contains variable bindings from the evaluation.
	Bindings map[string]interface{} `json:"bindings,omitempty"`
}

// Violation represents a single policy violation.
type Violation struct {
	// Rule is the name of the rule that was violated.
	Rule string `json:"rule"`

	// Message is a human-readable description of the violation.
	Message string `json:"message"`

	// Severity indicates the severity of the violation.
	Severity ViolationSeverity `json:"severity,omitempty"`

	// Details contains additional violation details.
	Details map[string]interface{} `json:"details,omitempty"`
}

// ViolationSeverity represents the severity level of a violation.
type ViolationSeverity string

const (
	// SeverityInfo indicates an informational violation.
	SeverityInfo ViolationSeverity = "info"

	// SeverityWarning indicates a warning violation.
	SeverityWarning ViolationSeverity = "warning"

	// SeverityError indicates an error violation.
	SeverityError ViolationSeverity = "error"

	// SeverityCritical indicates a critical violation.
	SeverityCritical ViolationSeverity = "critical"
)

// PolicyBundle represents a loaded policy.
type PolicyBundle struct {
	// Name is the unique identifier for the policy.
	Name string `json:"name"`

	// Version is the version of the policy.
	Version string `json:"version,omitempty"`

	// Content is the raw Rego policy content.
	Content string `json:"content"`

	// LoadedAt is when the policy was loaded.
	LoadedAt time.Time `json:"loaded_at"`

	// Package is the Rego package name.
	Package string `json:"package,omitempty"`

	// Path is the file path the policy was loaded from.
	Path string `json:"path,omitempty"`

	// Checksum is the SHA-256 checksum of the policy content.
	Checksum string `json:"checksum,omitempty"`
}

// PolicyChangeEvent represents a policy file change event.
type PolicyChangeEvent struct {
	// Name is the policy name.
	Name string

	// Content is the new policy content (nil if deleted).
	Content []byte

	// Deleted indicates whether the policy was deleted.
	Deleted bool

	// Timestamp is when the event occurred.
	Timestamp time.Time
}

// DecisionLog represents an audit log entry for policy decisions.
type DecisionLog struct {
	// ID is a unique identifier for this decision.
	ID string `json:"id"`

	// Timestamp is when the decision was made.
	Timestamp time.Time `json:"timestamp"`

	// PolicyName is the policy that was evaluated.
	PolicyName string `json:"policy_name"`

	// Input is the input that was evaluated.
	Input map[string]interface{} `json:"input"`

	// Result is the evaluation result.
	Result *EvaluationResult `json:"result"`

	// RequestID is an optional request correlation ID.
	RequestID string `json:"request_id,omitempty"`

	// Source identifies where the request came from.
	Source string `json:"source,omitempty"`
}

// EngineStats contains statistics about the policy engine.
type EngineStats struct {
	// PolicyCount is the number of loaded policies.
	PolicyCount int `json:"policy_count"`

	// EvaluationCount is the total number of evaluations.
	EvaluationCount int64 `json:"evaluation_count"`

	// AllowedCount is the number of allowed decisions.
	AllowedCount int64 `json:"allowed_count"`

	// DeniedCount is the number of denied decisions.
	DeniedCount int64 `json:"denied_count"`

	// ErrorCount is the number of evaluation errors.
	ErrorCount int64 `json:"error_count"`

	// AverageEvaluationTime is the average evaluation duration.
	AverageEvaluationTime time.Duration `json:"average_evaluation_time"`

	// LastEvaluationTime is when the last evaluation occurred.
	LastEvaluationTime time.Time `json:"last_evaluation_time,omitempty"`

	// InitializedAt is when the engine was initialized.
	InitializedAt time.Time `json:"initialized_at"`
}
