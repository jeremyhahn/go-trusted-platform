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

import "fmt"

// ErrEngineNotInitialized is returned when operations are attempted on an uninitialized engine.
type ErrEngineNotInitialized struct{}

func (e ErrEngineNotInitialized) Error() string {
	return "policy engine not initialized"
}

// ErrEngineAlreadyInitialized is returned when Initialize is called on an already initialized engine.
type ErrEngineAlreadyInitialized struct{}

func (e ErrEngineAlreadyInitialized) Error() string {
	return "policy engine already initialized"
}

// ErrPolicyNotFound is returned when a requested policy does not exist.
type ErrPolicyNotFound struct {
	Name string
}

func (e ErrPolicyNotFound) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("policy not found: %s", e.Name)
	}
	return "policy not found"
}

// ErrInvalidPolicy is returned when a policy fails validation or compilation.
type ErrInvalidPolicy struct {
	Name   string
	Reason string
}

func (e ErrInvalidPolicy) Error() string {
	if e.Name != "" && e.Reason != "" {
		return fmt.Sprintf("invalid policy %s: %s", e.Name, e.Reason)
	}
	if e.Name != "" {
		return fmt.Sprintf("invalid policy: %s", e.Name)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid policy: %s", e.Reason)
	}
	return "invalid policy"
}

// ErrEvaluationFailed is returned when policy evaluation fails.
type ErrEvaluationFailed struct {
	PolicyName string
	Reason     string
}

func (e ErrEvaluationFailed) Error() string {
	if e.PolicyName != "" && e.Reason != "" {
		return fmt.Sprintf("policy evaluation failed for %s: %s", e.PolicyName, e.Reason)
	}
	if e.PolicyName != "" {
		return fmt.Sprintf("policy evaluation failed for %s", e.PolicyName)
	}
	if e.Reason != "" {
		return fmt.Sprintf("policy evaluation failed: %s", e.Reason)
	}
	return "policy evaluation failed"
}

// ErrPolicyLoadFailed is returned when a policy fails to load.
type ErrPolicyLoadFailed struct {
	Name   string
	Path   string
	Reason string
}

func (e ErrPolicyLoadFailed) Error() string {
	if e.Name != "" && e.Reason != "" {
		return fmt.Sprintf("failed to load policy %s: %s", e.Name, e.Reason)
	}
	if e.Path != "" && e.Reason != "" {
		return fmt.Sprintf("failed to load policy from %s: %s", e.Path, e.Reason)
	}
	if e.Name != "" {
		return fmt.Sprintf("failed to load policy: %s", e.Name)
	}
	if e.Path != "" {
		return fmt.Sprintf("failed to load policy from: %s", e.Path)
	}
	return "failed to load policy"
}

// ErrInvalidInput is returned when evaluation input is invalid.
type ErrInvalidInput struct {
	Reason string
}

func (e ErrInvalidInput) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid input: %s", e.Reason)
	}
	return "invalid input"
}

// ErrPolicyDirNotFound is returned when the policy directory does not exist.
type ErrPolicyDirNotFound struct {
	Path string
}

func (e ErrPolicyDirNotFound) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("policy directory not found: %s", e.Path)
	}
	return "policy directory not found"
}

// ErrPolicyAlreadyExists is returned when attempting to load a policy that already exists.
type ErrPolicyAlreadyExists struct {
	Name string
}

func (e ErrPolicyAlreadyExists) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("policy already exists: %s", e.Name)
	}
	return "policy already exists"
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "configuration cannot be nil"
}

// ErrOPANotBuilt is returned by the engine of a build without the opa
// build tag.
type ErrOPANotBuilt struct{}

func (e ErrOPANotBuilt) Error() string {
	return "OPA policy engine not built: rebuild with the opa build tag"
}

// ErrWatcherNotStarted is returned when operations are attempted on a stopped watcher.
type ErrWatcherNotStarted struct{}

func (e ErrWatcherNotStarted) Error() string {
	return "policy watcher not started"
}

// ErrWatcherAlreadyStarted is returned when Start is called on an already running watcher.
type ErrWatcherAlreadyStarted struct{}

func (e ErrWatcherAlreadyStarted) Error() string {
	return "policy watcher already started"
}

// ErrWatcherFailed is returned when the file watcher encounters an error.
type ErrWatcherFailed struct {
	Reason string
}

func (e ErrWatcherFailed) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("policy watcher failed: %s", e.Reason)
	}
	return "policy watcher failed"
}

// ErrPolicyCompilationFailed is returned when a policy fails to compile.
type ErrPolicyCompilationFailed struct {
	Name   string
	Errors []string
}

func (e ErrPolicyCompilationFailed) Error() string {
	if e.Name != "" && len(e.Errors) > 0 {
		return fmt.Sprintf("policy compilation failed for %s: %v", e.Name, e.Errors)
	}
	if e.Name != "" {
		return fmt.Sprintf("policy compilation failed for %s", e.Name)
	}
	return "policy compilation failed"
}

// ErrEmptyPolicyContent is returned when policy content is empty.
type ErrEmptyPolicyContent struct {
	Name string
}

func (e ErrEmptyPolicyContent) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("empty policy content for: %s", e.Name)
	}
	return "empty policy content"
}

// ErrInvalidPolicyName is returned when a policy name is invalid.
type ErrInvalidPolicyName struct {
	Name   string
	Reason string
}

func (e ErrInvalidPolicyName) Error() string {
	if e.Name != "" && e.Reason != "" {
		return fmt.Sprintf("invalid policy name %q: %s", e.Name, e.Reason)
	}
	if e.Name != "" {
		return fmt.Sprintf("invalid policy name: %q", e.Name)
	}
	return "invalid policy name"
}

// ErrQueryFailed is returned when an OPA query fails.
type ErrQueryFailed struct {
	Query  string
	Reason string
}

func (e ErrQueryFailed) Error() string {
	if e.Query != "" && e.Reason != "" {
		return fmt.Sprintf("query %q failed: %s", e.Query, e.Reason)
	}
	if e.Query != "" {
		return fmt.Sprintf("query failed: %s", e.Query)
	}
	if e.Reason != "" {
		return fmt.Sprintf("query failed: %s", e.Reason)
	}
	return "query failed"
}
