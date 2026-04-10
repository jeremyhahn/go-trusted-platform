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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrEngineNotInitialized(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrEngineNotInitialized{}
		assert.Equal(t, "policy engine not initialized", err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrEngineNotInitialized{}
		assert.NotNil(t, err)
	})
}

func TestErrEngineAlreadyInitialized(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrEngineAlreadyInitialized{}
		assert.Equal(t, "policy engine already initialized", err.Error())
	})
}

func TestErrPolicyNotFound(t *testing.T) {
	t.Run("with name", func(t *testing.T) {
		err := ErrPolicyNotFound{Name: "test-policy"}
		assert.Equal(t, "policy not found: test-policy", err.Error())
	})

	t.Run("without name", func(t *testing.T) {
		err := ErrPolicyNotFound{}
		assert.Equal(t, "policy not found", err.Error())
	})
}

func TestErrInvalidPolicy(t *testing.T) {
	t.Run("with name and reason", func(t *testing.T) {
		err := ErrInvalidPolicy{Name: "test-policy", Reason: "syntax error"}
		assert.Equal(t, "invalid policy test-policy: syntax error", err.Error())
	})

	t.Run("with name only", func(t *testing.T) {
		err := ErrInvalidPolicy{Name: "test-policy"}
		assert.Equal(t, "invalid policy: test-policy", err.Error())
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrInvalidPolicy{Reason: "syntax error"}
		assert.Equal(t, "invalid policy: syntax error", err.Error())
	})

	t.Run("without name or reason", func(t *testing.T) {
		err := ErrInvalidPolicy{}
		assert.Equal(t, "invalid policy", err.Error())
	})
}

func TestErrEvaluationFailed(t *testing.T) {
	t.Run("with policy name and reason", func(t *testing.T) {
		err := ErrEvaluationFailed{PolicyName: "test-policy", Reason: "timeout"}
		assert.Equal(t, "policy evaluation failed for test-policy: timeout", err.Error())
	})

	t.Run("with policy name only", func(t *testing.T) {
		err := ErrEvaluationFailed{PolicyName: "test-policy"}
		assert.Equal(t, "policy evaluation failed for test-policy", err.Error())
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrEvaluationFailed{Reason: "timeout"}
		assert.Equal(t, "policy evaluation failed: timeout", err.Error())
	})

	t.Run("without policy name or reason", func(t *testing.T) {
		err := ErrEvaluationFailed{}
		assert.Equal(t, "policy evaluation failed", err.Error())
	})
}

func TestErrPolicyLoadFailed(t *testing.T) {
	t.Run("with name and reason", func(t *testing.T) {
		err := ErrPolicyLoadFailed{Name: "test-policy", Reason: "file not found"}
		assert.Equal(t, "failed to load policy test-policy: file not found", err.Error())
	})

	t.Run("with path and reason", func(t *testing.T) {
		err := ErrPolicyLoadFailed{Path: "/path/to/policy.rego", Reason: "permission denied"}
		assert.Equal(t, "failed to load policy from /path/to/policy.rego: permission denied", err.Error())
	})

	t.Run("with name only", func(t *testing.T) {
		err := ErrPolicyLoadFailed{Name: "test-policy"}
		assert.Equal(t, "failed to load policy: test-policy", err.Error())
	})

	t.Run("with path only", func(t *testing.T) {
		err := ErrPolicyLoadFailed{Path: "/path/to/policy.rego"}
		assert.Equal(t, "failed to load policy from: /path/to/policy.rego", err.Error())
	})

	t.Run("without name or path", func(t *testing.T) {
		err := ErrPolicyLoadFailed{}
		assert.Equal(t, "failed to load policy", err.Error())
	})
}

func TestErrInvalidInput(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidInput{Reason: "missing required field"}
		assert.Equal(t, "invalid input: missing required field", err.Error())
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidInput{}
		assert.Equal(t, "invalid input", err.Error())
	})
}

func TestErrPolicyDirNotFound(t *testing.T) {
	t.Run("with path", func(t *testing.T) {
		err := ErrPolicyDirNotFound{Path: "/var/policies"}
		assert.Equal(t, "policy directory not found: /var/policies", err.Error())
	})

	t.Run("without path", func(t *testing.T) {
		err := ErrPolicyDirNotFound{}
		assert.Equal(t, "policy directory not found", err.Error())
	})
}

func TestErrPolicyAlreadyExists(t *testing.T) {
	t.Run("with name", func(t *testing.T) {
		err := ErrPolicyAlreadyExists{Name: "test-policy"}
		assert.Equal(t, "policy already exists: test-policy", err.Error())
	})

	t.Run("without name", func(t *testing.T) {
		err := ErrPolicyAlreadyExists{}
		assert.Equal(t, "policy already exists", err.Error())
	})
}

func TestErrNilConfig(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrNilConfig{}
		assert.Equal(t, "configuration cannot be nil", err.Error())
	})
}

func TestErrWatcherNotStarted(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrWatcherNotStarted{}
		assert.Equal(t, "policy watcher not started", err.Error())
	})
}

func TestErrWatcherAlreadyStarted(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrWatcherAlreadyStarted{}
		assert.Equal(t, "policy watcher already started", err.Error())
	})
}

func TestErrWatcherFailed(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrWatcherFailed{Reason: "inotify limit reached"}
		assert.Equal(t, "policy watcher failed: inotify limit reached", err.Error())
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrWatcherFailed{}
		assert.Equal(t, "policy watcher failed", err.Error())
	})
}

func TestErrPolicyCompilationFailed(t *testing.T) {
	t.Run("with name and errors", func(t *testing.T) {
		err := ErrPolicyCompilationFailed{
			Name:   "test-policy",
			Errors: []string{"undefined reference", "type mismatch"},
		}
		assert.Contains(t, err.Error(), "policy compilation failed for test-policy")
		assert.Contains(t, err.Error(), "undefined reference")
	})

	t.Run("with name only", func(t *testing.T) {
		err := ErrPolicyCompilationFailed{Name: "test-policy"}
		assert.Equal(t, "policy compilation failed for test-policy", err.Error())
	})

	t.Run("without name", func(t *testing.T) {
		err := ErrPolicyCompilationFailed{}
		assert.Equal(t, "policy compilation failed", err.Error())
	})
}

func TestErrEmptyPolicyContent(t *testing.T) {
	t.Run("with name", func(t *testing.T) {
		err := ErrEmptyPolicyContent{Name: "test-policy"}
		assert.Equal(t, "empty policy content for: test-policy", err.Error())
	})

	t.Run("without name", func(t *testing.T) {
		err := ErrEmptyPolicyContent{}
		assert.Equal(t, "empty policy content", err.Error())
	})
}

func TestErrInvalidPolicyName(t *testing.T) {
	t.Run("with name and reason", func(t *testing.T) {
		err := ErrInvalidPolicyName{Name: "123policy", Reason: "must start with letter"}
		assert.Equal(t, `invalid policy name "123policy": must start with letter`, err.Error())
	})

	t.Run("with name only", func(t *testing.T) {
		err := ErrInvalidPolicyName{Name: "123policy"}
		assert.Equal(t, `invalid policy name: "123policy"`, err.Error())
	})

	t.Run("without name", func(t *testing.T) {
		err := ErrInvalidPolicyName{}
		assert.Equal(t, "invalid policy name", err.Error())
	})
}

func TestErrQueryFailed(t *testing.T) {
	t.Run("with query and reason", func(t *testing.T) {
		err := ErrQueryFailed{Query: "data.policy.allow", Reason: "compilation error"}
		assert.Equal(t, `query "data.policy.allow" failed: compilation error`, err.Error())
	})

	t.Run("with query only", func(t *testing.T) {
		err := ErrQueryFailed{Query: "data.policy.allow"}
		assert.Equal(t, "query failed: data.policy.allow", err.Error())
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrQueryFailed{Reason: "compilation error"}
		assert.Equal(t, "query failed: compilation error", err.Error())
	})

	t.Run("without query or reason", func(t *testing.T) {
		err := ErrQueryFailed{}
		assert.Equal(t, "query failed", err.Error())
	})
}

func TestErrorTypeAssertions(t *testing.T) {
	t.Run("ErrPolicyNotFound type assertion", func(t *testing.T) {
		var err error = ErrPolicyNotFound{Name: "test"}
		var target ErrPolicyNotFound
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrInvalidPolicy type assertion", func(t *testing.T) {
		var err error = ErrInvalidPolicy{Name: "test", Reason: "bad syntax"}
		var target ErrInvalidPolicy
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
		assert.Equal(t, "bad syntax", target.Reason)
	})

	t.Run("ErrEvaluationFailed type assertion", func(t *testing.T) {
		var err error = ErrEvaluationFailed{PolicyName: "test", Reason: "timeout"}
		var target ErrEvaluationFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.PolicyName)
		assert.Equal(t, "timeout", target.Reason)
	})
}
