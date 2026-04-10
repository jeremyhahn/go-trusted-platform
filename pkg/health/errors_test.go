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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrHealthCheckFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrHealthCheckFailed{
			Component: "database",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "database")
		assert.Contains(t, err.Error(), "connection refused")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrHealthCheckFailed{
			Component: "database",
		}

		assert.Contains(t, err.Error(), "database")
		assert.NotContains(t, err.Error(), "nil")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrComponentNotFound(t *testing.T) {
	err := ErrComponentNotFound{Name: "missing-component"}

	assert.Contains(t, err.Error(), "missing-component")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrCheckerNotRegistered(t *testing.T) {
	err := ErrCheckerNotRegistered{Name: "unregistered-checker"}

	assert.Contains(t, err.Error(), "unregistered-checker")
	assert.Contains(t, err.Error(), "not registered")
}

func TestErrCheckTimeout(t *testing.T) {
	err := ErrCheckTimeout{
		Component: "slow-component",
		Timeout:   "30s",
	}

	assert.Contains(t, err.Error(), "slow-component")
	assert.Contains(t, err.Error(), "30s")
	assert.Contains(t, err.Error(), "timeout")
}

func TestErrRegistryFull(t *testing.T) {
	err := ErrRegistryFull{MaxCheckers: 100}

	assert.Contains(t, err.Error(), "100")
	assert.Contains(t, err.Error(), "full")
}

func TestErrCheckerAlreadyRegistered(t *testing.T) {
	err := ErrCheckerAlreadyRegistered{Name: "duplicate-checker"}

	assert.Contains(t, err.Error(), "duplicate-checker")
	assert.Contains(t, err.Error(), "already registered")
}

func TestErrInvalidCheckerName(t *testing.T) {
	err := ErrInvalidCheckerName{
		Name:   "",
		Reason: "name cannot be empty",
	}

	assert.Contains(t, err.Error(), "name cannot be empty")
	assert.Contains(t, err.Error(), "invalid")
}

func TestErrConnectionFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("network unreachable")
		err := ErrConnectionFailed{
			Component: "database",
			Target:    "localhost:5432",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "database")
		assert.Contains(t, err.Error(), "localhost:5432")
		assert.Contains(t, err.Error(), "network unreachable")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrConnectionFailed{
			Component: "database",
			Target:    "localhost:5432",
		}

		assert.Contains(t, err.Error(), "database")
		assert.Contains(t, err.Error(), "localhost:5432")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrResourceUnavailable(t *testing.T) {
	err := ErrResourceUnavailable{
		Resource: "disk",
		Reason:   "no space left",
	}

	assert.Contains(t, err.Error(), "disk")
	assert.Contains(t, err.Error(), "no space left")
	assert.Contains(t, err.Error(), "unavailable")
}

func TestErrRegistryClosed(t *testing.T) {
	err := ErrRegistryClosed{}

	assert.Contains(t, err.Error(), "closed")
	assert.Contains(t, err.Error(), "registry")
}

func TestErrInvalidThreshold(t *testing.T) {
	err := ErrInvalidThreshold{
		Field:  "UsageWarning",
		Reason: "must be between 0 and 100",
	}

	assert.Contains(t, err.Error(), "UsageWarning")
	assert.Contains(t, err.Error(), "must be between 0 and 100")
}

func TestErrProbeNotConfigured(t *testing.T) {
	err := ErrProbeNotConfigured{ProbeType: ProbeLiveness}

	assert.Contains(t, err.Error(), "liveness")
	assert.Contains(t, err.Error(), "not configured")
}
