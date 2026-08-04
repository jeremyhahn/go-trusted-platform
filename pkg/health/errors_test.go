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
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestErrRegistryClosed(t *testing.T) {
	err := ErrRegistryClosed{}

	assert.Contains(t, err.Error(), "closed")
}
