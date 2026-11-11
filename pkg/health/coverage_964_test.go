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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closingChecker closes its registry the moment Register asks for its name.
// Register reads the name after its unlocked closed check and before it takes
// the lock, so this reproduces, deterministically, a Close that lands in that
// window.
type closingChecker struct {
	registry Registry
	closeErr error
}

func (c *closingChecker) Name() string {
	c.closeErr = c.registry.Close()
	return "late"
}

func (c *closingChecker) Check(ctx context.Context) ComponentHealth {
	return ComponentHealth{Name: "late", Status: StatusHealthy}
}

func TestRegister_CloseDuringRegistrationRejectsChecker(t *testing.T) {
	registry := NewRegistry()
	checker := &closingChecker{registry: registry}

	err := registry.Register(checker)

	require.NoError(t, checker.closeErr)
	var errClosed ErrRegistryClosed
	require.True(t, errors.As(err, &errClosed), "got %v", err)
	assert.Equal(t, 0, registry.Count(), "a closed registry must not keep the checker")
	assert.Empty(t, registry.List())
}

func TestRegister_InvalidCheckerReasons(t *testing.T) {
	tests := []struct {
		name    string
		checker HealthChecker
		reason  string
	}{
		{name: "nil checker", checker: nil, reason: "checker cannot be nil"},
		{name: "empty name", checker: &mockChecker{name: ""}, reason: "name cannot be empty"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()

			err := registry.Register(tc.checker)

			var errName ErrInvalidCheckerName
			require.True(t, errors.As(err, &errName), "got %v", err)
			assert.Equal(t, tc.reason, errName.Reason)
			assert.Equal(t, 0, registry.Count())
		})
	}
}
