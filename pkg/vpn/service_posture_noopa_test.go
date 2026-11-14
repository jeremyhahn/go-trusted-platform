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

//go:build !opa

// Without the opa tag there is no engine to compile a posture policy, so
// SetPosturePolicy refuses every well-formed policy as engine-unavailable
// and stores nothing; malformed requests are still refused as invalid.

package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetPosturePolicy_WithoutOPAIsEngineUnavailable(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "acme", Name: "vpn_posture", Module: testPolicy})
	var unavailable *ErrPolicyEngineUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)

	_, err = svc.SetPosturePolicy(ctx, PosturePolicy{Name: "p", Module: testPolicy})
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(err, &invalid), "a malformed request is refused before the engine: got %v", err)

	policies, err := svc.ListPosturePolicies(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, policies, "a refused policy is never stored")
}
