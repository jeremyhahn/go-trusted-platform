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

// A build without the opa tag refuses a delivered tenant posture policy as
// unavailable, and telemetry says why (#1691). make test-noopa runs
// this.

//go:build !opa

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

func TestApplyVPN_NoOPA_ATenantPostureChangeIsUnavailable(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()))
	assert.Len(t, r.gw.vpn.svc.Enrolments(), 1)

	tenant := laptopSection()
	tenant.PosturePolicies = []gwstate.DesiredVPNPosturePolicy{
		{TenantID: "tenant-a", Name: vpn.DefaultPosturePolicy, Module: "package vpn.posture\nallow := true\n"},
	}
	err := r.gw.applyVPN(ctx, tenant)
	var unavailable *vpn.ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	var notBuilt opa.ErrOPANotBuilt
	assert.True(t, errors.As(err, &notBuilt), "the cause is the missing opa tag: %v", err)
	snap := r.gw.collectVPN(ctx)
	require.Len(t, snap.PosturePolicyErrors, 1, "the refusal is visible in telemetry")
	assert.Contains(t, snap.PosturePolicyErrors[0], "opa build tag", "the operator is told why")
}
