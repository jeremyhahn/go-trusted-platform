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

// A delivered tenant posture policy compiles in a real OPA engine; the !opa
// build's behaviour is vpn_service_noopa_test.go (#1691).

//go:build opa

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

func TestApplyVPN_ReachesTheRunningService(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()))
	assert.Len(t, r.gw.vpn.svc.Enrolments(), 1)

	broken := laptopSection()
	broken.PosturePolicies = []gwstate.DesiredVPNPosturePolicy{
		{TenantID: "tenant-a", Name: vpn.DefaultPosturePolicy, Module: "package vpn.posture\nallow if {"},
	}
	err := r.gw.applyVPN(ctx, broken)
	var invalid *vpn.ErrPosturePolicyInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
	snap := r.gw.collectVPN(ctx)
	require.Len(t, snap.PosturePolicyErrors, 1, "the refused tenant is visible in telemetry")
	assert.Contains(t, snap.PosturePolicyErrors[0], "tenant-a")
}
