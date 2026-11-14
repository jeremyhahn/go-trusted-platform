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

//go:build opa

// Posture-policy tests that need the OPA engine to compile a policy. The
// !opa build refuses every policy (service_posture_noopa_test.go).

package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

func TestSetPosturePolicy_CompilesBeforeStoring(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	stored, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "acme", Name: "vpn_posture", Module: testPolicy})
	require.NoError(t, err)
	assert.Equal(t, testNow, stored.UpdatedAt)

	got, err := svc.GetPosturePolicy(ctx, "acme", "vpn_posture")
	require.NoError(t, err)
	assert.Equal(t, testPolicy, got.Module)
}

func TestSetPosturePolicy_RefusesInvalidPolicies(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "acme", Name: "vpn_posture", Module: "package other\n\nimport rego.v1\n\ndefault allow := true\n"})
	var invalidPolicy *ErrInvalidPosturePolicy
	require.True(t, errors.As(err, &invalidPolicy), "got %v", err)
	assert.Equal(t, "acme", invalidPolicy.TenantID)

	cases := map[string]PosturePolicy{
		"no tenant":   {Name: "p", Module: testPolicy},
		"no name":     {TenantID: "t", Module: testPolicy},
		"name path":   {TenantID: "t", Name: "../p", Module: testPolicy},
		"long name":   {TenantID: "t", Name: strings.Repeat("p", maxPolicyNameLength+1), Module: testPolicy},
		"huge module": {TenantID: "t", Name: "p", Module: strings.Repeat("#", maxModuleBytes+1)},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.SetPosturePolicy(ctx, policy)
			var invalid *ErrInvalidArgument
			require.True(t, errors.As(err, &invalid), "got %v", err)
		})
	}

	policies, err := svc.ListPosturePolicies(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, policies, "a refused policy is never stored")
}

func TestSetPosturePolicy_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.PutError = errors.New("raft unavailable")
	_, err := svc.SetPosturePolicy(context.Background(), PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
}

func TestDeletePosturePolicy_RemovesThePolicy(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	require.NoError(t, err)

	require.NoError(t, svc.DeletePosturePolicy(ctx, "t", "p"))
	var notFound *ErrPosturePolicyNotFound
	require.True(t, errors.As(svc.DeletePosturePolicy(ctx, "t", "p"), &notFound))
}

func TestDeletePosturePolicy_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	ctx := context.Background()
	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	require.NoError(t, err)
	storage.DeleteError = errors.New("raft unavailable")
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(svc.DeletePosturePolicy(ctx, "t", "p"), &unavailable))
}

func TestListPosturePolicies_FiltersByTenant(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, p := range []PosturePolicy{{TenantID: "b", Name: "p"}, {TenantID: "a", Name: "p"}} {
		p.Module = testPolicy
		_, err := svc.SetPosturePolicy(ctx, p)
		require.NoError(t, err)
	}
	all, err := svc.ListPosturePolicies(ctx, "")
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, "a", all[0].TenantID)
	tenantB, err := svc.ListPosturePolicies(ctx, "b")
	require.NoError(t, err)
	assert.Len(t, tenantB, 1)
}

func TestDesiredVPN_CarriesEveryPeerAndPolicy(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	empty, err := svc.DesiredVPN(ctx, "gw-1")
	require.NoError(t, err)
	require.NotNil(t, empty, "an empty set is still delivered, so the last revocation reaches the gateways")
	assert.Empty(t, empty.Peers)

	_, err = svc.EnrolPeer(ctx, Peer{TenantID: "t", DeviceID: "d", Zones: []string{"management"}})
	require.NoError(t, err)
	_, err = svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "vpn_posture", Module: testPolicy})
	require.NoError(t, err)

	section, err := svc.DesiredVPN(ctx, "gw-1")
	require.NoError(t, err)
	assert.Equal(t, []gwstate.DesiredVPNPeer{{TenantID: "t", DeviceID: "d", Zones: []string{"management"}}}, section.Peers)
	assert.Equal(t, []gwstate.DesiredVPNPosturePolicy{{TenantID: "t", Name: "vpn_posture", Module: testPolicy}}, section.PosturePolicies)
	require.NoError(t, (&gwstate.DesiredConfig{VPN: section}).Validate(), "the section is a valid desired-config section")
}
