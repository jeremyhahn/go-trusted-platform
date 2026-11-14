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

// Without the opa tag the VPN service has no engine to compile a posture
// policy: every transport refuses a well-formed policy as Unavailable and
// stores nothing, and a malformed request is still InvalidArgument.

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestVPNGRPCService_SetPosturePolicyWithoutOPAIsUnavailable(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	_, err := server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: vpnTestPolicy},
	})
	assert.Equal(t, codes.Unavailable, status.Code(err), "got %v", err)

	_, err = server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing policy")

	listed, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
	require.NoError(t, err)
	assert.Empty(t, listed.GetPolicies(), "a refused policy must not be stored")
}

func TestMCPProvidersSetPosturePolicyWithoutOPAIsUnavailable(t *testing.T) {
	server, _ := newVPNTestServer(t)

	for name, provider := range vpnProviders(server) {
		t.Run(name, func(t *testing.T) {
			_, err := provider.VPNPosturePolicySet(context.Background(), "acme", "corp", vpnTestPolicy)
			assert.Equal(t, codes.Unavailable, status.Code(err), "got %v", err)
		})
	}
}

func TestQUICVPNCategorySetPosturePolicyWithoutOPAIsUnavailable(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)

	resp := handler.HandleRequest(context.Background(), vpnCategoryRequest(t, quicwire.VPNSubSetPosturePolicy,
		&platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: vpnTestPolicy}}))
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}
