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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The daemon's local token validator names the principal a legacy-path token
// carries, so the gRPC interceptor can bind the caller's tenant.
var _ grpcapi.PrincipalTokenValidator = (*grpcTokenValidator)(nil)

// vpnLegacyJWTValidator is a legacy (bool-only) token validator that maps a
// token to the tenant it names.
type vpnLegacyJWTValidator map[string]string

func (v vpnLegacyJWTValidator) ValidateToken(_ context.Context, token string) (bool, error) {
	_, ok := v[token]
	return ok, nil
}

func (v vpnLegacyJWTValidator) TokenPrincipal(_ context.Context, token string) (*platformtoken.AuthorizedContext, error) {
	tenant, ok := v[token]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return &platformtoken.AuthorizedContext{Subject: "op", TenantID: tenant}, nil
}

// vpnAllowAllChecker grants every permission, so only the tenant guard can
// refuse a call.
type vpnAllowAllChecker struct{}

func (vpnAllowAllChecker) CheckPermission(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// TestVPNGRPC_LegacyTokenCallerIsTenantBound drives the VPN RPCs through the
// legacy-token gRPC interceptor: the token's tenant is bound, so a
// cross-tenant or empty-tenant request is refused, and a token naming no
// tenant cannot list at all (#2012 round 2 P1).
func TestVPNGRPC_LegacyTokenCallerIsTenantBound(t *testing.T) {
	server, _ := newVPNTestServer(t)
	interceptor := grpcapi.OIDCUnaryInterceptor(
		grpcapi.WithTokenValidator(vpnLegacyJWTValidator{"jwt-acme": "acme", "jwt-none": ""}),
		grpcapi.WithAuthorizationChecker(vpnAllowAllChecker{}),
	)

	call := func(method, token, tenant string) error {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
		info := &grpc.UnaryServerInfo{FullMethod: method}
		_, err := interceptor(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
			switch method {
			case platformv1.VPNService_ListPeers_FullMethodName:
				return server.ListPeers(ctx, &platformv1.ListVPNPeersRequest{TenantId: tenant})
			default:
				return server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{TenantId: tenant})
			}
		})
		return err
	}

	cases := []struct {
		token, tenant string
		want          codes.Code
	}{
		{"jwt-acme", "acme", codes.OK},
		{"jwt-acme", "globex", codes.PermissionDenied},
		{"jwt-acme", "", codes.PermissionDenied},
		{"jwt-none", "", codes.PermissionDenied},
		{"jwt-none", "globex", codes.PermissionDenied},
	}
	for _, method := range []string{
		platformv1.VPNService_ListPeers_FullMethodName,
		platformv1.VPNService_ListPosturePolicies_FullMethodName,
	} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.token+"/tenant="+tc.tenant, func(t *testing.T) {
				assert.Equal(t, tc.want, status.Code(call(method, tc.token, tc.tenant)))
			})
		}
	}
}
