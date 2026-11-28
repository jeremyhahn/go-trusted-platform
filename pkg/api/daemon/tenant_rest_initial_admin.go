package daemon

import (
	"context"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tenantRESTInitialAdmin serves the REST owner-invitation route
// (POST /api/v1/tenants/{id}/initial-admin-invitation) through the same
// *TenantGRPCServer the gRPC and QUIC transports use, so the authorization,
// inviter identity and invitation store are identical on every transport.
type tenantRESTInitialAdmin struct {
	server *TenantGRPCServer
}

var _ restapi.InitialAdminInvitationServer = (*tenantRESTInitialAdmin)(nil)

// newTenantRESTInitialAdmin returns nil when server is nil, so the REST route
// keeps answering 503 rather than dispatching to a missing server.
func newTenantRESTInitialAdmin(server *TenantGRPCServer) *tenantRESTInitialAdmin {
	if server == nil {
		return nil
	}
	return &tenantRESTInitialAdmin{server: server}
}

// CreateInitialAdminInvitation puts the verified REST caller on the context
// the gRPC server reads its caller from, then runs the gRPC RPC.
func (a *tenantRESTInitialAdmin) CreateInitialAdminInvitation(
	ctx context.Context,
	caller *platformtoken.AuthorizedContext,
	req *platformv1.CreateInitialAdminInvitationRequest,
) (*platformv1.CreateInitialAdminInvitationResponse, error) {
	if caller != nil {
		ctx = grpcapi.ContextWithAuthorizedContext(ctx, caller)
	}
	return a.server.CreateInitialAdminInvitation(ctx, req)
}
