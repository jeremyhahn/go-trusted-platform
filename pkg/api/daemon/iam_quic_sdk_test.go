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
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestSDKQUIC_IAMGetUnknownUser: a GetUser for an id no user has crosses the
// platform ALPN handshake and the framing to the IAM handler, which answers
// NotFound on the response frame rather than a transport error.
func TestSDKQUIC_IAMGetUnknownUser(t *testing.T) {
	bundle := operatorTLSBundle(t)
	handler := newTestQUICServiceHandler(logging.DefaultLogger(), mtlsQUICAuth(t, bundle))
	handler.SetIAMGRPCService(wiredIAMGRPCService(newMemIAM()))
	conn := newPhase35QUICClient(t, handler, bundle).Connection()
	callerTenant := leafOf(t, bundle.ClientCert).Subject.Organization[0]

	err := conn.Invoke(context.Background(), platformv1.PlatformIAMService_GetUser_FullMethodName,
		&platformv1.GetIAMUserRequest{TenantId: callerTenant, UserId: "no-such-user"}, &platformv1.IAMUserResponse{})
	require.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
}
