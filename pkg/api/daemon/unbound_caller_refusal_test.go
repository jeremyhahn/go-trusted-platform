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

//go:build iam && codec_msgpack

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestUnboundCallerIsRefusedOnEveryTransport pins the #646 rule the test
// fixtures now honour by calling as a tenant-bound identity or the Unix-socket
// operator: a caller with neither is refused with PermissionDenied on an IAM,
// a VPN and an MCP path, and reaches no store.
func TestUnboundCallerIsRefusedOnEveryTransport(t *testing.T) {
	unbound := context.Background()

	t.Run("IAM over QUIC", func(t *testing.T) {
		handler := newTestQUICServiceHandler(logging.DefaultLogger())
		handler.SetIAMGRPCService(wiredIAMGRPCService(newMemIAM()))

		resp := handler.HandleRequest(unbound, iamDirectRequest(t, quicwire.OpIAMCheckPermission,
			&platformv1.CheckIAMPermissionRequest{TenantId: "acme", SubjectId: "s", Resource: "document://1", Action: "read"}))
		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status, "payload %q", resp.Payload)
	})

	t.Run("VPN over gRPC", func(t *testing.T) {
		server, _ := newVPNTestServer(t)
		_, err := server.ListPeers(unbound, &platformv1.ListVPNPeersRequest{TenantId: "acme"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err %v", err)
	})

	t.Run("IAM over MCP", func(t *testing.T) {
		registry := wiredIAMToolRegistry(newMemIAM())
		got, err := registry.ExecuteTool(unbound, "iam_get_user", map[string]interface{}{"tenant_id": "acme", "user_id": "alice"})
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err %v", err)
	})
}
