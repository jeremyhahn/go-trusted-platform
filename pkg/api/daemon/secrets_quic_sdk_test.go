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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// connectSecretsQUIC serves the gRPC SecretsServerAdapter over client through
// the daemon's QUIC handler, which authorizes each sub-opcode with the scope
// its gRPC method requires, and returns a SecretsManagement client on the
// SDK's QUIC adapter for a caller holding scopes.
func connectSecretsQUIC(t *testing.T, client quicbaas.SecretsClient, scopes ...string) pb.SecretsManagementClient {
	t.Helper()
	validator := &quicScopeValidator{scopes: scopes}
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	require.NoError(t, err)
	handler.SetSecretsService(NewSecretsServerAdapter(client, slog.Default()))
	bundle := testutil.GenerateTestTLSBundle(t)
	conn := newPhase35QUICClient(t, handler, bundle, platform.WithBearerToken("operator-token")).Connection()
	return pb.NewSecretsManagementClient(conn)
}

// TestSDKQUIC_SecretVersions drives the version, rotate, rollback and status
// methods through the SDK's QUIC adapter and the daemon's OpSecretsCategory
// handler into the same adapter the gRPC transport serves.
func TestSDKQUIC_SecretVersions(t *testing.T) {
	// The fake's answers (version 3 from rotate, 4 from rollback) prove the
	// call reached it; its recorded requests are read only by the in-process
	// tests, since the race detector cannot see ordering through the socket.
	secrets := connectSecretsQUIC(t, &versionSecretsClient{}, "secrets:read", "secrets:list", "secrets:write")
	ctx := context.Background()

	got, err := secrets.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{SecretId: "db/pw", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, []byte("v1-data"), got.GetData())
	assert.Equal(t, "ops", got.GetVersion().GetCreatedBy())

	list, err := secrets.ListSecretVersions(ctx, &pb.ListSecretVersionsRequest{SecretId: "db/pw"})
	require.NoError(t, err)
	require.Len(t, list.GetVersions(), 2)

	rotated, err := secrets.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("v3")})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), rotated.GetNewVersion())

	rolled, err := secrets.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: "db/pw", TargetVersion: 1})
	require.NoError(t, err)
	assert.Equal(t, uint64(4), rolled.GetNewVersion())

	updated, err := secrets.UpdateSecretStatus(ctx, &pb.UpdateSecretStatusRequest{
		SecretId: "db/pw", Status: pb.SecretStatus_SECRET_STATUS_DISABLED})
	require.NoError(t, err)
	assert.Equal(t, pb.SecretStatus_SECRET_STATUS_DISABLED, updated.GetStatus())
}

// TestSDKQUIC_SecretVersionsRefuse checks the QUIC path refuses a read-only
// caller's rotate and version list, a missing secret id and an SDK failure with the codes
// gRPC gives.
func TestSDKQUIC_SecretVersionsRefuse(t *testing.T) {
	ctx := context.Background()

	readOnly := connectSecretsQUIC(t, &versionSecretsClient{}, "secrets:read")
	_, err := readOnly.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("v3")})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "rotate needs secrets:write: %v", err)

	_, err = readOnly.ListSecretVersions(ctx, &pb.ListSecretVersionsRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "list versions needs secrets:list: %v", err)

	_, err = readOnly.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{Version: 1})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "missing secret id: %v", err)

	failing := connectSecretsQUIC(t, &extSecretsClientMock{}, "secrets:read", "secrets:list", "secrets:write")
	_, err = failing.ListSecretVersions(ctx, &pb.ListSecretVersionsRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.NotFound, status.Code(err), "SDK list failure: %v", err)
	_, err = failing.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: "db/pw", TargetVersion: 1})
	assert.Equal(t, codes.Internal, status.Code(err), "SDK rollback failure: %v", err)
}
