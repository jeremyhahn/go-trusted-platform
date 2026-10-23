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

//go:build codec_msgpack

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// mockSecretsQUICService implements SecretsServiceInterface with in-memory
// state for QUIC secrets category tests.
type mockSecretsQUICService struct {
	// The version, rotate, rollback and status calls go to the real gRPC
	// adapter over a fake SDK secrets client, as the daemon wires them.
	*SecretsServerAdapter
	versions    *versionSecretsClient
	secrets     map[string][]byte
	policies    map[string]*pb.SecretRotationPolicy
	shouldErr   bool
	errToReturn error
}

var _ SecretsServiceInterface = (*mockSecretsQUICService)(nil)

func newMockSecretsQUICService() *mockSecretsQUICService {
	versions := &versionSecretsClient{}
	return &mockSecretsQUICService{
		SecretsServerAdapter: NewSecretsServerAdapter(versions, slog.Default()),
		versions:             versions,
		secrets:              make(map[string][]byte),
		policies:             make(map[string]*pb.SecretRotationPolicy),
	}
}

func (m *mockSecretsQUICService) StoreSecret(ctx context.Context, req *pb.StoreSecretRequest) (*pb.StoreSecretResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.secrets[req.SecretId] = req.Data
	return &pb.StoreSecretResponse{SecretId: req.SecretId, Version: 1, Timestamp: time.Now().Unix()}, nil
}

func (m *mockSecretsQUICService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	data, ok := m.secrets[req.SecretId]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &pb.GetSecretResponse{SecretId: req.SecretId, Version: 1, Data: data}, nil
}

func (m *mockSecretsQUICService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	resp := &pb.ListSecretsResponse{}
	for id := range m.secrets {
		resp.Secrets = append(resp.Secrets, &pb.Secret{SecretId: id})
	}
	return resp, nil
}

func (m *mockSecretsQUICService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	delete(m.secrets, req.SecretId)
	return &pb.DeleteSecretResponse{SecretId: req.SecretId, Deleted: true}, nil
}

func (m *mockSecretsQUICService) SetRotationPolicy(ctx context.Context, req *pb.SetRotationPolicyRequest) (*pb.SetRotationPolicyResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.policies[req.SecretId] = req.Policy
	return &pb.SetRotationPolicyResponse{SecretId: req.SecretId, Policy: req.Policy, Timestamp: time.Now().Unix()}, nil
}

func (m *mockSecretsQUICService) GetRotationPolicy(ctx context.Context, req *pb.GetRotationPolicyRequest) (*pb.GetRotationPolicyResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	policy, ok := m.policies[req.SecretId]
	if !ok {
		return nil, errors.New("policy not found")
	}
	return &pb.GetRotationPolicyResponse{SecretId: req.SecretId, Policy: policy}, nil
}

// newSecretsTestHandler builds a QUIC handler wired with the secrets mock.
func newSecretsTestHandler() (*QUICServiceHandler, *mockSecretsQUICService) {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	svc := newMockSecretsQUICService()
	handler.SetSecretsService(svc)
	return handler, svc
}

func TestHandleSecretsCategoryStoreGetDelete(t *testing.T) {
	handler, svc := newSecretsTestHandler()
	ctx := context.Background()

	t.Run("StoreSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubStore,
			&SecretsStoreRequest{SecretID: "db/password", Data: []byte("hunter2")})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsStoreResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "db/password", out.SecretID)
		assert.Equal(t, uint64(1), out.Version)
	})

	t.Run("StoreMissingData", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubStore,
			&SecretsStoreRequest{SecretID: "db/password"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGet,
			&SecretsGetRequest{SecretID: "db/password"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsGetResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, []byte("hunter2"), out.Data)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGet,
			&SecretsGetRequest{SecretID: "missing"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("ListSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubList, nil)
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsListResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Contains(t, out.SecretIDs, "db/password")
	})

	t.Run("DeleteSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubDelete,
			&SecretsDeleteRequest{SecretID: "db/password"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsDeleteResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.True(t, out.Deleted)
		assert.NotContains(t, svc.secrets, "db/password")
	})

	t.Run("DeleteMissingSecretID", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubDelete,
			&SecretsDeleteRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleSecretsCategoryRotationPolicy(t *testing.T) {
	handler, svc := newSecretsTestHandler()
	ctx := context.Background()

	t.Run("SetSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubSetRotationPolicy,
			&SecretsSetRotationPolicyRequest{
				SecretID: "db/password",
				Policy: &SecretsRotationPolicyPayload{
					Enabled:         true,
					IntervalSeconds: 3600,
					RetainVersions:  7,
				},
			})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsSetRotationPolicyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.Policy)
		assert.True(t, out.Policy.Enabled)
		assert.Equal(t, int32(7), out.Policy.RetainVersions)

		stored := svc.policies["db/password"]
		require.NotNil(t, stored)
		assert.Equal(t, int32(7), stored.RetainVersions)
		assert.Equal(t, int64(3600), stored.IntervalSeconds)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGetRotationPolicy,
			&SecretsGetRotationPolicyRequest{SecretID: "db/password"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out SecretsGetRotationPolicyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.Policy)
		assert.Equal(t, int32(7), out.Policy.RetainVersions)
	})

	t.Run("SetMissingPolicy", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubSetRotationPolicy,
			&SecretsSetRotationPolicyRequest{SecretID: "db/password"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGetRotationPolicy,
			&SecretsGetRotationPolicyRequest{SecretID: "missing"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

func TestHandleSecretsCategoryDispatch(t *testing.T) {
	handler, svc := newSecretsTestHandler()
	ctx := context.Background()

	t.Run("UnknownSubOpcode", func(t *testing.T) {
		// The authorization guard refuses an unclassified sub-opcode before
		// dispatch; the category handler still rejects it on its own.
		req := &quicwire.Request{Opcode: quicwire.OpSecretsCategory, Payload: []byte{0xEE}}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
		resp = handler.handleSecretsCategory(ctx, req)
		assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpSecretsCategory})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger())
		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubList, nil)
		resp := bare.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("BackendError", func(t *testing.T) {
		svc.shouldErr = true
		svc.errToReturn = errors.New("backend down")
		defer func() { svc.shouldErr = false }()

		req := kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubList, nil)
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// secretsVersionsRequest builds a secrets sub-operation whose payload is the
// quicbaas.kms.v1 request message, as the SDK QUIC adapter sends it.
func secretsVersionsRequest(t *testing.T, sub byte, msg interface{}) *quicwire.Request {
	t.Helper()
	return kmsExtendedRequest(t, quicwire.OpSecretsCategory, sub, msg)
}

func TestHandleSecretsCategoryVersions(t *testing.T) {
	handler, svc := newSecretsTestHandler()
	ctx := context.Background()

	t.Run("GetVersion", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubGetVersion,
			&pb.GetSecretVersionRequest{SecretId: "db/pw", Version: 1}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.GetSecretVersionResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, []byte("v1-data"), out.GetData())
		assert.Equal(t, "ops", out.GetVersion().GetCreatedBy())
		assert.Equal(t, 1, svc.versions.lastGetVersion.Version)
	})

	t.Run("ListVersions", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubListVersions,
			&pb.ListSecretVersionsRequest{SecretId: "db/pw"}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.ListSecretVersionsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.Len(t, out.GetVersions(), 2)
		assert.Equal(t, uint64(2), out.GetVersions()[1].GetVersion())
	})

	t.Run("Rotate", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubRotate,
			&pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("v3"), Metadata: map[string]string{"by": "ops"}}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.RotateSecretResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, uint64(3), out.GetNewVersion())
		assert.Equal(t, []byte("v3"), svc.versions.lastRotate.NewData)
		assert.Equal(t, "ops", svc.versions.lastRotate.Metadata["by"])
	})

	t.Run("Rollback", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubRollback,
			&pb.RollbackSecretRequest{SecretId: "db/pw", TargetVersion: 1}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.RollbackSecretResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, uint64(4), out.GetNewVersion())
		assert.Equal(t, 1, svc.versions.lastRollback.TargetVersion)
	})

	t.Run("UpdateStatus", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubUpdateStatus,
			&pb.UpdateSecretStatusRequest{SecretId: "db/pw", Status: pb.SecretStatus_SECRET_STATUS_DISABLED}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.UpdateSecretStatusResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, pb.SecretStatus_SECRET_STATUS_DISABLED, out.GetStatus())
	})
}

// TestHandleSecretsCategoryVersionsErrors holds each QUIC sub-operation to
// the class the gRPC method answers for the same input.
func TestHandleSecretsCategoryVersionsErrors(t *testing.T) {
	ctx := context.Background()
	requests := map[string]struct {
		sub     byte
		valid   interface{}
		noID    interface{}
		failing byte
	}{
		"GetVersion": {quicwire.SecretsSubGetVersion,
			&pb.GetSecretVersionRequest{SecretId: "db/pw", Version: 1}, &pb.GetSecretVersionRequest{Version: 1}, quicwire.StatusNotFound},
		"ListVersions": {quicwire.SecretsSubListVersions,
			&pb.ListSecretVersionsRequest{SecretId: "db/pw"}, &pb.ListSecretVersionsRequest{}, quicwire.StatusNotFound},
		"Rotate": {quicwire.SecretsSubRotate,
			&pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("x")}, &pb.RotateSecretRequest{NewData: []byte("x")}, quicwire.StatusInternalError},
		"Rollback": {quicwire.SecretsSubRollback,
			&pb.RollbackSecretRequest{SecretId: "db/pw", TargetVersion: 1}, &pb.RollbackSecretRequest{TargetVersion: 1}, quicwire.StatusInternalError},
		"UpdateStatus": {quicwire.SecretsSubUpdateStatus,
			&pb.UpdateSecretStatusRequest{SecretId: "db/pw", Status: pb.SecretStatus_SECRET_STATUS_ENABLED},
			&pb.UpdateSecretStatusRequest{Status: pb.SecretStatus_SECRET_STATUS_ENABLED}, quicwire.StatusInternalError},
	}

	for name, tc := range requests {
		t.Run(name, func(t *testing.T) {
			handler, _ := newSecretsTestHandler()
			resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, tc.sub, tc.noID))
			assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "missing secret_id")

			resp = handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpSecretsCategory, Payload: []byte{tc.sub, 0xC1}})
			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "undecodable payload")

			// An SDK client that fails every call answers the gRPC class.
			failing := newTestQUICServiceHandler(logging.DefaultLogger())
			failing.SetSecretsService(NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default()))
			resp = failing.HandleRequest(ctx, secretsVersionsRequest(t, tc.sub, tc.valid))
			assert.Equal(t, tc.failing, resp.Status, "SDK failure")
		})
	}

	handler, _ := newSecretsTestHandler()
	resp := handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubRotate, &pb.RotateSecretRequest{SecretId: "db/pw"}))
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "rotate without new data")
	resp = handler.HandleRequest(ctx, secretsVersionsRequest(t, quicwire.SecretsSubUpdateStatus, &pb.UpdateSecretStatusRequest{SecretId: "db/pw"}))
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "unspecified status")
}
