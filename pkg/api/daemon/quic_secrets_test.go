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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// mockSecretsQUICService implements SecretsServiceInterface with in-memory
// state for QUIC secrets category tests.
type mockSecretsQUICService struct {
	secrets     map[string][]byte
	policies    map[string]*pb.SecretRotationPolicy
	shouldErr   bool
	errToReturn error
}

var _ SecretsServiceInterface = (*mockSecretsQUICService)(nil)

func newMockSecretsQUICService() *mockSecretsQUICService {
	return &mockSecretsQUICService{
		secrets:  make(map[string][]byte),
		policies: make(map[string]*pb.SecretRotationPolicy),
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

// quicSecretsRequests is one request per secrets sub-operation.
func quicSecretsRequests(t *testing.T) map[string]*quicwire.Request {
	t.Helper()
	return map[string]*quicwire.Request{
		"Store": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubStore,
			&SecretsStoreRequest{SecretID: "db/password", Data: []byte("hunter2")}),
		"Get": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGet,
			&SecretsGetRequest{SecretID: "db/password"}),
		"List": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubList, nil),
		"Delete": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubDelete,
			&SecretsDeleteRequest{SecretID: "db/password"}),
		"SetRotationPolicy": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubSetRotationPolicy,
			&SecretsSetRotationPolicyRequest{SecretID: "db/password", Policy: &SecretsRotationPolicyPayload{Enabled: true}}),
		"GetRotationPolicy": kmsExtendedRequest(t, quicwire.OpSecretsCategory, quicwire.SecretsSubGetRotationPolicy,
			&SecretsGetRotationPolicyRequest{SecretID: "db/password"}),
	}
}

func newScopedQUICSecretsHandler() (*QUICServiceHandler, *countingSecretsClient) {
	adapter, client := newScopedSecretsAdapter()
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetSecretsService(adapter)
	return handler, client
}

func quicTenantContext(tenantID string) context.Context {
	return quic.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

func TestHandleSecretsCategory_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	handler, client := newScopedQUICSecretsHandler()
	for op, req := range quicSecretsRequests(t) {
		resp := handler.handleSecretsCategory(quicTenantContext("tenant-a"), req)
		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status, op)
	}
	assert.Zero(t, client.calls.Load(), "a tenant-bound QUIC caller reached the SDK")
}

func TestHandleSecretsCategory_SystemCallerReachesTheSDK(t *testing.T) {
	handler, client := newScopedQUICSecretsHandler()
	requests := quicSecretsRequests(t)
	for op, req := range requests {
		resp := handler.handleSecretsCategory(quicTenantContext("platform"), req)
		assert.Equal(t, quicwire.StatusOK, resp.Status, op)
	}
	assert.Equal(t, int32(len(requests)), client.calls.Load())
}
