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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newKMSExtendedTestHandler builds a QUIC handler with a seeded mock KMS
// service for KMS extended category tests.
func newKMSExtendedTestHandler() (*QUICServiceHandler, *mockKMSService) {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	svc := newMockKMSService()
	svc.keys["key-1"] = &pb.KeyHandle{
		KeyId:     "key-1",
		Version:   1,
		Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
	}
	svc.metadata["key-1"] = &pb.KeyMetadata{
		KeyId:     "key-1",
		Name:      "test-key",
		Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
	}
	handler.SetKMSService(svc)
	return handler, svc
}

// kmsExtendedRequest builds a category request with sub-opcode and payload.
func kmsExtendedRequest(t *testing.T, opcode byte, sub byte, body interface{}) *quicwire.Request {
	t.Helper()
	var payload []byte
	if body != nil {
		encoded, err := quicwire.EncodePayload(body)
		require.NoError(t, err)
		payload = encoded
	}
	return &quicwire.Request{
		Opcode:  opcode,
		Payload: append([]byte{sub}, payload...),
	}
}

func TestHandleKMSExtendedCategoryRevokeKey(t *testing.T) {
	handler, svc := newKMSExtendedTestHandler()
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubRevokeKey,
			&KMSRevokeKeyRequest{KeyID: "key-1", Reason: "compromised"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSRevokeKeyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "key-1", out.KeyID)
		assert.Equal(t, "KEY_STATUS_DISABLED", out.Status)
		assert.Equal(t, "RevokeKey", svc.lastOperation)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubRevokeKey,
			&KMSRevokeKeyRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("BackendError", func(t *testing.T) {
		svc.shouldErr = true
		svc.errToReturn = errors.New("backend down")
		defer func() { svc.shouldErr = false }()

		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubRevokeKey,
			&KMSRevokeKeyRequest{KeyID: "key-1"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestHandleKMSExtendedCategoryMetadata(t *testing.T) {
	handler, svc := newKMSExtendedTestHandler()
	ctx := context.Background()

	t.Run("GetSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetKeyMetadata,
			&KMSGetKeyMetadataRequest{KeyID: "key-1"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSGetKeyMetadataResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.Metadata)
		assert.Equal(t, "key-1", out.Metadata.KeyId)
		assert.Equal(t, "test-key", out.Metadata.Name)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetKeyMetadata,
			&KMSGetKeyMetadataRequest{KeyID: "missing"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("UpdateSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubUpdateKeyMetadata,
			&KMSUpdateKeyMetadataRequest{KeyID: "key-1", Name: "renamed"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSUpdateKeyMetadataResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.Metadata)
		assert.Equal(t, "renamed", out.Metadata.Name)
		assert.Equal(t, "UpdateKeyMetadata", svc.lastOperation)
	})

	t.Run("UpdateMissingKeyID", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubUpdateKeyMetadata,
			&KMSUpdateKeyMetadataRequest{Name: "renamed"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSExtendedCategoryPolicy(t *testing.T) {
	handler, svc := newKMSExtendedTestHandler()
	ctx := context.Background()

	t.Run("SetSuccess", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubSetKeyPolicy,
			&KMSSetKeyPolicyRequest{
				KeyID: "key-1",
				Policy: &KMSKeyPolicyPayload{
					KeyID:             "key-1",
					Version:           1,
					AllowedOperations: []string{"ENCRYPT", "DECRYPT"},
					AllowedPrincipals: []string{"user:alice"},
					RequireMFA:        true,
				},
			})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSSetKeyPolicyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "key-1", out.KeyID)
		assert.Equal(t, uint64(1), out.PolicyVersion)

		stored := svc.policies["key-1"]
		require.NotNil(t, stored)
		assert.Equal(t, []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_DECRYPT}, stored.AllowedOperations)
		assert.True(t, stored.RequireMfa)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		svc.policies["key-1"] = &pb.KeyPolicy{
			KeyId:             "key-1",
			Version:           4,
			AllowedOperations: []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN},
			AllowedPrincipals: []string{"role:admin"},
			ExpiresAt:         time.Now().Add(time.Hour).Unix(),
		}
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetKeyPolicy,
			&KMSGetKeyPolicyRequest{KeyID: "key-1"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSGetKeyPolicyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.Policy)
		assert.Equal(t, "key-1", out.Policy.KeyID)
		assert.Equal(t, uint64(4), out.Policy.Version)
		assert.Equal(t, []string{"KEY_USAGE_SIGN"}, out.Policy.AllowedOperations)
	})

	t.Run("SetMissingPolicy", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubSetKeyPolicy,
			&KMSSetKeyPolicyRequest{KeyID: "key-1"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetKeyPolicy,
			&KMSGetKeyPolicyRequest{KeyID: "missing"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

func TestHandleKMSExtendedCategoryAlgorithmsAndDispatch(t *testing.T) {
	handler, svc := newKMSExtendedTestHandler()
	ctx := context.Background()

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetSupportedAlgorithms, nil)
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSGetSupportedAlgorithmsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Contains(t, out.Algorithms, "AES-256-GCM")
	})

	t.Run("SupportedAlgorithmsError", func(t *testing.T) {
		svc.shouldErr = true
		svc.errToReturn = errors.New("backend down")
		defer func() { svc.shouldErr = false }()

		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetSupportedAlgorithms, nil)
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("UnknownSubOpcode", func(t *testing.T) {
		// The authorization guard refuses an unclassified sub-opcode before
		// dispatch; the category handler still rejects it on its own.
		req := &quicwire.Request{Opcode: quicwire.OpKMSExtendedCategory, Payload: []byte{0xEE}}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
		resp = handler.handleKMSExtendedCategory(ctx, req)
		assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		req := &quicwire.Request{Opcode: quicwire.OpKMSExtendedCategory}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger())
		req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubRevokeKey,
			&KMSRevokeKeyRequest{KeyID: "key-1"})
		resp := bare.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

func TestHandleKMSBackendStatusDelegatesToService(t *testing.T) {
	handler, svc := newKMSExtendedTestHandler()
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpKMSBackendStatus})
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out KMSBackendStatusResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "quicbaas", out.BackendType)
		assert.Equal(t, "healthy", out.BackendStatus)
		assert.Equal(t, "BackendStatus", svc.lastOperation)
	})

	t.Run("BackendError", func(t *testing.T) {
		svc.shouldErr = true
		svc.errToReturn = errors.New("backend down")
		defer func() { svc.shouldErr = false }()

		resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpKMSBackendStatus})
		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
