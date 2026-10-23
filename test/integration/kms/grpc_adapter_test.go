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

//go:build integration

package kms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

// The gRPC adapter names statuses and hashes the way the Unix, REST and QUIC
// adapters do (upper case, no dash in SHA-2 names); the multi-protocol suite
// compares them across transports.

func TestStatusProtoToString(t *testing.T) {
	tests := map[pb.KeyStatus]string{
		pb.KeyStatus_KEY_STATUS_ENABLED:          "ENABLED",
		pb.KeyStatus_KEY_STATUS_DISABLED:         "DISABLED",
		pb.KeyStatus_KEY_STATUS_PENDING_DELETION: "PENDING_DELETION",
		pb.KeyStatus_KEY_STATUS_COMPROMISED:      "COMPROMISED",
	}
	for status, want := range tests {
		assert.Equal(t, want, statusProtoToString(status))
	}
}

func TestStatusProtoToString_Unknown(t *testing.T) {
	assert.Equal(t, "UNSPECIFIED", statusProtoToString(pb.KeyStatus(99)))
}

func TestHashAlgorithmProtoToString(t *testing.T) {
	tests := map[pb.HashAlgorithm]string{
		pb.HashAlgorithm_HASH_ALG_SHA256:   "SHA256",
		pb.HashAlgorithm_HASH_ALG_SHA384:   "SHA384",
		pb.HashAlgorithm_HASH_ALG_SHA512:   "SHA512",
		pb.HashAlgorithm_HASH_ALG_SHA3_256: "SHA3-256",
	}
	for alg, want := range tests {
		assert.Equal(t, want, hashAlgorithmProtoToString(alg))
		assert.Equal(t, alg, hashAlgorithmStringToProto(want), "the name must round-trip")
	}
}

func TestHashAlgorithmProtoToString_Unknown(t *testing.T) {
	assert.Equal(t, "UNSPECIFIED", hashAlgorithmProtoToString(pb.HashAlgorithm(99)))
	assert.Equal(t, pb.HashAlgorithm_HASH_ALG_UNSPECIFIED, hashAlgorithmStringToProto("MD5"))
}

func TestErrGRPCMissingInResponse(t *testing.T) {
	err := error(ErrGRPCMissingInResponse{Method: "GetKeyMetadata", Field: "metadata"})
	assert.Equal(t, "gRPC GetKeyMetadata response carries no metadata", err.Error())
}

// emptyKMSClient answers every call it overrides with a successful,
// empty response: the shape a server that omits a message would send.
type emptyKMSClient struct {
	pb.KeyManagementClient
}

func (emptyKMSClient) GenerateKey(context.Context, *pb.GenerateKeyRequest, ...grpc.CallOption) (*pb.GenerateKeyResponse, error) {
	return &pb.GenerateKeyResponse{}, nil
}

func (emptyKMSClient) GetKey(context.Context, *pb.GetKeyRequest, ...grpc.CallOption) (*pb.GetKeyResponse, error) {
	return &pb.GetKeyResponse{}, nil
}

func (emptyKMSClient) GetKeyMetadata(context.Context, *pb.GetKeyMetadataRequest, ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error) {
	return &pb.GetKeyMetadataResponse{}, nil
}

func (emptyKMSClient) UpdateKeyMetadata(context.Context, *pb.UpdateKeyMetadataRequest, ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error) {
	return &pb.UpdateKeyMetadataResponse{}, nil
}

func (emptyKMSClient) GetKeyPolicy(context.Context, *pb.GetKeyPolicyRequest, ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error) {
	return &pb.GetKeyPolicyResponse{}, nil
}

type emptySecretsClient struct {
	pb.SecretsManagementClient
}

func (emptySecretsClient) GetSecretVersion(context.Context, *pb.GetSecretVersionRequest, ...grpc.CallOption) (*pb.GetSecretVersionResponse, error) {
	return &pb.GetSecretVersionResponse{}, nil
}

// TestGRPCAdapter_EmptyResponses: a response that omits the message the
// adapter reads is a typed error naming the method, never a nil-pointer
// panic that takes the whole suite down.
func TestGRPCAdapter_EmptyResponses(t *testing.T) {
	ctx := context.Background()
	g := &GRPCAdapter{kms: emptyKMSClient{}, secrets: emptySecretsClient{}}

	calls := map[string]func() error{
		"GenerateKey": func() error {
			_, err := g.KeyGenerate(ctx, KeyGenerateOptions{Name: "k"})
			return err
		},
		"GetKey": func() error {
			_, err := g.KeyGet(ctx, "k", 0)
			return err
		},
		"GetKeyMetadata": func() error {
			_, err := g.KeyMetadata(ctx, "k")
			return err
		},
		"UpdateKeyMetadata": func() error {
			_, err := g.KeyMetadataUpdate(ctx, "k", KeyMetadataUpdateOptions{})
			return err
		},
		"GetKeyPolicy": func() error {
			_, err := g.KeyPolicy(ctx, "k")
			return err
		},
		"GetSecretVersion": func() error {
			_, err := g.SecretsVersion(ctx, "s", 1)
			return err
		},
	}
	for method, call := range calls {
		var missing ErrGRPCMissingInResponse
		require.ErrorAs(t, call(), &missing, method)
		assert.Equal(t, method, missing.Method)
	}
}
