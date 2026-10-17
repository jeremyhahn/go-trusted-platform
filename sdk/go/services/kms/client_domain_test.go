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

package kms

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errGenerateRefused is the failure generateKeyRecorder answers with.
var errGenerateRefused = errors.New("generate refused")

// generateKeyRecorder records the GenerateKey request it receives.
type generateKeyRecorder struct {
	platformv1.KeyManagementServiceClient
	got *platformv1.GenerateKeyRequest
	err error
}

func (r *generateKeyRecorder) GenerateKey(_ context.Context, req *platformv1.GenerateKeyRequest, _ ...grpc.CallOption) (*platformv1.GenerateKeyResponse, error) {
	r.got = req
	if r.err != nil {
		return nil, r.err
	}
	return &platformv1.GenerateKeyResponse{Key: &platformv1.KMSKeyHandle{KeyId: req.GetName(), Version: 1}}, nil
}

// TestGenerateKeyDomain_NameIsTheKeyID proves the request's name is the
// key ID, not the display name: the server keys the new key on that name
// (docs/kms/api.md §2), so sending the display name created a key nobody
// could address by its ID.
func TestGenerateKeyDomain_NameIsTheKeyID(t *testing.T) {
	recorder := &generateKeyRecorder{}
	client := NewClientFromGRPC(recorder)

	result, err := client.GenerateKeyDomain(context.Background(), &GenerateKeyParams{
		KeyID:       "tenant-a-kek",
		Algorithm:   KeyAlgorithmAES256,
		Usages:      []KeyUsage{KeyUsageEncrypt},
		Name:        "Tenant A KEK",
		Description: "tenant A key encryption key",
	})
	if err != nil {
		t.Fatalf("GenerateKeyDomain: %v", err)
	}
	if recorder.got.GetName() != "tenant-a-kek" {
		t.Fatalf("request name = %q, want the key ID %q", recorder.got.GetName(), "tenant-a-kek")
	}
	if result.Key.KeyID != "tenant-a-kek" {
		t.Fatalf("key ID = %q, want %q", result.Key.KeyID, "tenant-a-kek")
	}
}

func TestGenerateKeyDomain_ServerError(t *testing.T) {
	client := NewClientFromGRPC(&generateKeyRecorder{err: errGenerateRefused})

	_, err := client.GenerateKeyDomain(context.Background(), &GenerateKeyParams{KeyID: "k"})
	var failed *ErrGenerateKeyFailed
	if !errors.As(err, &failed) || !errors.Is(err, errGenerateRefused) {
		t.Fatalf("err = %v, want ErrGenerateKeyFailed wrapping the server error", err)
	}
}
