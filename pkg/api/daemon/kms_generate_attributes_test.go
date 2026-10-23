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
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingKMSOwner is the owner the recording KMS stamps on every key, as
// the KMS records the caller rather than a requested owner.
const recordingKMSOwner = "kms-recorded-owner"

// newRecordingKMSClient returns a KMS client that keeps what generate and
// metadata update record, the way the KMS does, and refuses to delete a
// deletion-protected key. updates counts the metadata updates it served.
func newRecordingKMSClient(updates *int) *platformMockKMSClient {
	keys := map[string]*kms.KeyMetadataResponse{}
	lookup := func(keyID string) (*kms.KeyMetadataResponse, error) {
		meta, ok := keys[keyID]
		if !ok {
			return nil, sdkerrors.NewNotFound("kms.GetKeyMetadata", "no key "+keyID)
		}
		copied := *meta
		return &copied, nil
	}
	return &platformMockKMSClient{
		generateKeyFn: func(_ context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
			keys[req.Name] = &kms.KeyMetadataResponse{
				KeyID:              req.Name,
				Algorithm:          req.Algorithm,
				Status:             kms.KeyStatusEnabled,
				Usage:              req.Usage,
				Version:            1,
				Exportable:         req.Exportable,
				DeletionProtection: req.DeletionProtection,
				Owner:              recordingKMSOwner,
			}
			return &kms.GenerateKeyResponse{
				KeyID:              req.Name,
				Version:            1,
				Algorithm:          req.Algorithm,
				Exportable:         req.Exportable,
				DeletionProtection: req.DeletionProtection,
			}, nil
		},
		getKeyMetadataFn: func(_ context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
			return lookup(keyID)
		},
		updateKeyMetadataFn: func(_ context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
			meta, ok := keys[req.KeyID]
			if !ok {
				return nil, sdkerrors.NewNotFound("kms.UpdateKeyMetadata", "no key "+req.KeyID)
			}
			*updates++
			if req.Name != "" {
				meta.Name = req.Name
			}
			if req.Description != "" {
				meta.Description = req.Description
			}
			if len(req.Tags) > 0 {
				meta.Tags = req.Tags
			}
			return lookup(req.KeyID)
		},
		deleteKeyFn: func(_ context.Context, keyID string) error {
			meta, ok := keys[keyID]
			if !ok {
				return sdkerrors.NewNotFound("kms.DeleteKey", "no key "+keyID)
			}
			if meta.DeletionProtection {
				return sdkerrors.NewPreconditionFailed("kms.DeleteKey", "key "+keyID+" is deletion-protected")
			}
			delete(keys, keyID)
			return nil
		},
	}
}

func TestKMSServerAdapterGenerateKeyAttributes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("every attribute round-trips into the returned metadata", func(t *testing.T) {
		t.Parallel()
		var updates int
		adapter := NewKMSServerAdapter(newRecordingKMSClient(&updates), slog.Default())

		resp, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec: &pb.KeySpec{
				Algorithm:          pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
				Usage:              []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT},
				Exportable:         true,
				DeletionProtection: true,
			},
			Name:        "tenant-a-kek",
			Description: "tenant A key-encryption key",
			Tags:        map[string]string{"env": "prod"},
			Owner:       "requested-owner",
		})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if resp.GetKey().GetKeyId() != "tenant-a-kek" || resp.GetKey().GetVersion() != 1 {
			t.Errorf("key handle = %+v, want tenant-a-kek v1", resp.GetKey())
		}
		if resp.GetKey().GetAlgorithm() != pb.KeyAlgorithm_KEY_ALG_AES_256_GCM {
			t.Errorf("key handle algorithm = %v", resp.GetKey().GetAlgorithm())
		}
		meta := resp.GetMetadata()
		if meta == nil {
			t.Fatal("GenerateKey returned no metadata")
		}
		if !meta.GetExportable() || !meta.GetDeletionProtection() {
			t.Errorf("exportable=%t deletion_protection=%t, want both true", meta.GetExportable(), meta.GetDeletionProtection())
		}
		if meta.GetDescription() != "tenant A key-encryption key" || meta.GetTags()["env"] != "prod" {
			t.Errorf("description=%q tags=%v not recorded", meta.GetDescription(), meta.GetTags())
		}
		if meta.GetOwner() != recordingKMSOwner {
			t.Errorf("owner = %q, want the KMS-recorded %q", meta.GetOwner(), recordingKMSOwner)
		}
		if updates != 1 {
			t.Errorf("metadata updates = %d, want 1", updates)
		}
	})

	t.Run("without description or tags the metadata is read back, not updated", func(t *testing.T) {
		t.Parallel()
		var updates int
		adapter := NewKMSServerAdapter(newRecordingKMSClient(&updates), slog.Default())

		resp, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec: &pb.KeySpec{Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
			Name:    "plain-key",
		})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if resp.GetMetadata().GetKeyId() != "plain-key" || resp.GetMetadata().GetExportable() {
			t.Errorf("metadata = %+v, want plain-key, not exportable", resp.GetMetadata())
		}
		if updates != 0 {
			t.Errorf("metadata updates = %d, want 0", updates)
		}
	})

	t.Run("deletion protection refuses a delete", func(t *testing.T) {
		t.Parallel()
		var updates int
		adapter := NewKMSServerAdapter(newRecordingKMSClient(&updates), slog.Default())

		if _, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec: &pb.KeySpec{Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, DeletionProtection: true},
			Name:    "protected-key",
		}); err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		_, err := adapter.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: "protected-key"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("DeleteKey of a protected key: code %v (%v), want FailedPrecondition", status.Code(err), err)
		}
	})

	t.Run("a metadata failure after generate is classed by its cause", func(t *testing.T) {
		t.Parallel()
		client := &platformMockKMSClient{
			getKeyMetadataFn: func(context.Context, string) (*kms.KeyMetadataResponse, error) {
				return nil, sdkerrors.NewUnavailable("kms.GetKeyMetadata", "backend down")
			},
		}
		adapter := NewKMSServerAdapter(client, slog.Default())

		_, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec: &pb.KeySpec{Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
			Name:    "k",
		})
		var metaErr ErrKMSGeneratedKeyMetadata
		if !errors.As(err, &metaErr) || metaErr.KeyID != "key-1" {
			t.Fatalf("err = %v, want ErrKMSGeneratedKeyMetadata for key-1", err)
		}
		if status.Code(err) != codes.Unavailable {
			t.Errorf("code = %v, want Unavailable", status.Code(err))
		}
	})

	t.Run("a metadata update failure is surfaced", func(t *testing.T) {
		t.Parallel()
		// The default mock UpdateKeyMetadata fails.
		adapter := NewKMSServerAdapter(&platformMockKMSClient{}, slog.Default())

		_, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec:     &pb.KeySpec{Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
			Name:        "k",
			Description: "d",
		})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("err = %v, want the update failure", err)
		}
	})

	t.Run("no metadata from the KMS is an internal error", func(t *testing.T) {
		t.Parallel()
		client := &platformMockKMSClient{
			getKeyMetadataFn: func(context.Context, string) (*kms.KeyMetadataResponse, error) {
				return nil, nil
			},
		}
		adapter := NewKMSServerAdapter(client, slog.Default())

		_, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{
			KeySpec: &pb.KeySpec{Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
			Name:    "k",
		})
		if !errors.As(err, new(ErrKMSNilMetadata)) || status.Code(err) != codes.Internal {
			t.Fatalf("err = %v (code %v), want ErrKMSNilMetadata, Internal", err, status.Code(err))
		}
	})
}

func TestPlatformKMSBackendGenerateKeyAttributes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("every attribute round-trips into the returned metadata", func(t *testing.T) {
		t.Parallel()
		var updates int
		backend := newTestPlatformKMSBackend(newRecordingKMSClient(&updates), &platformMockCryptoClient{})

		resp, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{
				Algorithm:          int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				Usage:              []int32{int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT)},
				Exportable:         true,
				DeletionProtection: true,
			},
			Name:        "tenant-b-kek",
			Description: "tenant B key-encryption key",
			Tags:        map[string]string{"team": "crypto"},
			Owner:       "requested-owner",
		})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		meta := resp.Metadata
		if resp.Key.KeyID != "tenant-b-kek" || meta.KeyID != "tenant-b-kek" {
			t.Errorf("key = %+v metadata key = %q, want tenant-b-kek", resp.Key, meta.KeyID)
		}
		if !meta.Exportable || !meta.DeletionProtection {
			t.Errorf("exportable=%t deletion_protection=%t, want both true", meta.Exportable, meta.DeletionProtection)
		}
		if meta.Description != "tenant B key-encryption key" || meta.Tags["team"] != "crypto" {
			t.Errorf("description=%q tags=%v not recorded", meta.Description, meta.Tags)
		}
		if meta.Owner != recordingKMSOwner {
			t.Errorf("owner = %q, want the KMS-recorded %q", meta.Owner, recordingKMSOwner)
		}
		if resp.Key.Status != int32(platformv1.KeyStatus_KEY_STATUS_ENABLED) {
			t.Errorf("key status = %d, want enabled", resp.Key.Status)
		}
		if updates != 1 {
			t.Errorf("metadata updates = %d, want 1", updates)
		}
	})

	t.Run("deletion protection refuses a delete", func(t *testing.T) {
		t.Parallel()
		var updates int
		backend := newTestPlatformKMSBackend(newRecordingKMSClient(&updates), &platformMockCryptoClient{})

		if _, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{
				Algorithm:          int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				DeletionProtection: true,
			},
			Name: "protected-key",
		}); err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		_, err := backend.DeleteKey(ctx, &grpcapi.KMSDeleteKeyRequest{KeyID: "protected-key"})
		if !sdkerrors.IsClientError(err) || sdkerrors.Code(err) != sdkerrors.CodePreconditionFailed {
			t.Fatalf("DeleteKey of a protected key: %v, want PreconditionFailed", err)
		}
	})

	t.Run("a metadata failure after generate is surfaced", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			getKeyMetadataFn: func(context.Context, string) (*kms.KeyMetadataResponse, error) {
				return nil, sdkerrors.NewNotFound("kms.GetKeyMetadata", "gone")
			},
		}, &platformMockCryptoClient{})

		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256)},
			Name:    "k",
		})
		if !errors.As(err, new(ErrKMSGeneratedKeyMetadata)) || status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v (code %v), want ErrKMSGeneratedKeyMetadata, NotFound", err, status.Code(err))
		}
	})
}
