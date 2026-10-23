package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeDEKClient records the requests the DEK adapter sends and answers with
// fixed DEK metadata, or with err when it is set.
type fakeDEKClient struct {
	err        error
	info       dekclient.DEKInfo
	lastCreate *dekclient.CreateDEKRequest
	lastList   *dekclient.ListDEKsRequest
	lastRotate *dekclient.RotateDEKRequest
	lastDelete *dekclient.DeleteDEKRequest
	lastPath   string
}

func (f *fakeDEKClient) CreateDEK(ctx context.Context, req *dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
	f.lastCreate = req
	if f.err != nil {
		return nil, f.err
	}
	info := f.info
	return &dekclient.CreateDEKResponse{DEK: &info}, nil
}

func (f *fakeDEKClient) GetDEK(ctx context.Context, path string) (*dekclient.DEKInfo, error) {
	f.lastPath = path
	if f.err != nil {
		return nil, f.err
	}
	info := f.info
	return &info, nil
}

func (f *fakeDEKClient) ListDEKs(ctx context.Context, req *dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
	f.lastList = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.ListDEKsResponse{DEKs: []dekclient.DEKInfo{f.info}, TotalCount: 1}, nil
}

func (f *fakeDEKClient) RotateDEK(ctx context.Context, req *dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error) {
	f.lastRotate = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.RotateDEKResponse{Path: req.Path, OldVersion: 1, NewVersion: 2}, nil
}

func (f *fakeDEKClient) DeleteDEK(ctx context.Context, req *dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error) {
	f.lastDelete = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.DeleteDEKResponse{Path: req.Path, Deleted: true}, nil
}

func (f *fakeDEKClient) GetDEKStatus(ctx context.Context, path string) (*dekclient.DEKStatusResponse, error) {
	f.lastPath = path
	if f.err != nil {
		return nil, f.err
	}
	info := f.info
	return &dekclient.DEKStatusResponse{
		DEK:                  &info,
		ReencryptionProgress: &dekclient.ReencryptionProgress{InProgress: true, TotalKeys: 10, ProcessedKeys: 4, FailedKeys: 1},
	}, nil
}

func (f *fakeDEKClient) SetDefaultDEK(ctx context.Context, path string) (*dekclient.SetDefaultDEKResponse, error) {
	return nil, errKMSLifecycleMock{method: "SetDefaultDEK"}
}

func (f *fakeDEKClient) SetDEKSafety(ctx context.Context, req *dekclient.SetDEKSafetyRequest) error {
	return errKMSLifecycleMock{method: "SetDEKSafety"}
}

func (f *fakeDEKClient) ClearDEKSafety(ctx context.Context, path string) error {
	return errKMSLifecycleMock{method: "ClearDEKSafety"}
}

func (f *fakeDEKClient) StartReencryption(ctx context.Context, req *dekclient.StartReencryptionRequest) (*dekclient.StartReencryptionResponse, error) {
	return nil, errKMSLifecycleMock{method: "StartReencryption"}
}

func (f *fakeDEKClient) GetReencryptionProgress(ctx context.Context, req *dekclient.GetReencryptionProgressRequest) (*dekclient.ReencryptionProgressResponse, error) {
	return nil, errKMSLifecycleMock{method: "GetReencryptionProgress"}
}

func testDEKInfo() dekclient.DEKInfo {
	return dekclient.DEKInfo{
		Path:          "tenants/a/dek",
		Algorithm:     "AES-256-GCM",
		Version:       3,
		Status:        "active",
		IsDefault:     true,
		CreatedAt:     time.Unix(1700000000, 0),
		UsageCount:    25,
		MaxUsageCount: 100,
		BytesUsed:     10,
		MaxBytesUsed:  20,
		Description:   "orders",
		BackendType:   "software",
	}
}

func TestDEKServerAdapter_DelegatesToDEKClient(t *testing.T) {
	ctx := context.Background()
	client := &fakeDEKClient{info: testDEKInfo()}
	adapter := NewDEKServerAdapter(client, slog.Default())

	created, err := adapter.CreateDEK(ctx, &pb.CreateDEKRequest{
		Path:          "tenants/a/dek",
		Algorithm:     pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305,
		Description:   "orders",
		MaxOperations: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, dekAlgorithmToPb(client.lastCreate.Algorithm))
	assert.Equal(t, uint64(100), client.lastCreate.MaxOperations)
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, created.GetDek().GetAlgorithm())
	assert.Equal(t, uint64(3), created.GetDek().GetVersion())
	assert.Equal(t, int64(1700000000), created.GetDek().GetCreatedAt())
	assert.Zero(t, created.GetDek().GetRotatedAt(), "zero time maps to 0")

	got, err := adapter.GetDEK(ctx, &pb.GetDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, "tenants/a/dek", client.lastPath)
	assert.True(t, got.GetDek().GetIsDefault())

	listed, err := adapter.ListDEKs(ctx, &pb.ListDEKsRequest{Prefix: "tenants/", Recursive: true, Limit: 5})
	require.NoError(t, err)
	assert.Equal(t, &dekclient.ListDEKsRequest{Prefix: "tenants/", Recursive: true, Limit: 5}, client.lastList)
	require.Len(t, listed.GetDeks(), 1)
	assert.Equal(t, int32(1), listed.GetTotalCount())

	rotated, err := adapter.RotateDEK(ctx, &pb.RotateDEKRequest{Path: "tenants/a/dek", Background: true})
	require.NoError(t, err)
	assert.True(t, client.lastRotate.Background)
	assert.Equal(t, uint64(1), rotated.GetOldVersion())
	assert.Equal(t, uint64(2), rotated.GetNewVersion())

	deleted, err := adapter.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: "tenants/a/dek", Force: true, MigrateTo: "tenants/b/dek"})
	require.NoError(t, err)
	assert.Equal(t, &dekclient.DeleteDEKRequest{Path: "tenants/a/dek", Force: true, MigrateTo: "tenants/b/dek"}, client.lastDelete)
	assert.True(t, deleted.GetDeleted())

	st, err := adapter.GetDEKStatus(ctx, &pb.GetDEKStatusRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.InDelta(t, 50.0, st.GetUsagePercent(), 0.001, "the byte limit (10/20) dominates the count limit (25/100)")
	assert.Equal(t, int32(4), st.GetReencryptionProgress().GetProcessedKeys())
	assert.True(t, st.GetReencryptionProgress().GetInProgress())
}

func TestDEKServerAdapter_Errors(t *testing.T) {
	ctx := context.Background()
	calls := map[string]func(a *DEKServerAdapter, path string) error{
		"CreateDEK": func(a *DEKServerAdapter, path string) error {
			_, err := a.CreateDEK(ctx, &pb.CreateDEKRequest{Path: path})
			return err
		},
		"GetDEK": func(a *DEKServerAdapter, path string) error {
			_, err := a.GetDEK(ctx, &pb.GetDEKRequest{Path: path})
			return err
		},
		"RotateDEK": func(a *DEKServerAdapter, path string) error {
			_, err := a.RotateDEK(ctx, &pb.RotateDEKRequest{Path: path})
			return err
		},
		"DeleteDEK": func(a *DEKServerAdapter, path string) error {
			_, err := a.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: path})
			return err
		},
		"GetDEKStatus": func(a *DEKServerAdapter, path string) error {
			_, err := a.GetDEKStatus(ctx, &pb.GetDEKStatusRequest{Path: path})
			return err
		},
	}
	failing := map[string]codes.Code{
		"CreateDEK":    codes.Internal,
		"GetDEK":       codes.NotFound,
		"RotateDEK":    codes.Internal,
		"DeleteDEK":    codes.Internal,
		"GetDEKStatus": codes.NotFound,
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			unavailable := NewDEKServerAdapter(nil, slog.Default())
			assert.Equal(t, codes.Unavailable, status.Code(call(unavailable, "p")))

			client := &fakeDEKClient{info: testDEKInfo()}
			adapter := NewDEKServerAdapter(client, slog.Default())
			assert.Equal(t, codes.InvalidArgument, status.Code(call(adapter, "")))

			client.err = errKMSLifecycleMock{method: name}
			assert.Equal(t, failing[name], status.Code(call(adapter, "p")))
		})
	}

	t.Run("ListDEKs", func(t *testing.T) {
		_, err := NewDEKServerAdapter(nil, slog.Default()).ListDEKs(ctx, &pb.ListDEKsRequest{})
		assert.Equal(t, codes.Unavailable, status.Code(err))

		client := &fakeDEKClient{err: errKMSLifecycleMock{method: "ListDEKs"}}
		_, err = NewDEKServerAdapter(client, slog.Default()).ListDEKs(ctx, &pb.ListDEKsRequest{})
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestDEKAlgorithmToPb(t *testing.T) {
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, dekAlgorithmToPb("aes-256-gcm"))
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, dekAlgorithmToPb("ChaCha20-Poly1305"))
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, dekAlgorithmToPb("rot13"))
}

func TestDEKUsagePercent_NoLimits(t *testing.T) {
	assert.Zero(t, dekUsagePercent(&dekclient.DEKInfo{UsageCount: 99, BytesUsed: 99}))
}

// versionSecretsClient answers the secret version, rotate, rollback and
// status calls; every other method fails through extSecretsClientMock.
type versionSecretsClient struct {
	extSecretsClientMock
	lastGetVersion *secretsclient.GetSecretVersionRequest
	lastRotate     *secretsclient.RotateSecretRequest
	lastRollback   *secretsclient.RollbackSecretRequest
	lastStatus     *secretsclient.UpdateSecretStatusRequest
}

func (c *versionSecretsClient) GetVersion(ctx context.Context, req *secretsclient.GetSecretVersionRequest) (*secretsclient.SecretVersionInfo, error) {
	c.lastGetVersion = req
	return &secretsclient.SecretVersionInfo{SecretID: req.SecretID, Version: req.Version, Data: []byte("v1-data"), CreatedBy: "ops"}, nil
}

func (c *versionSecretsClient) ListVersions(ctx context.Context, secretID string) (*secretsclient.ListSecretVersionsResponse, error) {
	return &secretsclient.ListSecretVersionsResponse{Versions: []secretsclient.SecretVersionInfo{
		{SecretID: secretID, Version: 1, Data: []byte("v1-data")},
		{SecretID: secretID, Version: 2, Data: []byte("v2-data")},
	}}, nil
}

func (c *versionSecretsClient) Rotate(ctx context.Context, req *secretsclient.RotateSecretRequest) (*secretsclient.RotateSecretResponse, error) {
	c.lastRotate = req
	return &secretsclient.RotateSecretResponse{SecretID: req.SecretID, OldVersion: 2, NewVersion: 3}, nil
}

func (c *versionSecretsClient) Rollback(ctx context.Context, req *secretsclient.RollbackSecretRequest) (*secretsclient.RollbackSecretResponse, error) {
	c.lastRollback = req
	return &secretsclient.RollbackSecretResponse{SecretID: req.SecretID, NewVersion: 4}, nil
}

func (c *versionSecretsClient) UpdateStatus(ctx context.Context, req *secretsclient.UpdateSecretStatusRequest) error {
	c.lastStatus = req
	return nil
}

func TestSecretsServerAdapter_VersionsDelegateToSecretsClient(t *testing.T) {
	ctx := context.Background()
	client := &versionSecretsClient{}
	adapter := NewSecretsServerAdapter(client, slog.Default())

	got, err := adapter.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{SecretId: "db/pw", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, &secretsclient.GetSecretVersionRequest{SecretID: "db/pw", Version: 1}, client.lastGetVersion)
	assert.Equal(t, []byte("v1-data"), got.GetData())
	assert.Equal(t, "ops", got.GetVersion().GetCreatedBy())

	listed, err := adapter.ListSecretVersions(ctx, &pb.ListSecretVersionsRequest{SecretId: "db/pw"})
	require.NoError(t, err)
	require.Len(t, listed.GetVersions(), 2)
	assert.Equal(t, uint64(2), listed.GetVersions()[1].GetVersion())

	rotated, err := adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("v3"), Metadata: map[string]string{"by": "ops"}})
	require.NoError(t, err)
	assert.Equal(t, []byte("v3"), client.lastRotate.NewData)
	assert.Equal(t, "ops", client.lastRotate.Metadata["by"])
	assert.Equal(t, uint64(3), rotated.GetNewVersion())

	rolled, err := adapter.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: "db/pw", TargetVersion: 1})
	require.NoError(t, err)
	assert.Equal(t, 1, client.lastRollback.TargetVersion)
	assert.Equal(t, uint64(4), rolled.GetNewVersion())

	updated, err := adapter.UpdateSecretStatus(ctx, &pb.UpdateSecretStatusRequest{SecretId: "db/pw", Status: pb.SecretStatus_SECRET_STATUS_DISABLED})
	require.NoError(t, err)
	assert.Equal(t, secretsclient.SecretStatusDisabled, client.lastStatus.Status)
	assert.Equal(t, pb.SecretStatus_SECRET_STATUS_DISABLED, updated.GetStatus())
}

func TestSecretsServerAdapter_VersionsErrors(t *testing.T) {
	ctx := context.Background()
	calls := map[string]func(a *SecretsServerAdapter, id string) error{
		"GetSecretVersion": func(a *SecretsServerAdapter, id string) error {
			_, err := a.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{SecretId: id, Version: 1})
			return err
		},
		"ListSecretVersions": func(a *SecretsServerAdapter, id string) error {
			_, err := a.ListSecretVersions(ctx, &pb.ListSecretVersionsRequest{SecretId: id})
			return err
		},
		"RotateSecret": func(a *SecretsServerAdapter, id string) error {
			_, err := a.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: id, NewData: []byte("x")})
			return err
		},
		"RollbackSecret": func(a *SecretsServerAdapter, id string) error {
			_, err := a.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: id, TargetVersion: 1})
			return err
		},
		"UpdateSecretStatus": func(a *SecretsServerAdapter, id string) error {
			_, err := a.UpdateSecretStatus(ctx, &pb.UpdateSecretStatusRequest{SecretId: id, Status: pb.SecretStatus_SECRET_STATUS_ENABLED})
			return err
		},
	}
	failing := map[string]codes.Code{
		"GetSecretVersion":   codes.NotFound,
		"ListSecretVersions": codes.NotFound,
		"RotateSecret":       codes.Internal,
		"RollbackSecret":     codes.Internal,
		"UpdateSecretStatus": codes.Internal,
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.Unavailable, status.Code(call(NewSecretsServerAdapter(nil, slog.Default()), "db/pw")))

			adapter := NewSecretsServerAdapter(&extSecretsClientMock{}, slog.Default())
			assert.Equal(t, codes.InvalidArgument, status.Code(call(adapter, "")))
			assert.Equal(t, failing[name], status.Code(call(adapter, "db/pw")))
		})
	}

	adapter := NewSecretsServerAdapter(&versionSecretsClient{}, slog.Default())
	_, err := adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "rotate without new data")
	_, err = adapter.RollbackSecret(ctx, &pb.RollbackSecretRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "rollback without a target version")
	_, err = adapter.UpdateSecretStatus(ctx, &pb.UpdateSecretStatusRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "unspecified status")
}
