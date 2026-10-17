package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recordingKMSClient answers the public-key, rotation-policy and unwrap calls
// and records what the adapter sent; every other call falls through to
// platformMockKMSClient.
type recordingKMSClient struct {
	platformMockKMSClient
	err            error
	lastKeyID      string
	lastRotation   *kms.SetKeyRotationPolicyRequest
	lastUnwrap     *kms.UnwrapKeyRequest
	rotationPolicy *kms.KeyRotationPolicy
}

func (c *recordingKMSClient) GetPublicKey(_ context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	c.lastKeyID = keyID
	if c.err != nil {
		return nil, c.err
	}
	return &kms.GetPublicKeyResponse{KeyID: keyID, PublicKey: []byte("pub"), Algorithm: kms.AlgorithmECDSAP256, Version: 3}, nil
}

func (c *recordingKMSClient) SetKeyRotationPolicy(_ context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error) {
	c.lastRotation = req
	if c.err != nil {
		return nil, c.err
	}
	return c.rotationPolicy, nil
}

func (c *recordingKMSClient) GetKeyRotationPolicy(_ context.Context, keyID string) (*kms.KeyRotationPolicy, error) {
	c.lastKeyID = keyID
	if c.err != nil {
		return nil, c.err
	}
	return c.rotationPolicy, nil
}

func (c *recordingKMSClient) DeleteKeyRotationPolicy(_ context.Context, keyID string) error {
	c.lastKeyID = keyID
	return c.err
}

func (c *recordingKMSClient) UnwrapKey(_ context.Context, req *kms.UnwrapKeyRequest) (*kms.UnwrapKeyResponse, error) {
	c.lastUnwrap = req
	if c.err != nil {
		return nil, c.err
	}
	return &kms.UnwrapKeyResponse{KeyID: "unwrapped-1", Version: 1, Algorithm: req.Algorithm}, nil
}

// recordingCryptoClient answers the data-key calls and records what the
// adapter sent; every other call falls through to platformMockCryptoClient.
type recordingCryptoClient struct {
	platformMockCryptoClient
	err         error
	lastDataKey *quicbaas.GenerateDataKeyRequest
	lastWrapped *quicbaas.GenerateWrappedDataKeyRequest
}

func (c *recordingCryptoClient) GenerateDataKey(_ context.Context, req *quicbaas.GenerateDataKeyRequest) (*quicbaas.GenerateDataKeyResponse, error) {
	c.lastDataKey = req
	if c.err != nil {
		return nil, c.err
	}
	return &quicbaas.GenerateDataKeyResponse{KeyID: req.KeyID, Plaintext: []byte("plain"), CiphertextBlob: []byte("blob")}, nil
}

func (c *recordingCryptoClient) GenerateWrappedDataKey(_ context.Context, req *quicbaas.GenerateWrappedDataKeyRequest) (*quicbaas.GenerateWrappedDataKeyResponse, error) {
	c.lastWrapped = req
	if c.err != nil {
		return nil, c.err
	}
	return &quicbaas.GenerateWrappedDataKeyResponse{KeyID: req.KeyID, CiphertextBlob: []byte("blob")}, nil
}

// recordingDEKClient answers the default, safety and re-encryption calls and
// records what the adapter sent; every other call falls through to
// fakeDEKClient.
type recordingDEKClient struct {
	fakeDEKClient
	err          error
	lastSafety   *dekclient.SetDEKSafetyRequest
	lastStart    *dekclient.StartReencryptionRequest
	lastProgress *dekclient.GetReencryptionProgressRequest
	clearedPath  string
}

func (c *recordingDEKClient) SetDefaultDEK(_ context.Context, path string) (*dekclient.SetDefaultDEKResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &dekclient.SetDefaultDEKResponse{Path: path, PreviousDefault: "dek/old"}, nil
}

func (c *recordingDEKClient) SetDEKSafety(_ context.Context, req *dekclient.SetDEKSafetyRequest) error {
	c.lastSafety = req
	return c.err
}

func (c *recordingDEKClient) ClearDEKSafety(_ context.Context, path string) error {
	c.clearedPath = path
	return c.err
}

func (c *recordingDEKClient) StartReencryption(_ context.Context, req *dekclient.StartReencryptionRequest) (*dekclient.StartReencryptionResponse, error) {
	c.lastStart = req
	if c.err != nil {
		return nil, c.err
	}
	return &dekclient.StartReencryptionResponse{OperationID: "op-1", Path: req.Path, Started: true, EstimatedItems: 42}, nil
}

func (c *recordingDEKClient) GetReencryptionProgress(_ context.Context, req *dekclient.GetReencryptionProgressRequest) (*dekclient.ReencryptionProgressResponse, error) {
	c.lastProgress = req
	if c.err != nil {
		return nil, c.err
	}
	return &dekclient.ReencryptionProgressResponse{
		OperationID: req.OperationID,
		Path:        req.Path,
		Status:      "running",
		Progress: &dekclient.ReencryptionProgress{
			InProgress:    true,
			TotalKeys:     10,
			ProcessedKeys: 4,
			FailedKeys:    1,
			StartedAt:     time.Unix(1700000000, 0),
		},
	}, nil
}

var errSDKRPCTest = errors.New("sdk rpc test failure")

func TestKMSServerAdapter_GetPublicKey(t *testing.T) {
	t.Parallel()
	client := &recordingKMSClient{}
	adapter := NewKMSServerAdapter(client, slog.Default())

	resp, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, "key-1", resp.GetKeyId())
	assert.Equal(t, []byte("pub"), resp.GetPublicKey())
	assert.Equal(t, sdkAlgorithmToPb(kms.AlgorithmECDSAP256), resp.GetAlgorithm())
	assert.Equal(t, uint64(3), resp.GetVersion())
}

func TestKMSServerAdapter_GetPublicKey_RefusesBadRequests(t *testing.T) {
	t.Parallel()
	adapter := NewKMSServerAdapter(&recordingKMSClient{}, slog.Default())

	_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1", Version: 2})
	var gap ErrKMSSDKGap
	require.ErrorAs(t, err, &gap, "the SDK call takes no version, so a versioned request is a declared gap")
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	failing := NewKMSServerAdapter(&recordingKMSClient{err: errSDKRPCTest}, slog.Default())
	_, err = failing.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1"})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
}

func TestKMSServerAdapter_KeyRotationPolicy(t *testing.T) {
	t.Parallel()
	next := time.Unix(1800000000, 0)
	client := &recordingKMSClient{rotationPolicy: &kms.KeyRotationPolicy{
		Enabled: true, AutoRotate: true, IntervalSeconds: 3600, NextRotationAt: next, RetainVersions: 5,
	}}
	adapter := NewKMSServerAdapter(client, slog.Default())
	ctx := context.Background()

	setResp, err := adapter.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{
		KeyId:  "key-1",
		Policy: &pb.RotationPolicy{Enabled: true, AutoRotate: true, IntervalSeconds: 3600, RetainVersions: 5},
	})
	require.NoError(t, err)
	assert.Equal(t, &kms.SetKeyRotationPolicyRequest{
		KeyID: "key-1", AutoRotate: true, IntervalSeconds: 3600, RetainVersions: 5, Enabled: true,
	}, client.lastRotation)
	assert.Equal(t, next.Unix(), setResp.GetPolicy().GetNextRotation())
	assert.Equal(t, int32(5), setResp.GetPolicy().GetRetainVersions())

	getResp, err := adapter.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, "key-1", getResp.GetKeyId())
	assert.True(t, getResp.GetPolicy().GetAutoRotate())

	delResp, err := adapter.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{KeyId: "key-2"})
	require.NoError(t, err)
	assert.Equal(t, "key-2", delResp.GetKeyId())
	assert.Equal(t, "key-2", client.lastKeyID)
}

func TestKMSServerAdapter_KeyRotationPolicy_RefusesBadRequests(t *testing.T) {
	t.Parallel()
	adapter := NewKMSServerAdapter(&recordingKMSClient{}, slog.Default())
	ctx := context.Background()

	_, err := adapter.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{KeyId: "key-1"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing policy is refused")
	_, err = adapter.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{Policy: &pb.RotationPolicy{}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = adapter.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = adapter.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	failing := NewKMSServerAdapter(&recordingKMSClient{err: errSDKRPCTest}, slog.Default())
	_, err = failing.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{KeyId: "key-1", Policy: &pb.RotationPolicy{}})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
	_, err = failing.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: "key-1"})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
	_, err = failing.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{KeyId: "key-1"})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
}

func TestKMSServerAdapter_UnwrapKey(t *testing.T) {
	t.Parallel()
	client := &recordingKMSClient{}
	adapter := NewKMSServerAdapter(client, slog.Default())

	resp, err := adapter.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappingKeyId:     "wrap-1",
		WrappingAlgorithm: pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256,
		WrappedMaterial:   []byte("wrapped"),
		Algorithm:         pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		Name:              "imported",
		SourceKeyId:       "src-1",
		SourceVersion:     2,
	})
	require.NoError(t, err)
	assert.Equal(t, "unwrapped-1", resp.GetKey().GetKeyId())
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, resp.GetKey().GetAlgorithm())
	assert.Equal(t, "wrap-1", client.lastUnwrap.WrappingKeyID)
	assert.Equal(t, pbWrappingAlgorithmToSDK(pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256), client.lastUnwrap.WrappingAlgorithm)
	assert.Equal(t, "imported", client.lastUnwrap.Name)
	assert.Equal(t, 2, client.lastUnwrap.SourceVersion)
}

func TestKMSServerAdapter_UnwrapKey_RefusesBadRequests(t *testing.T) {
	t.Parallel()
	adapter := NewKMSServerAdapter(&recordingKMSClient{}, slog.Default())
	ctx := context.Background()

	_, err := adapter.UnwrapKey(ctx, &pb.UnwrapKeyRequest{WrappedMaterial: []byte("wrapped")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing wrapping key is refused")
	_, err = adapter.UnwrapKey(ctx, &pb.UnwrapKeyRequest{WrappingKeyId: "wrap-1"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "missing wrapped material is refused")

	failing := NewKMSServerAdapter(&recordingKMSClient{err: errSDKRPCTest}, slog.Default())
	_, err = failing.UnwrapKey(ctx, &pb.UnwrapKeyRequest{WrappingKeyId: "wrap-1", WrappedMaterial: []byte("w")})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
}

// TestKMSServerAdapter_DeclaredSDKGaps pins every KMS RPC the SDK client
// has no call for: each answers a typed ErrKMSSDKGap classified
// Unimplemented, never the generated "method X not implemented" stub.
func TestKMSServerAdapter_DeclaredSDKGaps(t *testing.T) {
	t.Parallel()
	adapter := NewKMSServerAdapter(&recordingKMSClient{}, slog.Default())
	ctx := context.Background()
	gaps := map[string]func() error{
		"DeleteKeyPolicy": func() error { _, err := adapter.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{}); return err },
		"BackendTest":     func() error { _, err := adapter.BackendTest(ctx, &pb.BackendTestRequest{}); return err },
		"SetKeySafety":    func() error { _, err := adapter.SetKeySafety(ctx, &pb.SetKeySafetyRequest{}); return err },
		"ClearKeySafety":  func() error { _, err := adapter.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{}); return err },
		"SafetyCheck":     func() error { _, err := adapter.SafetyCheck(ctx, &pb.SafetyCheckRequest{}); return err },
		"SafetyReport":    func() error { _, err := adapter.SafetyReport(ctx, &pb.SafetyReportRequest{}); return err },
	}
	for method, call := range gaps {
		err := call()
		var gap ErrKMSSDKGap
		require.ErrorAs(t, err, &gap, method)
		assert.Equal(t, method, gap.Method)
		assert.Equal(t, kmsClientUpstream, gap.Upstream)
		assert.Equal(t, codes.Unimplemented, status.Code(err), method)
		assert.NotEqual(t, "method "+method+" not implemented", status.Convert(err).Message(), method)
	}
}

func TestErrKMSSDKGap_NamesTheMethodAndUpstream(t *testing.T) {
	t.Parallel()
	err := ErrKMSSDKGap{Method: "BackendTest", Upstream: "kms.Client"}
	assert.Equal(t, "KMS BackendTest is a declared SDK gap: kms.Client has no BackendTest call", err.Error())
	assert.Equal(t, codes.Unimplemented, err.GRPCStatus().Code())
	assert.Equal(t, err.Error(), err.GRPCStatus().Message())
}

func TestCryptoServerAdapter_GenerateDataKeys(t *testing.T) {
	t.Parallel()
	client := &recordingCryptoClient{}
	adapter := NewCryptoServerAdapter(client, slog.Default())
	ctx := context.Background()
	spec := &pb.KeySpec{KeySize: 256}

	plain, err := adapter.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "key-1", KeySpec: spec, Context: []byte("aad")})
	require.NoError(t, err)
	assert.Equal(t, []byte("plain"), plain.GetPlaintext())
	assert.Equal(t, []byte("blob"), plain.GetCiphertextBlob())
	assert.Equal(t, &quicbaas.GenerateDataKeyRequest{KeyID: "key-1", KeySize: 256, Context: []byte("aad")}, client.lastDataKey)

	wrapped, err := adapter.GenerateWrappedDataKey(ctx, &pb.GenerateWrappedDataKeyRequest{KeyId: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), wrapped.GetCiphertextBlob())
	assert.Equal(t, 0, client.lastWrapped.KeySize, "no key spec lets the KMS choose the size")
}

func TestCryptoServerAdapter_GenerateDataKeys_RefuseBadRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	adapter := NewCryptoServerAdapter(&recordingCryptoClient{}, slog.Default())

	_, err := adapter.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = adapter.GenerateWrappedDataKey(ctx, &pb.GenerateWrappedDataKeyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	failing := NewCryptoServerAdapter(&recordingCryptoClient{err: errSDKRPCTest}, slog.Default())
	_, err = failing.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "key-1"})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
	_, err = failing.GenerateWrappedDataKey(ctx, &pb.GenerateWrappedDataKeyRequest{KeyId: "key-1"})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
}

func TestCryptoServerAdapter_GenerateRandom(t *testing.T) {
	t.Parallel()
	adapter := NewCryptoServerAdapter(&recordingCryptoClient{}, slog.Default())

	resp, err := adapter.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{NumBytes: 16})
	require.NoError(t, err)
	assert.Len(t, resp.GetRandomBytes(), 16)
}

func TestCryptoServerAdapter_GenerateRandom_RefusesBadRequests(t *testing.T) {
	t.Parallel()
	adapter := NewCryptoServerAdapter(&recordingCryptoClient{}, slog.Default())

	_, err := adapter.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = adapter.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{NumBytes: -1})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	failing := NewCryptoServerAdapter(&recordingCryptoClient{platformMockCryptoClient: platformMockCryptoClient{
		generateRandomFn: func(context.Context, *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
			return nil, errSDKRPCTest
		},
	}}, slog.Default())
	_, err = failing.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{NumBytes: 8})
	assert.ErrorContains(t, err, errSDKRPCTest.Error())
}

func TestDEKServerAdapter_DefaultAndSafety(t *testing.T) {
	t.Parallel()
	client := &recordingDEKClient{}
	adapter := NewDEKServerAdapter(client, slog.Default())
	ctx := context.Background()

	def, err := adapter.SetDefaultDEK(ctx, &pb.SetDefaultDEKRequest{Path: "dek/new"})
	require.NoError(t, err)
	assert.Equal(t, "dek/new", def.GetPath())
	assert.Equal(t, "dek/old", def.GetPreviousDefault())

	_, err = adapter.SetDEKSafety(ctx, &pb.SetDEKSafetyRequest{Path: "dek/new", MaxOperations: 100, MaxBytes: 4096, WarningPercent: 80})
	require.NoError(t, err)
	assert.Equal(t, &dekclient.SetDEKSafetyRequest{Path: "dek/new", MaxOperations: 100, MaxBytes: 4096, WarningPercent: 80}, client.lastSafety)

	cleared, err := adapter.ClearDEKSafety(ctx, &pb.ClearDEKSafetyRequest{Path: "dek/new"})
	require.NoError(t, err)
	assert.Equal(t, "dek/new", cleared.GetPath())
	assert.Equal(t, "dek/new", client.clearedPath)
}

func TestDEKServerAdapter_Reencryption(t *testing.T) {
	t.Parallel()
	client := &recordingDEKClient{}
	adapter := NewDEKServerAdapter(client, slog.Default())
	ctx := context.Background()

	started, err := adapter.StartReencryption(ctx, &pb.StartReencryptionRequest{Path: "dek/a", FromVersion: 1, ToVersion: 2, BatchSize: 50, Force: true})
	require.NoError(t, err)
	assert.Equal(t, "op-1", started.GetOperationId())
	assert.True(t, started.GetStarted())
	assert.Equal(t, int32(42), started.GetEstimatedItems())
	assert.Equal(t, &dekclient.StartReencryptionRequest{Path: "dek/a", FromVersion: 1, ToVersion: 2, BatchSize: 50, Force: true}, client.lastStart)

	progress, err := adapter.GetReencryptionProgress(ctx, &pb.GetReencryptionProgressRequest{Path: "dek/a", OperationId: "op-1"})
	require.NoError(t, err)
	assert.Equal(t, "running", progress.GetStatus())
	assert.Equal(t, int32(4), progress.GetProgress().GetProcessedKeys())
	assert.Equal(t, int64(1700000000), progress.GetProgress().GetStartedAt())
	assert.Equal(t, "op-1", client.lastProgress.OperationID)
}

func TestDEKServerAdapter_NewRPCs_RefuseBadRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	adapter := NewDEKServerAdapter(&recordingDEKClient{}, slog.Default())
	failing := NewDEKServerAdapter(&recordingDEKClient{err: errSDKRPCTest}, slog.Default())

	calls := map[string]func(a *DEKServerAdapter, path string) error{
		"SetDefaultDEK": func(a *DEKServerAdapter, path string) error {
			_, err := a.SetDefaultDEK(ctx, &pb.SetDefaultDEKRequest{Path: path})
			return err
		},
		"SetDEKSafety": func(a *DEKServerAdapter, path string) error {
			_, err := a.SetDEKSafety(ctx, &pb.SetDEKSafetyRequest{Path: path})
			return err
		},
		"ClearDEKSafety": func(a *DEKServerAdapter, path string) error {
			_, err := a.ClearDEKSafety(ctx, &pb.ClearDEKSafetyRequest{Path: path})
			return err
		},
		"StartReencryption": func(a *DEKServerAdapter, path string) error {
			_, err := a.StartReencryption(ctx, &pb.StartReencryptionRequest{Path: path})
			return err
		},
		"GetReencryptionProgress": func(a *DEKServerAdapter, path string) error {
			_, err := a.GetReencryptionProgress(ctx, &pb.GetReencryptionProgressRequest{Path: path})
			return err
		},
	}
	for name, call := range calls {
		assert.Equal(t, codes.InvalidArgument, status.Code(call(adapter, "")), "%s: a missing path is refused", name)
		assert.ErrorContains(t, call(failing, "dek/a"), errSDKRPCTest.Error(), name)
	}
}

func TestDEKReencryptionProgressToPb_NilStaysNil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, dekReencryptionProgressToPb(nil))
	assert.Nil(t, sdkKeyRotationPolicyToPb(nil))
}
