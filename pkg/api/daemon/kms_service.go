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
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	dbfactory "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// maxBatchSize is the maximum number of items allowed in a batch operation.
const maxBatchSize = 100

// KMSService wraps QuicBaaS's KMS SDK clients for platformd.
// It registers the following gRPC services using SDK-based adapters:
//   - KeyManagement: Key generation, rotation, import/export
//   - SecretsManagement: Secret storage and retrieval
//   - Crypto: Encryption/decryption operations
//   - DEKManagement: Data encryption key management
//
// The service uses the QuicBaaS SDK client interfaces (KMSClient, SecretsClient,
// CryptoClient) instead of direct internal package imports, providing a clean
// abstraction layer and transport-agnostic access to KMS functionality.
type KMSService struct {
	app           *app.App
	logger        *slog.Logger
	kmsAdapter    *KMSServerAdapter
	secretsServer *SecretsServerAdapter
	cryptoServer  *CryptoServerAdapter
	dekServer     *DEKServerAdapter
	running       atomic.Bool
	initialized   atomic.Bool
}

// NewKMSService creates a new KMS service that wraps QuicBaaS's KMS functionality.
// Returns nil if the app doesn't have QuicBaaS configured as its backend.
func NewKMSService(application *app.App, logger *slog.Logger) (*KMSService, error) {
	if application == nil {
		return nil, ErrInvalidConfig{Reason: "application is required for KMS service"}
	}

	// Check if QuicBaaS backend is available
	kmsSvc := application.KMS()
	if kmsSvc == nil {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS backend not available for KMS"}
	}

	return &KMSService{
		app:    application,
		logger: logger,
	}, nil
}

// initializeServers initializes the gRPC server adapters if not already initialized.
// This is called lazily to ensure QuicBaaS is fully started before accessing services.
func (s *KMSService) initializeServers() error {
	if s.initialized.Load() {
		return nil
	}

	// Get the QuicBaaS factory from app
	factory, ok := s.app.DAOFactory().(*dbfactory.Factory)
	if !ok {
		return ErrInvalidConfig{Reason: "datastore is not QuicBaaS"}
	}

	// Get the SDK client from the factory
	sdkClient := factory.SDK()
	if sdkClient == nil {
		return ErrInvalidConfig{Reason: "QuicBaaS SDK client not available"}
	}

	// Create SDK-based server adapters for gRPC service registration
	s.kmsAdapter = NewKMSServerAdapter(sdkClient.Security().KMS(), s.logger)
	s.secretsServer = NewSecretsServerAdapter(sdkClient.Security().Secrets(), s.logger)
	s.cryptoServer = NewCryptoServerAdapter(sdkClient.Security().Crypto(), s.logger)
	s.dekServer = NewDEKServerAdapter(sdkClient.Security().DEK(), s.logger)

	s.initialized.Store(true)
	return nil
}

// RegisterGRPCServices registers all KMS-related gRPC services with a gRPC server.
// This includes KeyManagement, SecretsManagement, Crypto, and DEKManagement services.
func (s *KMSService) RegisterGRPCServices(server *grpc.Server) error {
	if server == nil {
		return ErrInvalidConfig{Reason: "gRPC server is required"}
	}

	// Initialize servers if not already done
	if err := s.initializeServers(); err != nil {
		return err
	}

	// Register all KMS-related gRPC services with the gRPC server
	pb.RegisterKeyManagementServer(server, s.kmsAdapter)
	pb.RegisterSecretsManagementServer(server, s.secretsServer)
	pb.RegisterCryptoServer(server, s.cryptoServer)
	pb.RegisterDEKManagementServer(server, s.dekServer)

	s.logger.Info("KMS gRPC services registered",
		"services", []string{"KeyManagement", "SecretsManagement", "Crypto", "DEKManagement"})

	return nil
}

// Start starts the KMS service.
func (s *KMSService) Start(ctx context.Context) error {
	if s.running.Load() {
		return nil
	}
	s.running.Store(true)
	s.logger.Info("KMS service started")
	return nil
}

// Stop stops the KMS service.
func (s *KMSService) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}
	s.running.Store(false)
	s.logger.Info("KMS service stopped")
	return nil
}

// IsRunning returns whether the KMS service is running.
func (s *KMSService) IsRunning() bool {
	return s.running.Load()
}

// Name returns the service name.
func (s *KMSService) Name() string {
	return "kms"
}

// KMSServer returns the KeyManagement gRPC server adapter.
// Returns nil if the service is not initialized.
func (s *KMSService) KMSServer() *KMSServerAdapter {
	return s.kmsAdapter
}

// SecretsServer returns the SecretsManagement gRPC server adapter.
// Returns nil if the service is not initialized.
func (s *KMSService) SecretsServer() *SecretsServerAdapter {
	return s.secretsServer
}

// CryptoServer returns the Crypto gRPC server adapter.
// Returns nil if the service is not initialized.
func (s *KMSService) CryptoServer() *CryptoServerAdapter {
	return s.cryptoServer
}

// DEKServer returns the DEKManagement gRPC server adapter.
// Returns nil if the service is not initialized.
func (s *KMSService) DEKServer() *DEKServerAdapter {
	return s.dekServer
}

// KMSServerAdapter implements pb.KeyManagementServer by delegating to the SDK KMSClient.
// This adapter translates gRPC protobuf requests to SDK client calls.
type KMSServerAdapter struct {
	pb.UnimplementedKeyManagementServer
	client quicbaas.KMSClient
	logger *slog.Logger
}

// NewKMSServerAdapter creates a new KMS server adapter wrapping the SDK client.
func NewKMSServerAdapter(client quicbaas.KMSClient, logger *slog.Logger) *KMSServerAdapter {
	return &KMSServerAdapter{
		client: client,
		logger: logger,
	}
}

// GenerateKey implements pb.KeyManagementServer.GenerateKey.
func (a *KMSServerAdapter) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	// The generate request's name is the key ID (docs/kms/api.md §2).
	spec := req.GetKeySpec()
	sdkReq := &kms.GenerateKeyRequest{
		Name:               req.GetName(),
		Algorithm:          pbAlgorithmToSDK(spec.GetAlgorithm()),
		Usage:              pbUsagesToSDK(spec.GetUsage()),
		Exportable:         spec.GetExportable(),
		DeletionProtection: spec.GetDeletionProtection(),
	}

	resp, err := a.client.GenerateKey(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key generation failed: %v", err)
	}

	meta, err := recordGeneratedKeyMetadata(ctx, a.client, resp.KeyID, req.GetDescription(), req.GetTags())
	if err != nil {
		return nil, err
	}

	return &pb.GenerateKeyResponse{
		Key: &pb.KeyHandle{
			KeyId:     resp.KeyID,
			Version:   uint64(resp.Version),
			Algorithm: sdkAlgorithmToPb(resp.Algorithm),
		},
		Metadata:  sdkKeyMetadataToPb(meta),
		Timestamp: time.Now().Unix(),
	}, nil
}

// recordGeneratedKeyMetadata applies a generate request's description and
// tags to the key just generated and returns the metadata the KMS recorded.
// The SDK GenerateKeyRequest has no description or tags, so they travel as a
// metadata update; with neither, the metadata is read back as it stands. The
// SDK has no field for a key owner at all: the owner returned is the one the
// KMS recorded, never the requested one.
func recordGeneratedKeyMetadata(ctx context.Context, client quicbaas.KMSClient, keyID, description string, tags map[string]string) (*kms.KeyMetadataResponse, error) {
	var meta *kms.KeyMetadataResponse
	var err error
	if description == "" && len(tags) == 0 {
		meta, err = client.GetKeyMetadata(ctx, keyID)
	} else {
		meta, err = client.UpdateKeyMetadata(ctx, &kms.UpdateKeyMetadataRequest{
			KeyID:       keyID,
			Description: description,
			Tags:        tags,
		})
	}
	if err != nil {
		return nil, ErrKMSGeneratedKeyMetadata{KeyID: keyID, Err: err}
	}
	if meta == nil {
		return nil, ErrKMSGeneratedKeyMetadata{KeyID: keyID, Err: ErrKMSNilMetadata{}}
	}
	return meta, nil
}

// GetKey implements pb.KeyManagementServer.GetKey.
func (a *KMSServerAdapter) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	keyInfo, err := a.client.GetKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get key failed: %v", err)
	}

	return &pb.GetKeyResponse{
		Key: &pb.KeyHandle{
			KeyId:     keyInfo.KeyID,
			Version:   uint64(keyInfo.Version),
			Algorithm: sdkAlgorithmToPb(keyInfo.Algorithm),
		},
		Metadata: &pb.KeyMetadata{
			KeyId:     keyInfo.KeyID,
			Name:      keyInfo.Name,
			Algorithm: sdkAlgorithmToPb(keyInfo.Algorithm),
			Version:   uint64(keyInfo.Version),
		},
	}, nil
}

// GetPublicKey returns the DER-encoded (PKIX) public key of an asymmetric
// key. The SDK serves the current version only, so a request naming any other
// version is refused rather than answered with the current key.
func (a *KMSServerAdapter) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	resp, err := a.client.GetPublicKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get public key failed: %v", err)
	}
	if req.GetVersion() != 0 && req.GetVersion() != uint64(resp.Version) {
		return nil, status.Errorf(codes.NotFound, "public key version %d of key %s is not the current version %d",
			req.GetVersion(), req.GetKeyId(), resp.Version)
	}

	return &pb.GetPublicKeyResponse{
		KeyId:     resp.KeyID,
		PublicKey: resp.PublicKey,
		Algorithm: sdkAlgorithmToPb(resp.Algorithm),
		Version:   uint64(resp.Version),
		Timestamp: time.Now().Unix(),
	}, nil
}

// ListKeys implements pb.KeyManagementServer.ListKeys.
func (a *KMSServerAdapter) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	resp, err := a.client.ListKeys(ctx)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "list keys failed: %v", err)
	}

	// The SDK ListKeys call takes no paging or filter arguments, so the
	// adapter applies the request's filter, limit and cursor itself, over a
	// sorted copy so every page request slices the same order.
	keys := sortKeyInfos(resp.Keys)
	if len(req.GetFilter()) > 0 {
		keys, err = filterKeyInfos(keys, req.GetFilter())
		if err != nil {
			return nil, err
		}
	}

	start, end, nextCursor, hasMore, err := paginateKMSOffset(len(keys), req.GetLimit(), req.GetCursor())
	if err != nil {
		return nil, err
	}

	handles := make([]*pb.KeyHandle, 0, end-start)
	for _, k := range keys[start:end] {
		handles = append(handles, &pb.KeyHandle{
			KeyId:     k.KeyID,
			Version:   uint64(k.Version),
			Algorithm: sdkAlgorithmToPb(k.Algorithm),
		})
	}

	return &pb.ListKeysResponse{
		Keys:       handles,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		TotalCount: int32(len(keys)),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// RotateKey implements pb.KeyManagementServer.RotateKey.
func (a *KMSServerAdapter) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	resp, err := a.client.RotateKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key rotation failed: %v", err)
	}

	return &pb.RotateKeyResponse{
		KeyId:      resp.KeyID,
		OldVersion: rotatedFromVersion(resp.NewVersion),
		NewVersion: uint64(resp.NewVersion),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// DeleteKey implements pb.KeyManagementServer.DeleteKey.
func (a *KMSServerAdapter) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	err := a.client.DeleteKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key deletion failed: %v", err)
	}

	return &pb.DeleteKeyResponse{
		KeyId:  req.GetKeyId(),
		Status: pb.KeyStatus_KEY_STATUS_DELETED,
	}, nil
}

// ImportKey implements pb.KeyManagementServer.ImportKey by delegating to
// the SDK KMS client.
func (a *KMSServerAdapter) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if len(req.GetKeyMaterial()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key_material is required")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	sdkReq := &kms.ImportKeyRequest{
		KeyMaterial:   req.GetKeyMaterial(),
		WrappingKeyID: req.GetWrappingKeyId(),
		Name:          req.GetName(),
		Description:   req.GetDescription(),
		Tags:          req.GetTags(),
	}
	if req.GetKeySpec() != nil {
		sdkReq.Algorithm = pbAlgorithmToSDK(req.GetKeySpec().GetAlgorithm())
		sdkReq.Usage = pbUsagesToSDK(req.GetKeySpec().GetUsage())
	}

	resp, err := a.client.ImportKey(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key import failed: %v", err)
	}

	return &pb.ImportKeyResponse{
		Key: &pb.KeyHandle{
			KeyId:     resp.KeyID,
			Version:   uint64(resp.Version),
			Algorithm: sdkAlgorithmToPb(resp.Algorithm),
		},
		Timestamp: time.Now().Unix(),
	}, nil
}

// UpdateKeyStatus implements pb.KeyManagementServer.UpdateKeyStatus by
// delegating to the SDK KMS client. A version of zero targets all versions
// of the key, mirroring the quicbaas server-side semantics.
func (a *KMSServerAdapter) UpdateKeyStatus(ctx context.Context, req *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.GetStatus() == pb.KeyStatus_KEY_STATUS_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "status is required")
	}

	resp, err := a.client.UpdateKeyStatus(ctx, &kms.UpdateKeyStatusRequest{
		KeyID:   req.GetKeyId(),
		Version: int(req.GetVersion()),
		Status:  pbKeyStatusToSDK(req.GetStatus()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key status update failed: %v", err)
	}

	return &pb.UpdateKeyStatusResponse{
		KeyId:     resp.KeyID,
		Version:   uint64(resp.Version),
		Status:    sdkKeyStatusToPb(resp.Status),
		Timestamp: time.Now().Unix(),
	}, nil
}

// ExportKey implements pb.KeyManagementServer.ExportKey by delegating to
// the SDK KMS client. The exported material is wrapped with the requested
// wrapping key and never leaves the KMS in plaintext.
func (a *KMSServerAdapter) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.GetWrappingKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_key_id is required")
	}

	resp, err := a.client.ExportKey(ctx, &kms.ExportKeyRequest{
		KeyID:             req.GetKeyId(),
		WrappingKeyID:     req.GetWrappingKeyId(),
		WrappingAlgorithm: pbWrappingAlgorithmToSDK(req.GetWrappingAlgorithm()),
		Format:            pbExportFormatToSDK(req.GetFormat()),
		Version:           int(req.GetVersion()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key export failed: %v", err)
	}

	return &pb.ExportKeyResponse{
		KeyId:             resp.KeyID,
		Format:            sdkExportFormatToPb(resp.Format),
		WrappingKeyId:     resp.WrappingKeyID,
		WrappingAlgorithm: sdkWrappingAlgorithmToPb(resp.WrappingAlgorithm),
		WrappedMaterial:   resp.WrappedMaterial,
		Version:           uint64(resp.Version),
		Timestamp:         time.Now().Unix(),
	}, nil
}

// ListKeyVersions implements pb.KeyManagementServer.ListKeyVersions by
// delegating to the SDK KMS client.
func (a *KMSServerAdapter) ListKeyVersions(ctx context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	resp, err := a.client.ListKeyVersions(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "list key versions failed: %v", err)
	}

	versions := make([]*pb.KeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		info := &pb.KeyVersionInfo{
			Version:   uint64(v.Version),
			Status:    sdkKeyStatusToPb(v.Status),
			Algorithm: sdkAlgorithmToPb(v.Algorithm),
		}
		if !v.CreatedAt.IsZero() {
			info.CreatedAt = v.CreatedAt.Unix()
		}
		if !v.DisabledAt.IsZero() {
			info.DisabledAt = v.DisabledAt.Unix()
		}
		versions = append(versions, info)
	}

	return &pb.ListKeyVersionsResponse{
		KeyId:     resp.KeyID,
		Versions:  versions,
		Timestamp: time.Now().Unix(),
	}, nil
}

// SecretsServerAdapter implements pb.SecretsManagementServer by delegating to the SDK SecretsClient.
type SecretsServerAdapter struct {
	pb.UnimplementedSecretsManagementServer
	client quicbaas.SecretsClient
	logger *slog.Logger
}

// NewSecretsServerAdapter creates a new secrets server adapter wrapping the SDK client.
func NewSecretsServerAdapter(client quicbaas.SecretsClient, logger *slog.Logger) *SecretsServerAdapter {
	return &SecretsServerAdapter{
		client: client,
		logger: logger,
	}
}

// StoreSecret implements pb.SecretsManagementServer.StoreSecret.
func (a *SecretsServerAdapter) StoreSecret(ctx context.Context, req *pb.StoreSecretRequest) (*pb.StoreSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	// Convert protobuf data to SDK format
	data := make(map[string]interface{})
	data[secretRawKey] = req.GetData()

	sdkReq := &quicbaas.StoreSecretRequest{
		Path:     req.GetSecretId(),
		Data:     data,
		Metadata: req.GetMetadata(),
	}

	resp, err := a.client.Store(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "secret storage failed: %v", err)
	}

	return &pb.StoreSecretResponse{
		SecretId: req.GetSecretId(),
		Version:  uint64(resp.Version),
	}, nil
}

// GetSecret implements pb.SecretsManagementServer.GetSecret.
func (a *SecretsServerAdapter) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	var opts []quicbaas.SecretOption
	if req.GetVersion() > 0 {
		opts = append(opts, quicbaas.WithSecretVersion(int(req.GetVersion())))
	}

	secret, err := a.client.Get(ctx, req.GetSecretId(), opts...)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "secret not found: %v", err)
	}

	data, err := secretRawData(req.GetSecretId(), secret.Data)
	if err != nil {
		return nil, err
	}

	return &pb.GetSecretResponse{
		SecretId: req.GetSecretId(),
		Data:     data,
		Metadata: secret.Metadata,
		Version:  uint64(secret.Version),
	}, nil
}

// ListSecrets implements pb.SecretsManagementServer.ListSecrets.
func (a *SecretsServerAdapter) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}

	// ListSecretsRequest has no prefix field; GetSecretsByPrefix serves prefixes.
	paths, err := a.listSecretPaths(ctx, "")
	if err != nil {
		return nil, err
	}
	start, end, nextCursor, hasMore, err := paginateKMSOffset(len(paths), req.GetLimit(), req.GetCursor())
	if err != nil {
		return nil, err
	}

	secrets := make([]*pb.Secret, 0, end-start)
	for _, path := range paths[start:end] {
		secrets = append(secrets, &pb.Secret{
			SecretId: path,
		})
	}

	return &pb.ListSecretsResponse{
		Secrets:    secrets,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		TotalCount: int32(len(paths)),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// DeleteSecret implements pb.SecretsManagementServer.DeleteSecret.
func (a *SecretsServerAdapter) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	err := a.client.Delete(ctx, req.GetSecretId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "secret deletion failed: %v", err)
	}

	return &pb.DeleteSecretResponse{
		SecretId:  req.GetSecretId(),
		Deleted:   true,
		Timestamp: time.Now().Unix(),
	}, nil
}

// CryptoServerAdapter implements pb.CryptoServer by delegating to the SDK CryptoClient.
type CryptoServerAdapter struct {
	pb.UnimplementedCryptoServer
	client quicbaas.CryptoClient
	logger *slog.Logger
}

// NewCryptoServerAdapter creates a new crypto server adapter wrapping the SDK client.
func NewCryptoServerAdapter(client quicbaas.CryptoClient, logger *slog.Logger) *CryptoServerAdapter {
	return &CryptoServerAdapter{
		client: client,
		logger: logger,
	}
}

// Encrypt implements pb.CryptoServer.Encrypt.
func (a *CryptoServerAdapter) Encrypt(ctx context.Context, req *pb.CryptoEncryptRequest) (*pb.CryptoEncryptResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetPlaintext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	sdkReq := &quicbaas.EncryptRequest{
		KeyID:     req.GetKeyId(),
		Plaintext: req.GetPlaintext(),
		Context:   req.GetContext(),
	}

	resp, err := a.client.Encrypt(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "encryption failed: %v", err)
	}

	return &pb.CryptoEncryptResponse{
		Ciphertext: resp.Ciphertext,
		KeyVersion: uint64(resp.KeyVersion),
	}, nil
}

// Decrypt implements pb.CryptoServer.Decrypt.
func (a *CryptoServerAdapter) Decrypt(ctx context.Context, req *pb.CryptoDecryptRequest) (*pb.CryptoDecryptResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetCiphertext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	sdkReq := &quicbaas.DecryptRequest{
		KeyID:      req.GetKeyId(),
		Ciphertext: req.GetCiphertext(),
		Context:    req.GetContext(),
	}

	resp, err := a.client.Decrypt(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "decryption failed: %v", err)
	}

	return &pb.CryptoDecryptResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

// BatchEncrypt implements pb.CryptoServer.BatchEncrypt.
// It encrypts multiple items in a single request for improved throughput.
func (a *CryptoServerAdapter) BatchEncrypt(ctx context.Context, req *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	items := req.GetItems()
	if len(items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items cannot be empty")
	}

	if len(items) > maxBatchSize {
		return nil, status.Errorf(codes.InvalidArgument, "batch size exceeds maximum of %d items", maxBatchSize)
	}

	results := make([]*pb.BatchEncryptResult, 0, len(items))
	var keyVersion uint64

	for _, item := range items {
		sdkReq := &quicbaas.EncryptRequest{
			KeyID:     req.GetKeyId(),
			Plaintext: item.GetPlaintext(),
			Context:   item.GetContext(),
		}

		resp, err := a.client.Encrypt(ctx, sdkReq)
		if err != nil {
			results = append(results, &pb.BatchEncryptResult{
				Error: err.Error(),
			})
			continue
		}

		results = append(results, &pb.BatchEncryptResult{
			Ciphertext: resp.Ciphertext,
		})
		keyVersion = uint64(resp.KeyVersion)
	}

	return &pb.EncryptBatchResponse{
		KeyId:      req.GetKeyId(),
		KeyVersion: keyVersion,
		Results:    results,
		Timestamp:  time.Now().Unix(),
	}, nil
}

// BatchDecrypt implements pb.CryptoServer.BatchDecrypt.
// It decrypts multiple items in a single request for improved throughput.
func (a *CryptoServerAdapter) BatchDecrypt(ctx context.Context, req *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	items := req.GetItems()
	if len(items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items cannot be empty")
	}

	if len(items) > maxBatchSize {
		return nil, status.Errorf(codes.InvalidArgument, "batch size exceeds maximum of %d items", maxBatchSize)
	}

	results := make([]*pb.BatchDecryptResult, 0, len(items))

	for _, item := range items {
		sdkReq := &quicbaas.DecryptRequest{
			KeyID:      req.GetKeyId(),
			Ciphertext: item.GetCiphertext(),
			Context:    item.GetContext(),
		}

		resp, err := a.client.Decrypt(ctx, sdkReq)
		if err != nil {
			results = append(results, &pb.BatchDecryptResult{
				Error: err.Error(),
			})
			continue
		}

		results = append(results, &pb.BatchDecryptResult{
			Plaintext: resp.Plaintext,
		})
	}

	return &pb.DecryptBatchResponse{
		KeyId:     req.GetKeyId(),
		Results:   results,
		Timestamp: time.Now().Unix(),
	}, nil
}

// Rewrap implements pb.CryptoServer.Rewrap.
// It re-encrypts ciphertext with the latest key version without exposing plaintext externally.
// The plaintext is decrypted internally and immediately re-encrypted with the latest key version.
func (a *CryptoServerAdapter) Rewrap(ctx context.Context, req *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if len(req.GetCiphertext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	// Step 1: Decrypt the ciphertext with the source key version
	decryptReq := &quicbaas.DecryptRequest{
		KeyID:      req.GetKeyId(),
		Ciphertext: req.GetCiphertext(),
		Context:    req.GetContext(),
	}

	decryptResp, err := a.client.Decrypt(ctx, decryptReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "rewrap decryption failed: %v", err)
	}

	// Step 2: Re-encrypt with the latest key version
	// The SDK Encrypt operation uses the latest key version by default
	encryptReq := &quicbaas.EncryptRequest{
		KeyID:     req.GetKeyId(),
		Plaintext: decryptResp.Plaintext,
		Context:   req.GetContext(),
	}

	encryptResp, err := a.client.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "rewrap encryption failed: %v", err)
	}

	return &pb.RewrapResponse{
		KeyId:         req.GetKeyId(),
		OldKeyVersion: 0, // Source version not tracked by SDK decrypt response
		NewKeyVersion: uint64(encryptResp.KeyVersion),
		Ciphertext:    encryptResp.Ciphertext,
		Timestamp:     time.Now().Unix(),
	}, nil
}

// Sign implements pb.CryptoServer.Sign.
func (a *CryptoServerAdapter) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}

	sdkReq := &quicbaas.SignRequest{
		KeyID:     req.GetKeyId(),
		Data:      req.GetMessage(),
		HashAlg:   pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
		PreHashed: req.GetPreHashed(),
	}

	resp, err := a.client.Sign(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "signing failed: %v", err)
	}

	return &pb.SignResponse{
		Signature:  resp.Signature,
		KeyVersion: uint64(resp.KeyVersion),
	}, nil
}

// Verify implements pb.CryptoServer.Verify.
func (a *CryptoServerAdapter) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if len(req.GetSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	sdkReq := &quicbaas.VerifyRequest{
		KeyID:     req.GetKeyId(),
		Data:      req.GetMessage(),
		Signature: req.GetSignature(),
		HashAlg:   pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
	}

	resp, err := a.client.Verify(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "verification failed: %v", err)
	}

	return &pb.VerifyResponse{
		Valid: resp.Valid,
	}, nil
}

// Hash implements pb.CryptoServer.Hash by delegating to the SDK crypto
// client. Only the hash algorithms supported by the SDK crypto client
// (SHA-256, SHA-384, SHA-512) are accepted; an unspecified algorithm
// defaults to SHA-256.
func (a *CryptoServerAdapter) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	switch req.GetAlgorithm() {
	case pb.HashAlgorithm_HASH_ALG_UNSPECIFIED,
		pb.HashAlgorithm_HASH_ALG_SHA256,
		pb.HashAlgorithm_HASH_ALG_SHA384,
		pb.HashAlgorithm_HASH_ALG_SHA512:
		// Supported by the SDK crypto client.
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported hash algorithm: %s", req.GetAlgorithm())
	}

	resp, err := a.client.Hash(ctx, &quicbaas.HashRequest{
		Data:    req.GetData(),
		HashAlg: pbHashAlgorithmToSDK(req.GetAlgorithm()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "hashing failed: %v", err)
	}

	return &pb.HashResponse{
		Algorithm: sdkHashAlgorithmToPb(resp.HashAlg),
		Hash:      resp.Hash,
		Timestamp: time.Now().Unix(),
	}, nil
}

// GenerateHMAC implements pb.CryptoServer.GenerateHMAC by delegating to the
// SDK crypto client. Only the hash algorithms supported by the SDK crypto
// client (SHA-256, SHA-384, SHA-512) are accepted; an unspecified algorithm
// defaults to SHA-256.
func (a *CryptoServerAdapter) GenerateHMAC(ctx context.Context, req *pb.HMACRequest) (*pb.HMACResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}

	switch req.GetHashAlgorithm() {
	case pb.HashAlgorithm_HASH_ALG_UNSPECIFIED,
		pb.HashAlgorithm_HASH_ALG_SHA256,
		pb.HashAlgorithm_HASH_ALG_SHA384,
		pb.HashAlgorithm_HASH_ALG_SHA512:
		// Supported by the SDK crypto client.
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported hash algorithm: %s", req.GetHashAlgorithm())
	}

	resp, err := a.client.GenerateHMAC(ctx, &quicbaas.GenerateHMACRequest{
		KeyID:   req.GetKeyId(),
		Message: req.GetMessage(),
		HashAlg: pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "HMAC generation failed: %v", err)
	}

	return &pb.HMACResponse{
		KeyId:         resp.KeyID,
		KeyVersion:    uint64(resp.KeyVersion),
		Hmac:          resp.HMAC,
		HashAlgorithm: sdkHashAlgorithmToPb(resp.HashAlg),
		Timestamp:     time.Now().Unix(),
	}, nil
}

// VerifyHMAC implements pb.CryptoServer.VerifyHMAC by delegating to the SDK
// crypto client. Only the hash algorithms supported by the SDK crypto client
// (SHA-256, SHA-384, SHA-512) are accepted; an unspecified algorithm
// defaults to SHA-256.
func (a *CryptoServerAdapter) VerifyHMAC(ctx context.Context, req *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Crypto service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if len(req.GetHmac()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "hmac is required")
	}

	switch req.GetHashAlgorithm() {
	case pb.HashAlgorithm_HASH_ALG_UNSPECIFIED,
		pb.HashAlgorithm_HASH_ALG_SHA256,
		pb.HashAlgorithm_HASH_ALG_SHA384,
		pb.HashAlgorithm_HASH_ALG_SHA512:
		// Supported by the SDK crypto client.
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported hash algorithm: %s", req.GetHashAlgorithm())
	}

	resp, err := a.client.VerifyHMAC(ctx, &quicbaas.VerifyHMACRequest{
		KeyID:      req.GetKeyId(),
		Message:    req.GetMessage(),
		HMAC:       req.GetHmac(),
		HashAlg:    pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
		KeyVersion: int(req.GetKeyVersion()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "HMAC verification failed: %v", err)
	}

	return &pb.VerifyHMACResponse{
		KeyId:      req.GetKeyId(),
		KeyVersion: req.GetKeyVersion(),
		Valid:      resp.Valid,
		Timestamp:  time.Now().Unix(),
	}, nil
}

// DEKServerAdapter implements pb.DEKManagementServer by delegating to the SDK
// DEK client, the same client the REST DEK routes call.
type DEKServerAdapter struct {
	pb.UnimplementedDEKManagementServer
	client dekclient.Client
	logger *slog.Logger
}

// NewDEKServerAdapter creates a new DEK server adapter wrapping the SDK client.
func NewDEKServerAdapter(client dekclient.Client, logger *slog.Logger) *DEKServerAdapter {
	return &DEKServerAdapter{
		client: client,
		logger: logger,
	}
}

// CreateDEK creates a new Data Encryption Key.
func (a *DEKServerAdapter) CreateDEK(ctx context.Context, req *pb.CreateDEKRequest) (*pb.CreateDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	resp, err := a.client.CreateDEK(ctx, &dekclient.CreateDEKRequest{
		Path:           req.GetPath(),
		Algorithm:      pbAlgorithmToSDK(req.GetAlgorithm()).String(),
		Description:    req.GetDescription(),
		MaxOperations:  req.GetMaxOperations(),
		MaxBytes:       req.GetMaxBytes(),
		WarningPercent: int(req.GetWarningPercent()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK creation failed: %v", err)
	}

	return &pb.CreateDEKResponse{
		Dek:       dekInfoToPb(resp.DEK),
		Timestamp: time.Now().Unix(),
	}, nil
}

// GetDEK retrieves DEK metadata by path.
func (a *DEKServerAdapter) GetDEK(ctx context.Context, req *pb.GetDEKRequest) (*pb.GetDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	info, err := a.client.GetDEK(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "DEK not found: %v", err)
	}

	return &pb.GetDEKResponse{
		Dek:       dekInfoToPb(info),
		Timestamp: time.Now().Unix(),
	}, nil
}

// RotateDEK creates a new version of an existing DEK.
func (a *DEKServerAdapter) RotateDEK(ctx context.Context, req *pb.RotateDEKRequest) (*pb.RotateDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	resp, err := a.client.RotateDEK(ctx, &dekclient.RotateDEKRequest{
		Path:       req.GetPath(),
		Background: req.GetBackground(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK rotation failed: %v", err)
	}

	return &pb.RotateDEKResponse{
		Path:       resp.Path,
		OldVersion: uint64(resp.OldVersion),
		NewVersion: uint64(resp.NewVersion),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// DeleteDEK removes a DEK.
func (a *DEKServerAdapter) DeleteDEK(ctx context.Context, req *pb.DeleteDEKRequest) (*pb.DeleteDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	resp, err := a.client.DeleteDEK(ctx, &dekclient.DeleteDEKRequest{
		Path:      req.GetPath(),
		Force:     req.GetForce(),
		MigrateTo: req.GetMigrateTo(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK deletion failed: %v", err)
	}

	return &pb.DeleteDEKResponse{
		Path:      resp.Path,
		Deleted:   resp.Deleted,
		Timestamp: time.Now().Unix(),
	}, nil
}

// Algorithm conversion helpers

// pbAlgorithmToSDK converts a protobuf KeyAlgorithm to SDK KeyAlgorithm.
func pbAlgorithmToSDK(alg pb.KeyAlgorithm) kms.KeyAlgorithm {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALG_AES_256_GCM:
		return kms.AlgorithmAES256GCM
	case pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:
		return kms.AlgorithmChaCha20Poly1305
	case pb.KeyAlgorithm_KEY_ALG_RSA_2048:
		return kms.AlgorithmRSA2048
	case pb.KeyAlgorithm_KEY_ALG_RSA_4096:
		return kms.AlgorithmRSA4096
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P256:
		return kms.AlgorithmECDSAP256
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P384:
		return kms.AlgorithmECDSAP384
	case pb.KeyAlgorithm_KEY_ALG_ED25519:
		return kms.AlgorithmED25519
	default:
		return kms.AlgorithmAES256GCM
	}
}

// sdkAlgorithmToPb converts an SDK KeyAlgorithm to protobuf KeyAlgorithm.
func sdkAlgorithmToPb(alg kms.KeyAlgorithm) pb.KeyAlgorithm {
	switch alg {
	case kms.AlgorithmAES256GCM:
		return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case kms.AlgorithmChaCha20Poly1305:
		return pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case kms.AlgorithmRSA2048:
		return pb.KeyAlgorithm_KEY_ALG_RSA_2048
	case kms.AlgorithmRSA4096:
		return pb.KeyAlgorithm_KEY_ALG_RSA_4096
	case kms.AlgorithmECDSAP256:
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P256
	case kms.AlgorithmECDSAP384:
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P384
	case kms.AlgorithmED25519:
		return pb.KeyAlgorithm_KEY_ALG_ED25519
	default:
		return pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED
	}
}

// pbUsagesToSDK converts protobuf KeyUsage slice to SDK KeyUsage slice.
func pbUsagesToSDK(usages []pb.KeyUsage) []kms.KeyUsage {
	result := make([]kms.KeyUsage, 0, len(usages))
	for _, u := range usages {
		switch u {
		case pb.KeyUsage_KEY_USAGE_ENCRYPT:
			result = append(result, kms.KeyUsageEncrypt)
		case pb.KeyUsage_KEY_USAGE_DECRYPT:
			result = append(result, kms.KeyUsageDecrypt)
		case pb.KeyUsage_KEY_USAGE_SIGN:
			result = append(result, kms.KeyUsageSign)
		case pb.KeyUsage_KEY_USAGE_VERIFY:
			result = append(result, kms.KeyUsageVerify)
		case pb.KeyUsage_KEY_USAGE_WRAP_KEY:
			result = append(result, kms.KeyUsageWrap)
		}
	}
	return result
}

// pbHashAlgorithmToSDK converts a protobuf HashAlgorithm to SDK HashAlgorithm.
func pbHashAlgorithmToSDK(alg pb.HashAlgorithm) quicbaas.HashAlgorithm {
	switch alg {
	case pb.HashAlgorithm_HASH_ALG_SHA256:
		return quicbaas.HashSHA256
	case pb.HashAlgorithm_HASH_ALG_SHA384:
		return quicbaas.HashSHA384
	case pb.HashAlgorithm_HASH_ALG_SHA512:
		return quicbaas.HashSHA512
	default:
		return quicbaas.HashSHA256
	}
}

// sdkHashAlgorithmToPb converts an SDK HashAlgorithm to protobuf HashAlgorithm.
func sdkHashAlgorithmToPb(alg quicbaas.HashAlgorithm) pb.HashAlgorithm {
	switch alg {
	case quicbaas.HashSHA256:
		return pb.HashAlgorithm_HASH_ALG_SHA256
	case quicbaas.HashSHA384:
		return pb.HashAlgorithm_HASH_ALG_SHA384
	case quicbaas.HashSHA512:
		return pb.HashAlgorithm_HASH_ALG_SHA512
	default:
		return pb.HashAlgorithm_HASH_ALG_UNSPECIFIED
	}
}

// pbWrappingAlgorithmToSDK converts a protobuf WrappingAlgorithm to the SDK
// WrappingAlgorithm. An unspecified algorithm maps to the SDK zero value
// (RFC 3394 AES Key Wrap).
func pbWrappingAlgorithmToSDK(alg pb.WrappingAlgorithm) kms.WrappingAlgorithm {
	switch alg {
	case pb.WrappingAlgorithm_WRAP_ALG_AES_KWP:
		return kms.WrapAlgAESKWP
	case pb.WrappingAlgorithm_WRAP_ALG_AES_GCM:
		return kms.WrapAlgAESGCM
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256:
		return kms.WrapAlgRSAOAEPSHA256
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384:
		return kms.WrapAlgRSAOAEPSHA384
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512:
		return kms.WrapAlgRSAOAEPSHA512
	case pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW:
		return kms.WrapAlgECDHESA256KW
	default:
		return kms.WrapAlgAESKW
	}
}

// sdkWrappingAlgorithmToPb converts an SDK WrappingAlgorithm to protobuf
// WrappingAlgorithm.
func sdkWrappingAlgorithmToPb(alg kms.WrappingAlgorithm) pb.WrappingAlgorithm {
	switch alg {
	case kms.WrapAlgAESKW:
		return pb.WrappingAlgorithm_WRAP_ALG_AES_KW
	case kms.WrapAlgAESKWP:
		return pb.WrappingAlgorithm_WRAP_ALG_AES_KWP
	case kms.WrapAlgAESGCM:
		return pb.WrappingAlgorithm_WRAP_ALG_AES_GCM
	case kms.WrapAlgRSAOAEPSHA256:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256
	case kms.WrapAlgRSAOAEPSHA384:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384
	case kms.WrapAlgRSAOAEPSHA512:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512
	case kms.WrapAlgECDHESA256KW:
		return pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW
	default:
		return pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED
	}
}

// pbExportFormatToSDK converts a protobuf ExportFormat to the SDK
// ExportFormat. An unspecified format defaults to raw key bytes.
func pbExportFormatToSDK(f pb.ExportFormat) kms.ExportFormat {
	switch f {
	case pb.ExportFormat_EXPORT_FORMAT_JWK:
		return kms.ExportFormatJWK
	case pb.ExportFormat_EXPORT_FORMAT_PEM:
		return kms.ExportFormatPEM
	default:
		return kms.ExportFormatRaw
	}
}

// sdkExportFormatToPb converts an SDK ExportFormat to protobuf ExportFormat.
func sdkExportFormatToPb(f kms.ExportFormat) pb.ExportFormat {
	switch f {
	case kms.ExportFormatRaw:
		return pb.ExportFormat_EXPORT_FORMAT_RAW
	case kms.ExportFormatJWK:
		return pb.ExportFormat_EXPORT_FORMAT_JWK
	case kms.ExportFormatPEM:
		return pb.ExportFormat_EXPORT_FORMAT_PEM
	default:
		return pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED
	}
}
