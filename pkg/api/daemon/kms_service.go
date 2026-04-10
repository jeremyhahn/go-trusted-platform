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
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
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
	s.kmsAdapter = NewKMSServerAdapter(sdkClient.KMS(), s.logger)
	s.secretsServer = NewSecretsServerAdapter(sdkClient.Secrets(), s.logger)
	s.cryptoServer = NewCryptoServerAdapter(sdkClient.Crypto(), s.logger)
	s.dekServer = NewDEKServerAdapter(sdkClient.KMS(), s.logger)

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

	// Extract algorithm and usage from KeySpec
	var algorithm kms.KeyAlgorithm
	var usage []kms.KeyUsage

	if req.GetKeySpec() != nil {
		algorithm = pbAlgorithmToSDK(req.GetKeySpec().GetAlgorithm())
		usage = pbUsagesToSDK(req.GetKeySpec().GetUsage())
	}

	sdkReq := &kms.GenerateKeyRequest{
		Name:      req.GetName(),
		Algorithm: algorithm,
		Usage:     usage,
	}

	resp, err := a.client.GenerateKey(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key generation failed: %v", err)
	}

	return &pb.GenerateKeyResponse{
		Key: &pb.KeyHandle{
			KeyId:   resp.KeyID,
			Version: uint64(resp.Version),
		},
	}, nil
}

// GetKey implements pb.KeyManagementServer.GetKey.
func (a *KMSServerAdapter) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	keyInfo, err := a.client.GetKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
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

// ListKeys implements pb.KeyManagementServer.ListKeys.
func (a *KMSServerAdapter) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	resp, err := a.client.ListKeys(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list keys failed: %v", err)
	}

	keys := make([]*pb.KeyHandle, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, &pb.KeyHandle{
			KeyId:     k.KeyID,
			Version:   uint64(k.Version),
			Algorithm: sdkAlgorithmToPb(k.Algorithm),
		})
	}

	return &pb.ListKeysResponse{
		Keys: keys,
	}, nil
}

// RotateKey implements pb.KeyManagementServer.RotateKey.
func (a *KMSServerAdapter) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	resp, err := a.client.RotateKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key rotation failed: %v", err)
	}

	return &pb.RotateKeyResponse{
		KeyId:      resp.KeyID,
		NewVersion: uint64(resp.NewVersion),
	}, nil
}

// DeleteKey implements pb.KeyManagementServer.DeleteKey.
func (a *KMSServerAdapter) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	err := a.client.DeleteKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key deletion failed: %v", err)
	}

	return &pb.DeleteKeyResponse{
		KeyId:  req.GetKeyId(),
		Status: pb.KeyStatus_KEY_STATUS_DELETED,
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

	// Convert protobuf data to SDK format
	data := make(map[string]interface{})
	data["_raw"] = req.GetData()

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

	var opts []quicbaas.SecretOption
	if req.GetVersion() > 0 {
		opts = append(opts, quicbaas.WithSecretVersion(int(req.GetVersion())))
	}

	secret, err := a.client.Get(ctx, req.GetSecretId(), opts...)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "secret not found: %v", err)
	}

	// Extract raw data if available
	var data []byte
	if rawData, ok := secret.Data["_raw"].([]byte); ok {
		data = rawData
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

	// ListSecretsRequest doesn't have a prefix field, use empty string
	resp, err := a.client.List(ctx, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secrets failed: %v", err)
	}

	secrets := make([]*pb.Secret, 0, len(resp.Paths))
	for _, path := range resp.Paths {
		secrets = append(secrets, &pb.Secret{
			SecretId: path,
		})
	}

	return &pb.ListSecretsResponse{
		Secrets: secrets,
	}, nil
}

// DeleteSecret implements pb.SecretsManagementServer.DeleteSecret.
func (a *SecretsServerAdapter) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}

	err := a.client.Delete(ctx, req.GetSecretId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "secret deletion failed: %v", err)
	}

	return &pb.DeleteSecretResponse{
		SecretId: req.GetSecretId(),
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

	sdkReq := &quicbaas.EncryptRequest{
		KeyID:     req.GetKeyId(),
		Plaintext: req.GetPlaintext(),
		Context:   req.GetContext(),
	}

	resp, err := a.client.Encrypt(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encryption failed: %v", err)
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

	sdkReq := &quicbaas.DecryptRequest{
		KeyID:      req.GetKeyId(),
		Ciphertext: req.GetCiphertext(),
		Context:    req.GetContext(),
	}

	resp, err := a.client.Decrypt(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decryption failed: %v", err)
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
		return nil, status.Errorf(codes.Internal, "rewrap decryption failed: %v", err)
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
		return nil, status.Errorf(codes.Internal, "rewrap encryption failed: %v", err)
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

	sdkReq := &quicbaas.SignRequest{
		KeyID:   req.GetKeyId(),
		Data:    req.GetMessage(),
		HashAlg: pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
	}

	resp, err := a.client.Sign(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
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

	sdkReq := &quicbaas.VerifyRequest{
		KeyID:     req.GetKeyId(),
		Data:      req.GetMessage(),
		Signature: req.GetSignature(),
		HashAlg:   pbHashAlgorithmToSDK(req.GetHashAlgorithm()),
	}

	resp, err := a.client.Verify(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verification failed: %v", err)
	}

	return &pb.VerifyResponse{
		Valid: resp.Valid,
	}, nil
}

// DEKServerAdapter implements pb.DEKManagementServer by delegating to the SDK KMSClient.
// DEK (Data Encryption Key) operations use the KMS client for key management.
type DEKServerAdapter struct {
	pb.UnimplementedDEKManagementServer
	client quicbaas.KMSClient
	logger *slog.Logger
}

// NewDEKServerAdapter creates a new DEK server adapter wrapping the SDK client.
func NewDEKServerAdapter(client quicbaas.KMSClient, logger *slog.Logger) *DEKServerAdapter {
	return &DEKServerAdapter{
		client: client,
		logger: logger,
	}
}

// CreateDEK implements pb.DEKManagementServer.CreateDEK.
func (a *DEKServerAdapter) CreateDEK(ctx context.Context, req *pb.CreateDEKRequest) (*pb.CreateDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}

	// DEK creation uses the KMS GenerateKey with encryption-specific parameters
	sdkReq := &kms.GenerateKeyRequest{
		Name:      req.GetPath(),
		Algorithm: kms.AlgorithmAES256GCM,
		Usage:     []kms.KeyUsage{kms.KeyUsageEncrypt, kms.KeyUsageDecrypt},
	}

	resp, err := a.client.GenerateKey(ctx, sdkReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK creation failed: %v", err)
	}

	return &pb.CreateDEKResponse{
		Dek: &pb.DEKMetadata{
			Path:    req.GetPath(),
			Version: uint64(resp.Version),
		},
	}, nil
}

// GetDEK implements pb.DEKManagementServer.GetDEK.
func (a *DEKServerAdapter) GetDEK(ctx context.Context, req *pb.GetDEKRequest) (*pb.GetDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}

	keyInfo, err := a.client.GetKey(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "DEK not found: %v", err)
	}

	return &pb.GetDEKResponse{
		Dek: &pb.DEKMetadata{
			Path:    req.GetPath(),
			Version: uint64(keyInfo.Version),
		},
	}, nil
}

// RotateDEK implements pb.DEKManagementServer.RotateDEK.
func (a *DEKServerAdapter) RotateDEK(ctx context.Context, req *pb.RotateDEKRequest) (*pb.RotateDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}

	resp, err := a.client.RotateKey(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK rotation failed: %v", err)
	}

	return &pb.RotateDEKResponse{
		Path:       req.GetPath(),
		NewVersion: uint64(resp.NewVersion),
	}, nil
}

// DeleteDEK implements pb.DEKManagementServer.DeleteDEK.
func (a *DEKServerAdapter) DeleteDEK(ctx context.Context, req *pb.DeleteDEKRequest) (*pb.DeleteDEKResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}

	err := a.client.DeleteKey(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK deletion failed: %v", err)
	}

	return &pb.DeleteDEKResponse{
		Path:    req.GetPath(),
		Deleted: true,
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
