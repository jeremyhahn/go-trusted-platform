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

// Package kms provides CLI commands for KMS operations.
//
// NOTE: The testable execution interfaces have been deprecated.
// The platform KMS service does not use the same dependency injection
// pattern as the go-quicbaas KMS service. CLI commands now use
// cli.NewBaseCommand(flags) directly without the testable executor pattern.
package kms

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// KeyManagementClient interface for dependency injection
type KeyManagementClient interface {
	GenerateKey(ctx context.Context, in *platformv1.GenerateKeyRequest, opts ...grpc.CallOption) (*platformv1.GenerateKeyResponse, error)
	GetKey(ctx context.Context, in *platformv1.GetKeyRequest, opts ...grpc.CallOption) (*platformv1.GetKeyResponse, error)
	ListKeys(ctx context.Context, in *platformv1.ListKeysRequest, opts ...grpc.CallOption) (*platformv1.ListKeysResponse, error)
	DeleteKey(ctx context.Context, in *platformv1.DeleteKeyRequest, opts ...grpc.CallOption) (*platformv1.DeleteKeyResponse, error)
	RotateKey(ctx context.Context, in *platformv1.RotateKeyRequest, opts ...grpc.CallOption) (*platformv1.RotateKeyResponse, error)
	BackendStatus(ctx context.Context, in *platformv1.BackendStatusRequest, opts ...grpc.CallOption) (*platformv1.BackendStatusResponse, error)
}

// CryptoManagementClient interface for dependency injection
type CryptoManagementClient interface {
	Encrypt(ctx context.Context, in *platformv1.EncryptRequest, opts ...grpc.CallOption) (*platformv1.EncryptResponse, error)
	Decrypt(ctx context.Context, in *platformv1.DecryptRequest, opts ...grpc.CallOption) (*platformv1.DecryptResponse, error)
	Sign(ctx context.Context, in *platformv1.SignRequest, opts ...grpc.CallOption) (*platformv1.SignResponse, error)
	Verify(ctx context.Context, in *platformv1.VerifyRequest, opts ...grpc.CallOption) (*platformv1.VerifyResponse, error)
	GenerateHMAC(ctx context.Context, in *platformv1.HMACRequest, opts ...grpc.CallOption) (*platformv1.HMACResponse, error)
	VerifyHMAC(ctx context.Context, in *platformv1.VerifyHMACRequest, opts ...grpc.CallOption) (*platformv1.VerifyHMACResponse, error)
	GenerateRandom(ctx context.Context, in *platformv1.GenerateRandomRequest, opts ...grpc.CallOption) (*platformv1.GenerateRandomResponse, error)
	Hash(ctx context.Context, in *platformv1.HashRequest, opts ...grpc.CallOption) (*platformv1.HashResponse, error)
	GenerateDataKey(ctx context.Context, in *platformv1.GenerateDataKeyRequest, opts ...grpc.CallOption) (*platformv1.GenerateDataKeyResponse, error)
	GenerateWrappedDataKey(ctx context.Context, in *platformv1.GenerateWrappedDataKeyRequest, opts ...grpc.CallOption) (*platformv1.GenerateWrappedDataKeyResponse, error)
}

// Printer interface for dependency injection
type Printer interface {
	Print(v interface{}) error
	PrintKeyValue(key, value string)
	PrintSuccess(message string)
	PrintInfo(message string)
	PrintWarning(message string)
	PrintError(message string)
}

// CommandExecutor holds dependencies for command execution
type CommandExecutor struct {
	KMSClient    KeyManagementClient
	CryptoClient CryptoManagementClient
	Printer      Printer
	Ctx          context.Context
	OutputFormat cli.OutputFormat
	Output       io.Writer
}

// ErrKeyGenerationFailed is returned when key generation fails
type ErrKeyGenerationFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyGenerationFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to generate key %s: %v", e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to generate key %s", e.KeyID)
}

// ErrKeyGetFailed is returned when getting a key fails
type ErrKeyGetFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyGetFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to get key %s: %v", e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to get key %s", e.KeyID)
}

// ErrKeyListFailed is returned when listing keys fails
type ErrKeyListFailed struct {
	Err error
}

func (e ErrKeyListFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to list keys: %v", e.Err)
	}
	return "failed to list keys"
}

// ErrKeyDeleteFailed is returned when deleting a key fails
type ErrKeyDeleteFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyDeleteFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to delete key %s: %v", e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to delete key %s", e.KeyID)
}

// ErrKeyRotateFailed is returned when rotating a key fails
type ErrKeyRotateFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyRotateFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to rotate key %s: %v", e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to rotate key %s", e.KeyID)
}

// ErrTestableNotImplemented is returned when testable execution functions are called
type ErrTestableNotImplemented struct {
	Function string
}

func (e ErrTestableNotImplemented) Error() string {
	return fmt.Sprintf("testable execution function %s is not implemented in platform KMS service", e.Function)
}
