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

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// KeyManagementClient interface for dependency injection using SDK domain types.
type KeyManagementClient interface {
	GenerateKeyDomain(ctx context.Context, params *kmssvc.GenerateKeyParams) (*kmssvc.GenerateKeyResult, error)
	GetKeyDomain(ctx context.Context, keyID string, version uint64) (*kmssvc.GetKeyResult, error)
	ListKeysDomain(ctx context.Context, limit int32, cursor string) (*kmssvc.ListKeysResult, error)
	DeleteKeyDomain(ctx context.Context, keyID string, pendingWindowDays int32, force bool) (*kmssvc.DeleteKeyResult, error)
	RotateKeyDomain(ctx context.Context, keyID string, retainOldVersion bool) (*kmssvc.RotateKeyResult, error)
	BackendStatusDomain(ctx context.Context) (*kmssvc.BackendStatusResult, error)
}

// CryptoManagementClient interface for dependency injection using SDK domain types.
type CryptoManagementClient interface {
	EncryptDomain(ctx context.Context, keyID string, plaintext, aadContext, nonce []byte) (*kmssvc.EncryptResult, error)
	DecryptDomain(ctx context.Context, keyID string, ciphertext, aadContext, nonce []byte, keyVersion uint64) (*kmssvc.DecryptResult, error)
	SignDomain(ctx context.Context, keyID string, message []byte, hashAlgorithm kmssvc.HashAlgorithm) (*kmssvc.SignResult, error)
	VerifyDomain(ctx context.Context, keyID string, message, signature []byte, hashAlgorithm kmssvc.HashAlgorithm, keyVersion uint64) (*kmssvc.VerifyResult, error)
	HMACDomain(ctx context.Context, keyID string, message []byte, hashAlgorithm kmssvc.HashAlgorithm) (*kmssvc.HMACResult, error)
	VerifyHMACDomain(ctx context.Context, keyID string, message, hmac []byte, hashAlgorithm kmssvc.HashAlgorithm, keyVersion uint64) (*kmssvc.VerifyHMACResult, error)
	GenerateRandomDomain(ctx context.Context, numBytes int32) (*kmssvc.GenerateRandomResult, error)
	HashDomain(ctx context.Context, data []byte, algorithm kmssvc.HashAlgorithm) (*kmssvc.HashResult, error)
	GenerateDataKeyDomain(ctx context.Context, keyID string, algorithm kmssvc.KeyAlgorithm, keySize int32, aadContext []byte) (*kmssvc.GenerateDataKeyResult, error)
	GenerateWrappedDataKeyDomain(ctx context.Context, wrappingKeyID string, algorithm kmssvc.KeyAlgorithm, keySize int32, aadContext []byte) (*kmssvc.GenerateWrappedDataKeyResult, error)
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
