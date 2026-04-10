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

package secrets

import (
	"context"
	"time"
)

// SecretsCommands defines the central command set for Secrets integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type SecretsCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Secret Management Commands (platformctl secrets ...)
	Store(ctx context.Context, opts StoreOptions) (*StoreResult, error)
	Get(ctx context.Context, name string) (*GetResult, error)
	List(ctx context.Context, opts ListOptions) (*ListResult, error)
	Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error)
	Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error)
	Versions(ctx context.Context, name string) (*VersionsResult, error)
	Version(ctx context.Context, name string, version int) (*VersionResult, error)
	Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error)
	Status(ctx context.Context, name string, enabled bool) (*StatusResult, error)
	Policy(ctx context.Context, name string) (*PolicyResult, error)
	PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error)
	Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error)
}

// StoreOptions contains options for storing a new secret.
type StoreOptions struct {
	Name        string
	Data        []byte
	Description string
	Metadata    map[string]string
	Tags        map[string]string
	ExpiresAt   time.Time
	TenantID    string
	KeyID       string
	Algorithm   string
}

// StoreResult contains the result of a secret store operation.
type StoreResult struct {
	SecretID  string
	Version   uint64
	Timestamp time.Time
}

// GetResult contains the result of a secret retrieval operation.
type GetResult struct {
	SecretID      string
	Version       uint64
	Data          []byte
	Metadata      map[string]string
	Algorithm     string
	KeyIdentifier string
	CreatedAt     time.Time
	Timestamp     time.Time
}

// ListOptions contains options for listing secrets.
type ListOptions struct {
	Limit  int32
	Cursor string
}

// ListResult contains the result of a secrets list operation.
type ListResult struct {
	Secrets    []SecretSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// SecretSummary contains summary information about a secret.
type SecretSummary struct {
	SecretID       string
	Name           string
	CurrentVersion uint64
	Description    string
	Owner          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DeleteResult contains the result of a secret deletion operation.
type DeleteResult struct {
	SecretID  string
	Deleted   bool
	Timestamp time.Time
}

// RotateResult contains the result of a secret rotation operation.
type RotateResult struct {
	SecretID   string
	OldVersion uint64
	NewVersion uint64
	Timestamp  time.Time
}

// VersionsResult contains the result of a secret versions list operation.
type VersionsResult struct {
	SecretID   string
	Versions   []VersionInfo
	HasMore    bool
	NextCursor string
}

// VersionInfo contains information about a specific secret version.
type VersionInfo struct {
	Version   uint64
	CreatedAt time.Time
	CreatedBy string
	ExpiresAt time.Time
	DeletedAt time.Time
}

// VersionResult contains the result of retrieving a specific secret version.
type VersionResult struct {
	SecretID  string
	Version   uint64
	Data      []byte
	Metadata  map[string]string
	CreatedAt time.Time
	CreatedBy string
	ExpiresAt time.Time
	Timestamp time.Time
}

// RollbackResult contains the result of a secret rollback operation.
type RollbackResult struct {
	SecretID   string
	NewVersion uint64
	Timestamp  time.Time
}

// StatusResult contains the result of a secret status update operation.
type StatusResult struct {
	SecretID  string
	Status    string
	Timestamp time.Time
}

// PolicyResult contains the result of a secret policy retrieval operation.
type PolicyResult struct {
	SecretID        string
	Enabled         bool
	IntervalSeconds int64
	NextRotation    time.Time
	RetainVersions  int32
	RotationLambda  string
	UpdatedAt       time.Time
}

// PolicySetOptions contains options for setting a secret rotation policy.
type PolicySetOptions struct {
	Enabled         bool
	IntervalSeconds int64
	RetainVersions  int32
	RotationLambda  string
}

// PolicySetResult contains the result of a secret policy set operation.
type PolicySetResult struct {
	SecretID  string
	Timestamp time.Time
}

// PrefixResult contains the result of a secrets prefix search operation.
type PrefixResult struct {
	Secrets    map[string]PrefixSecretData
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// PrefixSecretData contains secret data from a prefix search.
type PrefixSecretData struct {
	Data     []byte
	Metadata map[string]string
	Version  int64
}
