// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package objectstorage

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ObjectStorageCommands is the operation set every transport adapter
// implements, so one scenario exercises platformctl and each SDK protocol.
type ObjectStorageCommands interface {
	// Name identifies the transport under test.
	Name() string

	// Setup connects the adapter to the running platformd.
	Setup(ctx context.Context) error

	// Teardown releases the adapter's resources.
	Teardown() error

	// Put stores an object.
	Put(ctx context.Context, req *platformv1.PutObjectRequest) (*platformv1.PutObjectResponse, error)

	// Get reads an object and its data.
	Get(ctx context.Context, req *platformv1.GetObjectRequest) (*platformv1.GetObjectResponse, error)

	// Head reads the metadata of an object without its data.
	Head(ctx context.Context, req *platformv1.HeadObjectRequest) (*platformv1.HeadObjectResponse, error)

	// List lists objects by key prefix.
	List(ctx context.Context, req *platformv1.ListObjectsRequest) (*platformv1.ListObjectsResponse, error)

	// Copy copies an object to a new key.
	Copy(ctx context.Context, req *platformv1.CopyObjectRequest) (*platformv1.CopyObjectResponse, error)

	// ListByTag lists the objects carrying a tag.
	ListByTag(ctx context.Context, req *platformv1.ListObjectsByTagRequest) (*platformv1.ListObjectsResponse, error)

	// Delete removes an object.
	Delete(ctx context.Context, req *platformv1.DeleteObjectRequest) (*platformv1.DeleteObjectResponse, error)
}

// ErrConnectionFailed reports an adapter that could not reach platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

// Error implements error.
func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrNoServiceClient reports an SDK client whose transport wired no object
// storage service client.
type ErrNoServiceClient struct {
	Protocol string
}

// Error implements error.
func (e ErrNoServiceClient) Error() string {
	return fmt.Sprintf("the %s SDK client has no object storage service client", e.Protocol)
}

// ErrCLICommandFailed reports a platformctl invocation that exited non-zero.
type ErrCLICommandFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements error.
func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("platformctl %v failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying error.
func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIDecodeFailed reports platformctl output that is not the expected reply.
type ErrCLIDecodeFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements error.
func (e ErrCLIDecodeFailed) Error() string {
	return fmt.Sprintf("decoding platformctl %v output failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying error.
func (e ErrCLIDecodeFailed) Unwrap() error { return e.Err }

// ErrObjectStorageNotConfigured reports a platformd that does not serve the
// object storage service, a missing prerequisite rather than a failed call.
type ErrObjectStorageNotConfigured struct {
	Transport string
	Err       error
}

// Error implements error.
func (e ErrObjectStorageNotConfigured) Error() string {
	return fmt.Sprintf("%s: platformd does not serve object storage: %v", e.Transport, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrObjectStorageNotConfigured) Unwrap() error { return e.Err }
