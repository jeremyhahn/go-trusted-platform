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

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives the object storage service through the platform SDK
// client, pinned to one protocol.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	// bearer, when set, supplies the bearer the transport presents: the
	// REST adapter reaches the admin-gated webservice routes with the
	// harness admin session's bearer.
	bearer  func(ctx context.Context) (string, error)
	client  platform.Client
	objects platformv1.ObjectStorageServiceClient
}

// NewGRPCAdapter returns an adapter pinned to gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoint := helpers.GetGRPCEndpoint()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewRESTAdapter returns an adapter pinned to REST.
func NewRESTAdapter() *SDKAdapter {
	endpoint := helpers.GetRESTEndpoint()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
		bearer: helpers.HarnessAdminSession().Bearer,
	}
}

// NewQUICAdapter returns an adapter pinned to QUIC.
func NewQUICAdapter() *SDKAdapter {
	endpoint := helpers.GetQUICEndpoint()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewMCPAdapter returns an adapter pinned to MCP.
func NewMCPAdapter() *SDKAdapter {
	endpoint := helpers.GetMCPEndpoint()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewUnixAdapter returns an adapter pinned to gRPC over the Unix socket.
func NewUnixAdapter() *SDKAdapter {
	endpoint := helpers.GetSocketPath()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoint),
			)
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the SDK client.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	options := a.options()
	if a.bearer != nil {
		token, err := a.bearer(ctx)
		if err != nil {
			return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
		}
		options.BearerToken = token
	}
	client, err := platform.Connect(ctx, options)
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.objects = client.ObjectStorage()
	if a.objects == nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: ErrNoServiceClient{Protocol: a.name}}
	}
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// Put stores an object.
func (a *SDKAdapter) Put(ctx context.Context, req *platformv1.PutObjectRequest) (*platformv1.PutObjectResponse, error) {
	return a.objects.PutObject(ctx, req)
}

// Get reads an object.
func (a *SDKAdapter) Get(ctx context.Context, req *platformv1.GetObjectRequest) (*platformv1.GetObjectResponse, error) {
	return a.objects.GetObject(ctx, req)
}

// Head reads the metadata of an object.
func (a *SDKAdapter) Head(ctx context.Context, req *platformv1.HeadObjectRequest) (*platformv1.HeadObjectResponse, error) {
	return a.objects.HeadObject(ctx, req)
}

// List lists objects by key prefix.
func (a *SDKAdapter) List(ctx context.Context, req *platformv1.ListObjectsRequest) (*platformv1.ListObjectsResponse, error) {
	return a.objects.ListObjects(ctx, req)
}

// Copy copies an object.
func (a *SDKAdapter) Copy(ctx context.Context, req *platformv1.CopyObjectRequest) (*platformv1.CopyObjectResponse, error) {
	return a.objects.CopyObject(ctx, req)
}

// ListByTag lists the objects carrying a tag.
func (a *SDKAdapter) ListByTag(ctx context.Context, req *platformv1.ListObjectsByTagRequest) (*platformv1.ListObjectsResponse, error) {
	return a.objects.ListObjectsByTag(ctx, req)
}

// Delete removes an object.
func (a *SDKAdapter) Delete(ctx context.Context, req *platformv1.DeleteObjectRequest) (*platformv1.DeleteObjectResponse, error) {
	return a.objects.DeleteObject(ctx, req)
}
