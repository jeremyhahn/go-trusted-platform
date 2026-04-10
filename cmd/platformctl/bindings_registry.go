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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// RegistryBinding exposes registry service methods to the Wails frontend.
type RegistryBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewRegistryBinding creates a new RegistryBinding.
func NewRegistryBinding(logger *slog.Logger, conn *ConnectionBinding) *RegistryBinding {
	return &RegistryBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *RegistryBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// List returns a paginated list of artifacts in the registry.
func (b *RegistryBinding) List(repository string, limit int32, offset int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Registry().List(b.conn.ctx, &platformv1.ListArtifactsRequest{
		Repository: repository,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Inspect retrieves detailed metadata about an artifact.
func (b *RegistryBinding) Inspect(repository string, reference string, digest string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Registry().Inspect(b.conn.ctx, &platformv1.InspectArtifactRequest{
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Delete removes an artifact from the registry.
func (b *RegistryBinding) Delete(repository string, reference string, digest string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Registry().Delete(b.conn.ctx, &platformv1.DeleteArtifactRequest{
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Status returns the current status of the registry.
func (b *RegistryBinding) Status() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Registry().Status(b.conn.ctx, &platformv1.RegistryStatusRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
