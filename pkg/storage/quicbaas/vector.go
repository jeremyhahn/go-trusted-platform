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

package quicbaas

import (
	"context"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
)

// Reasons ErrVectorUnavailable carries.
const (
	vectorNotCompiledReason = "this build carries no vector service (rebuild with WITH_VECTOR=1)"
	vectorDisabledReason    = "the vector service is disabled (quicbaas.vector.enabled is false)"
)

// VectorServiceConfig turns the embedded server's vector database on
// (vector.enabled). It needs a build that carries the vector service
// (WITH_VECTOR=1, which adds the vector and qrdb_vector tags): Validate
// refuses an enabled section in any other build.
type VectorServiceConfig struct {
	// Enabled starts the embedded server's vector service. Default false.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// Active reports whether the vector service is enabled. A nil receiver is
// the absent section and means disabled.
func (c *VectorServiceConfig) Active() bool {
	return c != nil && c.Enabled
}

// validateVector refuses a vector section the build cannot serve.
func (c *Config) validateVector() error {
	if c.Vector.Active() && !vectorCompiled {
		return ErrInvalidConfig{Field: "Vector", Reason: vectorNotCompiledReason}
	}
	return nil
}

// vectorUnavailableReason returns why the embedded server serves no vector
// service, or "" when it does.
func (c *Config) vectorUnavailableReason() string {
	if !vectorCompiled {
		return vectorNotCompiledReason
	}
	if !c.Vector.Active() {
		return vectorDisabledReason
	}
	return ""
}

// withVectorAvailability returns client unchanged when the embedded server
// serves the vector service, and otherwise a client whose Vector() fails
// every call with ErrVectorUnavailable.
func withVectorAvailability(cfg *Config, client quicbaas.Client) quicbaas.Client {
	reason := cfg.vectorUnavailableReason()
	if reason == "" {
		return client
	}
	return clientWithoutVector{
		Client: client,
		vector: unavailableVectorClient{err: ErrVectorUnavailable{Reason: reason}},
	}
}

// clientWithoutVector is an SDK client whose vector service is absent.
// Every other service is the wrapped client's.
type clientWithoutVector struct {
	quicbaas.Client
	vector quicbaas.VectorClient
}

// Vector returns the client that reports the vector service absent.
func (c clientWithoutVector) Vector() quicbaas.VectorClient {
	return c.vector
}

// unavailableVectorClient answers every vector.Client call with err.
type unavailableVectorClient struct {
	err ErrVectorUnavailable
}

func (c unavailableVectorClient) CreateNamespace(context.Context, *vector.CreateNamespaceRequest) (*vector.CreateNamespaceResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) DeleteNamespace(context.Context, *vector.DeleteNamespaceRequest) (*vector.DeleteNamespaceResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) ListNamespaces(context.Context, *vector.ListNamespacesRequest) (*vector.ListNamespacesResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) GetNamespaceInfo(context.Context, *vector.GetNamespaceInfoRequest) (*vector.GetNamespaceInfoResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Upsert(context.Context, *vector.UpsertRequest) (*vector.UpsertResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) BatchUpsert(context.Context, *vector.BatchUpsertRequest) (*vector.BatchUpsertResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Get(context.Context, *vector.GetRequest) (*vector.GetResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Delete(context.Context, *vector.DeleteRequest) (*vector.DeleteResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) BatchDelete(context.Context, *vector.BatchDeleteRequest) (*vector.BatchDeleteResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) List(context.Context, *vector.ListVectorsRequest) (*vector.ListVectorsResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) UpdateMetadata(context.Context, *vector.UpdateMetadataRequest) (*vector.UpdateMetadataResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) SearchSimilar(context.Context, *vector.SearchSimilarRequest) (*vector.SearchSimilarResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) SearchByID(context.Context, *vector.SearchByIDRequest) (*vector.SearchByIDResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) HybridSearch(context.Context, *vector.HybridSearchRequest) (*vector.HybridSearchResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) SearchByMetadata(context.Context, *vector.SearchByMetadataRequest) (*vector.SearchByMetadataResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) RebuildIndex(context.Context, *vector.RebuildIndexRequest) (*vector.RebuildIndexResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) GetIndexProgress(context.Context, *vector.GetIndexProgressRequest) (*vector.GetIndexProgressResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Export(context.Context, *vector.ExportRequest) ([]*vector.ExportResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Import(context.Context, []*vector.ImportRequest) (*vector.ImportResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) Compact(context.Context, *vector.CompactRequest) (*vector.CompactResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) GetCompactionProgress(context.Context, *vector.GetCompactionProgressRequest) (*vector.GetCompactionProgressResponse, error) {
	return nil, c.err
}

func (c unavailableVectorClient) GetStats(context.Context, *vector.GetStatsRequest) (*vector.GetStatsResponse, error) {
	return nil, c.err
}
