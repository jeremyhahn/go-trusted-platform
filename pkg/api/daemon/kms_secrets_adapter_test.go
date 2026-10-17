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
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// jsonSecretsClient keeps each secret's data map the way the go-quicbaas
// secrets backend does: JSON-encoded, so bytes read back as base64 text.
// List answers the paths in store order, which is not sorted.
type jsonSecretsClient struct {
	extSecretsClientMock
	paths []string
	data  map[string]map[string]interface{}
}

func newJSONSecretsClient() *jsonSecretsClient {
	return &jsonSecretsClient{data: map[string]map[string]interface{}{}}
}

func (c *jsonSecretsClient) Store(ctx context.Context, req *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	raw, err := json.Marshal(req.Data)
	if err != nil {
		return nil, err
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	if _, ok := c.data[req.Path]; !ok {
		c.paths = append(c.paths, req.Path)
	}
	c.data[req.Path] = decoded
	return &secrets.StoreSecretResponse{Version: 1}, nil
}

func (c *jsonSecretsClient) Get(ctx context.Context, path string, opts ...secrets.GetOption) (*secrets.Secret, error) {
	data, ok := c.data[path]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return &secrets.Secret{Path: path, Data: data, Version: 1}, nil
}

func (c *jsonSecretsClient) List(ctx context.Context, prefix string) (*secrets.ListSecretsResponse, error) {
	return &secrets.ListSecretsResponse{Paths: c.paths}, nil
}

func TestSecretsServerAdapter_GetSecret_ReturnsStoredBytes(t *testing.T) {
	ctx := context.Background()
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())
	stored := []byte{0x00, 0xff, 'p', 'w', 0x7f}

	_, err := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: "db/password", Data: stored})
	require.NoError(t, err)

	got, err := adapter.GetSecret(ctx, &pb.GetSecretRequest{SecretId: "db/password"})
	require.NoError(t, err)
	assert.Equal(t, stored, got.GetData())
}

func TestSecretsServerAdapter_GetSecret_ReadsValueStoredOverREST(t *testing.T) {
	client := newJSONSecretsClient()
	// REST stores the caller's bytes under the same "value" key.
	client.data["api/token"] = map[string]interface{}{"value": "c2VjcmV0"}
	client.paths = []string{"api/token"}
	adapter := NewSecretsServerAdapter(client, slog.Default())

	got, err := adapter.GetSecret(context.Background(), &pb.GetSecretRequest{SecretId: "api/token"})
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), got.GetData())
}

func TestSecretsServerAdapter_GetSecret_MalformedValueIsInternal(t *testing.T) {
	client := newJSONSecretsClient()
	client.data["api/token"] = map[string]interface{}{"value": "not base64!"}
	adapter := NewSecretsServerAdapter(client, slog.Default())

	_, err := adapter.GetSecret(context.Background(), &pb.GetSecretRequest{SecretId: "api/token"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// storeSecrets stores one secret per path, in the order given.
func storeSecrets(t *testing.T, adapter *SecretsServerAdapter, paths ...string) {
	t.Helper()
	for _, path := range paths {
		_, err := adapter.StoreSecret(context.Background(), &pb.StoreSecretRequest{SecretId: path, Data: []byte(path)})
		require.NoError(t, err)
	}
}

func secretIDs(resp *pb.ListSecretsResponse) []string {
	ids := make([]string, 0, len(resp.GetSecrets()))
	for _, s := range resp.GetSecrets() {
		ids = append(ids, s.GetSecretId())
	}
	return ids
}

func TestSecretsServerAdapter_ListSecrets_PagesByLimitAndCursor(t *testing.T) {
	ctx := context.Background()
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())
	storeSecrets(t, adapter, "c", "a", "b")

	first, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, secretIDs(first))
	assert.Equal(t, "b", first.GetNextCursor())
	assert.True(t, first.GetHasMore())
	assert.Equal(t, int32(3), first.GetTotalCount())

	last, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{Limit: 2, Cursor: first.GetNextCursor()})
	require.NoError(t, err)
	assert.Equal(t, []string{"c"}, secretIDs(last))
	assert.Empty(t, last.GetNextCursor())
	assert.False(t, last.GetHasMore())

	all, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, secretIDs(all))
	assert.Empty(t, all.GetNextCursor())
}

func TestSecretsServerAdapter_ListSecrets_NegativeLimitIsInvalidArgument(t *testing.T) {
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())

	_, err := adapter.ListSecrets(context.Background(), &pb.ListSecretsRequest{Limit: -1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
