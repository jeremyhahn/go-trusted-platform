package daemon

import (
	"context"
	"log/slog"
	"math"
	"testing"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPrefixProvider(t *testing.T, ids ...string) (*MCPServiceProvider, *jsonSecretsClient) {
	t.Helper()
	client := newJSONSecretsClient()
	adapter := NewSecretsServerAdapter(client, slog.Default())
	storeTestSecrets(t, adapter, ids...)
	provider := &MCPServiceProvider{}
	provider.SetSecretsPrefixService(adapter)
	return provider, client
}

func TestMCPServiceProviderSecretGetByPrefix(t *testing.T) {
	provider, _ := newPrefixProvider(t, "app/a", "app/b", "other/c")
	ctx := context.Background()

	result, err := provider.SecretGetByPrefix(ctx, "app/", true, 0, "")
	require.NoError(t, err)
	resp, ok := result.(*pb.GetSecretsByPrefixResponse)
	require.True(t, ok, "result is %T", result)
	require.Len(t, resp.GetSecrets(), 2)
	assert.NotContains(t, resp.GetSecrets(), "other/c")
	assert.Equal(t, []byte("value-app/b"), resp.GetSecrets()["app/b"].GetData()[secretPrefixDataKey])

	result, err = provider.SecretGetByPrefix(ctx, "app/", false, 1, "")
	require.NoError(t, err)
	paged := result.(*pb.GetSecretsByPrefixResponse)
	require.Len(t, paged.GetSecrets(), 1)
	assert.True(t, paged.GetHasMore())

	result, err = provider.SecretGetByPrefix(ctx, "app/", false, 1, paged.GetNextCursor())
	require.NoError(t, err)
	next := result.(*pb.GetSecretsByPrefixResponse)
	require.Len(t, next.GetSecrets(), 1)
	assert.False(t, next.GetHasMore())

	var seen []string
	for _, page := range []*pb.GetSecretsByPrefixResponse{paged, next} {
		for id, entry := range page.GetSecrets() {
			seen = append(seen, id)
			assert.Empty(t, entry.GetData(), "include_data unset returns no data for %s", id)
		}
	}
	assert.ElementsMatch(t, []string{"app/a", "app/b"}, seen)
}

func TestMCPServiceProviderSecretGetByPrefix_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("NoServiceWired", func(t *testing.T) {
		_, err := (&MCPServiceProvider{}).SecretGetByPrefix(ctx, "app/", false, 0, "")
		var unavailable ErrServiceNotAvailable
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, "secrets", unavailable.Service)
	})

	t.Run("EmptyPrefix", func(t *testing.T) {
		provider, _ := newPrefixProvider(t)
		_, err := provider.SecretGetByPrefix(ctx, "", false, 0, "")
		var invalid ErrKMSInvalidParameter
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "prefix", invalid.Parameter)
	})

	t.Run("LimitOutOfRange", func(t *testing.T) {
		provider, _ := newPrefixProvider(t)
		for _, limit := range []int{-1, math.MaxInt32 + 1} {
			_, err := provider.SecretGetByPrefix(ctx, "app/", false, limit, "")
			var invalid ErrKMSInvalidParameter
			require.ErrorAs(t, err, &invalid, "limit %d", limit)
			assert.Equal(t, "limit", invalid.Parameter)
		}
	})

	t.Run("UpstreamError", func(t *testing.T) {
		provider, client := newPrefixProvider(t, "app/a")
		client.listErr = errJSONSecretsList
		_, err := provider.SecretGetByPrefix(ctx, "app/", false, 0, "")
		var opErr ErrSecretsOperationFailed
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "GetSecretsByPrefix", opErr.Operation)
	})
}
