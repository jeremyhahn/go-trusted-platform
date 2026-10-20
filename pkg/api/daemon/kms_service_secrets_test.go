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
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

var errJSONSecretsList = errors.New("list failed")

// jsonSecretsClient keeps secret data the way the SDK embedded transport
// does: the data map is JSON-encoded on Store and decoded on Get, so a
// []byte value comes back as a base64 string.
type jsonSecretsClient struct {
	extSecretsClientMock
	store   map[string][]byte
	listErr error
	getErr  error
}

func newJSONSecretsClient() *jsonSecretsClient {
	return &jsonSecretsClient{store: make(map[string][]byte)}
}

func (c *jsonSecretsClient) Store(_ context.Context, req *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	encoded, err := json.Marshal(req.Data)
	if err != nil {
		return nil, err
	}
	c.store[req.Path] = encoded
	return &secrets.StoreSecretResponse{Version: 1}, nil
}

func (c *jsonSecretsClient) Get(_ context.Context, path string, _ ...secrets.GetOption) (*secrets.Secret, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	encoded, ok := c.store[path]
	if !ok {
		return nil, errors.New("not found")
	}
	data := make(map[string]interface{})
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	return &secrets.Secret{Path: path, Data: data, Metadata: map[string]string{"k": "v"}, Version: 3}, nil
}

func (c *jsonSecretsClient) List(_ context.Context, prefix string) (*secrets.ListSecretsResponse, error) {
	if c.listErr != nil {
		return nil, c.listErr
	}
	paths := make([]string, 0, len(c.store))
	for path := range c.store {
		if strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}
	return &secrets.ListSecretsResponse{Paths: paths}, nil
}

func (c *jsonSecretsClient) Delete(_ context.Context, path string) error {
	delete(c.store, path)
	return nil
}

func storeTestSecrets(t *testing.T, adapter *SecretsServerAdapter, ids ...string) {
	t.Helper()
	for _, id := range ids {
		_, err := adapter.StoreSecret(context.Background(), &pb.StoreSecretRequest{SecretId: id, Data: []byte("value-" + id)})
		require.NoError(t, err)
	}
}

func TestSecretRawData(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		want    []byte
		wantErr bool
	}{
		{name: "bytes", data: map[string]interface{}{secretRawKey: []byte("abc")}, want: []byte("abc")},
		{name: "base64 string", data: map[string]interface{}{secretRawKey: "YWJj"}, want: []byte("abc")},
		{name: "absent", data: map[string]interface{}{"other": "x"}},
		{name: "null", data: map[string]interface{}{secretRawKey: nil}},
		{name: "not base64", data: map[string]interface{}{secretRawKey: "%%%"}, wantErr: true},
		{name: "number", data: map[string]interface{}{secretRawKey: 42.0}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := secretRawData("s1", tt.data)
			if tt.wantErr {
				var rawErr ErrSecretRawData
				require.ErrorAs(t, err, &rawErr)
				assert.Equal(t, "s1", rawErr.SecretID)
				assert.Equal(t, codes.DataLoss, status.Code(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretsServerAdapter_GetSecret_JSONTransportRoundTrip(t *testing.T) {
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())
	storeTestSecrets(t, adapter, "db/password")

	resp, err := adapter.GetSecret(context.Background(), &pb.GetSecretRequest{SecretId: "db/password"})

	require.NoError(t, err)
	assert.Equal(t, []byte("value-db/password"), resp.GetData())
	assert.Equal(t, uint64(3), resp.GetVersion())
}

func TestSecretsServerAdapter_GetSecret_UndecodableData(t *testing.T) {
	client := newJSONSecretsClient()
	client.store["bad"] = []byte(`{"_raw":"%%%"}`)
	adapter := NewSecretsServerAdapter(client, slog.Default())

	_, err := adapter.GetSecret(context.Background(), &pb.GetSecretRequest{SecretId: "bad"})

	assert.Equal(t, codes.DataLoss, status.Code(err))
}

func TestSecretsServerAdapter_ListSecrets_Pages(t *testing.T) {
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())
	storeTestSecrets(t, adapter, "c", "a", "b")
	ctx := context.Background()

	first, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{Limit: 2})
	require.NoError(t, err)
	require.Len(t, first.GetSecrets(), 2)
	assert.Equal(t, "a", first.GetSecrets()[0].GetSecretId())
	assert.Equal(t, "b", first.GetSecrets()[1].GetSecretId())
	assert.True(t, first.GetHasMore())
	assert.Equal(t, int32(3), first.GetTotalCount())

	second, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{Limit: 2, Cursor: first.GetNextCursor()})
	require.NoError(t, err)
	require.Len(t, second.GetSecrets(), 1)
	assert.Equal(t, "c", second.GetSecrets()[0].GetSecretId())
	assert.False(t, second.GetHasMore())
	assert.Empty(t, second.GetNextCursor())
}

func TestSecretsServerAdapter_ListSecrets_Errors(t *testing.T) {
	client := newJSONSecretsClient()
	adapter := NewSecretsServerAdapter(client, slog.Default())

	_, err := adapter.ListSecrets(context.Background(), &pb.ListSecretsRequest{Cursor: "not-a-number"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	client.listErr = errJSONSecretsList
	_, err = adapter.ListSecrets(context.Background(), &pb.ListSecretsRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestSecretsServerAdapter_DeleteSecret_ReportsDeleted(t *testing.T) {
	client := newJSONSecretsClient()
	adapter := NewSecretsServerAdapter(client, slog.Default())
	storeTestSecrets(t, adapter, "gone")

	resp, err := adapter.DeleteSecret(context.Background(), &pb.DeleteSecretRequest{SecretId: "gone"})

	require.NoError(t, err)
	assert.True(t, resp.GetDeleted())
	assert.Equal(t, "gone", resp.GetSecretId())
	assert.NotContains(t, client.store, "gone")
}

func TestSecretsServerAdapter_GetSecretsByPrefix(t *testing.T) {
	adapter := NewSecretsServerAdapter(newJSONSecretsClient(), slog.Default())
	storeTestSecrets(t, adapter, "app/a", "app/b", "other/c")
	ctx := context.Background()

	withData, err := adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Prefix: "app/", IncludeData: true})
	require.NoError(t, err)
	require.Len(t, withData.GetSecrets(), 2)
	assert.Equal(t, int32(2), withData.GetTotalCount())
	entry := withData.GetSecrets()["app/a"]
	require.NotNil(t, entry)
	assert.Equal(t, []byte("value-app/a"), entry.GetData()[secretPrefixDataKey])
	assert.Equal(t, int64(3), entry.GetVersion())
	assert.Equal(t, "v", entry.GetMetadata()["k"])

	paged, err := adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Prefix: "app/", Limit: 1})
	require.NoError(t, err)
	require.Len(t, paged.GetSecrets(), 1)
	assert.Empty(t, paged.GetSecrets()["app/a"].GetData())
	assert.True(t, paged.GetHasMore())
	assert.Equal(t, "1", paged.GetNextCursor())
}

// unservedSecretsClient refuses the secrets methods the pinned SDK's
// embedded transport does not route, the way that transport answers them.
type unservedSecretsClient struct {
	extSecretsClientMock
}

func unservedSecretsMethod(method string) error {
	return sdkerrors.NewUnimplemented(method, "embedded: unknown method: quicbaas.Secrets/"+method)
}

func (c *unservedSecretsClient) Rotate(context.Context, *secrets.RotateSecretRequest) (*secrets.RotateSecretResponse, error) {
	return nil, unservedSecretsMethod("Rotate")
}

func (c *unservedSecretsClient) UpdateStatus(context.Context, *secrets.UpdateSecretStatusRequest) error {
	return unservedSecretsMethod("UpdateStatus")
}

func (c *unservedSecretsClient) SetRotationPolicy(context.Context, *secrets.SetRotationPolicyRequest) error {
	return unservedSecretsMethod("SetRotationPolicy")
}

func (c *unservedSecretsClient) GetRotationPolicy(context.Context, string) (*secrets.RotationPolicy, error) {
	return nil, unservedSecretsMethod("GetRotationPolicy")
}

// An SDK that does not serve a secrets method answers Unimplemented on the
// wire, not Internal or NotFound, so a caller can tell the declared gap from
// a failure.
func TestSecretsServerAdapter_UnservedMethodsAnswerUnimplemented(t *testing.T) {
	ctx := context.Background()
	adapter := NewSecretsServerAdapter(&unservedSecretsClient{}, slog.Default())

	_, err := adapter.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("x")})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "rotate: %v", err)

	_, err = adapter.UpdateSecretStatus(ctx, &pb.UpdateSecretStatusRequest{SecretId: "db/pw", Status: pb.SecretStatus_SECRET_STATUS_DISABLED})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "update status: %v", err)

	_, err = adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{SecretId: "db/pw", Policy: &pb.SecretRotationPolicy{}})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "set policy: %v", err)

	_, err = adapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: "db/pw"})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "get policy: %v", err)
}

func TestSecretsServerAdapter_GetSecretsByPrefix_Errors(t *testing.T) {
	ctx := context.Background()

	_, err := NewSecretsServerAdapter(nil, slog.Default()).GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	client := newJSONSecretsClient()
	adapter := NewSecretsServerAdapter(client, slog.Default())
	storeTestSecrets(t, adapter, "app/a")

	_, err = adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Cursor: "-1"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	client.getErr = errors.New("backend down")
	_, err = adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Prefix: "app/", IncludeData: true})
	assert.Equal(t, codes.Internal, status.Code(err))

	client.getErr = nil
	client.store["app/bad"] = []byte(`{"_raw":7}`)
	_, err = adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Prefix: "app/", IncludeData: true})
	assert.Equal(t, codes.DataLoss, status.Code(err))

	client.listErr = errJSONSecretsList
	_, err = adapter.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{Prefix: "app/"})
	assert.Equal(t, codes.Internal, status.Code(err))
}
