//go:build integration

package tenant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePayload(t *testing.T) {
	type tenantDoc struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	t.Run("enveloped body decodes its payload", func(t *testing.T) {
		var got tenantDoc
		body := []byte(`{"code":200,"success":true,"payload":{"id":"t-1","name":"acme"}}`)
		require.NoError(t, decodePayload(body, &got))
		require.Equal(t, tenantDoc{ID: "t-1", Name: "acme"}, got)
	})

	t.Run("enveloped array decodes its payload", func(t *testing.T) {
		var got []tenantDoc
		body := []byte(`{"code":200,"success":true,"payload":[{"id":"t-1"},{"id":"t-2"}]}`)
		require.NoError(t, decodePayload(body, &got))
		require.Len(t, got, 2)
		require.Equal(t, "t-2", got[1].ID)
	})

	t.Run("bare object decodes as is", func(t *testing.T) {
		var got tenantDoc
		require.NoError(t, decodePayload([]byte(`{"id":"t-1","name":"acme"}`), &got))
		require.Equal(t, tenantDoc{ID: "t-1", Name: "acme"}, got)
	})

	t.Run("bare array decodes as is", func(t *testing.T) {
		var got []tenantDoc
		require.NoError(t, decodePayload([]byte(` [{"id":"t-1"}]`), &got))
		require.Len(t, got, 1)
		require.Equal(t, "t-1", got[0].ID)
	})

	t.Run("empty body yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload([]byte(" \n"))
		require.NoError(t, err)
		require.Nil(t, payload)
		got := tenantDoc{ID: "unchanged"}
		require.NoError(t, decodePayload(nil, &got))
		require.Equal(t, "unchanged", got.ID)
	})

	t.Run("malformed body fails", func(t *testing.T) {
		var got tenantDoc
		require.Error(t, decodePayload([]byte(`{"id":`), &got))
	})
}
