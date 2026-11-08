//go:build integration

package ca

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnwrapPayload(t *testing.T) {
	t.Run("enveloped body decodes its payload", func(t *testing.T) {
		body := []byte(`{"code":200,"success":true,"payload":{"serial":"01"}}`)
		payload, err := unwrapPayload(body)
		require.NoError(t, err)
		require.JSONEq(t, `{"serial":"01"}`, string(payload))
	})

	t.Run("bare object decodes as is", func(t *testing.T) {
		body := []byte(`{"serial":"01"}`)
		payload, err := unwrapPayload(body)
		require.NoError(t, err)
		require.Equal(t, body, payload)
	})

	t.Run("bare array decodes as is", func(t *testing.T) {
		body := []byte(`[{"serial":"01"}]`)
		payload, err := unwrapPayload(body)
		require.NoError(t, err)
		require.Equal(t, body, payload)
	})

	t.Run("empty body yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload([]byte(" \n"))
		require.NoError(t, err)
		require.Nil(t, payload)
	})

	t.Run("null payload yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload([]byte(`{"code":200,"success":true,"payload":null}`))
		require.NoError(t, err)
		require.Nil(t, payload)
	})

	t.Run("malformed body fails", func(t *testing.T) {
		_, err := unwrapPayload([]byte(`{"serial":`))
		require.Error(t, err)
	})
}
