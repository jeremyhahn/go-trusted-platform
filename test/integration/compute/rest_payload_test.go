//go:build integration

package compute_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestUnwrapPayload(t *testing.T) {
	t.Run("enveloped body decodes its payload", func(t *testing.T) {
		body := []byte(`{"code":200,"success":true,"payload":{"vms":[{"id":"vm-1"}]}}`)
		payload, err := unwrapPayload("GET /api/v1/compute/vms", 200, body)
		require.NoError(t, err)
		var out pb.ListVMsResponse
		require.NoError(t, protojson.Unmarshal(payload, &out))
		require.Len(t, out.GetVms(), 1)
		require.Equal(t, "vm-1", out.GetVms()[0].GetId())
	})

	t.Run("bare object decodes as is", func(t *testing.T) {
		body := []byte(`{"vms":[{"id":"vm-1"}]}`)
		payload, err := unwrapPayload("GET /api/v1/compute/vms", 200, body)
		require.NoError(t, err)
		require.Equal(t, body, payload)
	})

	t.Run("empty body yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload("DELETE /api/v1/compute/vms/vm-1", 204, []byte(" \n"))
		require.NoError(t, err)
		require.Nil(t, payload)
	})

	t.Run("null payload yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload("DELETE /api/v1/compute/vms/vm-1", 200, []byte(`{"code":200,"success":true,"payload":null}`))
		require.NoError(t, err)
		require.Nil(t, payload)
	})

	t.Run("malformed body is a request failure", func(t *testing.T) {
		_, err := unwrapPayload("GET /api/v1/compute/vms", 200, []byte(`{"vms":`))
		var reqErr ErrRESTRequestFailed
		require.ErrorAs(t, err, &reqErr)
		require.Equal(t, 200, reqErr.StatusCode)
	})
}
