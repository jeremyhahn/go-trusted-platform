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

package rest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestVTPMBundleReads_ResolveToTheServedRoutes(t *testing.T) {
	t.Run("GetBundle", func(t *testing.T) {
		a, seen := vtpmAdapterReplying(t, `{"id":"b1","mode":"pre-assigned","manifest":{"hostname":"node-1"}}`)

		resp := &platformv1.GetBundleResponse{}
		invokeVTPM(t, a, platformv1.VTPMService_GetBundle_FullMethodName,
			&platformv1.GetBundleRequest{Id: "b1"}, resp)

		assert.Equal(t, http.MethodGet, seen.method)
		assert.Equal(t, "/api/v1/vtpm/bundles/b1", seen.path)
		assert.Equal(t, "b1", resp.GetBundle().GetId())
		assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, resp.GetBundle().GetMode())
		assert.Equal(t, "node-1", resp.GetBundle().GetManifest().GetHostname())
	})
	t.Run("ValidateBundle", func(t *testing.T) {
		a, seen := vtpmAdapterReplying(t, `{"valid":false,"errors":["nvram missing"]}`)

		resp := &platformv1.ValidateBundleResponse{}
		invokeVTPM(t, a, platformv1.VTPMService_ValidateBundle_FullMethodName,
			&platformv1.ValidateBundleRequest{Id: "b1"}, resp)

		assert.Equal(t, http.MethodPost, seen.method)
		assert.Equal(t, "/api/v1/vtpm/bundles/b1/validate", seen.path)
		assert.False(t, resp.GetValid())
		assert.Equal(t, []string{"nvram missing"}, resp.GetErrors())
	})

	paths := []struct {
		name   string
		method string
		req    proto.Message
		suffix string
	}{
		{"GetBundlePath", platformv1.VTPMService_GetBundlePath_FullMethodName,
			&platformv1.GetBundlePathRequest{Id: "b1"}, ""},
		{"GetTPMSocketPath", platformv1.VTPMService_GetTPMSocketPath_FullMethodName,
			&platformv1.GetTPMSocketPathRequest{Id: "b1"}, "/tpm-socket"},
		{"GetNVRAMPath", platformv1.VTPMService_GetNVRAMPath_FullMethodName,
			&platformv1.GetNVRAMPathRequest{Id: "b1"}, "/nvram"},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			a, seen := vtpmAdapterReplying(t, `{"path":"/var/vtpm/b1`+tc.suffix+`"}`)

			resp := &platformv1.GetBundlePathResponse{}
			var reply proto.Message = resp
			socket := &platformv1.GetTPMSocketPathResponse{}
			nvram := &platformv1.GetNVRAMPathResponse{}
			switch tc.name {
			case "GetTPMSocketPath":
				reply = socket
			case "GetNVRAMPath":
				reply = nvram
			}
			invokeVTPM(t, a, tc.method, tc.req, reply)

			want := "/api/v1/vtpm/bundles/b1/path"
			if tc.suffix != "" {
				want = "/api/v1/vtpm/bundles/b1" + tc.suffix
			}
			assert.Equal(t, http.MethodGet, seen.method)
			assert.Equal(t, want, seen.path)
			got := resp.GetPath() + socket.GetPath() + nvram.GetPath()
			assert.Equal(t, "/var/vtpm/b1"+tc.suffix, got)
		})
	}
}

func TestVTPMBundleReads_EmptyIDNeverReachesTheWire(t *testing.T) {
	calls := []struct {
		name       string
		method     string
		req, reply proto.Message
	}{
		{"GetBundle", platformv1.VTPMService_GetBundle_FullMethodName,
			&platformv1.GetBundleRequest{}, &platformv1.GetBundleResponse{}},
		{"ValidateBundle", platformv1.VTPMService_ValidateBundle_FullMethodName,
			&platformv1.ValidateBundleRequest{}, &platformv1.ValidateBundleResponse{}},
		{"GetBundlePath", platformv1.VTPMService_GetBundlePath_FullMethodName,
			&platformv1.GetBundlePathRequest{}, &platformv1.GetBundlePathResponse{}},
		{"GetTPMSocketPath", platformv1.VTPMService_GetTPMSocketPath_FullMethodName,
			&platformv1.GetTPMSocketPathRequest{}, &platformv1.GetTPMSocketPathResponse{}},
		{"GetNVRAMPath", platformv1.VTPMService_GetNVRAMPath_FullMethodName,
			&platformv1.GetNVRAMPathRequest{}, &platformv1.GetNVRAMPathResponse{}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			a, seen := vtpmAdapterReplying(t, `{}`)

			err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply)

			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, seen.path)
		})
	}
}
