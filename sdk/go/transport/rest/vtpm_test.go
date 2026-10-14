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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vtpmCall is what the fake daemon saw of one vTPM request.
type vtpmCall struct {
	method string
	path   string
	query  url.Values
	body   map[string]any
}

// vtpmAdapterReplying starts a fake daemon that answers every vTPM request
// with payload in the platform envelope and records the request.
func vtpmAdapterReplying(t *testing.T, payload string) (*Adapter, *vtpmCall) {
	t.Helper()
	seen := &vtpmCall{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err == nil && len(raw) > 0 {
			seen.body = map[string]any{}
			err = json.Unmarshal(raw, &seen.body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen.method, seen.path, seen.query = r.Method, r.URL.Path, r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":` + payload + `}`))
	})
	return a, seen
}

func invokeVTPM(t *testing.T, a *Adapter, method string, req, resp proto.Message) {
	t.Helper()
	require.NoError(t, a.Connection().Invoke(context.Background(), method, req, resp))
}

func TestVTPMStart_PutsTheBundleIDInThePath(t *testing.T) {
	a, seen := vtpmAdapterReplying(t,
		`{"status":{"success":true},"bundle_id":"b1","running":true,"socket_path":"/run/b1.sock"}`)

	resp := &platformv1.StartVTPMResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_StartVTPM_FullMethodName,
		&platformv1.StartVTPMRequest{BundleId: "b1"}, resp)

	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/api/v1/vtpm/bundles/b1/start", seen.path)
	assert.NotContains(t, seen.body, "bundle_id", "the bundle id travels in the path")
	assert.True(t, resp.GetRunning())
	assert.Equal(t, "/run/b1.sock", resp.GetSocketPath())
}

func TestVTPMQuote_SendsNonceAndPCRsAndDecodesPCRValues(t *testing.T) {
	a, seen := vtpmAdapterReplying(t,
		`{"status":{"success":true},"bundle_id":"b1","quote":"cXVvdGU=","signature":"c2ln",`+
			`"pcr_values":{"7":"AAE="},"hash_algorithm":"SHA256"}`)

	resp := &platformv1.QuoteVTPMResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_QuoteVTPM_FullMethodName,
		&platformv1.QuoteVTPMRequest{BundleId: "b1", Nonce: []byte("nonce"), Pcrs: []int32{0, 7}}, resp)

	assert.Equal(t, "/api/v1/vtpm/bundles/b1/quote", seen.path)
	assert.Equal(t, "bm9uY2U=", seen.body["nonce"], "bytes travel base64")
	assert.Equal(t, []any{float64(0), float64(7)}, seen.body["pcrs"])
	assert.Equal(t, []byte("quote"), resp.GetQuote())
	assert.Equal(t, []byte("sig"), resp.GetSignature())
	assert.Equal(t, map[int32][]byte{7: {0x00, 0x01}}, resp.GetPcrValues())
	assert.Equal(t, "SHA256", resp.GetHashAlgorithm())
}

func TestVTPMSeal_SendsDataAndAuthValue(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{"status":{"success":true},"bundle_id":"b1","sealed_data":"c2VhbGVk"}`)

	resp := &platformv1.SealVTPMResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_SealVTPM_FullMethodName,
		&platformv1.SealVTPMRequest{BundleId: "b1", Data: []byte("secret"), AuthValue: "pw"}, resp)

	assert.Equal(t, "/api/v1/vtpm/bundles/b1/seal", seen.path)
	assert.Equal(t, "c2VjcmV0", seen.body["data"])
	assert.Equal(t, "pw", seen.body["auth_value"])
	assert.Equal(t, []byte("sealed"), resp.GetSealedData())
}

func TestVTPMReadPCR_NamesTheIndexInTheQuery(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{"status":{"success":true},"bundle_id":"b1","pcr_index":7,"value":"AAE="}`)

	resp := &platformv1.ReadVTPMPCRResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_ReadVTPMPCR_FullMethodName,
		&platformv1.ReadVTPMPCRRequest{BundleId: "b1", PcrIndex: 7}, resp)

	assert.Equal(t, http.MethodGet, seen.method)
	assert.Equal(t, "/api/v1/vtpm/bundles/b1/pcrs", seen.path)
	assert.Equal(t, "7", seen.query.Get("pcr_index"))
	assert.Equal(t, int32(7), resp.GetPcrIndex())
	assert.Equal(t, []byte{0x00, 0x01}, resp.GetValue())
}

func TestVTPMCreateBundle_SendsTheDaemonBodyAndDecodesTheBundle(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{"id":"b1","mode":"template","manifest":{"id":"b1","mode":"template","ek_algorithm":"RSA"}}`)

	resp := &platformv1.CreateBundleResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_CreateBundle_FullMethodName,
		&platformv1.CreateBundleRequest{Options: &platformv1.CreateBundleOptions{
			Mode:        platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
			EkAlgorithm: platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
		}}, resp)

	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/api/v1/vtpm/bundles", seen.path)
	assert.Equal(t, "template", seen.body["mode"])
	assert.Equal(t, "RSA", seen.body["ek_algorithm"])
	assert.NotContains(t, seen.body, "options", "the daemon takes the options flat")
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, resp.GetBundle().GetMode())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_RSA, resp.GetBundle().GetManifest().GetEkAlgorithm())
}

func TestVTPMListBundles_FiltersTravelInTheQuery(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{"bundles":[{"id":"b1","mode":"pre-assigned"}],"total":1}`)

	resp := &platformv1.ListBundlesResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_ListBundles_FullMethodName,
		&platformv1.ListBundlesRequest{Options: &platformv1.ListBundleOptions{
			Mode:            platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Labels:          map[string]string{"env": "prod"},
			Limit:           10,
			DeviceProfileId: 3,
		}}, resp)

	assert.Equal(t, http.MethodGet, seen.method)
	assert.Equal(t, "/api/v1/vtpm/bundles", seen.path)
	assert.Equal(t, "BUNDLE_MODE_PRE_ASSIGNED", seen.query.Get("mode"))
	assert.Equal(t, []string{"env=prod"}, seen.query["labels"])
	assert.Equal(t, "10", seen.query.Get("limit"))
	assert.Equal(t, "3", seen.query.Get("device_profile_id"))
	assert.Empty(t, seen.query.Get("offset"), "a zero offset is omitted")
	assert.Equal(t, int32(1), resp.GetTotal())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, resp.GetBundles()[0].GetMode())
}

func TestVTPMDeleteBundle_PutsTheIDInThePath(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{"success":true,"message":"bundle deleted"}`)

	resp := &platformv1.DeleteBundleResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_DeleteBundle_FullMethodName,
		&platformv1.DeleteBundleRequest{Id: "b1"}, resp)

	assert.Equal(t, http.MethodDelete, seen.method)
	assert.Equal(t, "/api/v1/vtpm/bundles/b1", seen.path)
	assert.True(t, resp.GetStatus().GetSuccess())
}

func TestVTPMRuntime_EmptyBundleIDNeverReachesTheWire(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{}`)

	err := a.Connection().Invoke(context.Background(), platformv1.VTPMService_StartVTPM_FullMethodName,
		&platformv1.StartVTPMRequest{}, &platformv1.StartVTPMResponse{})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, seen.path)
}

func TestVTPMCreateBundle_UnknownModeNeverReachesTheWire(t *testing.T) {
	a, seen := vtpmAdapterReplying(t, `{}`)

	err := a.Connection().Invoke(context.Background(), platformv1.VTPMService_CreateBundle_FullMethodName,
		&platformv1.CreateBundleRequest{Options: &platformv1.CreateBundleOptions{Mode: platformv1.BundleMode(99)}},
		&platformv1.CreateBundleResponse{})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, seen.path)
}
