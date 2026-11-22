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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const templateReplyJSON = `{"id":"tpl-1","description":"golden","tpm_state_dir":"/t/tpm","nvram_path":"/t/nvram",` +
	`"secure_boot_keys_dir":"/t/sb","ek_algorithm":"ECC","secure_boot_enabled":true,"created_at":"2026-11-16T12:00:00Z"}`

func TestVTPMTemplates_EveryCallReachesItsRoute(t *testing.T) {
	tests := []struct {
		name   string
		rpc    string
		req    proto.Message
		resp   proto.Message
		reply  string
		method string
		path   string
		body   map[string]any
	}{
		{
			name: "create",
			rpc:  platformv1.VTPMService_CreateTemplate_FullMethodName,
			req: &platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{
				Id: "tpl-1", Description: "golden", EkAlgorithm: platformv1.EKAlgorithm_EK_ALGORITHM_RSA, SecureBootEnabled: true,
			}},
			resp:   &platformv1.CreateTemplateResponse{},
			reply:  templateReplyJSON,
			method: http.MethodPost,
			path:   "/api/v1/vtpm/templates",
			body: map[string]any{
				"id": "tpl-1", "description": "golden", "ek_algorithm": "RSA", "secure_boot_enabled": true,
			},
		},
		{
			name:   "list",
			rpc:    platformv1.VTPMService_ListTemplates_FullMethodName,
			req:    &platformv1.ListTemplatesRequest{},
			resp:   &platformv1.ListTemplatesResponse{},
			reply:  `{"templates":[` + templateReplyJSON + `]}`,
			method: http.MethodGet,
			path:   "/api/v1/vtpm/templates",
		},
		{
			name:   "get",
			rpc:    platformv1.VTPMService_GetTemplate_FullMethodName,
			req:    &platformv1.GetTemplateRequest{Id: "tpl-1"},
			resp:   &platformv1.GetTemplateResponse{},
			reply:  templateReplyJSON,
			method: http.MethodGet,
			path:   "/api/v1/vtpm/templates/tpl-1",
		},
		{
			name:   "delete",
			rpc:    platformv1.VTPMService_DeleteTemplate_FullMethodName,
			req:    &platformv1.DeleteTemplateRequest{Id: "tpl-1"},
			resp:   &platformv1.DeleteTemplateResponse{},
			reply:  `{"success":true,"message":"template deleted"}`,
			method: http.MethodDelete,
			path:   "/api/v1/vtpm/templates/tpl-1",
		},
		{
			name: "clone",
			rpc:  platformv1.VTPMService_CloneTemplate_FullMethodName,
			req: &platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{
				TemplateId: "tpl-1", Hostname: "node-a", Labels: map[string]string{"role": "edge"},
			}},
			resp:   &platformv1.CloneTemplateResponse{},
			reply:  `{"id":"bundle-1","mode":"template","cloned_from":"tpl-1","manifest":{"id":"bundle-1","hostname":"node-a"}}`,
			method: http.MethodPost,
			path:   "/api/v1/vtpm/templates/tpl-1/clone",
			body:   map[string]any{"hostname": "node-a", "labels": map[string]any{"role": "edge"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, seen := vtpmAdapterReplying(t, tt.reply)
			invokeVTPM(t, a, tt.rpc, tt.req, tt.resp)

			assert.Equal(t, tt.method, seen.method)
			assert.Equal(t, tt.path, seen.path)
			if tt.body != nil {
				assert.Equal(t, tt.body, seen.body)
			}
		})
	}
}

func TestVTPMTemplates_RepliesDecode(t *testing.T) {
	created := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	assertTemplate := func(t *testing.T, tpl *platformv1.Template) {
		t.Helper()
		require.NotNil(t, tpl)
		assert.Equal(t, "tpl-1", tpl.GetId())
		assert.Equal(t, "golden", tpl.GetDescription())
		assert.Equal(t, "/t/tpm", tpl.GetTpmStateDir())
		assert.Equal(t, "/t/nvram", tpl.GetNvramPath())
		assert.Equal(t, "/t/sb", tpl.GetSecureBootKeysDir())
		assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, tpl.GetEkAlgorithm())
		assert.True(t, tpl.GetSecureBootEnabled())
		assert.True(t, created.Equal(tpl.GetCreatedAt().AsTime()))
	}

	a, _ := vtpmAdapterReplying(t, templateReplyJSON)
	created1 := &platformv1.CreateTemplateResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_CreateTemplate_FullMethodName,
		&platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{Id: "tpl-1"}}, created1)
	assert.True(t, created1.GetStatus().GetSuccess())
	assertTemplate(t, created1.GetTemplate())

	got := &platformv1.GetTemplateResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_GetTemplate_FullMethodName, &platformv1.GetTemplateRequest{Id: "tpl-1"}, got)
	assertTemplate(t, got.GetTemplate())

	a, _ = vtpmAdapterReplying(t, `{"templates":[`+templateReplyJSON+`]}`)
	list := &platformv1.ListTemplatesResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_ListTemplates_FullMethodName, &platformv1.ListTemplatesRequest{}, list)
	require.Len(t, list.GetTemplates(), 1)
	assertTemplate(t, list.GetTemplates()[0])

	a, _ = vtpmAdapterReplying(t, `{"success":true,"message":"template deleted"}`)
	deleted := &platformv1.DeleteTemplateResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_DeleteTemplate_FullMethodName, &platformv1.DeleteTemplateRequest{Id: "tpl-1"}, deleted)
	assert.True(t, deleted.GetStatus().GetSuccess())
	assert.Equal(t, "template deleted", deleted.GetStatus().GetMessage())

	a, _ = vtpmAdapterReplying(t, `{"id":"bundle-1","mode":"template","cloned_from":"tpl-1","manifest":{"id":"bundle-1","hostname":"node-a"}}`)
	cloned := &platformv1.CloneTemplateResponse{}
	invokeVTPM(t, a, platformv1.VTPMService_CloneTemplate_FullMethodName,
		&platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{TemplateId: "tpl-1", Hostname: "node-a"}}, cloned)
	assert.True(t, cloned.GetStatus().GetSuccess())
	assert.Equal(t, "bundle-1", cloned.GetBundle().GetId())
	assert.Equal(t, "node-a", cloned.GetBundle().GetManifest().GetHostname())
}

func TestVTPMTemplates_RefusedBeforeTheWire(t *testing.T) {
	tests := []struct {
		name string
		rpc  string
		req  proto.Message
		resp proto.Message
	}{
		{"get empty id", platformv1.VTPMService_GetTemplate_FullMethodName,
			&platformv1.GetTemplateRequest{}, &platformv1.GetTemplateResponse{}},
		{"delete empty id", platformv1.VTPMService_DeleteTemplate_FullMethodName,
			&platformv1.DeleteTemplateRequest{}, &platformv1.DeleteTemplateResponse{}},
		{"create empty id", platformv1.VTPMService_CreateTemplate_FullMethodName,
			&platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{}}, &platformv1.CreateTemplateResponse{}},
		{"clone empty template id", platformv1.VTPMService_CloneTemplate_FullMethodName,
			&platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{Hostname: "node-a"}}, &platformv1.CloneTemplateResponse{}},
		{"create unknown ek algorithm", platformv1.VTPMService_CreateTemplate_FullMethodName,
			&platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{Id: "tpl-1", EkAlgorithm: platformv1.EKAlgorithm(99)}},
			&platformv1.CreateTemplateResponse{}},
		{"clone empty hostname", platformv1.VTPMService_CloneTemplate_FullMethodName,
			&platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{TemplateId: "tpl-1"}}, &platformv1.CloneTemplateResponse{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, seen := vtpmAdapterReplying(t, `{}`)
			err := a.Connection().Invoke(context.Background(), tt.rpc, tt.req, tt.resp)

			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, seen.path, "no request reaches the server")
		})
	}
}
