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

package vtpm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The SDK REST template translations are proven against the real vTPM
// handler (docs/sdk/engineering.md): each rpc goes through the SDK REST
// adapter, the built router and the handler to a fake service, which checks
// the arguments it receives; the test then checks the decoded reply.

func TestSDKREST_CreateTemplate(t *testing.T) {
	created := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	client := connectVTPMSDK(t, &mockVTPMService{
		createTemplateFn: func(_ context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			assert.Equal(t, "golden", opts.ID)
			assert.Equal(t, "golden image", opts.Description)
			assert.Equal(t, vtpm.EKAlgorithmECC, opts.EKAlgorithm)
			assert.True(t, opts.SecureBootEnabled)
			tmpl := createTestTemplate("golden")
			tmpl.EKAlgorithm = vtpm.EKAlgorithmECC
			tmpl.CreatedAt = created
			return tmpl, nil
		},
	})

	resp, err := client.CreateTemplate(context.Background(), &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                "golden",
			Description:       "golden image",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
			SecureBootEnabled: true,
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	tmpl := resp.GetTemplate()
	assert.Equal(t, "golden", tmpl.GetId())
	assert.Equal(t, "Test template", tmpl.GetDescription())
	assert.Equal(t, "/templates/golden/tpm", tmpl.GetTpmStateDir())
	assert.Equal(t, "/templates/golden/ovmf/OVMF_VARS.fd", tmpl.GetNvramPath())
	assert.Equal(t, "/templates/golden/secure-boot-keys", tmpl.GetSecureBootKeysDir())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, tmpl.GetEkAlgorithm())
	assert.True(t, tmpl.GetSecureBootEnabled())
	assert.True(t, created.Equal(tmpl.GetCreatedAt().AsTime()))
}

func TestSDKREST_GetTemplate(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		getTemplateFn: func(_ context.Context, id string) (*vtpm.Template, error) {
			assert.Equal(t, "golden", id)
			return createTestTemplate(id), nil
		},
	})

	resp, err := client.GetTemplate(context.Background(), &platformv1.GetTemplateRequest{Id: "golden"})

	require.NoError(t, err)
	assert.Equal(t, "golden", resp.GetTemplate().GetId())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_RSA, resp.GetTemplate().GetEkAlgorithm())
	assert.Equal(t, "/templates/golden/tpm", resp.GetTemplate().GetTpmStateDir())
}

func TestSDKREST_GetTemplate_NotFoundKeepsItsStatus(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		getTemplateFn: func(_ context.Context, id string) (*vtpm.Template, error) {
			return nil, vtpm.ErrTemplateNotFound{ID: id}
		},
	})

	_, err := client.GetTemplate(context.Background(), &platformv1.GetTemplateRequest{Id: "gone"})

	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDKREST_ListTemplates(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		listTemplatesFn: func(_ context.Context) ([]*vtpm.Template, error) {
			second := createTestTemplate("t2")
			second.EKAlgorithm = vtpm.EKAlgorithmECC
			return []*vtpm.Template{createTestTemplate("t1"), second}, nil
		},
	})

	resp, err := client.ListTemplates(context.Background(), &platformv1.ListTemplatesRequest{})

	require.NoError(t, err)
	require.Len(t, resp.GetTemplates(), 2)
	assert.Equal(t, "t1", resp.GetTemplates()[0].GetId())
	assert.Equal(t, "t2", resp.GetTemplates()[1].GetId())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, resp.GetTemplates()[1].GetEkAlgorithm())
}

func TestSDKREST_DeleteTemplate(t *testing.T) {
	var deleted string
	client := connectVTPMSDK(t, &mockVTPMService{
		deleteTemplateFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	})

	resp, err := client.DeleteTemplate(context.Background(), &platformv1.DeleteTemplateRequest{Id: "golden"})

	require.NoError(t, err)
	assert.Equal(t, "golden", deleted)
	assert.True(t, resp.GetStatus().GetSuccess())
}

func TestSDKREST_CloneTemplate(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		cloneTemplateFn: func(_ context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			assert.Equal(t, "golden", opts.TemplateID)
			assert.Equal(t, "web-01", opts.Hostname)
			assert.Equal(t, map[string]string{"env": "prod"}, opts.Labels)
			return createTestBundle("b1"), nil
		},
	})

	resp, err := client.CloneTemplate(context.Background(), &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: "golden",
			Hostname:   "web-01",
			Labels:     map[string]string{"env": "prod"},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "b1", resp.GetBundle().GetId())
	assert.Equal(t, "test-host", resp.GetBundle().GetManifest().GetHostname())
}

func TestSDKREST_CloneTemplate_MissingHostnameRefused(t *testing.T) {
	called := false
	client := connectVTPMSDK(t, &mockVTPMService{
		cloneTemplateFn: func(_ context.Context, _ *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			called = true
			return nil, nil
		},
	})

	_, err := client.CloneTemplate(context.Background(), &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{TemplateId: "golden"},
	})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.False(t, called, "a refused clone must not reach the service")
}
