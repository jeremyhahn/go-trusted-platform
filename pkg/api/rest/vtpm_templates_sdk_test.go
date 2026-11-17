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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// pathedTemplateService is the handler mock whose created templates carry
// the on-disk paths a real vtpm.Service fills in.
type pathedTemplateService struct {
	*mockVTPMService
}

func (s *pathedTemplateService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	tpl, err := s.mockVTPMService.CreateTemplate(ctx, opts)
	if err != nil {
		return nil, err
	}
	setTemplatePaths(tpl)
	return tpl, nil
}

func setTemplatePaths(tpl *vtpm.Template) {
	tpl.TPMStateDir = "/var/lib/vtpm/templates/" + tpl.ID + "/tpm"
	tpl.NVRAMPath = "/var/lib/vtpm/templates/" + tpl.ID + "/OVMF_VARS.fd"
	tpl.SecureBootKeysDir = "/var/lib/vtpm/templates/" + tpl.ID + "/keys"
}

// connectDaemonVTPMSDK serves the daemon's vTPM handlers over TLS and returns
// the SDK client that reaches them through the REST transport.
func connectDaemonVTPMSDK(t *testing.T, service VTPMServiceInterface) platformv1.VTPMServiceClient {
	t.Helper()

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewVTPMHandlers(service, slog.New(slog.DiscardHandler)).RegisterRoutes(root)

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewVTPMServiceClient(adapter.Connection())
}

func assertTemplatePaths(t *testing.T, id string, tpl *platformv1.Template) {
	t.Helper()
	assert.Equal(t, "/var/lib/vtpm/templates/"+id+"/tpm", tpl.GetTpmStateDir())
	assert.Equal(t, "/var/lib/vtpm/templates/"+id+"/OVMF_VARS.fd", tpl.GetNvramPath())
	assert.Equal(t, "/var/lib/vtpm/templates/"+id+"/keys", tpl.GetSecureBootKeysDir())
}

func seededTemplateService(ids ...string) *mockVTPMService {
	svc := newMockVTPMService()
	for _, id := range ids {
		tpl := &vtpm.Template{
			ID:                id,
			Description:       "golden image",
			EKAlgorithm:       vtpm.EKAlgorithmECC,
			SecureBootEnabled: true,
			CreatedAt:         time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC),
		}
		setTemplatePaths(tpl)
		svc.templates[id] = tpl
	}
	return svc
}

func TestDaemonSDKREST_CreateTemplateCarriesPaths(t *testing.T) {
	client := connectDaemonVTPMSDK(t, &pathedTemplateService{newMockVTPMService()})

	resp, err := client.CreateTemplate(context.Background(), &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                "golden",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
			SecureBootEnabled: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "golden", resp.GetTemplate().GetId())
	assertTemplatePaths(t, "golden", resp.GetTemplate())
}

func TestDaemonSDKREST_GetTemplateCarriesPaths(t *testing.T) {
	client := connectDaemonVTPMSDK(t, seededTemplateService("golden"))

	resp, err := client.GetTemplate(context.Background(), &platformv1.GetTemplateRequest{Id: "golden"})
	require.NoError(t, err)
	assert.Equal(t, "golden image", resp.GetTemplate().GetDescription())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, resp.GetTemplate().GetEkAlgorithm())
	assertTemplatePaths(t, "golden", resp.GetTemplate())
}

func TestDaemonSDKREST_ListTemplatesCarryPaths(t *testing.T) {
	client := connectDaemonVTPMSDK(t, seededTemplateService("golden"))

	resp, err := client.ListTemplates(context.Background(), &platformv1.ListTemplatesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetTemplates(), 1)
	assertTemplatePaths(t, "golden", resp.GetTemplates()[0])
}

func TestDaemonSDKREST_CloneTemplateCarriesManifest(t *testing.T) {
	client := connectDaemonVTPMSDK(t, seededTemplateService("golden"))

	resp, err := client.CloneTemplate(context.Background(), &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: "golden",
			Hostname:   "web-01",
			Labels:     map[string]string{"env": "prod"},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())

	bundle := resp.GetBundle()
	assert.NotEmpty(t, bundle.GetId())
	assert.Equal(t, "golden", bundle.GetClonedFrom())

	manifest := bundle.GetManifest()
	require.NotNil(t, manifest, "the daemon's flat clone reply must decode into a Manifest")
	assert.Equal(t, "web-01", manifest.GetHostname())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, manifest.GetEkAlgorithm())
	assert.True(t, manifest.GetSecureBootEnabled())
	assert.Equal(t, map[string]string{"env": "prod"}, manifest.GetLabels())
}
