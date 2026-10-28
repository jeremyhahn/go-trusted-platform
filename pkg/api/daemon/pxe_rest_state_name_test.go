// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	pxerest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const restStateNodeMAC = "00:11:22:33:44:d6"

// putDeviceState sends body to PUT /api/v1/pxe/devices/{id}/state through the
// operator PXE router, whose protojson decoder is the one the daemon serves.
func putDeviceState(t *testing.T, f *webhookFixture, deviceID, body string) *httptest.ResponseRecorder {
	t.Helper()
	logger := logging.DefaultLogger()
	router := pxerest.NewPXERouter(logger, f.svc, response.NewResponseWriter(logger, nil), true)
	root := mux.NewRouter()
	router.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/"+deviceID+"/state", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

// bootingDevice registers a node and netboots it, ready to enter installing.
func bootingDevice(t *testing.T, f *webhookFixture) *pxe.DeviceInfo {
	t.Helper()
	ctx := context.Background()
	device, err := f.backend.RegisterDevice(ctx, restStateNodeMAC, "port-d6")
	require.NoError(t, err)
	require.NoError(t, f.backend.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "netboot"))
	return device
}

// The body the JavaScript SDK's updateState sends (Codex review 7999): the
// state as its protobuf name, so the REST decoder reads installing and the
// certificate binding is admitted, and the bound installer completes.
func TestRESTUpdateState_ProtobufStateNameBindsTheInstallerCertificate(t *testing.T) {
	f := newWebhookFixture(t)
	device := bootingDevice(t, f)
	installer := f.issuerB.issue(t, webhookSerial+3)
	fingerprint := pxe.CertificateSHA256(installer.Raw)

	rec := putDeviceState(t, f, device.ID,
		`{"state":"PROVISIONING_STATE_INSTALLING","installCertificateSha256":"`+fingerprint+`"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"PROVISIONING_STATE_INSTALLING"`)
	bound, err := f.backend.GetDevice(context.Background(), device.ID)
	require.NoError(t, err)
	assert.Equal(t, pxe.StateInstalling, bound.State)
	assert.Equal(t, fingerprint, bound.InstallCertificateSHA256)

	_, err = f.svc.WebhookComplete(grpcContext(verifiedState(installer)),
		&platformv1.PXEWebhookCompleteRequest{MacAddress: restStateNodeMAC, Success: true})
	require.NoError(t, err)
	assert.Equal(t, pxe.StateInstallComplete, f.state(t, restStateNodeMAC))
}

// The body the JavaScript SDK sent before the fix: protojson drops the short
// name "INSTALLING" as an unknown enum value, the state arrives unspecified,
// and the certificate-bearing update is refused without binding anything.
func TestRESTUpdateState_ShortStateNameIsRefused(t *testing.T) {
	f := newWebhookFixture(t)
	device := bootingDevice(t, f)
	fingerprint := pxe.CertificateSHA256(f.issuerB.issue(t, webhookSerial+3).Raw)

	rec := putDeviceState(t, f, device.ID,
		`{"state":"INSTALLING","installCertificateSha256":"`+fingerprint+`"}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), ErrPXEInstallCertificateState{State: string(pxe.StateUnknown)}.Error())
	unbound, err := f.backend.GetDevice(context.Background(), device.ID)
	require.NoError(t, err)
	assert.Equal(t, pxe.StateBooting, unbound.State)
	assert.Empty(t, unbound.InstallCertificateSHA256)
}
