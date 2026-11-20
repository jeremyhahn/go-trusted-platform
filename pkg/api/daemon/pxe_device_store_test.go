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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	"github.com/stretchr/testify/require"
)

// TestPXEBackend_CompletionReportAfterRestart enrols a device on one PXE
// backend, then starts a second backend over the same datastore (a daemon
// restart): the device is back in its state with its IDevID binding, and
// its install-completion report succeeds (#2028).
func TestPXEBackend_CompletionReportAfterRestart(t *testing.T) {
	ctx := context.Background()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(ctx))
	t.Cleanup(func() { _ = storage.Stop(ctx) })
	cert := webhookIdentityCert(t)
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	pxeStore, err := quicbaas.NewPXEDeviceStore(storage, app.SystemTenantID, logger)
	require.NoError(t, err)
	first, err := pxeGRPCServiceWithStore(ctx, logger, pxeSectionApp(), pxeEnabledSection(t),
		pxeTestFlowManager(t, &pxeRecordingPort{}), pxeStore)
	require.NoError(t, err)
	device, err := first.pxeService.RegisterDevice(ctx, webhookIdentityMAC, "port-1")
	require.NoError(t, err)
	require.NoError(t, first.pxeService.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "booting"))
	require.NoError(t, first.pxeService.UpdateDeviceState(ctx, device.ID, pxe.StateInstalling, "installing"))
	require.NoError(t, first.pxeService.RecordIDevIDFingerprint(ctx, device.ID, webhookIdentityFingerprint(cert)))

	restarted, err := pxeGRPCServiceWithStore(ctx, logger, pxeSectionApp(), pxeEnabledSection(t),
		pxeTestFlowManager(t, &pxeRecordingPort{}), pxeStore)
	require.NoError(t, err)
	got, err := restarted.pxeService.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	require.Equal(t, pxe.StateInstalling, got.State)
	require.Equal(t, webhookIdentityFingerprint(cert), got.IDevIDFingerprint)
	require.NotEmpty(t, got.Events)

	router := restpxe.NewPXERouter(logger, restarted, response.NewResponseWriter(logger, nil), true)
	router.SetWebhookSecret(webhookIdentitySecret)
	root := mux.NewRouter()
	router.RegisterMachineFacingRoutes(root.PathPrefix("/api/v1").Subrouter())
	f := &webhookIdentityFixture{svc: restarted.pxeService, root: root, deviceID: device.ID}

	rec := f.report(cert)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, pxe.StateInstallComplete, f.state(t))
}

// TestPXEDeviceStoreFor_NoDatastore: an app without the quicbaas DAO
// factory gets no device store, so the backend keeps devices in memory.
func TestPXEDeviceStoreFor_NoDatastore(t *testing.T) {
	for _, a := range []*app.App{pxeSectionApp(), nil} {
		store, err := pxeDeviceStoreFor(a, nil)
		require.NoError(t, err)
		require.Nil(t, store)
	}
}

// fakePXEDatastoreClient is a quicbaas.Storage that reports its transport.
type fakePXEDatastoreClient struct {
	quicbaas.Storage
	embedded bool
}

func (f fakePXEDatastoreClient) IsEmbedded() bool { return f.embedded }

// TestPXEDeviceStoreForClient_RefusesRemoteTransport: the pinned go-quicbaas
// REST KV handlers neither page List nor carry the system tenant, so an
// enabled PXE backend over a remote transport is refused instead of
// persisting records it cannot reload completely or scope (#2028 Codex).
func TestPXEDeviceStoreForClient_RefusesRemoteTransport(t *testing.T) {
	remote := fakePXEDatastoreClient{Storage: quicbaas.NewMockStorage(), embedded: false}
	store, err := pxeDeviceStoreForClient(remote, nil)
	require.Error(t, err)
	require.Nil(t, store)
	var cfgErr pxe.ErrInvalidConfiguration
	require.True(t, errors.As(err, &cfgErr), "want pxe.ErrInvalidConfiguration, got %T: %v", err, err)
	require.Equal(t, "quicbaas.transport", cfgErr.Field)
	require.NotEmpty(t, cfgErr.Reason)

	embedded := fakePXEDatastoreClient{Storage: quicbaas.NewMockStorage(), embedded: true}
	store, err = pxeDeviceStoreForClient(embedded, nil)
	require.NoError(t, err)
	require.NotNil(t, store)
}
