// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

package rest

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// sdkCAAgainstRoutes serves the daemon's CA routes and returns a CA client
// over the Go SDK's real REST transport, authenticated as adminToken.
func sdkCAAgainstRoutes(t *testing.T, ca CAServiceInterface) platformv1.CAServiceClient {
	t.Helper()
	router := mux.NewRouter()
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	guard := NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{adminToken: {scopeCertsRevoke}}}, nil, nil)
	NewCAHandlers(ca, slog.Default(), nil).WithScopeGuard(guard).RegisterRoutes(router)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	// The SDK refuses plaintext REST; trust the test server's certificate.
	trustServer := platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL), trustServer, platform.WithBearerToken(adminToken)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })
	return platformv1.NewCAServiceClient(adapter.Connection())
}

// The Go SDK revokes through the daemon's DELETE route and decodes the
// protobuf response, Status and timestamps included (Codex 8097).
func TestCARevoke_GoSDKAgainstDaemonRoute(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("sdk-revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	client := sdkCAAgainstRoutes(t, ca)
	resp, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		DeleteKeys: true,
	})
	require.NoError(t, err)

	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, serial, resp.GetSerial())
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED, resp.GetCertificateStatus())
	assert.Equal(t, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, resp.GetReason())
	require.NotNil(t, resp.GetRevokedAt())
	assert.NotZero(t, resp.GetRevokedAt().GetSeconds())
	require.NotNil(t, resp.GetTimestamp())
	assert.NotZero(t, resp.GetTimestamp().GetSeconds())

	assert.NotContains(t, ca.certStore.certs, serial, "the SDK call must reach CA Revoke")
	require.Len(t, ca.revokedKeyAttrs, 1)
	require.NotNil(t, ca.revokedKeyAttrs[0], "DeleteKeys must cross the transport")
	assert.Equal(t, "sdk-revoke.test.com", ca.revokedKeyAttrs[0].CN)
}

// An SDK revocation of an unknown serial surfaces as an error, and revokes
// nothing.
func TestCARevoke_GoSDKUnknownSerial(t *testing.T) {
	ca := newMockCAService()
	client := sdkCAAgainstRoutes(t, ca)

	_, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{Serial: "0badc0de"})
	require.Error(t, err)
	assert.Empty(t, ca.revokedKeyAttrs)
}
