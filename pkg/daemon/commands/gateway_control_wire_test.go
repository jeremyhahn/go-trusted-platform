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

package commands

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
)

// restOnlyDaemon is a daemon with a REST server and neither the gateway gRPC
// service nor the VPN control plane.
type restOnlyDaemon struct {
	rest *daemon.RESTServer
}

func (d restOnlyDaemon) GatewayGRPCService() *daemon.GatewayService { return nil }
func (d restOnlyDaemon) VPNControlPlane() *vpn.Service              { return nil }
func (d restOnlyDaemon) RESTServer() *daemon.RESTServer             { return d.rest }

func newDaemonRESTServer(t *testing.T) *daemon.RESTServer {
	t.Helper()
	cfg := daemon.DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := daemon.NewService(cfg)
	require.NoError(t, err)
	rest, err := daemon.NewRESTServer(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return rest
}

// asGateway sends r over a TLS connection whose verified client certificate
// names gatewayID.
func asGateway(r *http.Request, gatewayID string) *http.Request {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: gatewayID}}
	r.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
		VerifiedChains:    [][]*x509.Certificate{{leaf}},
	}
	return r
}

func newGatewayControlPlaneForTest(t *testing.T, desired string) *gatewayControlPlane {
	t.Helper()
	store, err := gwstate.NewFileStore(t.TempDir())
	require.NoError(t, err)
	return &gatewayControlPlane{Store: store, DesiredCfg: sourceFor(t, desired)}
}

// TestWireGatewayControlPlane_MountsGatewayRoutesOnDaemonREST is the
// daemon-only control plane: with no webservice listener, gatewayd's
// telemetry lands in the control plane's store and its desired configuration
// comes from the config tree, both through the daemon REST server.
func TestWireGatewayControlPlane_MountsGatewayRoutesOnDaemonREST(t *testing.T) {
	rest := newDaemonRESTServer(t)
	gw := newGatewayControlPlaneForTest(t, "gateway:\n  desired:\n    version: rev-7\n")
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	wireGatewayControlPlane(logger, restOnlyDaemon{rest: rest}, gw)

	body, err := json.Marshal(&gwstate.Snapshot{GatewayID: "edge-01", Hostname: "gw.example.com"})
	require.NoError(t, err)
	post := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", bytes.NewReader(body))
	post.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rest.Router().ServeHTTP(rec, asGateway(post, "edge-01"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	snap, err := gw.Store.Get("edge-01")
	require.NoError(t, err)
	assert.Equal(t, "gw.example.com", snap.Hostname)

	get := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/edge-01", nil)
	rec = httptest.NewRecorder()
	rest.Router().ServeHTTP(rec, asGateway(get, "edge-01"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "rev-7")
}

// TestWireGatewayControlPlane_NilControlPlaneMountsNothing: when the gateway
// state store could not be opened, the daemon serves no gateway routes rather
// than routes that fail every request.
func TestWireGatewayControlPlane_NilControlPlaneMountsNothing(t *testing.T) {
	rest := newDaemonRESTServer(t)
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	wireGatewayControlPlane(logger, restOnlyDaemon{rest: rest}, nil)

	get := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/edge-01", nil)
	rec := httptest.NewRecorder()
	rest.Router().ServeHTTP(rec, asGateway(get, "edge-01"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestWireGatewayControlPlane_WithoutDaemonRESTWiresTheStoreOnly is the
// webservice mode, where the daemon REST server is off and the webservice
// router serves the gateway routes: wiring must not need a REST server.
func TestWireGatewayControlPlane_WithoutDaemonRESTWiresTheStoreOnly(t *testing.T) {
	gw := newGatewayControlPlaneForTest(t, "gateway: {}\n")
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	assert.NotPanics(t, func() {
		wireGatewayControlPlane(logger, restOnlyDaemon{}, gw)
	})
}
