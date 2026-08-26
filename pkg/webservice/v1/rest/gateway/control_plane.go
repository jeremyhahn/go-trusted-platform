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

package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ControlPlane is the small surface the WebUI + gatewayd both speak
// to over /api/v1/gateway. gatewayd POSTs telemetry on a tick; the
// WebUI reads cached state; both consume the desired-config endpoint
// for the intended configuration the CP wants applied.
type ControlPlane struct {
	logger     *logging.Logger
	store      gwstate.Store
	cfgSource  DesiredConfigSource
	respWriter response.HttpWriter
}

// DesiredConfigSource produces the CP-side intended configuration
// for a gateway. The platform's config tree is the source of truth;
// implementations select the gateway-relevant subset (BGP ASN, IPAM
// pools, PXE flag, etc.) and return it as a JSON-encodable map. The
// gatewayd reload loop polls this on a periodic tick and applies
// any deltas locally.
type DesiredConfigSource interface {
	DesiredConfig(gatewayID string) (map[string]interface{}, error)
}

// GatewayStateStore is a re-export of pkg/sdn/gateway/state.Store so
// the webservice handler-registry params block doesn't have to
// import the state package directly. The concrete implementation
// (FileStore) lives in pkg/sdn/gateway/state.
type GatewayStateStore = gwstate.Store

// NewControlPlane constructs a control-plane router. store and
// cfgSource may both be nil — the routes are still registered, but
// the handlers return 503 with the structured loud-failure envelope
// so callers can tell "service down" apart from "no data yet."
func NewControlPlane(logger *logging.Logger, store gwstate.Store, cfgSource DesiredConfigSource, respWriter response.HttpWriter) *ControlPlane {
	return &ControlPlane{
		logger:     logger,
		store:      store,
		cfgSource:  cfgSource,
		respWriter: respWriter,
	}
}

// RegisterRoutes mounts the control-plane endpoints under the parent
// /api/v1 subrouter.
//
//	GET  /api/v1/gateway/state                  - List all reported gateways (newest first)
//	GET  /api/v1/gateway/state/{id}             - Get a specific gateway's snapshot
//	POST /api/v1/gateway/telemetry              - gatewayd reports its current state
//	GET  /api/v1/gateway/desired-config/{id}    - gatewayd pulls intended config
//	DELETE /api/v1/gateway/state/{id}           - admin clears a stale gateway record
//
// The two gatewayd-facing routes — telemetry and desired-config — bind
// their gateway_id to the verified mTLS client certificate, so a gateway
// reaches only its own record. The three state routes are the WebUI's
// fleet-wide read/admin surface and are deliberately NOT cert-bound:
// choosing the operator authorization they should carry (JWT scope vs
// RBAC role) is an owner decision, tracked separately.
func (c *ControlPlane) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/gateway").Subrouter()
	sr.HandleFunc("/state", c.listState).Methods("GET")
	sr.HandleFunc("/state/{id}", c.getState).Methods("GET")
	sr.HandleFunc("/state/{id}", c.deleteState).Methods("DELETE")
	sr.HandleFunc("/telemetry", c.postTelemetry).Methods("POST")
	sr.HandleFunc("/desired-config/{id}", c.getDesiredConfig).Methods("GET")
}

func (c *ControlPlane) listState(w http.ResponseWriter, r *http.Request) {
	if c.store == nil {
		c.respWriter.Error500(w, r, ErrGatewayControlNotConfigured{})
		return
	}
	snaps, err := c.store.List()
	if err != nil {
		c.respWriter.Error500(w, r, err)
		return
	}
	c.respWriter.Success200(w, r, map[string]interface{}{
		"gateways": snaps,
		"total":    len(snaps),
	})
}

func (c *ControlPlane) getState(w http.ResponseWriter, r *http.Request) {
	if c.store == nil {
		c.respWriter.Error500(w, r, ErrGatewayControlNotConfigured{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		c.respWriter.Error400(w, r, ErrGatewayIDRequired{})
		return
	}
	snap, err := c.store.Get(id)
	if err != nil {
		var nf gwstate.ErrSnapshotNotFound
		if errors.As(err, &nf) {
			c.respWriter.Error404(w, r, err)
			return
		}
		c.respWriter.Error500(w, r, err)
		return
	}
	c.respWriter.Success200(w, r, snap)
}

func (c *ControlPlane) deleteState(w http.ResponseWriter, r *http.Request) {
	if c.store == nil {
		c.respWriter.Error500(w, r, ErrGatewayControlNotConfigured{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		c.respWriter.Error400(w, r, ErrGatewayIDRequired{})
		return
	}
	if err := c.store.Delete(id); err != nil {
		var nf gwstate.ErrSnapshotNotFound
		if errors.As(err, &nf) {
			c.respWriter.Error404(w, r, err)
			return
		}
		c.respWriter.Error500(w, r, err)
		return
	}
	c.respWriter.Success200(w, r, map[string]interface{}{"deleted": true, "id": id})
}

// postTelemetry accepts the JSON body posted by gatewayd.
//
// The body's gateway_id is NOT taken on trust. It must equal the Common
// Name of the verified mTLS client certificate on the connection
// (gatewayPrincipal), so a gateway can only ever report its own state:
// possession of any valid gateway certificate previously let a caller
// overwrite every other gateway's snapshot just by naming it in the
// body. Requests with no verified certificate are refused 401, and a
// verified certificate naming someone else's gateway_id is refused 403.
//
// Authentication runs before the body is read so an unidentified caller
// cannot make the control plane buffer a request at all.
func (c *ControlPlane) postTelemetry(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.authenticatedGateway(w, r)
	if !ok {
		return
	}
	if c.store == nil {
		c.respWriter.Error500(w, r, ErrGatewayControlNotConfigured{})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		c.respWriter.Error400(w, r, err)
		return
	}
	if len(body) == 0 {
		c.respWriter.Error400(w, r, ErrEmptyTelemetryBody{})
		return
	}
	var snap gwstate.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		c.respWriter.Error400(w, r, err)
		return
	}
	if strings.TrimSpace(snap.GatewayID) == "" {
		c.respWriter.Error400(w, r, ErrGatewayIDRequired{})
		return
	}
	if !c.authorizeGatewayID(w, r, principal, snap.GatewayID) {
		return
	}
	if err := c.store.Put(&snap); err != nil {
		c.respWriter.Error500(w, r, err)
		return
	}
	c.respWriter.Success200(w, r, map[string]interface{}{
		"accepted":    true,
		"gateway_id":  snap.GatewayID,
		"received_at": snap.ReceivedAt,
	})
}

// getDesiredConfig returns the CP-side intended config for a gateway.
// gatewayd polls this on a periodic tick and reconciles any deltas
// locally. The configuration shape is intentionally opaque to the
// REST layer — the gateway-side reload loop owns the schema.
//
// The {id} path segment is bound to the verified mTLS client
// certificate's Common Name on the same terms as postTelemetry. Desired
// configuration carries a gateway's intended BGP ASN, IPAM pools and
// PXE posture, so an unbound {id} would let any gateway enumerate the
// control plane's intent for the whole fleet.
func (c *ControlPlane) getDesiredConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.authenticatedGateway(w, r)
	if !ok {
		return
	}
	if c.cfgSource == nil {
		c.respWriter.Error500(w, r, ErrGatewayControlNotConfigured{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		c.respWriter.Error400(w, r, ErrGatewayIDRequired{})
		return
	}
	if !c.authorizeGatewayID(w, r, principal, id) {
		return
	}
	cfg, err := c.cfgSource.DesiredConfig(id)
	if err != nil {
		c.respWriter.Error500(w, r, err)
		return
	}
	c.respWriter.Success200(w, r, map[string]interface{}{
		"gateway_id": id,
		"config":     cfg,
	})
}

// ErrGatewayControlNotConfigured signals that the control-plane
// router is reachable but no store / config source is wired.
type ErrGatewayControlNotConfigured struct{}

func (ErrGatewayControlNotConfigured) Error() string {
	return "gateway: control-plane not configured on this daemon"
}

// ErrGatewayIDRequired signals a missing path or body parameter.
type ErrGatewayIDRequired struct{}

func (ErrGatewayIDRequired) Error() string {
	return "gateway: gateway_id is required"
}

// ErrEmptyTelemetryBody signals a POST with no JSON body.
type ErrEmptyTelemetryBody struct{}

func (ErrEmptyTelemetryBody) Error() string {
	return "gateway: telemetry body cannot be empty"
}
