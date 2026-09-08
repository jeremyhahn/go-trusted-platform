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
	DesiredConfig(gatewayID string) (*gwstate.DesiredConfig, error)
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

// RegisterRoutes mounts the OPERATOR half of the control-plane surface on
// the provided router, which the caller must have gated.
//
//	GET    /api/v1/gateway/state         - List all reported gateways (newest first)
//	GET    /api/v1/gateway/state/{id}    - Get a specific gateway's snapshot
//	DELETE /api/v1/gateway/state/{id}    - Clear a stale gateway record
//
// These are the WebUI's fleet-wide read and admin surface. They are not
// cert-bound, because the caller is a human operator rather than a
// gateway: a fleet-wide list is precisely what no single gateway's
// certificate should authorise. Which operator authorization they carry
// (JWT scope versus RBAC role) was previously left open here; #165 answers
// it with the same RBAC role guard #159 established for the rest of the
// API, and the caller supplies it.
//
// The gatewayd-facing half is RegisterGatewayFacingRoutes and must not be
// mounted here — it authenticates itself and would be broken by a role
// guard.
func (c *ControlPlane) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/gateway").Subrouter()
	sr.HandleFunc("/state", c.listState).Methods("GET")
	sr.HandleFunc("/state/{id}", c.getState).Methods("GET")
	sr.HandleFunc("/state/{id}", c.deleteState).Methods("DELETE")
}

// RegisterGatewayFacingRoutes mounts the two routes gatewayd itself calls,
// and takes the UNGATED router.
//
//	POST /api/v1/gateway/telemetry            - gatewayd reports its current state
//	GET  /api/v1/gateway/desired-config/{id}  - gatewayd pulls intended config
//
// They are ungated because they are already authenticated, by a seam
// appropriate to a machine principal rather than to a person: both call
// authenticatedGateway, which requires a verified mTLS client certificate
// and refuses 401 without one, then bind the request's gateway_id to that
// certificate's Common Name and refuse 403 when they disagree. A gateway
// therefore reaches only its own record.
//
// Mounting a role guard in front of these would demand a bearer token from
// a caller whose credential is a certificate, and would break every
// gateway in the fleet. The correct reading is not "these routes are
// unauthenticated" but "these routes authenticate differently", which is
// what #165 scope item 2 asks each machine-facing surface to establish.
func (c *ControlPlane) RegisterGatewayFacingRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/gateway").Subrouter()
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
	if cfg == nil {
		cfg = &gwstate.DesiredConfig{}
	}
	// The document the gateway will refuse is refused here first, so a
	// control plane serving a malformed intent learns it from its own log
	// rather than from a gateway that never converges.
	if err := cfg.Validate(); err != nil {
		c.respWriter.Error500(w, r, err)
		return
	}
	if cfg.GatewayID == "" {
		cfg.GatewayID = id
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
