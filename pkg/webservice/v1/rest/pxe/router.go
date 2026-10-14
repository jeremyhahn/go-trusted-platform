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

// Package pxe implements REST endpoints under /api/v1/pxe.
package pxe

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/pxe"

// PXERouter wires REST endpoints onto a PXEServiceServer.
type PXERouter struct {
	logger     *logging.Logger
	server     platformv1.PXEServiceServer
	respWriter response.HttpWriter
	// webhookEnabled is pxe.ServiceConfig.WebhookEnabled: whether the
	// install-completion webhook is mounted at all.
	webhookEnabled bool
	router.WebServiceRouter
}

// NewPXERouter creates a new router.
func NewPXERouter(
	logger *logging.Logger,
	server platformv1.PXEServiceServer,
	respWriter response.HttpWriter,
	webhookEnabled bool,
) *PXERouter {
	return &PXERouter{
		logger:         logger,
		server:         server,
		respWriter:     respWriter,
		webhookEnabled: webhookEnabled,
	}
}

// RegisterRoutes mounts PXE routes.
//
//	GET    /api/v1/pxe/status                     - GetStatus
//	POST   /api/v1/pxe/start                      - StartService
//	POST   /api/v1/pxe/stop                       - StopService
//	GET    /api/v1/pxe/devices                    - ListDevices
//	POST   /api/v1/pxe/devices                    - RegisterDevice
//	GET    /api/v1/pxe/devices/{id}               - GetDevice
//	DELETE /api/v1/pxe/devices/{id}               - RemoveDevice
//	GET    /api/v1/pxe/devices/mac/{mac}          - GetDeviceByMAC
//	PUT    /api/v1/pxe/devices/{id}/state         - UpdateState
//	POST   /api/v1/pxe/devices/{id}/enrolled      - SetDeviceEnrolled
//	POST   /api/v1/pxe/devices/{id}/authorize     - Authorize
//	POST   /api/v1/pxe/devices/{id}/quarantine    - Quarantine
//	POST   /api/v1/pxe/devices/{id}/retry         - Retry
//	GET    /api/v1/pxe/devices/{id}/events        - GetEvents
//	POST   /api/v1/pxe/webhook/complete           - WebhookComplete (only when enabled)
//
// RegisterRoutes registers the OPERATOR half of the PXE surface on the
// provided router, which the caller must have gated: the service controls
// (start / stop / status) and the device lifecycle, including authorize,
// quarantine, retry and the provisioning-state write.
//
// The install-completion webhook is NOT here — see
// RegisterMachineFacingRoutes, and #238.
func (r *PXERouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/status", r.getStatus).Methods("GET")
	sr.HandleFunc("/start", r.startService).Methods("POST")
	sr.HandleFunc("/stop", r.stopService).Methods("POST")
	sr.HandleFunc("/devices", r.listDevices).Methods("GET")
	sr.HandleFunc("/devices", r.registerDevice).Methods("POST")
	sr.HandleFunc("/devices/mac/{mac}", r.getDeviceByMAC).Methods("GET")
	sr.HandleFunc("/devices/{id}", r.getDevice).Methods("GET")
	sr.HandleFunc("/devices/{id}", r.removeDevice).Methods("DELETE")
	sr.HandleFunc("/devices/{id}/state", r.updateState).Methods("PUT")
	sr.HandleFunc("/devices/{id}/enrolled", r.setEnrolled).Methods("POST")
	sr.HandleFunc("/devices/{id}/authorize", r.authorize).Methods("POST")
	sr.HandleFunc("/devices/{id}/quarantine", r.quarantine).Methods("POST")
	sr.HandleFunc("/devices/{id}/retry", r.retry).Methods("POST")
	sr.HandleFunc("/devices/{id}/events", r.getEvents).Methods("GET")
}

// RegisterMachineFacingRoutes registers the install-completion webhook, and
// takes the UNGATED router.
//
//	POST /api/v1/pxe/webhook/complete
//
// It registers nothing unless the operator enabled the webhook
// (pxe.ServiceConfig.WebhookEnabled, false by default): a disabled webhook is
// an unknown path, answered 404, and the service's WebhookComplete is never
// reached. Off is the default because of what follows.
//
// It is ungated because its caller is a booting node with no operator
// session — and, unlike the gateway's telemetry pair or the EAB-authenticated
// provisioning routes, **it presents no credential and the server checks
// none**: the handler decodes the body and the service identifies the device
// by a MAC address taken from it. `pkg/compute/pxe/config.go` declares and
// REQUIRES a `WebhookSecret` described as "the HMAC secret for webhook
// authentication" which nothing ever reads.
//
// That is tracked as #238 and is deliberately not fixed here. Choosing what a
// booting node presents — HMAC over the body with the secret that already
// exists, IDevID over mTLS as gatewayd uses, or a provisioning-session token
// — is an architecture decision, and inventing one inside a gating change
// would build a second authentication mechanism nobody ratified.
//
// So this method is not an endorsement: it is the boundary of what #165 can
// close, drawn explicitly so the route is not mistaken for one this campaign
// has certified.
func (r *PXERouter) RegisterMachineFacingRoutes(parent *mux.Router) {
	if !r.webhookEnabled {
		return
	}
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/webhook/complete", r.webhookComplete).Methods("POST")
}

func (r *PXERouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "pxe"})
		return false
	}
	return true
}

func (r *PXERouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetStatus(req.Context(), &platformv1.GetPXEStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) startService(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.StartService(req.Context(), &platformv1.StartPXEServiceRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) stopService(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.StopService(req.Context(), &platformv1.StopPXEServiceRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) listDevices(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListDevices(req.Context(), &platformv1.ListPXEDevicesRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) registerDevice(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.RegisterPXEDeviceRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.RegisterDevice(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

func (r *PXERouter) getDevice(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetDevice(req.Context(), &platformv1.GetPXEDeviceRequest{DeviceId: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) removeDevice(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.RemoveDevice(req.Context(), &platformv1.RemovePXEDeviceRequest{DeviceId: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) getDeviceByMAC(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetDeviceByMAC(req.Context(), &platformv1.GetPXEDeviceByMACRequest{MacAddress: mux.Vars(req)["mac"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) updateState(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.UpdatePXEStateRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.DeviceId = mux.Vars(req)["id"]
	resp, err := r.server.UpdateState(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) setEnrolled(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.SetPXEDeviceEnrolledRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.DeviceId = mux.Vars(req)["id"]
	resp, err := r.server.SetDeviceEnrolled(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) authorize(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.AuthorizePXEDeviceRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.DeviceId = mux.Vars(req)["id"]
	resp, err := r.server.Authorize(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) quarantine(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.QuarantinePXEDeviceRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.DeviceId = mux.Vars(req)["id"]
	resp, err := r.server.Quarantine(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) retry(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.Retry(req.Context(), &platformv1.RetryPXEDeviceRequest{DeviceId: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) getEvents(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetEvents(req.Context(), &platformv1.GetPXEEventsRequest{DeviceId: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *PXERouter) webhookComplete(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.PXEWebhookCompleteRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.WebhookComplete(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
