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

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tlspeer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
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
	// scopeAuthorizer is the per-route scope check the operator and gateway
	// routes take on top of the admin gate; nil leaves them on the gate.
	scopeAuthorizer middleware.ScopeAuthorizer
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
//	POST   /api/v1/pxe/devices/{id}/certificate   - BindDeviceCertificate
//	POST   /api/v1/pxe/devices/{id}/authorize     - Authorize
//	POST   /api/v1/pxe/devices/{id}/quarantine    - Quarantine
//	POST   /api/v1/pxe/devices/{id}/retry         - Retry
//	GET    /api/v1/pxe/devices/{id}/events        - GetEvents
//	POST   /api/v1/pxe/webhook/complete           - WebhookComplete (only when enabled)
//
// RegisterRoutes registers the OPERATOR half of the PXE surface on the
// provided router, which the caller must have gated: the service controls
// (start / stop / status) and the device lifecycle, including authorize,
// quarantine, retry and the provisioning-state write. Each route also takes
// the scope its PXEService RPC takes on gRPC.
//
// The install-completion webhook is NOT here: its caller is a booting node,
// authenticated by its device certificate over mTLS rather than an operator
// session — see RegisterMachineFacingRoutes.
func (r *PXERouter) RegisterRoutes(parent *mux.Router) {
	r.mount(parent.PathPrefix(basePath).Subrouter(), r.operatorRoutes())
}

// scopedRoute is one REST route and the gRPC method it stands for. The gRPC
// method names the scope the route takes, read from the gRPC catalog
// (pkg/api/grpc/method_permissions.go), so REST cannot drift from gRPC.
type scopedRoute struct {
	method  string
	path    string
	rpc     string
	handler http.HandlerFunc
}

// operatorRoutes is the operator half of the PXE surface, relative to
// basePath. /devices/mac/{mac} precedes /devices/{id}, which would match it.
func (r *PXERouter) operatorRoutes() []scopedRoute {
	return []scopedRoute{
		{http.MethodGet, "/status", pxeRPC("GetStatus"), r.getStatus},
		{http.MethodPost, "/start", pxeRPC("StartService"), r.startService},
		{http.MethodPost, "/stop", pxeRPC("StopService"), r.stopService},
		{http.MethodGet, "/devices", pxeRPC("ListDevices"), r.listDevices},
		{http.MethodPost, "/devices", pxeRPC("RegisterDevice"), r.registerDevice},
		{http.MethodGet, "/devices/mac/{mac}", pxeRPC("GetDeviceByMAC"), r.getDeviceByMAC},
		{http.MethodGet, "/devices/{id}", pxeRPC("GetDevice"), r.getDevice},
		{http.MethodDelete, "/devices/{id}", pxeRPC("RemoveDevice"), r.removeDevice},
		{http.MethodPut, "/devices/{id}/state", pxeRPC("UpdateState"), r.updateState},
		{http.MethodPost, "/devices/{id}/enrolled", pxeRPC("SetDeviceEnrolled"), r.setEnrolled},
		{http.MethodPost, "/devices/{id}/certificate", pxeRPC("BindDeviceCertificate"), r.bindCertificate},
		{http.MethodPost, "/devices/{id}/authorize", pxeRPC("Authorize"), r.authorize},
		{http.MethodPost, "/devices/{id}/quarantine", pxeRPC("Quarantine"), r.quarantine},
		{http.MethodPost, "/devices/{id}/retry", pxeRPC("Retry"), r.retry},
		{http.MethodGet, "/devices/{id}/events", pxeRPC("GetEvents"), r.getEvents},
	}
}

// pxeRPC returns the full gRPC method name of a PXEService RPC.
func pxeRPC(name string) string {
	return "/" + platformv1.PXEService_ServiceDesc.ServiceName + "/" + name
}

// mount registers routes on sr, each behind the scope the gRPC catalog gives
// its RPC.
func (r *PXERouter) mount(sr *mux.Router, routes []scopedRoute) {
	for _, route := range routes {
		scope := grpcapi.ScopeForMethod(route.rpc)
		sr.Handle(route.path, r.requireScope(scope, route.handler)).Methods(route.method)
	}
}

// SetScopeAuthorizer supplies the scope check every operator and gateway
// route takes on top of the admin gate. Nil leaves the routes on the role
// gate alone, which is the case under the legacy JWT handler: its sessions
// carry roles, not scopes.
func (r *PXERouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps handler in the scope check when one is configured.
func (r *PXERouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// RegisterMachineFacingRoutes registers the install-completion webhook, and
// takes the UNGATED router.
//
//	POST /api/v1/pxe/webhook/complete
//
// It registers nothing unless the operator enabled the webhook
// (pxe.ServiceConfig.WebhookEnabled, false by default): a disabled webhook is
// an unknown path, answered 404, and the service's WebhookComplete is never
// reached.
//
// It is ungated because its caller is a booting node with no operator
// session. The node authenticates with its device certificate over mTLS, as
// gatewayd does on its control plane (#238): the handler refuses a request
// with no verified client certificate, and passes the connection's TLS state
// to the service, which takes the identity from the
// verified client certificate chain only and updates the record whose bound
// certificate fingerprint (POST /devices/{id}/certificate,
// BindDeviceCertificate) it is. A request with no verified client
// certificate is answered 401; one whose certificate is bound to no
// device, or whose body names another device's MAC, is answered 403. The
// device state changes in neither case.
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
	filter, err := deviceFilter(req.URL.Query())
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.ListDevices(req.Context(), &platformv1.ListPXEDevicesRequest{Filter: filter})
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

func (r *PXERouter) bindCertificate(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.BindPXEDeviceCertificateRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.DeviceId = mux.Vars(req)["id"]
	resp, err := r.server.BindDeviceCertificate(req.Context(), pbReq)
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
	// The node authenticates by the verified client certificate of this
	// connection (#238). A request with none is refused here, before the
	// body is read; the service then binds the certificate to the device,
	// as it does on every transport.
	if _, err := tlspeer.VerifiedLeaf(req.TLS); err != nil {
		r.respWriter.Error401(w, req, err)
		return
	}
	pbReq := &platformv1.PXEWebhookCompleteRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	ctx := channelbind.WithConnectionTLS(req.Context(), channelbind.TransportREST, req.TLS)
	resp, err := r.server.WebhookComplete(ctx, pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
