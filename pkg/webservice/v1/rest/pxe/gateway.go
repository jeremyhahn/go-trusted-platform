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

package pxe

// Provisioning Gateway over REST.
//
// gatewayd reports the devices it sees on the provisioning VLAN through the
// ProvisioningGateway RPCs (pkg/api/grpc/proto/provisioning.proto). Each RPC
// names a device by MAC, which travels as the {mac} path segment; the
// handlers translate the report onto the PXE service the gRPC PXEService
// serves. GetBootConfig has no route: platformd holds no per-MAC boot
// configuration to answer it from (docs/provisioning/api.md §4).

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// gatewayBasePath is the collection the gateway's device reports
	// name their device under.
	gatewayBasePath = "/provisioning/devices"

	// Registration outcomes RegisterProvisioningDeviceResponse.status names.
	statusRegistered        = "registered"
	statusAlreadyRegistered = "already_registered"

	// Install outcomes NotifyInstallCompleteRequest.status names.
	installSuccess = "success"
	installFailure = "failure"

	// provisioningStatePrefix turns a reported state ("booting") into its
	// ProvisioningState enum name ("PROVISIONING_STATE_BOOTING").
	provisioningStatePrefix = "PROVISIONING_STATE_"
)

// RegisterGatewayRoutes mounts the gateway's device reports on parent, which
// the caller gates to the admin role. Each route also takes the scope its
// ProvisioningGateway RPC takes on gRPC.
func (r *PXERouter) RegisterGatewayRoutes(parent *mux.Router) {
	r.mount(parent.PathPrefix(gatewayBasePath).Subrouter(), r.gatewayRoutes())
}

// gatewayRoutes is the gateway's device reports, relative to gatewayBasePath.
func (r *PXERouter) gatewayRoutes() []scopedRoute {
	return []scopedRoute{
		{http.MethodPost, "/{mac}/register", gatewayRPC("RegisterPXEDevice"), r.registerGatewayDevice},
		{http.MethodPost, "/{mac}/state", gatewayRPC("ReportDeviceState"), r.reportDeviceState},
		{http.MethodPost, "/{mac}/install-complete", gatewayRPC("NotifyInstallComplete"), r.notifyInstallComplete},
	}
}

// gatewayRPC returns the full gRPC method name of a ProvisioningGateway RPC.
func gatewayRPC(name string) string {
	return "/" + platformv1.ProvisioningGateway_ServiceDesc.ServiceName + "/" + name
}

// registerGatewayDevice serves RegisterPXEDevice. A device the service
// already holds answers with its existing ID and "already_registered".
func (r *PXERouter) registerGatewayDevice(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.RegisterProvisioningDeviceRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	mac := mux.Vars(req)["mac"]
	registered, err := r.server.RegisterDevice(req.Context(), &platformv1.RegisterPXEDeviceRequest{
		MacAddress: mac,
		PortId:     pbReq.GetPortId(),
	})
	if status.Code(err) == codes.AlreadyExists {
		existing, lookupErr := r.server.GetDeviceByMAC(req.Context(), &platformv1.GetPXEDeviceByMACRequest{MacAddress: mac})
		if lookupErr != nil {
			protorest.WriteError(w, req, r.respWriter, lookupErr)
			return
		}
		protorest.WriteSuccess(w, req, r.respWriter, &platformv1.RegisterProvisioningDeviceResponse{
			DeviceId: existing.GetDevice().GetId(),
			Status:   statusAlreadyRegistered,
		})
		return
	}
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, &platformv1.RegisterProvisioningDeviceResponse{
		DeviceId: registered.GetDevice().GetId(),
		Status:   statusRegistered,
	})
}

// reportDeviceState serves ReportDeviceState: the device is found by MAC and
// moved to the reported state.
func (r *PXERouter) reportDeviceState(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.ReportDeviceStateRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	state, err := provisioningState(pbReq.GetState())
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	device, err := r.server.GetDeviceByMAC(req.Context(), &platformv1.GetPXEDeviceByMACRequest{MacAddress: mux.Vars(req)["mac"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	if _, err := r.server.UpdateState(req.Context(), &platformv1.UpdatePXEStateRequest{
		DeviceId: device.GetDevice().GetId(),
		State:    state,
		Reason:   pbReq.GetReason(),
	}); err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, &platformv1.ReportDeviceStateResponse{})
}

// notifyInstallComplete serves NotifyInstallComplete. It is the operation
// the booting node's /pxe/webhook/complete performs, relayed by a gateway
// that holds the admin role and provisioning:write — it does not open the
// uncredentialed path #238 tracks.
func (r *PXERouter) notifyInstallComplete(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.NotifyInstallCompleteRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	outcome := pbReq.GetStatus()
	if outcome != installSuccess && outcome != installFailure {
		r.respWriter.Error400(w, req, &ErrInvalidInstallStatus{Status: outcome})
		return
	}
	if _, err := r.server.WebhookComplete(req.Context(), &platformv1.PXEWebhookCompleteRequest{
		MacAddress: mux.Vars(req)["mac"],
		Success:    outcome == installSuccess,
	}); err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, &platformv1.NotifyInstallCompleteResponse{})
}

// provisioningState maps a reported state name ("booting",
// "install_complete") onto its ProvisioningState. Unspecified is not a
// state a device can be moved to.
func provisioningState(name string) (platformv1.ProvisioningState, error) {
	value, ok := platformv1.ProvisioningState_value[provisioningStatePrefix+strings.ToUpper(name)]
	if !ok || value == int32(platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED) {
		return platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED, &ErrUnknownDeviceState{State: name}
	}
	return platformv1.ProvisioningState(value), nil
}
