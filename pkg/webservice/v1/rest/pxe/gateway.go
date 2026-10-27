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

	// The reasons an install outcome records on the device, as the node's
	// own webhook records them.
	installCompleteReason = "OS installation completed successfully"
	installFailedReason   = "OS installation failed"

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
	if !r.updateStateByMAC(w, req, state, pbReq.GetReason()) {
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, &platformv1.ReportDeviceStateResponse{})
}

// updateStateByMAC moves the device the path's {mac} names to state, through
// the operator RPCs the gateway's admin role and provisioning:write admit. It
// writes the error response and returns false when either call fails.
func (r *PXERouter) updateStateByMAC(w http.ResponseWriter, req *http.Request, state platformv1.ProvisioningState, reason string) bool {
	device, err := r.server.GetDeviceByMAC(req.Context(), &platformv1.GetPXEDeviceByMACRequest{MacAddress: mux.Vars(req)["mac"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return false
	}
	if _, err := r.server.UpdateState(req.Context(), &platformv1.UpdatePXEStateRequest{
		DeviceId: device.GetDevice().GetId(),
		State:    state,
		Reason:   reason,
	}); err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return false
	}
	return true
}

// notifyInstallComplete serves NotifyInstallComplete: a gateway that holds the
// admin role and provisioning:write reports the outcome of a node's install,
// naming the node by MAC. It records the same state change as the node's own
// /pxe/webhook/complete, but through the operator RPCs: the webhook takes the
// node's identity from the node's mTLS certificate (#238), which a relaying
// gateway does not hold.
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
	state, reason := platformv1.ProvisioningState_PROVISIONING_STATE_FAILED, installFailedReason
	if outcome == installSuccess {
		state, reason = platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE, installCompleteReason
	}
	if !r.updateStateByMAC(w, req, state, reason) {
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
