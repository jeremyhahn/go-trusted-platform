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

package rest

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Compute REST Errors
// =============================================================================

// ErrComputeServiceNotAvailable is returned when no compute service is
// configured.
type ErrComputeServiceNotAvailable struct{}

func (e ErrComputeServiceNotAvailable) Error() string {
	return "compute service not available"
}

// =============================================================================
// Compute Routes
// =============================================================================

// computeBasePath is the prefix of every compute route.
const computeBasePath = "/api/v1/compute"

// The scopes a caller needs for each compute route, the same tiers the gRPC
// ComputeService enforces (pkg/api/daemon/method_permissions.go).
const (
	scopeContainerRead   = "container:read"
	scopeContainerWrite  = "container:write"
	scopeContainerDelete = "container:delete"
	scopeVMRead          = "vm:read"
	scopeVMWrite         = "vm:write"
	scopeVMDelete        = "vm:delete"
)

// ComputeHandlers serves the compute (VM and container) REST routes on the
// daemon listener. Every route runs one ComputeService RPC over protobuf JSON
// (protoRPC) behind the scope its gRPC twin requires.
type ComputeHandlers struct {
	protoResponder
	compute platformv1.ComputeServiceServer
	guard   *ScopeGuard
}

// computeRoute is one compute route: its verb, path, scope and handler.
type computeRoute struct {
	method  string
	path    string
	scope   string
	handler http.HandlerFunc
}

// NewComputeHandlers creates the compute REST handlers. A nil compute service
// answers every admitted request with 503; a nil guard refuses every request.
func NewComputeHandlers(compute platformv1.ComputeServiceServer, guard *ScopeGuard, logger *slog.Logger) *ComputeHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &ComputeHandlers{
		protoResponder: protoResponder{logger: logger},
		compute:        compute,
		guard:          guard,
	}
}

// RegisterRoutes mounts every compute route behind the scope it requires.
func (h *ComputeHandlers) RegisterRoutes(router *mux.Router) {
	for _, route := range h.routes() {
		router.HandleFunc(computeBasePath+route.path, h.guard.Require(route.scope, route.handler)).Methods(route.method)
	}
	h.logger.Info("Compute REST routes registered")
}

// routes is the compute route table. Path variables are named after the
// request field they set ({id}, {vmId}, {diskId}, {snapshotId}).
// Streaming RPCs (console, logs, attach) have no REST route.
func (h *ComputeHandlers) routes() []computeRoute {
	return []computeRoute{
		// Virtual machines
		{http.MethodPost, "/vms", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.CreateVM)},
		{http.MethodGet, "/vms", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.ListVMs)},
		{http.MethodGet, "/vms/{id}", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.GetVM)},
		{http.MethodDelete, "/vms/{id}", scopeVMDelete, computeRPC(h, platformv1.ComputeServiceServer.DeleteVM)},
		{http.MethodPost, "/vms/{id}/start", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.StartVM)},
		{http.MethodPost, "/vms/{id}/stop", scopeVMWrite, vmPowerRPC(h, stopVMOptions, platformv1.ComputeServiceServer.StopVM)},
		{http.MethodPost, "/vms/{id}/reboot", scopeVMWrite, vmPowerRPC(h, rebootVMOptions, platformv1.ComputeServiceServer.RebootVM)},
		{http.MethodPost, "/vms/{id}/suspend", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.SuspendVM)},
		{http.MethodPost, "/vms/{id}/resume", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.ResumeVM)},
		{http.MethodGet, "/vms/{id}/metrics", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.GetVMMetrics)},
		{http.MethodPost, "/vms/{vmId}/migrate", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.MigrateVM)},

		// Inbound migration (the destination half of MigrateVM)
		{http.MethodPost, "/migrations/prepare", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.PrepareMigration)},
		{http.MethodPost, "/migrations/{receiverId}/finalize", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.FinalizeMigration)},

		// Disks
		{http.MethodPost, "/vms/{vmId}/disks", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.AttachDisk)},
		{http.MethodDelete, "/vms/{vmId}/disks/{diskId}", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.DetachDisk)},
		{http.MethodPatch, "/vms/{vmId}/disks/{diskId}", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.ResizeDisk)},

		// Snapshots
		{http.MethodPost, "/vms/{vmId}/snapshots", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.CreateSnapshot)},
		{http.MethodGet, "/vms/{vmId}/snapshots", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.ListSnapshots)},
		{http.MethodGet, "/vms/{vmId}/snapshots/{snapshotId}", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.GetSnapshot)},
		{http.MethodDelete, "/vms/{vmId}/snapshots/{snapshotId}", scopeVMDelete, computeRPC(h, platformv1.ComputeServiceServer.DeleteSnapshot)},
		{http.MethodPost, "/vms/{vmId}/snapshots/{snapshotId}/restore", scopeVMWrite, computeRPC(h, platformv1.ComputeServiceServer.RestoreSnapshot)},

		// VM attestation
		{http.MethodPost, "/vms/{vmId}/attest", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.AttestVM)},
		{http.MethodPost, "/vms/{vmId}/attest/verify", scopeVMRead, computeRPC(h, platformv1.ComputeServiceServer.VerifyVMAttestation)},

		// Containers
		{http.MethodPost, "/containers", scopeContainerWrite, computeRPC(h, platformv1.ComputeServiceServer.CreateContainer)},
		{http.MethodGet, "/containers", scopeContainerRead, computeRPC(h, platformv1.ComputeServiceServer.ListContainers)},
		{http.MethodGet, "/containers/{id}", scopeContainerRead, computeRPC(h, platformv1.ComputeServiceServer.GetContainer)},
		{http.MethodDelete, "/containers/{id}", scopeContainerDelete, computeRPC(h, platformv1.ComputeServiceServer.DeleteContainer)},
		{http.MethodPost, "/containers/{id}/start", scopeContainerWrite, computeRPC(h, platformv1.ComputeServiceServer.StartContainer)},
		{http.MethodPost, "/containers/{id}/stop", scopeContainerWrite, computeRPC(h, platformv1.ComputeServiceServer.StopContainer)},
		{http.MethodPost, "/containers/{id}/exec", scopeContainerWrite, computeRPC(h, platformv1.ComputeServiceServer.ExecContainer)},
		{http.MethodPost, "/containers/{id}/attest", scopeContainerRead, computeRPC(h, platformv1.ComputeServiceServer.AttestContainer)},
		{http.MethodGet, "/containers/{id}/metrics", scopeContainerRead, computeRPC(h, platformv1.ComputeServiceServer.GetContainerMetrics)},
	}
}

// computeRPC serves one ComputeService RPC over protobuf JSON (protoRPC).
func computeRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *ComputeHandlers, rpc func(platformv1.ComputeServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return protoRPC(h.protoResponder, h.computeService, rpc)
}

// vmPowerRPC serves StopVM or RebootVM as computeRPC does, and first moves the
// reply's write deadline to the stop's reply window (docs/compute/api.md). A
// graceful stop waits up to the guest's power-down window, which is as long
// as the server's default write timeout, so without this the server closes
// the connection before the VM has stopped and the client sees EOF.
func vmPowerRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *ComputeHandlers, options func(PReq) compute.StopOptions, rpc func(platformv1.ComputeServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	extend := func(w http.ResponseWriter, req PReq) {
		deadline := time.Now().Add(options(req).ReplyWindow())
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
			h.logger.Warn("compute: cannot extend the reply deadline", "error", err)
		}
	}
	return protoRPCPrepared(h.protoResponder, h.computeService, extend, rpc)
}

// stopVMOptions is the stop a StopVMRequest asks for.
func stopVMOptions(req *platformv1.StopVMRequest) compute.StopOptions {
	return compute.StopOptions{
		Force:   req.GetForce(),
		Timeout: time.Duration(req.GetTimeoutSeconds()) * time.Second,
	}
}

// rebootVMOptions is the stop half of the reboot a RebootVMRequest asks for.
func rebootVMOptions(req *platformv1.RebootVMRequest) compute.StopOptions {
	return compute.StopOptions{Force: req.GetForce()}
}

// computeService returns the compute service, or ErrComputeServiceNotAvailable
// when none is configured.
func (h *ComputeHandlers) computeService() (platformv1.ComputeServiceServer, error) {
	if h.compute == nil {
		return nil, ErrComputeServiceNotAvailable{}
	}
	return h.compute, nil
}
