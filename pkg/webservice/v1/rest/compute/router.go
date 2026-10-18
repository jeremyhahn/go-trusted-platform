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

// Package compute implements the REST surface for /api/v1/compute.
//
// All handlers delegate to a platformv1.ComputeServiceServer (the in-process
// gRPC service implementation that backs sdk/go/services/compute via the
// embedded transport). The REST layer never reaches into pkg/compute
// directly — it speaks proto request/response messages, decoded from JSON
// using protojson, so the WebUI receives the same shapes that sdk/go and
// sdk/javascript expose.
package compute

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// basePath is mounted under the parent /api/v1 subrouter.
	basePath = "/compute"

	// scopeContainerRead is the scope container attestation requires, the
	// one the gRPC method enforces.
	scopeContainerRead = "container:read"
)

// ComputeRouter wires REST endpoints onto a ComputeServiceServer.
type ComputeRouter struct {
	handlers        *Handlers
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// NewComputeRouter constructs a router that delegates to the supplied
// gRPC server implementation.
func NewComputeRouter(
	logger *logging.Logger,
	server platformv1.ComputeServiceServer,
	respWriter response.HttpWriter,
) *ComputeRouter {
	return &ComputeRouter{
		handlers: NewHandlers(logger, server, respWriter),
	}
}

// SetScopeAuthorizer supplies the scope check container attestation takes
// on top of the admin gate. Nil leaves the route on the role gate alone,
// which is the case under the legacy JWT handler: its sessions carry roles,
// not scopes.
func (r *ComputeRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps handler in the scope check when an authorizer is set.
func (r *ComputeRouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// RegisterRoutes attaches all compute REST routes on the parent router.
func (r *ComputeRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	r.registerVMRoutes(sr)
	r.registerSnapshotRoutes(sr)
	r.registerDiskRoutes(sr)
	r.registerContainerRoutes(sr)
	r.registerAttestationRoutes(sr)
}

// registerVMRoutes registers virtual machine lifecycle endpoints.
//
//	POST   /api/v1/compute/vms                       - CreateVM
//	GET    /api/v1/compute/vms                       - ListVMs
//	GET    /api/v1/compute/vms/{id}                  - GetVM
//	DELETE /api/v1/compute/vms/{id}                  - DeleteVM
//	POST   /api/v1/compute/vms/{id}/start            - StartVM
//	POST   /api/v1/compute/vms/{id}/stop             - StopVM
//	POST   /api/v1/compute/vms/{id}/reboot           - RebootVM
//	POST   /api/v1/compute/vms/{id}/suspend          - SuspendVM
//	POST   /api/v1/compute/vms/{id}/resume           - ResumeVM
//	GET    /api/v1/compute/vms/{id}/metrics          - GetVMMetrics
//	POST   /api/v1/compute/vms/{id}/migrate          - MigrateVM
func (r *ComputeRouter) registerVMRoutes(sr *mux.Router) {
	sr.HandleFunc("/vms", r.handlers.CreateVM).Methods("POST")
	sr.HandleFunc("/vms", r.handlers.ListVMs).Methods("GET")
	sr.HandleFunc("/vms/{id}", r.handlers.GetVM).Methods("GET")
	sr.HandleFunc("/vms/{id}", r.handlers.DeleteVM).Methods("DELETE")
	sr.HandleFunc("/vms/{id}/start", r.handlers.StartVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/stop", r.handlers.StopVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/reboot", r.handlers.RebootVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/suspend", r.handlers.SuspendVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/resume", r.handlers.ResumeVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/metrics", r.handlers.GetVMMetrics).Methods("GET")
	sr.HandleFunc("/vms/{id}/migrate", r.handlers.MigrateVM).Methods("POST")
}

// registerDiskRoutes registers VM disk attachment endpoints.
//
//	POST   /api/v1/compute/vms/{id}/disks            - AttachDisk
//	DELETE /api/v1/compute/vms/{id}/disks/{diskId}   - DetachDisk
//	PATCH  /api/v1/compute/vms/{id}/disks/{diskId}   - ResizeDisk
func (r *ComputeRouter) registerDiskRoutes(sr *mux.Router) {
	sr.HandleFunc("/vms/{id}/disks", r.handlers.AttachDisk).Methods("POST")
	sr.HandleFunc("/vms/{id}/disks/{diskId}", r.handlers.DetachDisk).Methods("DELETE")
	sr.HandleFunc("/vms/{id}/disks/{diskId}", r.handlers.ResizeDisk).Methods("PATCH")
}

// registerSnapshotRoutes registers VM snapshot endpoints.
//
//	POST   /api/v1/compute/vms/{id}/snapshots                       - CreateSnapshot
//	GET    /api/v1/compute/vms/{id}/snapshots                       - ListSnapshots
//	DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}          - DeleteSnapshot
//	POST   /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore  - RestoreSnapshot
func (r *ComputeRouter) registerSnapshotRoutes(sr *mux.Router) {
	sr.HandleFunc("/vms/{id}/snapshots", r.handlers.CreateSnapshot).Methods("POST")
	sr.HandleFunc("/vms/{id}/snapshots", r.handlers.ListSnapshots).Methods("GET")
	sr.HandleFunc("/vms/{id}/snapshots/{snapshotId}", r.handlers.DeleteSnapshot).Methods("DELETE")
	sr.HandleFunc("/vms/{id}/snapshots/{snapshotId}/restore", r.handlers.RestoreSnapshot).Methods("POST")
}

// registerContainerRoutes registers container lifecycle endpoints.
//
//	POST   /api/v1/compute/containers                       - CreateContainer
//	GET    /api/v1/compute/containers                       - ListContainers
//	GET    /api/v1/compute/containers/{id}                  - GetContainer
//	DELETE /api/v1/compute/containers/{id}                  - DeleteContainer
//	POST   /api/v1/compute/containers/{id}/start            - StartContainer
//	POST   /api/v1/compute/containers/{id}/stop             - StopContainer
//	POST   /api/v1/compute/containers/{id}/exec             - ExecContainer
//	GET    /api/v1/compute/containers/{id}/metrics          - GetContainerMetrics
func (r *ComputeRouter) registerContainerRoutes(sr *mux.Router) {
	sr.HandleFunc("/containers", r.handlers.CreateContainer).Methods("POST")
	sr.HandleFunc("/containers", r.handlers.ListContainers).Methods("GET")
	sr.HandleFunc("/containers/{id}", r.handlers.GetContainer).Methods("GET")
	sr.HandleFunc("/containers/{id}", r.handlers.DeleteContainer).Methods("DELETE")
	sr.HandleFunc("/containers/{id}/start", r.handlers.StartContainer).Methods("POST")
	sr.HandleFunc("/containers/{id}/stop", r.handlers.StopContainer).Methods("POST")
	sr.HandleFunc("/containers/{id}/exec", r.handlers.ExecContainer).Methods("POST")
	sr.HandleFunc("/containers/{id}/metrics", r.handlers.GetContainerMetrics).Methods("GET")
}

// registerAttestationRoutes registers VM and container attestation
// endpoints. Container attestation also requires container:read when a
// scope authorizer is set.
//
//	POST   /api/v1/compute/vms/{id}/attest          - AttestVM
//	POST   /api/v1/compute/vms/{id}/attest/verify   - VerifyVMAttestation
//	POST   /api/v1/compute/containers/{id}/attest   - AttestContainer
func (r *ComputeRouter) registerAttestationRoutes(sr *mux.Router) {
	sr.HandleFunc("/vms/{id}/attest", r.handlers.AttestVM).Methods("POST")
	sr.HandleFunc("/vms/{id}/attest/verify", r.handlers.VerifyVMAttestation).Methods("POST")
	sr.Handle("/containers/{id}/attest", r.requireScope(scopeContainerRead, r.handlers.AttestContainer)).Methods("POST")
}
