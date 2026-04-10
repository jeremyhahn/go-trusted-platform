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

package router

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/vtpm"
)

// VTPMInstanceRouter handles vTPM instance-related routes.
type VTPMInstanceRouter struct {
	handler vtpm.RestHandler
	WebServiceRouter
}

// NewVTPMInstanceRouter creates a new VTPMInstanceRouter.
func NewVTPMInstanceRouter(handler vtpm.RestHandler) WebServiceRouter {
	return &VTPMInstanceRouter{
		handler: handler,
	}
}

// RegisterRoutes registers all vTPM instance routes.
func (r *VTPMInstanceRouter) RegisterRoutes(router *mux.Router) {
	// Instance CRUD operations
	r.createInstance(router)
	r.listInstances(router)
	r.getInstance(router)
	r.getInstanceByProfile(router)
	r.deleteInstance(router)

	// Instance lifecycle operations
	r.startInstance(router)
	r.stopInstance(router)
	r.getInstanceStatus(router)

	// EK certificate operations
	r.exportEKCertificate(router)
	r.getEKFingerprint(router)
}

// POST /api/v1/vtpm/instances - Create vTPM instance
func (r *VTPMInstanceRouter) createInstance(router *mux.Router) {
	router.HandleFunc("/vtpm/instances", r.handler.CreateInstance).Methods("POST")
}

// GET /api/v1/vtpm/instances - List vTPM instances
func (r *VTPMInstanceRouter) listInstances(router *mux.Router) {
	router.HandleFunc("/vtpm/instances", r.handler.ListInstances).Methods("GET")
}

// GET /api/v1/vtpm/instances/{id} - Get vTPM instance by ID
func (r *VTPMInstanceRouter) getInstance(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}", r.handler.GetInstance).Methods("GET")
}

// GET /api/v1/vtpm/instances/profile/{profile_id} - Get vTPM instance by profile ID
func (r *VTPMInstanceRouter) getInstanceByProfile(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/profile/{profile_id:[0-9]+}", r.handler.GetInstanceByProfile).Methods("GET")
}

// DELETE /api/v1/vtpm/instances/{id} - Delete vTPM instance
func (r *VTPMInstanceRouter) deleteInstance(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}", r.handler.DeleteInstance).Methods("DELETE")
}

// POST /api/v1/vtpm/instances/{id}/start - Start vTPM instance
func (r *VTPMInstanceRouter) startInstance(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}/start", r.handler.StartInstance).Methods("POST")
}

// POST /api/v1/vtpm/instances/{id}/stop - Stop vTPM instance
func (r *VTPMInstanceRouter) stopInstance(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}/stop", r.handler.StopInstance).Methods("POST")
}

// GET /api/v1/vtpm/instances/{id}/status - Get vTPM instance status
func (r *VTPMInstanceRouter) getInstanceStatus(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}/status", r.handler.GetInstanceStatus).Methods("GET")
}

// GET /api/v1/vtpm/instances/{id}/ek - Export EK certificate (PEM)
func (r *VTPMInstanceRouter) exportEKCertificate(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}/ek", r.handler.ExportEKCertificate).Methods("GET")
}

// GET /api/v1/vtpm/instances/{id}/ek/fingerprint - Get EK fingerprint
func (r *VTPMInstanceRouter) getEKFingerprint(router *mux.Router) {
	router.HandleFunc("/vtpm/instances/{id}/ek/fingerprint", r.handler.GetEKFingerprint).Methods("GET")
}
