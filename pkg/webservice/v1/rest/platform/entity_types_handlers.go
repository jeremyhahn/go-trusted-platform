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

package platform

import (
	"context"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// EntityTypeLister narrows the surface the entity-types handler needs
// from the daemon.Service (PlatformDaemon.ListEntityTypes). Defined as
// an interface so tests can stand in a fake.
type EntityTypeLister interface {
	ListEntityTypes(ctx context.Context, req *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error)
}

// SetEntityTypeLister hooks up the daemon.Service (or a fake) used by
// GET /platform/entity-types. When unset the endpoint answers 503.
func (h *PlatformHandlers) SetEntityTypeLister(l EntityTypeLister) {
	h.entityTypeLister = l
}

// ErrEntityTypeListerUnavailable is returned when no EntityTypeLister
// is wired into the handlers.
type ErrEntityTypeListerUnavailable struct{}

func (ErrEntityTypeListerUnavailable) Error() string {
	return "platform: entity type lister is not configured on this daemon"
}

// EntityTypeResponse is one storage entity type and its entity count.
type EntityTypeResponse struct {
	Name        string `json:"name"`
	EntityCount uint64 `json:"entityCount"`
	Status      string `json:"status"`
}

// EntityTypesResponse is the reply of GET /api/v1/platform/entity-types.
// It leaves out the daemon's database path on purpose: a filesystem
// path on the daemon host must not leave the host.
type EntityTypesResponse struct {
	EntityTypes   []EntityTypeResponse `json:"entityTypes"`
	TotalEntities uint64               `json:"totalEntities"`
	ActiveTypes   uint32               `json:"activeTypes"`
}

// ListEntityTypes handles GET /api/v1/platform/entity-types.
func (h *PlatformHandlers) ListEntityTypes(w http.ResponseWriter, r *http.Request) {
	if h.entityTypeLister == nil {
		h.respWriter.Error503(w, r, ErrEntityTypeListerUnavailable{})
		return
	}
	resp, err := h.entityTypeLister.ListEntityTypes(r.Context(), &platformv1.ListEntityTypesRequest{})
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	entries := resp.GetEntityTypes()
	out := EntityTypesResponse{
		EntityTypes:   make([]EntityTypeResponse, 0, len(entries)),
		TotalEntities: resp.GetTotalEntities(),
		ActiveTypes:   resp.GetActiveTypes(),
	}
	for _, e := range entries {
		if e == nil {
			continue
		}
		out.EntityTypes = append(out.EntityTypes, EntityTypeResponse{
			Name:        e.GetName(),
			EntityCount: e.GetEntityCount(),
			Status:      e.GetStatus(),
		})
	}
	h.respWriter.Success200(w, r, out)
}
