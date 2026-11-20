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
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DaemonOps is the part of the daemon Service (pkg/api/daemon) behind the
// REST routes for PlatformDaemon.Shutdown, UpdateConfig and ListEntityTypes
// (#2047). It takes the gRPC messages so the REST answer is the daemon's.
type DaemonOps interface {
	Shutdown(ctx context.Context, req *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error)
	UpdateConfig(ctx context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error)
	ListEntityTypes(ctx context.Context, req *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error)
}

// ErrDaemonOpsUnavailable is returned (503) before SetDaemonOps is wired.
type ErrDaemonOpsUnavailable struct{}

func (ErrDaemonOpsUnavailable) Error() string {
	return "platform: daemon operations are not configured on this daemon"
}

// ProbeResponse is the REST answer of the liveness and readiness probes.
type ProbeResponse struct {
	Alive     *bool  `json:"alive,omitempty"`
	Ready     *bool  `json:"ready,omitempty"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// ShutdownBody is the body of POST /platform/shutdown.
type ShutdownBody struct {
	Graceful       bool   `json:"graceful"`
	TimeoutSeconds uint32 `json:"timeout_seconds"`
}

// UpdateConfigBody is the body of PATCH /platform/config.
type UpdateConfigBody struct {
	Section string            `json:"section"`
	Values  map[string]string `json:"values"`
	Persist bool              `json:"persist"`
}

// OperationResult is the REST answer of Shutdown and UpdateConfig.
type OperationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// EntityTypeEntry is one entity type in the ListEntityTypes answer.
type EntityTypeEntry struct {
	Name   string `json:"name"`
	Count  uint64 `json:"count"`
	Status string `json:"status"`
}

// EntityTypesResponse is the REST answer of GET /platform/entity-types.
type EntityTypesResponse struct {
	EntityTypes   []EntityTypeEntry `json:"entity_types"`
	TotalEntities uint64            `json:"total_entities"`
	ActiveTypes   uint32            `json:"active_types"`
}

// SetDaemonOps wires the daemon Service into the Shutdown, UpdateConfig and
// ListEntityTypes routes; unset, they answer 503.
func (h *PlatformHandlers) SetDaemonOps(ops DaemonOps) {
	h.daemonOps = ops
}

// SetDaemonOps wires the daemon Service into the daemon-operation routes.
func (r *PlatformRouter) SetDaemonOps(ops DaemonOps) {
	r.handlers.SetDaemonOps(ops)
}

// registerDaemonRoutes registers the PlatformDaemon operations that had no
// REST route (#2047):
// GET    /api/v1/platform/health/live   - Liveness probe
// GET    /api/v1/platform/health/ready  - Readiness probe
// PATCH  /api/v1/platform/config        - Apply one configuration section
// POST   /api/v1/platform/shutdown      - Shut the daemon down
// GET    /api/v1/platform/entity-types  - List the stored entity types
func (r *PlatformRouter) registerDaemonRoutes(router *mux.Router) {
	router.HandleFunc("/health/live", r.handlers.Liveness).Methods("GET")
	router.HandleFunc("/health/ready", r.handlers.Readiness).Methods("GET")
	router.HandleFunc("/config", r.handlers.UpdateConfig).Methods("PATCH")
	router.HandleFunc("/shutdown", r.handlers.Shutdown).Methods("POST")
	router.HandleFunc("/entity-types", r.handlers.ListEntityTypes).Methods("GET")
}

func probeResponse(p health.Probe) ProbeResponse {
	return ProbeResponse{
		Status:    string(p.Status),
		Timestamp: p.Timestamp.UTC().Format(time.RFC3339Nano),
	}
}

// Liveness handles GET /api/v1/platform/health/live.
func (h *PlatformHandlers) Liveness(w http.ResponseWriter, r *http.Request) {
	p := health.Liveness()
	resp := probeResponse(p)
	resp.Alive = &p.OK
	h.respWriter.Success200(w, r, resp)
}

// Readiness handles GET /api/v1/platform/health/ready. It answers 200 with
// ready=false when a component is unhealthy, so the console can show it.
func (h *PlatformHandlers) Readiness(w http.ResponseWriter, r *http.Request) {
	ready := true
	p := health.Probe{OK: true, Status: health.StatusHealthy, Timestamp: time.Now()}
	if h.healthRegistry != nil {
		p = health.Readiness(r.Context(), h.healthRegistry)
		ready = p.OK
	}
	resp := probeResponse(p)
	resp.Ready = &ready
	h.respWriter.Success200(w, r, resp)
}

// UpdateConfig handles PATCH /api/v1/platform/config.
func (h *PlatformHandlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if h.daemonOps == nil {
		h.respWriter.Error503(w, r, ErrDaemonOpsUnavailable{})
		return
	}
	var body UpdateConfigBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respWriter.Error400(w, r, errors.New("platform: invalid update config body: "+err.Error()))
		return
	}
	if body.Section == "" {
		h.respWriter.Error400(w, r, errors.New("platform: section is required"))
		return
	}
	resp, err := h.daemonOps.UpdateConfig(r.Context(), &platformv1.UpdateConfigRequest{
		Section: &platformv1.ConfigSection{Section: body.Section, Values: body.Values},
		Persist: body.Persist,
	})
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, operationResult(resp.GetStatus()))
}

// Shutdown handles POST /api/v1/platform/shutdown. An empty body is a
// graceful shutdown with the daemon's configured timeout.
func (h *PlatformHandlers) Shutdown(w http.ResponseWriter, r *http.Request) {
	if h.daemonOps == nil {
		h.respWriter.Error503(w, r, ErrDaemonOpsUnavailable{})
		return
	}
	body := ShutdownBody{Graceful: true}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.respWriter.Error400(w, r, errors.New("platform: invalid shutdown body: "+err.Error()))
			return
		}
	}
	h.logger.Warnf("platform: shutdown requested over REST by %s (graceful=%v)", callerActor(r), body.Graceful)
	resp, err := h.daemonOps.Shutdown(r.Context(), &platformv1.ShutdownRequest{
		Graceful:       body.Graceful,
		TimeoutSeconds: body.TimeoutSeconds,
	})
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, operationResult(resp.GetStatus()))
}

// ListEntityTypes handles GET /api/v1/platform/entity-types.
func (h *PlatformHandlers) ListEntityTypes(w http.ResponseWriter, r *http.Request) {
	if h.daemonOps == nil {
		h.respWriter.Error503(w, r, ErrDaemonOpsUnavailable{})
		return
	}
	resp, err := h.daemonOps.ListEntityTypes(r.Context(), &platformv1.ListEntityTypesRequest{})
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	out := EntityTypesResponse{
		EntityTypes:   make([]EntityTypeEntry, 0, len(resp.GetEntityTypes())),
		TotalEntities: resp.GetTotalEntities(),
		ActiveTypes:   resp.GetActiveTypes(),
	}
	for _, t := range resp.GetEntityTypes() {
		out.EntityTypes = append(out.EntityTypes, EntityTypeEntry{
			Name:   t.GetName(),
			Count:  t.GetEntityCount(),
			Status: t.GetStatus(),
		})
	}
	h.respWriter.Success200(w, r, out)
}

func operationResult(s *platformv1.Status) OperationResult {
	out := OperationResult{Success: s.GetSuccess(), Message: s.GetMessage()}
	if e := s.GetError(); e != nil {
		out.Error = e.GetMessage()
	}
	return out
}
