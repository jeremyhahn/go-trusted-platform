// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// clusterRESTHandlers is the REST adapter for the Cluster gRPC service.
// It reuses the gRPC handler implementation so REST and gRPC remain
// behaviorally identical (e.g., both report the same "Unimplemented"
// state when no cluster coordinator is wired).
type clusterRESTHandlers struct {
	service *ClusterGRPCService
}

func newClusterRESTHandlers(svc *ClusterGRPCService) *clusterRESTHandlers {
	return &clusterRESTHandlers{service: svc}
}

// registerClusterRoutes mounts the cluster endpoints under /cluster.
//
// Routes mirror the gRPC method set:
//
//	GET  /cluster/status
//	GET  /cluster/nodes
//	POST /cluster/bootstrap
//	POST /cluster/join
//	POST /cluster/leave
func (h *clusterRESTHandlers) registerClusterRoutes(router *mux.Router) {
	r := router.PathPrefix("/cluster").Subrouter()
	r.HandleFunc("/status", h.status).Methods(http.MethodGet)
	r.HandleFunc("/nodes", h.nodes).Methods(http.MethodGet)
	r.HandleFunc("/bootstrap", h.bootstrap).Methods(http.MethodPost)
	r.HandleFunc("/join", h.join).Methods(http.MethodPost)
	r.HandleFunc("/leave", h.leave).Methods(http.MethodPost)
}

// clusterErrorToHTTP maps gRPC codes/sentinels into HTTP statuses so
// dashboard widgets can distinguish "not configured" (503) from
// "internal error" (500).
func clusterErrorToHTTP(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var notConfigured ErrClusterNotConfigured
	if errors.As(err, &notConfigured) {
		return http.StatusServiceUnavailable
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Unimplemented, codes.Unavailable:
			return http.StatusServiceUnavailable
		case codes.InvalidArgument:
			return http.StatusBadRequest
		case codes.PermissionDenied:
			return http.StatusForbidden
		case codes.Unauthenticated:
			return http.StatusUnauthorized
		case codes.NotFound:
			return http.StatusNotFound
		case codes.AlreadyExists:
			return http.StatusConflict
		}
	}
	return http.StatusInternalServerError
}

func (h *clusterRESTHandlers) status(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeRESTJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrClusterNotConfigured{}.Error()})
		return
	}
	resp, err := h.service.GetStatus(r.Context(), &platformv1.GetClusterStatusRequest{})
	if err != nil {
		writeRESTJSON(w, clusterErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, resp)
}

func (h *clusterRESTHandlers) nodes(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeRESTJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrClusterNotConfigured{}.Error()})
		return
	}
	resp, err := h.service.ListNodes(r.Context(), &platformv1.ListClusterNodesRequest{})
	if err != nil {
		writeRESTJSON(w, clusterErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, resp)
}

func (h *clusterRESTHandlers) bootstrap(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeRESTJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrClusterNotConfigured{}.Error()})
		return
	}
	var in platformv1.BootstrapClusterRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	resp, err := h.service.Bootstrap(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, clusterErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, resp)
}

func (h *clusterRESTHandlers) join(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeRESTJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrClusterNotConfigured{}.Error()})
		return
	}
	var in platformv1.JoinClusterRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	resp, err := h.service.Join(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, clusterErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, resp)
}

func (h *clusterRESTHandlers) leave(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeRESTJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrClusterNotConfigured{}.Error()})
		return
	}
	var in platformv1.LeaveClusterRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	resp, err := h.service.Leave(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, clusterErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, resp)
}
