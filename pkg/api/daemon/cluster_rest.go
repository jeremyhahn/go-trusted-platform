// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// clusterRESTHandlers is the REST adapter for the Cluster gRPC service.
// It calls the registered gRPC service so REST and gRPC stay behaviorally
// identical (e.g., both report the service as unavailable when no cluster
// coordinator is wired).
type clusterRESTHandlers struct {
	service platformv1.ClusterServiceServer
}

func newClusterRESTHandlers(svc platformv1.ClusterServiceServer) *clusterRESTHandlers {
	return &clusterRESTHandlers{service: svc}
}

// registerClusterRoutes mounts the cluster endpoints under /cluster.
//
// Routes mirror the gRPC method set:
//
//	GET  /cluster/status   ?include_nodes=<bool>
//	GET  /cluster/nodes    ?role=<n>&state=<n> (each repeatable), ?page=<n>&page_size=<n>
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
		case codes.AlreadyExists, codes.FailedPrecondition:
			// FailedPrecondition is a conflict with the cluster's state (#665).
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
	req := &platformv1.GetClusterStatusRequest{}
	if v := r.URL.Query().Get("include_nodes"); v != "" {
		include, err := strconv.ParseBool(v)
		if err != nil {
			writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid include_nodes: " + err.Error()})
			return
		}
		req.IncludeNodes = include
	}
	resp, err := h.service.GetStatus(r.Context(), req)
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
	req, err := clusterNodesQuery(r)
	if err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	resp, err := h.service.ListNodes(r.Context(), req)
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

// clusterNodesQuery builds the ListNodes request from the GET /cluster/nodes
// query: every role and state value (the numeric NodeRole and NodeState
// enums) filters, and page or page_size sets the 1-based pagination.
func clusterNodesQuery(r *http.Request) (*platformv1.ListClusterNodesRequest, error) {
	q := r.URL.Query()
	req := &platformv1.ListClusterNodesRequest{}
	for _, v := range q["role"] {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid role %q: %w", v, err)
		}
		req.Roles = append(req.Roles, platformv1.NodeRole(n))
	}
	for _, v := range q["state"] {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid state %q: %w", v, err)
		}
		req.States = append(req.States, platformv1.NodeState(n))
	}
	if q.Has("page") || q.Has("page_size") {
		page, err := parseClusterUint32(q.Get("page"))
		if err != nil {
			return nil, fmt.Errorf("invalid page: %w", err)
		}
		size, err := parseClusterUint32(q.Get("page_size"))
		if err != nil {
			return nil, fmt.Errorf("invalid page_size: %w", err)
		}
		req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: size}
	}
	return req, nil
}

// parseClusterUint32 parses a decimal uint32 query value; empty is 0.
func parseClusterUint32(v string) (uint32, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
