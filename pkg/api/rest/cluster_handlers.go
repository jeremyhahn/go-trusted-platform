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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Cluster route scopes, as the cluster RPCs require on gRPC, QUIC and MCP.
const (
	clusterReadScope  = "cluster:read"
	clusterWriteScope = "cluster:write"
)

// errClusterNotConfigured is the answer of every cluster route when the
// listener has no cluster server.
const errClusterNotConfigured = "cluster service not configured"

// ClusterHandlers serves the cluster routes from the Cluster gRPC server,
// so the console listener answers the paths the daemon REST listener
// serves, with the same wire format and status codes.
type ClusterHandlers struct {
	server platformv1.ClusterServiceServer
	guard  RouteGuard
}

// NewClusterHandlers creates the cluster REST handlers. Each route requires
// cluster:read or cluster:write as its RPC does on gRPC; a nil guard
// refuses every route with 403.
func NewClusterHandlers(server platformv1.ClusterServiceServer, guard RouteGuard) *ClusterHandlers {
	if guard == nil {
		guard = (*ScopeGuard)(nil)
	}
	return &ClusterHandlers{server: server, guard: guard}
}

// RegisterRoutes mounts the cluster routes on a router rooted at /api/v1:
//
//	GET  /cluster/status   ?include_nodes=<bool>
//	GET  /cluster/nodes    ?role=<n>&state=<n> (each repeatable), ?page=<n>&page_size=<n>
//	POST /cluster/bootstrap
//	POST /cluster/join
//	POST /cluster/leave
func (h *ClusterHandlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/cluster/status", h.guard.Require(clusterReadScope, h.status)).Methods(http.MethodGet)
	router.HandleFunc("/cluster/nodes", h.guard.Require(clusterReadScope, h.nodes)).Methods(http.MethodGet)
	router.HandleFunc("/cluster/bootstrap", h.guard.Require(clusterWriteScope, h.bootstrap)).Methods(http.MethodPost)
	router.HandleFunc("/cluster/join", h.guard.Require(clusterWriteScope, h.join)).Methods(http.MethodPost)
	router.HandleFunc("/cluster/leave", h.guard.Require(clusterWriteScope, h.leave)).Methods(http.MethodPost)
}

func (h *ClusterHandlers) status(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		writeClusterError(w, http.StatusServiceUnavailable, errClusterNotConfigured)
		return
	}
	req := &platformv1.GetClusterStatusRequest{}
	if v := r.URL.Query().Get("include_nodes"); v != "" {
		include, err := strconv.ParseBool(v)
		if err != nil {
			writeClusterError(w, http.StatusBadRequest, "invalid include_nodes: "+err.Error())
			return
		}
		req.IncludeNodes = include
	}
	resp, err := h.server.GetStatus(r.Context(), req)
	writeClusterResult(w, resp, err)
}

func (h *ClusterHandlers) nodes(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		writeClusterError(w, http.StatusServiceUnavailable, errClusterNotConfigured)
		return
	}
	req, err := clusterNodesRequest(r)
	if err != nil {
		writeClusterError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.server.ListNodes(r.Context(), req)
	writeClusterResult(w, resp, err)
}

func (h *ClusterHandlers) bootstrap(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		writeClusterError(w, http.StatusServiceUnavailable, errClusterNotConfigured)
		return
	}
	var in platformv1.BootstrapClusterRequest
	if err := decodeClusterBody(w, r, &in); err != nil {
		writeClusterError(w, clusterBodyStatus(err), err.Error())
		return
	}
	resp, err := h.server.Bootstrap(r.Context(), &in)
	writeClusterResult(w, resp, err)
}

func (h *ClusterHandlers) join(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		writeClusterError(w, http.StatusServiceUnavailable, errClusterNotConfigured)
		return
	}
	var in platformv1.JoinClusterRequest
	if err := decodeClusterBody(w, r, &in); err != nil {
		writeClusterError(w, clusterBodyStatus(err), err.Error())
		return
	}
	resp, err := h.server.Join(r.Context(), &in)
	writeClusterResult(w, resp, err)
}

func (h *ClusterHandlers) leave(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		writeClusterError(w, http.StatusServiceUnavailable, errClusterNotConfigured)
		return
	}
	var in platformv1.LeaveClusterRequest
	if err := decodeClusterBody(w, r, &in); err != nil {
		writeClusterError(w, clusterBodyStatus(err), err.Error())
		return
	}
	resp, err := h.server.Leave(r.Context(), &in)
	writeClusterResult(w, resp, err)
}

// clusterStatusCode maps a cluster RPC error to the HTTP status the daemon
// REST listener answers with, so the dashboard tells "not configured" (503)
// from a conflict (409) or an internal error (500).
func clusterStatusCode(err error) int {
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
			return http.StatusConflict
		}
	}
	return http.StatusInternalServerError
}

// clusterNodesRequest builds the ListNodes request from the GET
// /cluster/nodes query: every role and state value (the numeric NodeRole and
// NodeState enums) filters, and page or page_size sets the 1-based
// pagination.
func clusterNodesRequest(r *http.Request) (*platformv1.ListClusterNodesRequest, error) {
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
		page, err := parseClusterQueryUint32(q.Get("page"))
		if err != nil {
			return nil, fmt.Errorf("invalid page: %w", err)
		}
		size, err := parseClusterQueryUint32(q.Get("page_size"))
		if err != nil {
			return nil, fmt.Errorf("invalid page_size: %w", err)
		}
		req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: size}
	}
	return req, nil
}

// parseClusterQueryUint32 parses a decimal uint32 query value; empty is 0.
func parseClusterQueryUint32(v string) (uint32, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// maxClusterBodyBytes bounds a cluster write request body: the bootstrap,
// join and leave requests carry a few names and seed addresses, so 64 KiB
// is ample, and a larger body answers 413 before it is buffered or decoded.
const maxClusterBodyBytes = 64 << 10

// decodeClusterBody decodes a JSON request body of at most
// maxClusterBodyBytes; an absent or empty body leaves out untouched.
func decodeClusterBody(w http.ResponseWriter, r *http.Request, out any) error {
	if r.Body == nil {
		return nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxClusterBodyBytes))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

// clusterBodyStatus maps a decodeClusterBody error to 413 when the body
// exceeded maxClusterBodyBytes and to 400 otherwise.
func clusterBodyStatus(err error) int {
	if errors.As(err, new(*http.MaxBytesError)) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// writeClusterResult writes resp with 200, or err's mapped status with an
// {"error": ...} body.
func writeClusterResult(w http.ResponseWriter, resp any, err error) {
	if err != nil {
		writeClusterError(w, clusterStatusCode(err), err.Error())
		return
	}
	writeClusterJSON(w, http.StatusOK, resp)
}

func writeClusterError(w http.ResponseWriter, code int, msg string) {
	writeClusterJSON(w, code, map[string]string{"error": msg})
}

func writeClusterJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
