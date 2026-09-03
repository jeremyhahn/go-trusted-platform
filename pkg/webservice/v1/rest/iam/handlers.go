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

package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultLimit  int32 = 50
	maxLimit      int32 = 1000
	defaultOffset int32 = 0

	requestTimeout = 30 * time.Second
)

// IAMClient defines the interface for IAM operations used by REST handlers.
// This abstracts the underlying transport (gRPC, SDK, etc.) from the REST layer.
type IAMClient interface {
	// User operations
	CreateUser(ctx context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error)
	GetUser(ctx context.Context, tenantID, userID string) (*iamsdk.User, error)
	ListUsers(ctx context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error)
	UpdateUser(ctx context.Context, tenantID, userID string, req *iamsdk.UpdateUserRequest) (*iamsdk.User, error)
	DeleteUser(ctx context.Context, tenantID, userID string) error
	AssignRole(ctx context.Context, tenantID, userID, roleID string) error
	RevokeRole(ctx context.Context, tenantID, userID, roleID string) error

	// Group operations
	CreateGroup(ctx context.Context, tenantID string, req *iamsdk.CreateGroupRequest) (*iamsdk.Group, error)
	GetGroup(ctx context.Context, tenantID, groupID string) (*iamsdk.Group, error)
	ListGroups(ctx context.Context, tenantID string, req *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error)
	UpdateGroup(ctx context.Context, tenantID, groupID string, req *iamsdk.UpdateGroupRequest) (*iamsdk.Group, error)
	DeleteGroup(ctx context.Context, tenantID, groupID string) error
	AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error

	// Role operations
	CreateRole(ctx context.Context, tenantID string, req *iamsdk.CreateRoleRequest) (*iamsdk.Role, error)
	GetRole(ctx context.Context, tenantID, roleID string) (*iamsdk.Role, error)
	ListRoles(ctx context.Context, tenantID string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error)
	UpdateRole(ctx context.Context, tenantID, roleID string, req *iamsdk.UpdateRoleRequest) (*iamsdk.Role, error)
	DeleteRole(ctx context.Context, tenantID, roleID string) error

	// Tenant operations
	CreateTenant(ctx context.Context, req *CreateTenantRequest) (*TenantResponse, error)
	GetTenant(ctx context.Context, tenantID string) (*TenantResponse, error)
	ListTenants(ctx context.Context, limit, offset int32) (*ListTenantsResponse, error)
	UpdateTenant(ctx context.Context, tenantID string, req *UpdateTenantRequest) (*TenantResponse, error)
	DeleteTenant(ctx context.Context, tenantID string) error

	// Policy operations
	CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest) (*PolicyResponse, error)
	GetPolicy(ctx context.Context, tenantID, policyName string) (*PolicyResponse, error)
	ListPolicies(ctx context.Context, tenantID string, limit, offset int32) (*ListPoliciesResponse, error)
	UpdatePolicy(ctx context.Context, tenantID, policyName string, req *UpdatePolicyRequest) (*PolicyResponse, error)
	DeletePolicy(ctx context.Context, tenantID, policyName string) error
	ValidatePolicy(ctx context.Context, tenantID, specYAML string) (*ValidatePolicyResponse, error)
	TestPolicy(ctx context.Context, tenantID string, req *TestPolicyRequest) (*TestPolicyResponse, error)

	// App operations
	RegisterApp(ctx context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error)
	GetApp(ctx context.Context, tenantID, clientID string) (*iamsdk.Application, error)
	ListApps(ctx context.Context, tenantID string, limit, offset int32) (*ListAppsResponse, error)
	UpdateApp(ctx context.Context, tenantID, clientID string, req *iamsdk.UpdateAppRequest) (*iamsdk.Application, error)
	DeleteApp(ctx context.Context, tenantID, clientID string) error
	RotateAppSecret(ctx context.Context, tenantID, clientID string) (*RotateSecretResponse, error)
}

// PEPClient defines the interface for PEP operations used by REST handlers.
type PEPClient interface {
	// Check performs an authorization check.
	Check(ctx context.Context, req *iamsdk.CheckRequest) (*iamsdk.CheckResponse, error)
}

// IAMHandlers provides REST handlers for IAM operations
type IAMHandlers struct {
	logger     *logging.Logger
	iamClient  IAMClient
	pepClient  PEPClient
	respWriter response.HttpWriter
}

// NewIAMHandlers creates a new IAMHandlers instance
func NewIAMHandlers(
	logger *logging.Logger,
	iamClient IAMClient,
	pepClient PEPClient,
	respWriter response.HttpWriter,
) *IAMHandlers {
	return &IAMHandlers{
		logger:     logger,
		iamClient:  iamClient,
		pepClient:  pepClient,
		respWriter: respWriter,
	}
}

// Helper methods

// getTenantID resolves the active tenant in priority order:
//  1. URL path variable {tenant} — tenant-scoped routes like
//     /iam/tenants/{tenant}/users, gated by RequireOwnTenant
//  2. the verified session's tenant — flat routes like /iam/users,
//     where the WebUI doesn't carry the tenant in the URL
//
// This dual-mode resolution lets the same handler back both
// /api/v1/iam/users (flat, browser-friendly) and
// /api/v1/iam/tenants/{tenant}/users (explicit, machine-friendly)
// without duplicating the handler body.
func (h *IAMHandlers) getTenantID(r *http.Request) string {
	if t := mux.Vars(r)["tenant"]; t != "" {
		// Guarded by RequireOwnTenant, which requires the named tenant to
		// be the caller's own, so this is not a caller-chosen value.
		return t
	}
	// Flat routes resolve the tenant from the VERIFIED session the auth
	// middleware published — never by decoding a token again.
	//
	// This used to base64-decode the request's JWT payload without
	// verifying it, and to fall back to the `jwt`/`token` cookie whenever
	// the Authorization header was not a Bearer. That let the two halves
	// disagree: a caller could authenticate with a valid header token for
	// tenant A and attach a forged cookie naming tenant B, passing the
	// role guard as A while the handler operated on B. Reading the session
	// makes one verified identity the source for both decisions.
	//
	// Empty when no session exists, which fails closed: the IAM routes are
	// gated, so a request that reaches a handler always carries one.
	if session, ok := iammw.GetSessionFromContext(r.Context()); ok && session != nil {
		return session.TenantID()
	}
	return ""
}

func (h *IAMHandlers) getUserID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *IAMHandlers) getGroupID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *IAMHandlers) getRoleID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *IAMHandlers) getPolicyID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *IAMHandlers) getAppID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *IAMHandlers) getRoleName(r *http.Request) string {
	return mux.Vars(r)["role"]
}

func (h *IAMHandlers) getMemberID(r *http.Request) string {
	return mux.Vars(r)["user"]
}

func (h *IAMHandlers) getPaginationParams(r *http.Request) (int32, int32) {
	limit := defaultLimit
	offset := defaultOffset

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.ParseInt(o, 10, 32); err == nil {
			offset = int32(parsed)
			if offset < 0 {
				offset = defaultOffset
			}
		}
	}

	return limit, offset
}

func (h *IAMHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *IAMHandlers) decodeJSON(r *http.Request, v interface{}) error {
	// IAM REST request structs intentionally accept extra unknown fields
	// because the JS SDK includes redundant context such as `tenantId`
	// in the request body even though the server already parses tenant
	// from the URL path. Rejecting unknowns would force every page to
	// strip those fields client-side. Validation of required fields
	// happens after decode in each handler.
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *IAMHandlers) handleError(w http.ResponseWriter, r *http.Request, err error) {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "not found"):
		h.respWriter.Error404(w, r, err)
	case strings.Contains(errStr, "invalid"),
		strings.Contains(errStr, "required"),
		strings.Contains(errStr, "already exists"):
		h.respWriter.Error400(w, r, err)
	case strings.Contains(errStr, "permission denied"),
		strings.Contains(errStr, "unauthenticated"):
		h.respWriter.Error401(w, r, err)
	default:
		h.respWriter.Error500(w, r, err)
	}
}

// handleGRPCError maps gRPC status codes to HTTP error responses.
func (h *IAMHandlers) handleGRPCError(w http.ResponseWriter, r *http.Request, err error) {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			h.respWriter.Error404(w, r, err)
		case codes.InvalidArgument, codes.AlreadyExists, codes.FailedPrecondition, codes.OutOfRange:
			h.respWriter.Error400(w, r, err)
		case codes.PermissionDenied, codes.Unauthenticated:
			h.respWriter.Error401(w, r, err)
		default:
			h.respWriter.Error500(w, r, err)
		}
		return
	}
	h.respWriter.Error500(w, r, err)
}

// timeFromTimestamp converts a protobuf Timestamp to a *time.Time.
// Returns nil if ts is nil.
func timeFromTimestamp(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// User Handlers

// CreateUser handles POST /api/v1/iam/tenants/{tenant}/users
func (h *IAMHandlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req CreateUserRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Username defaults to the email local-part when the WebUI form
	// only supplies an email. The IAM SDK rejects empty usernames.
	username := req.Username
	if username == "" {
		if at := strings.IndexByte(req.Email, '@'); at > 0 {
			username = req.Email[:at]
		} else {
			username = req.Email
		}
	}
	sdkReq := &iamsdk.CreateUserRequest{
		Username:    username,
		Email:       req.Email,
		DisplayName: req.Name,
		Roles:       req.Roles,
		Groups:      req.Groups,
		Metadata:    req.Attributes,
	}

	user, err := h.iamClient.CreateUser(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, userToResponse(user))
}

// ListUsers handles GET /api/v1/iam/tenants/{tenant}/users
func (h *IAMHandlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.ListUsersRequest{
		PageSize: int(limit),
		Filter:   r.URL.Query().Get("email"),
		RoleID:   r.URL.Query().Get("role"),
		GroupID:  r.URL.Query().Get("group"),
	}

	resp, err := h.iamClient.ListUsers(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	users := make([]UserResponse, 0, len(resp.Users))
	for i := range resp.Users {
		users = append(users, userToResponse(&resp.Users[i]))
	}

	h.respWriter.Success200(w, r, ListUsersResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Pagination.TotalCount),
			Limit:  limit,
			Offset: offset,
		},
		Users: users,
	})
}

// GetUser handles GET /api/v1/iam/tenants/{tenant}/users/{id}
func (h *IAMHandlers) GetUser(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	userID := h.getUserID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingUserID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	user, err := h.iamClient.GetUser(ctx, tenantID, userID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, userToResponse(user))
}

// UpdateUser handles PUT /api/v1/iam/tenants/{tenant}/users/{id}
func (h *IAMHandlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	userID := h.getUserID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingUserID{})
		return
	}

	var req UpdateUserRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.UpdateUserRequest{
		Email:       req.Email,
		DisplayName: req.Name,
		Metadata:    req.Attributes,
	}

	user, err := h.iamClient.UpdateUser(ctx, tenantID, userID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, userToResponse(user))
}

// DeleteUser handles DELETE /api/v1/iam/tenants/{tenant}/users/{id}
func (h *IAMHandlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	userID := h.getUserID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingUserID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeleteUser(ctx, tenantID, userID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "user deleted successfully",
	})
}

// AssignUserRole handles POST /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}
func (h *IAMHandlers) AssignUserRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	userID := h.getUserID(r)
	roleName := h.getRoleName(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingUserID{})
		return
	}
	if roleName == "" {
		h.respWriter.Error400(w, r, ErrMissingRole{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.AssignRole(ctx, tenantID, userID, roleName)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "role assigned successfully",
	})
}

// RevokeUserRole handles DELETE /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}
func (h *IAMHandlers) RevokeUserRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	userID := h.getUserID(r)
	roleName := h.getRoleName(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingUserID{})
		return
	}
	if roleName == "" {
		h.respWriter.Error400(w, r, ErrMissingRole{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.RevokeRole(ctx, tenantID, userID, roleName)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "role revoked successfully",
	})
}

func userToResponse(u *iamsdk.User) UserResponse {
	resp := UserResponse{
		ID:          u.ID,
		TenantID:    u.TenantID,
		Email:       u.Email,
		Name:        u.DisplayName,
		Roles:       u.Roles,
		Groups:      u.Groups,
		Attributes:  u.Metadata,
		MFAVerified: u.MFAEnabled,
	}
	if !u.CreatedAt.IsZero() {
		t := u.CreatedAt
		resp.CreatedAt = &t
	}
	if !u.UpdatedAt.IsZero() {
		t := u.UpdatedAt
		resp.UpdatedAt = &t
	}
	if u.LastLoginAt != nil && !u.LastLoginAt.IsZero() {
		resp.LastAuth = u.LastLoginAt
	}
	return resp
}

// Group Handlers

// CreateGroup handles POST /api/v1/iam/tenants/{tenant}/groups
func (h *IAMHandlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req CreateGroupRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.CreateGroupRequest{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	group, err := h.iamClient.CreateGroup(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, groupToResponse(group))
}

// ListGroups handles GET /api/v1/iam/tenants/{tenant}/groups
func (h *IAMHandlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.ListGroupsRequest{
		PageSize: int(limit),
	}

	resp, err := h.iamClient.ListGroups(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	groups := make([]GroupResponse, 0, len(resp.Groups))
	for i := range resp.Groups {
		groups = append(groups, groupToResponse(&resp.Groups[i]))
	}

	h.respWriter.Success200(w, r, ListGroupsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Pagination.TotalCount),
			Limit:  limit,
			Offset: offset,
		},
		Groups: groups,
	})
}

// GetGroup handles GET /api/v1/iam/tenants/{tenant}/groups/{id}
func (h *IAMHandlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	groupID := h.getGroupID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if groupID == "" {
		h.respWriter.Error400(w, r, ErrMissingGroupID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	group, err := h.iamClient.GetGroup(ctx, tenantID, groupID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, groupToResponse(group))
}

// UpdateGroup handles PUT /api/v1/iam/tenants/{tenant}/groups/{id}
func (h *IAMHandlers) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	groupID := h.getGroupID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if groupID == "" {
		h.respWriter.Error400(w, r, ErrMissingGroupID{})
		return
	}

	var req UpdateGroupRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.UpdateGroupRequest{
		Name:        req.Name,
		Description: req.Description,
	}

	group, err := h.iamClient.UpdateGroup(ctx, tenantID, groupID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, groupToResponse(group))
}

// DeleteGroup handles DELETE /api/v1/iam/tenants/{tenant}/groups/{id}
func (h *IAMHandlers) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	groupID := h.getGroupID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if groupID == "" {
		h.respWriter.Error400(w, r, ErrMissingGroupID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeleteGroup(ctx, tenantID, groupID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "group deleted successfully",
	})
}

// AddGroupMember handles POST /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}
func (h *IAMHandlers) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	groupID := h.getGroupID(r)
	userID := h.getMemberID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if groupID == "" {
		h.respWriter.Error400(w, r, ErrMissingGroupID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingMember{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.AddGroupMember(ctx, tenantID, groupID, userID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "member added successfully",
	})
}

// RemoveGroupMember handles DELETE /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}
func (h *IAMHandlers) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	groupID := h.getGroupID(r)
	userID := h.getMemberID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if groupID == "" {
		h.respWriter.Error400(w, r, ErrMissingGroupID{})
		return
	}
	if userID == "" {
		h.respWriter.Error400(w, r, ErrMissingMember{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.RemoveGroupMember(ctx, tenantID, groupID, userID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "member removed successfully",
	})
}

func groupToResponse(g *iamsdk.Group) GroupResponse {
	resp := GroupResponse{
		ID:          g.ID,
		TenantID:    g.TenantID,
		Name:        g.Name,
		Description: g.Description,
	}
	if !g.CreatedAt.IsZero() {
		t := g.CreatedAt
		resp.CreatedAt = &t
	}
	if !g.UpdatedAt.IsZero() {
		t := g.UpdatedAt
		resp.UpdatedAt = &t
	}
	return resp
}

// Role Handlers

// CreateRole handles POST /api/v1/iam/tenants/{tenant}/roles
func (h *IAMHandlers) CreateRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req CreateRoleRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.CreateRoleRequest{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	role, err := h.iamClient.CreateRole(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, roleToResponse(role))
}

// ListRoles handles GET /api/v1/iam/tenants/{tenant}/roles
func (h *IAMHandlers) ListRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.ListRolesRequest{
		PageSize: int(limit),
	}

	resp, err := h.iamClient.ListRoles(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	roles := make([]RoleResponse, 0, len(resp.Roles))
	for i := range resp.Roles {
		roles = append(roles, roleToResponse(&resp.Roles[i]))
	}

	h.respWriter.Success200(w, r, ListRolesResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Pagination.TotalCount),
			Limit:  limit,
			Offset: offset,
		},
		Roles: roles,
	})
}

// GetRole handles GET /api/v1/iam/tenants/{tenant}/roles/{id}
func (h *IAMHandlers) GetRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	roleID := h.getRoleID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if roleID == "" {
		h.respWriter.Error400(w, r, ErrMissingRoleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	role, err := h.iamClient.GetRole(ctx, tenantID, roleID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, roleToResponse(role))
}

// UpdateRole handles PUT /api/v1/iam/tenants/{tenant}/roles/{id}
func (h *IAMHandlers) UpdateRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	roleID := h.getRoleID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if roleID == "" {
		h.respWriter.Error400(w, r, ErrMissingRoleID{})
		return
	}

	var req UpdateRoleRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.UpdateRoleRequest{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	role, err := h.iamClient.UpdateRole(ctx, tenantID, roleID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, roleToResponse(role))
}

// DeleteRole handles DELETE /api/v1/iam/tenants/{tenant}/roles/{id}
func (h *IAMHandlers) DeleteRole(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	roleID := h.getRoleID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if roleID == "" {
		h.respWriter.Error400(w, r, ErrMissingRoleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeleteRole(ctx, tenantID, roleID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "role deleted successfully",
	})
}

func roleToResponse(r *iamsdk.Role) RoleResponse {
	resp := RoleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
	}
	if !r.CreatedAt.IsZero() {
		t := r.CreatedAt
		resp.CreatedAt = &t
	}
	if !r.UpdatedAt.IsZero() {
		t := r.UpdatedAt
		resp.UpdatedAt = &t
	}
	return resp
}

// Tenant Handlers

// CreateTenant handles POST /api/v1/iam/tenants
func (h *IAMHandlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.CreateTenant(ctx, &req)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// ListTenants handles GET /api/v1/iam/tenants
func (h *IAMHandlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.ListTenants(ctx, limit, offset)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// GetTenant handles GET /api/v1/iam/tenants/{tenant}
func (h *IAMHandlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.GetTenant(ctx, tenantID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// UpdateTenant handles PUT /api/v1/iam/tenants/{tenant}
func (h *IAMHandlers) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req UpdateTenantRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.UpdateTenant(ctx, tenantID, &req)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// DeleteTenant handles DELETE /api/v1/iam/tenants/{tenant}
func (h *IAMHandlers) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeleteTenant(ctx, tenantID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "tenant deleted successfully",
	})
}

// Policy Handlers

// CreatePolicy handles POST /api/v1/iam/tenants/{tenant}/policies
func (h *IAMHandlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req CreatePolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "policy name is required"})
		return
	}
	if req.SpecYAML == "" {
		h.respWriter.Error400(w, r, ErrInvalidPolicySpec{Reason: "policy spec is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.CreatePolicy(ctx, tenantID, &req)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// ListPolicies handles GET /api/v1/iam/tenants/{tenant}/policies
func (h *IAMHandlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.ListPolicies(ctx, tenantID, limit, offset)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// GetPolicy handles GET /api/v1/iam/tenants/{tenant}/policies/{id}
func (h *IAMHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	policyID := h.getPolicyID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if policyID == "" {
		h.respWriter.Error400(w, r, ErrMissingPolicyID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// UpdatePolicy handles PUT /api/v1/iam/tenants/{tenant}/policies/{id}
func (h *IAMHandlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	policyID := h.getPolicyID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if policyID == "" {
		h.respWriter.Error400(w, r, ErrMissingPolicyID{})
		return
	}

	var req UpdatePolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.UpdatePolicy(ctx, tenantID, policyID, &req)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// DeletePolicy handles DELETE /api/v1/iam/tenants/{tenant}/policies/{id}
func (h *IAMHandlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	policyID := h.getPolicyID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if policyID == "" {
		h.respWriter.Error400(w, r, ErrMissingPolicyID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeletePolicy(ctx, tenantID, policyID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "policy deleted successfully",
	})
}

// ValidatePolicy handles POST /api/v1/iam/tenants/{tenant}/policies/validate
func (h *IAMHandlers) ValidatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req ValidatePolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.SpecYAML == "" {
		h.respWriter.Error400(w, r, ErrInvalidPolicySpec{Reason: "policy spec is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.ValidatePolicy(ctx, tenantID, req.SpecYAML)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// TestPolicy handles POST /api/v1/iam/tenants/{tenant}/policies/test
func (h *IAMHandlers) TestPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req TestPolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.SubjectID == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "subject_id is required"})
		return
	}
	if req.Action == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "action is required"})
		return
	}
	if req.Resource == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "resource is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.TestPolicy(ctx, tenantID, &req)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// App Handlers

// RegisterApp handles POST /api/v1/iam/tenants/{tenant}/apps
func (h *IAMHandlers) RegisterApp(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	var req RegisterAppRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "app name is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	req.Resolve()
	sdkReq := &iamsdk.RegisterAppRequest{
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   parseGrantTypes(req.GrantTypes),
	}

	app, err := h.iamClient.RegisterApp(ctx, tenantID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, appToResponse(app))
}

// ListApps handles GET /api/v1/iam/tenants/{tenant}/apps
func (h *IAMHandlers) ListApps(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.ListApps(ctx, tenantID, limit, offset)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

// GetApp handles GET /api/v1/iam/tenants/{tenant}/apps/{id}
func (h *IAMHandlers) GetApp(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	appID := h.getAppID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if appID == "" {
		h.respWriter.Error400(w, r, ErrMissingAppID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	app, err := h.iamClient.GetApp(ctx, tenantID, appID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, appToResponse(app))
}

// UpdateApp handles PUT /api/v1/iam/tenants/{tenant}/apps/{id}
func (h *IAMHandlers) UpdateApp(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	appID := h.getAppID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if appID == "" {
		h.respWriter.Error400(w, r, ErrMissingAppID{})
		return
	}

	var req UpdateAppRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sdkReq := &iamsdk.UpdateAppRequest{
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   parseGrantTypes(req.GrantTypes),
	}

	app, err := h.iamClient.UpdateApp(ctx, tenantID, appID, sdkReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, appToResponse(app))
}

// DeleteApp handles DELETE /api/v1/iam/tenants/{tenant}/apps/{id}
func (h *IAMHandlers) DeleteApp(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	appID := h.getAppID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if appID == "" {
		h.respWriter.Error400(w, r, ErrMissingAppID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.iamClient.DeleteApp(ctx, tenantID, appID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "app deleted successfully",
	})
}

// RotateAppSecret handles POST /api/v1/iam/tenants/{tenant}/apps/{id}/rotate
func (h *IAMHandlers) RotateAppSecret(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	appID := h.getAppID(r)

	if tenantID == "" {
		h.respWriter.Error400(w, r, ErrMissingTenantID{})
		return
	}
	if appID == "" {
		h.respWriter.Error400(w, r, ErrMissingAppID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.iamClient.RotateAppSecret(ctx, tenantID, appID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, resp)
}

func appToResponse(a *iamsdk.Application) AppResponse {
	resp := AppResponse{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		TenantID:     a.TenantID,
		Name:         a.Name,
		RedirectURIs: a.RedirectURIs,
		GrantTypes:   grantTypesToStrings(a.GrantTypes),
	}
	if !a.CreatedAt.IsZero() {
		t := a.CreatedAt
		resp.CreatedAt = &t
	}
	if !a.UpdatedAt.IsZero() {
		t := a.UpdatedAt
		resp.UpdatedAt = &t
	}
	return resp
}

// parseGrantTypes converts string grant types to SDK GrantType values.
func parseGrantTypes(types []string) []iamsdk.GrantType {
	if len(types) == 0 {
		return nil
	}
	result := make([]iamsdk.GrantType, 0, len(types))
	for _, t := range types {
		result = append(result, iamsdk.ParseGrantType(t))
	}
	return result
}

// grantTypesToStrings converts SDK GrantType values to string representations.
func grantTypesToStrings(types []iamsdk.GrantType) []string {
	if len(types) == 0 {
		return nil
	}
	result := make([]string, 0, len(types))
	for _, t := range types {
		result = append(result, t.String())
	}
	return result
}
