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

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultLimit  int32 = 50
	maxLimit      int32 = 1000
	defaultOffset int32 = 0

	requestTimeout = 30 * time.Second
)

// IAMHandlers provides REST handlers for IAM operations
type IAMHandlers struct {
	logger     *logging.Logger
	iamClient  iampb.IAMServiceClient
	pepClient  iampb.PEPServiceClient
	respWriter response.HttpWriter
}

// NewIAMHandlers creates a new IAMHandlers instance
func NewIAMHandlers(
	logger *logging.Logger,
	iamClient iampb.IAMServiceClient,
	pepClient iampb.PEPServiceClient,
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

func (h *IAMHandlers) getTenantID(r *http.Request) string {
	return mux.Vars(r)["tenant"]
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
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (h *IAMHandlers) handleGRPCError(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		h.respWriter.Error500(w, r, err)
		return
	}

	switch st.Code() {
	case codes.NotFound:
		h.respWriter.Error404(w, r, err)
	case codes.InvalidArgument:
		h.respWriter.Error400(w, r, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		h.respWriter.Error401(w, r, err)
	case codes.AlreadyExists:
		h.respWriter.Error400(w, r, err)
	default:
		h.respWriter.Error500(w, r, err)
	}
}

func timeFromTimestamp(ts interface{ AsTime() time.Time }) *time.Time {
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

	grpcReq := &iampb.CreateUserRequest{
		TenantId:   tenantID,
		Email:      req.Email,
		Name:       req.Name,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Attributes: req.Attributes,
	}

	resp, err := h.iamClient.CreateUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.userToResponse(resp))
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

	grpcReq := &iampb.ListUsersRequest{
		TenantId: tenantID,
		Limit:    limit,
		Offset:   offset,
		Email:    r.URL.Query().Get("email"),
		Role:     r.URL.Query().Get("role"),
		Group:    r.URL.Query().Get("group"),
	}

	resp, err := h.iamClient.ListUsers(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	users := make([]UserResponse, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, h.userToResponse(u))
	}

	h.respWriter.Success200(w, r, ListUsersResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
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

	grpcReq := &iampb.GetUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	}

	resp, err := h.iamClient.GetUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.userToResponse(resp))
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

	grpcReq := &iampb.UpdateUserRequest{
		TenantId:   tenantID,
		UserId:     userID,
		Email:      req.Email,
		Name:       req.Name,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Attributes: req.Attributes,
	}

	resp, err := h.iamClient.UpdateUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.userToResponse(resp))
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

	grpcReq := &iampb.DeleteUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	}

	resp, err := h.iamClient.DeleteUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.AssignRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		Role:     roleName,
	}

	resp, err := h.iamClient.AssignRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.RevokeRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		Role:     roleName,
	}

	resp, err := h.iamClient.RevokeRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
		Message: "role revoked successfully",
	})
}

func (h *IAMHandlers) userToResponse(u *iampb.User) UserResponse {
	return UserResponse{
		ID:          u.Id,
		TenantID:    u.TenantId,
		Email:       u.Email,
		Name:        u.Name,
		Roles:       u.Roles,
		Groups:      u.Groups,
		Attributes:  u.Attributes,
		MFAVerified: u.MfaVerified,
		CreatedAt:   timeFromTimestamp(u.CreatedAt),
		UpdatedAt:   timeFromTimestamp(u.UpdatedAt),
		LastAuth:    timeFromTimestamp(u.LastAuth),
	}
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

	grpcReq := &iampb.CreateGroupRequest{
		TenantId:    tenantID,
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	resp, err := h.iamClient.CreateGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.groupToResponse(resp))
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

	grpcReq := &iampb.ListGroupsRequest{
		TenantId: tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.iamClient.ListGroups(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	groups := make([]GroupResponse, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		groups = append(groups, h.groupToResponse(g))
	}

	h.respWriter.Success200(w, r, ListGroupsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
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

	grpcReq := &iampb.GetGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	}

	resp, err := h.iamClient.GetGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.groupToResponse(resp))
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

	grpcReq := &iampb.UpdateGroupRequest{
		TenantId:    tenantID,
		GroupId:     groupID,
		Name:        req.Name,
		Description: req.Description,
	}

	resp, err := h.iamClient.UpdateGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.groupToResponse(resp))
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

	grpcReq := &iampb.DeleteGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	}

	resp, err := h.iamClient.DeleteGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.AddUserToGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
		UserId:   userID,
	}

	resp, err := h.iamClient.AddUserToGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.RemoveUserFromGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
		UserId:   userID,
	}

	resp, err := h.iamClient.RemoveUserFromGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
		Message: "member removed successfully",
	})
}

func (h *IAMHandlers) groupToResponse(g *iampb.Group) GroupResponse {
	return GroupResponse{
		ID:          g.Id,
		TenantID:    g.TenantId,
		Name:        g.Name,
		Description: g.Description,
		Members:     g.Members,
		CreatedAt:   timeFromTimestamp(g.CreatedAt),
		UpdatedAt:   timeFromTimestamp(g.UpdatedAt),
	}
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

	grpcReq := &iampb.CreateRoleRequest{
		TenantId:    tenantID,
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	resp, err := h.iamClient.CreateRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.roleToResponse(resp))
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

	grpcReq := &iampb.ListRolesRequest{
		TenantId: tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.iamClient.ListRoles(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	roles := make([]RoleResponse, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		roles = append(roles, h.roleToResponse(r))
	}

	h.respWriter.Success200(w, r, ListRolesResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
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

	grpcReq := &iampb.GetRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	}

	resp, err := h.iamClient.GetRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.roleToResponse(resp))
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

	grpcReq := &iampb.UpdateRoleRequest{
		TenantId:    tenantID,
		RoleId:      roleID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	resp, err := h.iamClient.UpdateRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.roleToResponse(resp))
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

	grpcReq := &iampb.DeleteRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	}

	resp, err := h.iamClient.DeleteRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
		Message: "role deleted successfully",
	})
}

func (h *IAMHandlers) roleToResponse(r *iampb.Role) RoleResponse {
	return RoleResponse{
		ID:          r.Id,
		TenantID:    r.TenantId,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
		CreatedAt:   timeFromTimestamp(r.CreatedAt),
		UpdatedAt:   timeFromTimestamp(r.UpdatedAt),
	}
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

	var settings *iampb.TenantSettings
	if req.Settings != nil {
		settings = &iampb.TenantSettings{
			MaxUsers:    req.Settings.MaxUsers,
			MfaRequired: req.Settings.MFARequired,
		}
	}

	grpcReq := &iampb.CreateTenantRequest{
		Id:       req.ID,
		Name:     req.Name,
		Settings: settings,
	}

	resp, err := h.iamClient.CreateTenant(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.tenantToResponse(resp))
}

// ListTenants handles GET /api/v1/iam/tenants
func (h *IAMHandlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &iampb.ListTenantsRequest{
		Limit:  limit,
		Offset: offset,
	}

	resp, err := h.iamClient.ListTenants(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	tenants := make([]TenantResponse, 0, len(resp.Tenants))
	for _, t := range resp.Tenants {
		tenants = append(tenants, h.tenantToResponse(t))
	}

	h.respWriter.Success200(w, r, ListTenantsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
			Limit:  limit,
			Offset: offset,
		},
		Tenants: tenants,
	})
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

	grpcReq := &iampb.GetTenantRequest{
		Id: tenantID,
	}

	resp, err := h.iamClient.GetTenant(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.tenantToResponse(resp))
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

	var settings *iampb.TenantSettings
	if req.Settings != nil {
		settings = &iampb.TenantSettings{
			MaxUsers:    req.Settings.MaxUsers,
			MfaRequired: req.Settings.MFARequired,
		}
	}

	grpcReq := &iampb.UpdateTenantRequest{
		Id:       tenantID,
		Name:     req.Name,
		Settings: settings,
	}

	resp, err := h.iamClient.UpdateTenant(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.tenantToResponse(resp))
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

	grpcReq := &iampb.DeleteTenantRequest{
		Id: tenantID,
	}

	resp, err := h.iamClient.DeleteTenant(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
		Message: "tenant deleted successfully",
	})
}

func (h *IAMHandlers) tenantToResponse(t *iampb.Tenant) TenantResponse {
	var settings *TenantSettings
	if t.Settings != nil {
		settings = &TenantSettings{
			MaxUsers:    t.Settings.MaxUsers,
			MFARequired: t.Settings.MfaRequired,
		}
	}

	return TenantResponse{
		ID:        t.Id,
		Name:      t.Name,
		Settings:  settings,
		CreatedAt: timeFromTimestamp(t.CreatedAt),
		UpdatedAt: timeFromTimestamp(t.UpdatedAt),
	}
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

	grpcReq := &iampb.CreatePolicyRequest{
		TenantId:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		SpecYaml:    []byte(req.SpecYAML),
		Labels:      req.Labels,
	}

	resp, err := h.iamClient.CreatePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.policyToResponse(resp))
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

	grpcReq := &iampb.ListPoliciesRequest{
		TenantId: tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.iamClient.ListPolicies(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	policies := make([]PolicyResponse, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		policies = append(policies, h.policyToResponse(p))
	}

	h.respWriter.Success200(w, r, ListPoliciesResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
			Limit:  limit,
			Offset: offset,
		},
		Policies: policies,
	})
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

	grpcReq := &iampb.GetPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyID,
	}

	resp, err := h.iamClient.GetPolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.policyToResponse(resp))
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

	grpcReq := &iampb.UpdatePolicyRequest{
		TenantId:    tenantID,
		PolicyName:  policyID,
		Description: req.Description,
		Priority:    req.Priority,
		Labels:      req.Labels,
	}

	if req.SpecYAML != "" {
		grpcReq.SpecYaml = []byte(req.SpecYAML)
	}

	resp, err := h.iamClient.UpdatePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.policyToResponse(resp))
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

	grpcReq := &iampb.DeletePolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyID,
	}

	resp, err := h.iamClient.DeletePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.ValidatePolicyRequest{
		TenantId: tenantID,
		SpecYaml: []byte(req.SpecYAML),
	}

	resp, err := h.iamClient.ValidatePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, ValidatePolicyResponse{
		Valid:  resp.Valid,
		Errors: resp.Errors,
	})
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

	subject := &iampb.Subject{
		Id:         req.SubjectID,
		TenantId:   tenantID,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Attributes: req.Attributes,
	}

	grpcReq := &iampb.TestPolicyRequest{
		TenantId: tenantID,
		Subject:  subject,
		Action:   req.Action,
		Resource: req.Resource,
		Context:  req.Context,
	}

	resp, err := h.iamClient.TestPolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, TestPolicyResponse{
		Allowed:          resp.Allowed,
		MatchedPolicy:    resp.MatchedPolicy,
		MatchedRule:      resp.MatchedRule,
		EvaluationTimeNs: resp.EvaluationTimeNs,
	})
}

func (h *IAMHandlers) policyToResponse(p *iampb.Policy) PolicyResponse {
	return PolicyResponse{
		Name:        p.Name,
		TenantID:    p.TenantId,
		Description: p.Description,
		Priority:    p.Priority,
		SpecYAML:    strings.TrimSpace(string(p.SpecYaml)),
		Labels:      p.Labels,
		CreatedAt:   timeFromTimestamp(p.CreatedAt),
		UpdatedAt:   timeFromTimestamp(p.UpdatedAt),
	}
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

	grpcReq := &iampb.RegisterAppRequest{
		TenantId:       tenantID,
		Name:           req.Name,
		RedirectUris:   req.RedirectURIs,
		GrantTypes:     req.GrantTypes,
		ResponseTypes:  req.ResponseTypes,
		ResourcePrefix: req.ResourcePrefix,
	}

	resp, err := h.iamClient.RegisterApp(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.appToResponse(resp))
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

	grpcReq := &iampb.ListAppsRequest{
		TenantId: tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.iamClient.ListApps(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	apps := make([]AppResponse, 0, len(resp.Apps))
	for _, a := range resp.Apps {
		apps = append(apps, h.appToResponse(a))
	}

	h.respWriter.Success200(w, r, ListAppsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(resp.Total),
			Limit:  limit,
			Offset: offset,
		},
		Apps: apps,
	})
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

	grpcReq := &iampb.GetAppRequest{
		TenantId: tenantID,
		ClientId: appID,
	}

	resp, err := h.iamClient.GetApp(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.appToResponse(resp))
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

	grpcReq := &iampb.UpdateAppRequest{
		TenantId:       tenantID,
		ClientId:       appID,
		Name:           req.Name,
		RedirectUris:   req.RedirectURIs,
		GrantTypes:     req.GrantTypes,
		ResponseTypes:  req.ResponseTypes,
		ResourcePrefix: req.ResourcePrefix,
	}

	resp, err := h.iamClient.UpdateApp(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.appToResponse(resp))
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

	grpcReq := &iampb.DeleteAppRequest{
		TenantId: tenantID,
		ClientId: appID,
	}

	resp, err := h.iamClient.DeleteApp(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Success,
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

	grpcReq := &iampb.RotateAppSecretRequest{
		TenantId: tenantID,
		ClientId: appID,
	}

	resp, err := h.iamClient.RotateAppSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RotateSecretResponse{
		ClientID:     resp.ClientId,
		Name:         resp.Name,
		ClientSecret: resp.ClientSecret,
	})
}

func (h *IAMHandlers) appToResponse(a *iampb.Application) AppResponse {
	return AppResponse{
		ClientID:       a.ClientId,
		ClientSecret:   a.ClientSecret,
		TenantID:       a.TenantId,
		Name:           a.Name,
		RedirectURIs:   a.RedirectUris,
		GrantTypes:     a.GrantTypes,
		ResponseTypes:  a.ResponseTypes,
		ResourcePrefix: a.ResourcePrefix,
		CreatedAt:      timeFromTimestamp(a.CreatedAt),
		UpdatedAt:      timeFromTimestamp(a.UpdatedAt),
	}
}
