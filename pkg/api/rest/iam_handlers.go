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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// IAM REST Handler Constants
// =============================================================================

const (
	defaultIAMLimit   int32 = 50
	maxIAMLimit       int32 = 1000
	defaultIAMOffset  int32 = 0
	iamRequestTimeout       = 30 * time.Second
)

// =============================================================================
// IAM REST Handler Errors
// =============================================================================

// ErrIAMServiceUnavailable is returned when the IAM service is not available.
type ErrIAMServiceUnavailable struct{}

func (e ErrIAMServiceUnavailable) Error() string {
	return "IAM service not available"
}

// ErrIAMMissingTenantID is returned when the tenant ID is required but not provided.
type ErrIAMMissingTenantID struct{}

func (e ErrIAMMissingTenantID) Error() string {
	return "tenant ID is required"
}

// ErrIAMMissingUserID is returned when the user ID is required but not provided.
type ErrIAMMissingUserID struct{}

func (e ErrIAMMissingUserID) Error() string {
	return "user ID is required"
}

// ErrIAMMissingRoleID is returned when the role ID is required but not provided.
type ErrIAMMissingRoleID struct{}

func (e ErrIAMMissingRoleID) Error() string {
	return "role ID is required"
}

// ErrIAMMissingGroupID is returned when the group ID is required but not provided.
type ErrIAMMissingGroupID struct{}

func (e ErrIAMMissingGroupID) Error() string {
	return "group ID is required"
}

// ErrIAMMissingPolicyID is returned when the policy ID is required but not provided.
type ErrIAMMissingPolicyID struct{}

func (e ErrIAMMissingPolicyID) Error() string {
	return "policy ID is required"
}

// ErrIAMInvalidRequestBody is returned when the request body is invalid.
type ErrIAMInvalidRequestBody struct {
	Reason string
}

func (e ErrIAMInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrIAMMissingToken is returned when a token is required but not provided.
type ErrIAMMissingToken struct{}

func (e ErrIAMMissingToken) Error() string {
	return "token is required"
}

// ErrIAMOperationFailed is returned when an IAM operation fails.
type ErrIAMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrIAMOperationFailed) Error() string {
	return fmt.Sprintf("IAM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrIAMOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Request/Response Types
// =============================================================================

// IAMErrorResponse represents an error response.
type IAMErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// IAMSuccessResponse represents a generic success response.
type IAMSuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// IAMPaginatedResponse contains pagination metadata.
type IAMPaginatedResponse struct {
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// --- User Types ---

// IAMCreateUserRequest represents a user creation request.
type IAMCreateUserRequest struct {
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// IAMUpdateUserRequest represents a user update request.
type IAMUpdateUserRequest struct {
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// IAMUserResponse represents a user in API responses.
type IAMUserResponse struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Email       string            `json:"email"`
	Name        string            `json:"name,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	MFAVerified bool              `json:"mfa_verified"`
	CreatedAt   *time.Time        `json:"created_at,omitempty"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty"`
	LastAuth    *time.Time        `json:"last_auth,omitempty"`
}

// IAMListUsersResponse represents a list of users.
type IAMListUsersResponse struct {
	IAMPaginatedResponse
	Users []IAMUserResponse `json:"users"`
}

// --- Role Types ---

// IAMCreateRoleRequest represents a role creation request.
type IAMCreateRoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// IAMUpdateRoleRequest represents a role update request.
type IAMUpdateRoleRequest struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// IAMRoleResponse represents a role in API responses.
type IAMRoleResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// IAMListRolesResponse represents a list of roles.
type IAMListRolesResponse struct {
	IAMPaginatedResponse
	Roles []IAMRoleResponse `json:"roles"`
}

// --- Group Types ---

// IAMCreateGroupRequest represents a group creation request.
type IAMCreateGroupRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// IAMUpdateGroupRequest represents a group update request.
type IAMUpdateGroupRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// IAMGroupResponse represents a group in API responses.
type IAMGroupResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Members     []string   `json:"members,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// IAMListGroupsResponse represents a list of groups.
type IAMListGroupsResponse struct {
	IAMPaginatedResponse
	Groups []IAMGroupResponse `json:"groups"`
}

// --- Policy Types ---

// IAMCreatePolicyRequest represents a policy creation request.
type IAMCreatePolicyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	SpecYAML    string            `json:"spec_yaml"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// IAMUpdatePolicyRequest represents a policy update request.
type IAMUpdatePolicyRequest struct {
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	SpecYAML    string            `json:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// IAMPolicyResponse represents a policy in API responses.
type IAMPolicyResponse struct {
	Name        string            `json:"name"`
	TenantID    string            `json:"tenant_id"`
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority"`
	SpecYAML    string            `json:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   *time.Time        `json:"created_at,omitempty"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty"`
}

// IAMListPoliciesResponse represents a list of policies.
type IAMListPoliciesResponse struct {
	IAMPaginatedResponse
	Policies []IAMPolicyResponse `json:"policies"`
}

// --- Token Types ---

// IAMIssueTokenRequest represents a token issuance request.
type IAMIssueTokenRequest struct {
	UserID    string   `json:"user_id"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn int64    `json:"expires_in,omitempty"`
}

// IAMIssueTokenResponse represents a token issuance response.
type IAMIssueTokenResponse struct {
	TokenID      string `json:"token_id"`
	AccessToken  string `json:"access_token" secret:"true"`
	RefreshToken string `json:"refresh_token,omitempty" secret:"true"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// IAMValidateTokenRequest represents a token validation request.
type IAMValidateTokenRequest struct {
	Token string `json:"token" secret:"true"`
}

// IAMValidateTokenResponse represents a token validation response.
type IAMValidateTokenResponse struct {
	Valid     bool     `json:"valid"`
	UserID    string   `json:"user_id,omitempty"`
	TenantID  string   `json:"tenant_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresAt int64    `json:"expires_at,omitempty"`
}

// IAMRefreshTokenRequest represents a token refresh request.
type IAMRefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" secret:"true"`
}

// IAMRevokeTokenRequest represents a token revocation request.
type IAMRevokeTokenRequest struct {
	TokenID string `json:"token_id,omitempty"`
	Token   string `json:"token,omitempty" secret:"true"`
}

// =============================================================================
// IAM Handlers
// =============================================================================

// IAMHandlers provides REST API handlers for IAM operations.
type IAMHandlers struct {
	iamClient platformv1.PlatformIAMServiceClient
	logger    *slog.Logger
}

// NewIAMHandlers creates a new IAMHandlers instance.
func NewIAMHandlers(iamClient platformv1.PlatformIAMServiceClient, logger *slog.Logger) *IAMHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &IAMHandlers{
		iamClient: iamClient,
		logger:    logger,
	}
}

// RegisterRoutes registers all IAM routes on the provided router.
func (h *IAMHandlers) RegisterRoutes(router *mux.Router) {
	// User endpoints
	router.HandleFunc("/api/v1/iam/users", h.handleCreateUser).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/users", h.handleListUsers).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/users/{id}", h.handleGetUser).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/users/{id}", h.handleUpdateUser).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/iam/users/{id}", h.handleDeleteUser).Methods(http.MethodDelete)

	// Role endpoints
	router.HandleFunc("/api/v1/iam/roles", h.handleCreateRole).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/roles", h.handleListRoles).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/roles/{id}", h.handleGetRole).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/roles/{id}", h.handleUpdateRole).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/iam/roles/{id}", h.handleDeleteRole).Methods(http.MethodDelete)

	// Group endpoints
	router.HandleFunc("/api/v1/iam/groups", h.handleCreateGroup).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/groups", h.handleListGroups).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/groups/{id}", h.handleGetGroup).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/groups/{id}", h.handleUpdateGroup).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/iam/groups/{id}", h.handleDeleteGroup).Methods(http.MethodDelete)

	// Policy endpoints
	router.HandleFunc("/api/v1/iam/policies", h.handleCreatePolicy).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/policies", h.handleListPolicies).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/policies/{id}", h.handleGetPolicy).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/iam/policies/{id}", h.handleUpdatePolicy).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/iam/policies/{id}", h.handleDeletePolicy).Methods(http.MethodDelete)

	// Token endpoints
	router.HandleFunc("/api/v1/iam/tokens", h.handleIssueToken).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/tokens/validate", h.handleValidateToken).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/tokens/refresh", h.handleRefreshToken).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/iam/tokens/revoke", h.handleRevokeToken).Methods(http.MethodPost)

	h.logger.Info("IAM REST routes registered")
}

// =============================================================================
// User Handlers
// =============================================================================

// handleCreateUser handles POST /api/v1/iam/users
func (h *IAMHandlers) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	var req IAMCreateUserRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateIAMUserRequest{
		TenantId:   tenantID,
		Email:      req.Email,
		Name:       req.Name,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Attributes: req.Attributes,
	}

	resp, err := h.iamClient.CreateUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "create_user", err)
		return
	}

	h.logger.Info("User created", "user_id", resp.User.Id, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusCreated, h.userToResponse(resp.User))
}

// handleListUsers handles GET /api/v1/iam/users
func (h *IAMHandlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Convert limit/offset to page/pageSize for gRPC
	page := uint32(1)
	if offset > 0 && limit > 0 {
		page = uint32(offset/limit) + 1
	}

	grpcReq := &platformv1.ListIAMUsersRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(limit),
			Page:     page,
		},
		EmailFilter: r.URL.Query().Get("email"),
		RoleFilter:  r.URL.Query().Get("role"),
		GroupFilter: r.URL.Query().Get("group"),
	}

	resp, err := h.iamClient.ListUsers(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "list_users", err)
		return
	}

	users := make([]IAMUserResponse, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, h.userToResponse(u))
	}

	h.writeJSON(w, http.StatusOK, IAMListUsersResponse{
		IAMPaginatedResponse: IAMPaginatedResponse{
			Total:  resp.Total,
			Limit:  limit,
			Offset: offset,
		},
		Users: users,
	})
}

// handleGetUser handles GET /api/v1/iam/users/{id}
func (h *IAMHandlers) handleGetUser(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	userID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingUserID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	}

	resp, err := h.iamClient.GetUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "get_user", err)
		return
	}

	h.writeJSON(w, http.StatusOK, h.userToResponse(resp.User))
}

// handleUpdateUser handles PUT /api/v1/iam/users/{id}
func (h *IAMHandlers) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	userID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingUserID{})
		return
	}

	var req IAMUpdateUserRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.UpdateIAMUserRequest{
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
		h.handleGRPCError(w, "update_user", err)
		return
	}

	h.logger.Info("User updated", "user_id", userID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, h.userToResponse(resp.User))
}

// handleDeleteUser handles DELETE /api/v1/iam/users/{id}
func (h *IAMHandlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	userID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingUserID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	}

	_, err := h.iamClient.DeleteUser(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "delete_user", err)
		return
	}

	h.logger.Info("User deleted", "user_id", userID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, IAMSuccessResponse{
		Success: true,
		Message: "user deleted successfully",
	})
}

// =============================================================================
// Role Handlers
// =============================================================================

// handleCreateRole handles POST /api/v1/iam/roles
func (h *IAMHandlers) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	var req IAMCreateRoleRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateIAMRoleRequest{
		TenantId:    tenantID,
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	resp, err := h.iamClient.CreateRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "create_role", err)
		return
	}

	h.logger.Info("Role created", "role_id", resp.Role.Id, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusCreated, h.roleToResponse(resp.Role))
}

// handleListRoles handles GET /api/v1/iam/roles
func (h *IAMHandlers) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Convert limit/offset to page/pageSize for gRPC
	page := uint32(1)
	if offset > 0 && limit > 0 {
		page = uint32(offset/limit) + 1
	}

	grpcReq := &platformv1.ListIAMRolesRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(limit),
			Page:     page,
		},
	}

	resp, err := h.iamClient.ListRoles(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "list_roles", err)
		return
	}

	roles := make([]IAMRoleResponse, 0, len(resp.Roles))
	for _, role := range resp.Roles {
		roles = append(roles, h.roleToResponse(role))
	}

	h.writeJSON(w, http.StatusOK, IAMListRolesResponse{
		IAMPaginatedResponse: IAMPaginatedResponse{
			Total:  resp.Total,
			Limit:  limit,
			Offset: offset,
		},
		Roles: roles,
	})
}

// handleGetRole handles GET /api/v1/iam/roles/{id}
func (h *IAMHandlers) handleGetRole(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	roleID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if roleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingRoleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	}

	resp, err := h.iamClient.GetRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "get_role", err)
		return
	}

	h.writeJSON(w, http.StatusOK, h.roleToResponse(resp.Role))
}

// handleUpdateRole handles PUT /api/v1/iam/roles/{id}
func (h *IAMHandlers) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	roleID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if roleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingRoleID{})
		return
	}

	var req IAMUpdateRoleRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.UpdateIAMRoleRequest{
		TenantId:    tenantID,
		RoleId:      roleID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	resp, err := h.iamClient.UpdateRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "update_role", err)
		return
	}

	h.logger.Info("Role updated", "role_id", roleID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, h.roleToResponse(resp.Role))
}

// handleDeleteRole handles DELETE /api/v1/iam/roles/{id}
func (h *IAMHandlers) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	roleID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if roleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingRoleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	}

	_, err := h.iamClient.DeleteRole(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "delete_role", err)
		return
	}

	h.logger.Info("Role deleted", "role_id", roleID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, IAMSuccessResponse{
		Success: true,
		Message: "role deleted successfully",
	})
}

// =============================================================================
// Group Handlers
// =============================================================================

// handleCreateGroup handles POST /api/v1/iam/groups
func (h *IAMHandlers) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	var req IAMCreateGroupRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateIAMGroupRequest{
		TenantId:    tenantID,
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	resp, err := h.iamClient.CreateGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "create_group", err)
		return
	}

	h.logger.Info("Group created", "group_id", resp.Group.Id, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusCreated, h.groupToResponse(resp.Group))
}

// handleListGroups handles GET /api/v1/iam/groups
func (h *IAMHandlers) handleListGroups(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Convert limit/offset to page/pageSize for gRPC
	page := uint32(1)
	if offset > 0 && limit > 0 {
		page = uint32(offset/limit) + 1
	}

	grpcReq := &platformv1.ListIAMGroupsRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(limit),
			Page:     page,
		},
	}

	resp, err := h.iamClient.ListGroups(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "list_groups", err)
		return
	}

	groups := make([]IAMGroupResponse, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		groups = append(groups, h.groupToResponse(g))
	}

	h.writeJSON(w, http.StatusOK, IAMListGroupsResponse{
		IAMPaginatedResponse: IAMPaginatedResponse{
			Total:  resp.Total,
			Limit:  limit,
			Offset: offset,
		},
		Groups: groups,
	})
}

// handleGetGroup handles GET /api/v1/iam/groups/{id}
func (h *IAMHandlers) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	groupID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if groupID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingGroupID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	}

	resp, err := h.iamClient.GetGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "get_group", err)
		return
	}

	h.writeJSON(w, http.StatusOK, h.groupToResponse(resp.Group))
}

// handleUpdateGroup handles PUT /api/v1/iam/groups/{id}
func (h *IAMHandlers) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	groupID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if groupID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingGroupID{})
		return
	}

	var req IAMUpdateGroupRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.UpdateIAMGroupRequest{
		TenantId:    tenantID,
		GroupId:     groupID,
		Name:        req.Name,
		Description: req.Description,
	}

	resp, err := h.iamClient.UpdateGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "update_group", err)
		return
	}

	h.logger.Info("Group updated", "group_id", groupID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, h.groupToResponse(resp.Group))
}

// handleDeleteGroup handles DELETE /api/v1/iam/groups/{id}
func (h *IAMHandlers) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	groupID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if groupID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingGroupID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	}

	_, err := h.iamClient.DeleteGroup(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "delete_group", err)
		return
	}

	h.logger.Info("Group deleted", "group_id", groupID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, IAMSuccessResponse{
		Success: true,
		Message: "group deleted successfully",
	})
}

// =============================================================================
// Policy Handlers
// =============================================================================

// handleCreatePolicy handles POST /api/v1/iam/policies
func (h *IAMHandlers) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	var req IAMCreatePolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: "policy name is required"})
		return
	}
	if req.SpecYAML == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: "policy spec_yaml is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateIAMPolicyRequest{
		TenantId:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		SpecYaml:    []byte(req.SpecYAML),
		Labels:      req.Labels,
	}

	resp, err := h.iamClient.CreatePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "create_policy", err)
		return
	}

	h.logger.Info("Policy created", "policy_name", resp.Policy.Name, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusCreated, h.policyToResponse(resp.Policy))
}

// handleListPolicies handles GET /api/v1/iam/policies
func (h *IAMHandlers) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	limit, offset := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Convert limit/offset to page/pageSize for gRPC
	page := uint32(1)
	if offset > 0 && limit > 0 {
		page = uint32(offset/limit) + 1
	}

	grpcReq := &platformv1.ListIAMPoliciesRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(limit),
			Page:     page,
		},
	}

	resp, err := h.iamClient.ListPolicies(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "list_policies", err)
		return
	}

	policies := make([]IAMPolicyResponse, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		policies = append(policies, h.policyToResponse(p))
	}

	h.writeJSON(w, http.StatusOK, IAMListPoliciesResponse{
		IAMPaginatedResponse: IAMPaginatedResponse{
			Total:  resp.Total,
			Limit:  limit,
			Offset: offset,
		},
		Policies: policies,
	})
}

// handleGetPolicy handles GET /api/v1/iam/policies/{id}
func (h *IAMHandlers) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	policyID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingPolicyID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyID,
	}

	resp, err := h.iamClient.GetPolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "get_policy", err)
		return
	}

	h.writeJSON(w, http.StatusOK, h.policyToResponse(resp.Policy))
}

// handleUpdatePolicy handles PUT /api/v1/iam/policies/{id}
func (h *IAMHandlers) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	policyID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingPolicyID{})
		return
	}

	var req IAMUpdatePolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.UpdateIAMPolicyRequest{
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
		h.handleGRPCError(w, "update_policy", err)
		return
	}

	h.logger.Info("Policy updated", "policy_name", policyID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, h.policyToResponse(resp.Policy))
}

// handleDeletePolicy handles DELETE /api/v1/iam/policies/{id}
func (h *IAMHandlers) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	policyID := h.getPathParam(r, "id")

	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}
	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingPolicyID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyID,
	}

	_, err := h.iamClient.DeletePolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "delete_policy", err)
		return
	}

	h.logger.Info("Policy deleted", "policy_name", policyID, "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, IAMSuccessResponse{
		Success: true,
		Message: "policy deleted successfully",
	})
}

// =============================================================================
// Token Handlers
// =============================================================================

// handleIssueToken handles POST /api/v1/iam/tokens
func (h *IAMHandlers) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingTenantID{})
		return
	}

	var req IAMIssueTokenRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.UserID == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingUserID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateIAMTokenRequest{
		TenantId:  tenantID,
		UserId:    req.UserID,
		Scopes:    req.Scopes,
		ExpiresIn: req.ExpiresIn,
	}

	resp, err := h.iamClient.CreateToken(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "issue_token", err)
		return
	}

	h.logger.Info("Token issued", "token_id", resp.TokenId, "user_id", req.UserID)
	h.writeJSON(w, http.StatusCreated, IAMIssueTokenResponse{
		TokenID:      resp.TokenId,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		TokenType:    resp.TokenType,
	})
}

// handleValidateToken handles POST /api/v1/iam/tokens/validate
func (h *IAMHandlers) handleValidateToken(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	var req IAMValidateTokenRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Token == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingToken{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.VerifyIAMTokenRequest{
		Token: req.Token,
	}

	resp, err := h.iamClient.VerifyToken(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "validate_token", err)
		return
	}

	h.writeJSON(w, http.StatusOK, IAMValidateTokenResponse{
		Valid:     resp.Valid,
		UserID:    resp.UserId,
		TenantID:  resp.TenantId,
		Scopes:    resp.Scopes,
		ExpiresAt: resp.ExpiresAt,
	})
}

// handleRefreshToken handles POST /api/v1/iam/tokens/refresh
func (h *IAMHandlers) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	var req IAMRefreshTokenRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.RefreshToken == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingToken{})
		return
	}

	// First verify the refresh token to extract user and tenant info
	ctx, cancel := h.createContext()
	defer cancel()

	verifyReq := &platformv1.VerifyIAMTokenRequest{
		Token: req.RefreshToken,
	}

	verifyResp, err := h.iamClient.VerifyToken(ctx, verifyReq)
	if err != nil {
		h.handleGRPCError(w, "refresh_token", err)
		return
	}

	if !verifyResp.Valid {
		h.writeError(w, http.StatusUnauthorized, ErrIAMOperationFailed{
			Operation: "refresh_token",
			Cause:     &MessageError{Msg: "invalid refresh token"},
		})
		return
	}

	// Create a new token with the same scopes
	createReq := &platformv1.CreateIAMTokenRequest{
		TenantId: verifyResp.TenantId,
		UserId:   verifyResp.UserId,
		Scopes:   verifyResp.Scopes,
	}

	createResp, err := h.iamClient.CreateToken(ctx, createReq)
	if err != nil {
		h.handleGRPCError(w, "refresh_token", err)
		return
	}

	h.logger.Info("Token refreshed", "token_id", createResp.TokenId, "user_id", verifyResp.UserId)
	h.writeJSON(w, http.StatusOK, IAMIssueTokenResponse{
		TokenID:      createResp.TokenId,
		AccessToken:  createResp.AccessToken,
		RefreshToken: createResp.RefreshToken,
		ExpiresIn:    createResp.ExpiresIn,
		TokenType:    createResp.TokenType,
	})
}

// handleRevokeToken handles POST /api/v1/iam/tokens/revoke
func (h *IAMHandlers) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if h.iamClient == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrIAMServiceUnavailable{})
		return
	}

	var req IAMRevokeTokenRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrIAMInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.TokenID == "" && req.Token == "" {
		h.writeError(w, http.StatusBadRequest, ErrIAMMissingToken{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.RevokeIAMTokenRequest{
		TokenId: req.TokenID,
		Token:   req.Token,
	}

	_, err := h.iamClient.RevokeToken(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, "revoke_token", err)
		return
	}

	h.logger.Info("Token revoked", "token_id", req.TokenID)
	h.writeJSON(w, http.StatusOK, IAMSuccessResponse{
		Success: true,
		Message: "token revoked successfully",
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

// getTenantID extracts tenant ID from request header or query parameter.
func (h *IAMHandlers) getTenantID(r *http.Request) string {
	// Try header first
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID != "" {
		return tenantID
	}
	// Fall back to query parameter
	return r.URL.Query().Get("tenant_id")
}

// getPathParam extracts a path parameter from the request.
func (h *IAMHandlers) getPathParam(r *http.Request, key string) string {
	vars := mux.Vars(r)
	return vars[key]
}

// getPaginationParams extracts pagination parameters from query string.
func (h *IAMHandlers) getPaginationParams(r *http.Request) (int32, int32) {
	limit := defaultIAMLimit
	offset := defaultIAMOffset

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxIAMLimit {
				limit = maxIAMLimit
			}
			if limit < 1 {
				limit = defaultIAMLimit
			}
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.ParseInt(o, 10, 32); err == nil {
			offset = int32(parsed)
			if offset < 0 {
				offset = defaultIAMOffset
			}
		}
	}

	return limit, offset
}

// createContext creates a context with timeout for gRPC calls.
func (h *IAMHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), iamRequestTimeout)
}

// decodeJSON decodes JSON from request body.
func (h *IAMHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// writeJSON writes a JSON response.
func (h *IAMHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *IAMHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, IAMErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// handleGRPCError maps gRPC errors to appropriate HTTP status codes.
func (h *IAMHandlers) handleGRPCError(w http.ResponseWriter, operation string, err error) {
	st, ok := status.FromError(err)
	if !ok {
		h.logger.Error("IAM operation failed", "operation", operation, "error", err)
		h.writeError(w, http.StatusInternalServerError, ErrIAMOperationFailed{
			Operation: operation,
			Cause:     err,
		})
		return
	}

	var httpStatus int
	switch st.Code() {
	case codes.NotFound:
		httpStatus = http.StatusNotFound
	case codes.InvalidArgument:
		httpStatus = http.StatusBadRequest
	case codes.AlreadyExists:
		httpStatus = http.StatusConflict
	case codes.PermissionDenied:
		httpStatus = http.StatusForbidden
	case codes.Unauthenticated:
		httpStatus = http.StatusUnauthorized
	case codes.ResourceExhausted:
		httpStatus = http.StatusTooManyRequests
	case codes.FailedPrecondition:
		httpStatus = http.StatusPreconditionFailed
	case codes.Unavailable:
		httpStatus = http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		httpStatus = http.StatusGatewayTimeout
	default:
		httpStatus = http.StatusInternalServerError
	}

	h.logger.Error("IAM operation failed",
		"operation", operation,
		"grpc_code", st.Code().String(),
		"error", st.Message())

	h.writeError(w, httpStatus, ErrIAMOperationFailed{
		Operation: operation,
		Cause:     &MessageError{Msg: fmt.Sprintf("%s", st.Message())},
	})
}

// userToResponse converts a proto IAMUser to IAMUserResponse.
func (h *IAMHandlers) userToResponse(u *platformv1.IAMUser) IAMUserResponse {
	resp := IAMUserResponse{
		ID:          u.Id,
		TenantID:    u.TenantId,
		Email:       u.Email,
		Name:        u.Name,
		Roles:       u.Roles,
		Groups:      u.Groups,
		Attributes:  u.Attributes,
		MFAVerified: u.MfaVerified,
	}

	if u.CreatedAt != nil {
		t := u.CreatedAt.AsTime()
		resp.CreatedAt = &t
	}
	if u.UpdatedAt != nil {
		t := u.UpdatedAt.AsTime()
		resp.UpdatedAt = &t
	}
	if u.LastAuth != nil {
		t := u.LastAuth.AsTime()
		resp.LastAuth = &t
	}

	return resp
}

// roleToResponse converts a proto IAMRole to IAMRoleResponse.
func (h *IAMHandlers) roleToResponse(r *platformv1.IAMRole) IAMRoleResponse {
	resp := IAMRoleResponse{
		ID:          r.Id,
		TenantID:    r.TenantId,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
	}

	if r.CreatedAt != nil {
		t := r.CreatedAt.AsTime()
		resp.CreatedAt = &t
	}
	if r.UpdatedAt != nil {
		t := r.UpdatedAt.AsTime()
		resp.UpdatedAt = &t
	}

	return resp
}

// groupToResponse converts a proto IAMGroup to IAMGroupResponse.
func (h *IAMHandlers) groupToResponse(g *platformv1.IAMGroup) IAMGroupResponse {
	resp := IAMGroupResponse{
		ID:          g.Id,
		TenantID:    g.TenantId,
		Name:        g.Name,
		Description: g.Description,
		Members:     g.Members,
	}

	if g.CreatedAt != nil {
		t := g.CreatedAt.AsTime()
		resp.CreatedAt = &t
	}
	if g.UpdatedAt != nil {
		t := g.UpdatedAt.AsTime()
		resp.UpdatedAt = &t
	}

	return resp
}

// policyToResponse converts a proto IAMPolicy to IAMPolicyResponse.
func (h *IAMHandlers) policyToResponse(p *platformv1.IAMPolicy) IAMPolicyResponse {
	resp := IAMPolicyResponse{
		Name:        p.Name,
		TenantID:    p.TenantId,
		Description: p.Description,
		Priority:    p.Priority,
		SpecYAML:    strings.TrimSpace(string(p.SpecYaml)),
		Labels:      p.Labels,
	}

	if p.CreatedAt != nil {
		t := p.CreatedAt.AsTime()
		resp.CreatedAt = &t
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		resp.UpdatedAt = &t
	}

	return resp
}
