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

package quic

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// IAM pagination defaults
const (
	iamDefaultLimit int32 = 50
	iamMaxLimit     int32 = 1000
)

// IAM-specific sentinel errors
var (
	// ErrIAMServiceNotAvailable is returned when the IAM service is not configured.
	ErrIAMServiceNotAvailable = errors.New("IAM service not available")

	// ErrIAMMissingTenantID is returned when tenant ID is required but not provided.
	ErrIAMMissingTenantID = errors.New("tenant ID is required")

	// ErrIAMMissingUserID is returned when user ID is required but not provided.
	ErrIAMMissingUserID = errors.New("user ID is required")

	// ErrIAMMissingRoleID is returned when role ID is required but not provided.
	ErrIAMMissingRoleID = errors.New("role ID is required")

	// ErrIAMMissingGroupID is returned when group ID is required but not provided.
	ErrIAMMissingGroupID = errors.New("group ID is required")

	// ErrIAMMissingEmail is returned when email is required but not provided.
	ErrIAMMissingEmail = errors.New("email is required")

	// ErrIAMMissingName is returned when name is required but not provided.
	ErrIAMMissingName = errors.New("name is required")

	// ErrIAMMissingSubjectID is returned when subject ID is required but not provided.
	ErrIAMMissingSubjectID = errors.New("subject ID is required")

	// ErrIAMMissingResource is returned when resource is required but not provided.
	ErrIAMMissingResource = errors.New("resource is required")

	// ErrIAMMissingAction is returned when action is required but not provided.
	ErrIAMMissingAction = errors.New("action is required")
)

// IAMService defines the interface for IAM operations.
// Implementations should handle tenant isolation and authorization checks.
type IAMService interface {
	// User operations
	CreateUser(ctx context.Context, tenantID string, req *IAMCreateUserRequest) (*IAMUserInfo, error)
	GetUser(ctx context.Context, tenantID, userID string) (*IAMUserInfo, error)
	ListUsers(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMUserListResponse, error)
	UpdateUser(ctx context.Context, tenantID, userID string, req *IAMUpdateUserRequest) (*IAMUserInfo, error)
	DeleteUser(ctx context.Context, tenantID, userID string) error

	// Role operations
	CreateRole(ctx context.Context, tenantID string, req *IAMCreateRoleRequest) (*IAMRoleInfo, error)
	GetRole(ctx context.Context, tenantID, roleID string) (*IAMRoleInfo, error)
	ListRoles(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMRoleListResponse, error)
	UpdateRole(ctx context.Context, tenantID, roleID string, req *IAMUpdateRoleRequest) (*IAMRoleInfo, error)
	DeleteRole(ctx context.Context, tenantID, roleID string) error
	AssignRole(ctx context.Context, tenantID, userID, roleID string) error
	RevokeRole(ctx context.Context, tenantID, userID, roleID string) error

	// Group operations
	CreateGroup(ctx context.Context, tenantID string, req *IAMCreateGroupRequest) (*IAMGroupInfo, error)
	GetGroup(ctx context.Context, tenantID, groupID string) (*IAMGroupInfo, error)
	ListGroups(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMGroupListResponse, error)
	UpdateGroup(ctx context.Context, tenantID, groupID string, req *IAMUpdateGroupRequest) (*IAMGroupInfo, error)
	DeleteGroup(ctx context.Context, tenantID, groupID string) error
	AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error

	// Authorization operations
	CheckPermission(ctx context.Context, req *IAMCheckPermissionRequest) (*IAMCheckPermissionResponse, error)
}

// IAMHandler handles IAM operations over QUIC
type IAMHandler struct {
	service IAMService
	logger  *logging.Logger
}

// NewIAMHandler creates a new IAM handler
func NewIAMHandler(logger *logging.Logger, service IAMService) *IAMHandler {
	return &IAMHandler{
		service: service,
		logger:  logger,
	}
}

// HandleRequest processes an IAM request and returns a response
func (h *IAMHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// User operations
	case quicwire.OpIAMUserCreate:
		return h.handleUserCreate(ctx, req)
	case quicwire.OpIAMUserGet:
		return h.handleUserGet(ctx, req)
	case quicwire.OpIAMUserList:
		return h.handleUserList(ctx, req)
	case quicwire.OpIAMUserUpdate:
		return h.handleUserUpdate(ctx, req)
	case quicwire.OpIAMUserDelete:
		return h.handleUserDelete(ctx, req)

	// Role operations
	case quicwire.OpIAMRoleCreate:
		return h.handleRoleCreate(ctx, req)
	case quicwire.OpIAMRoleGet:
		return h.handleRoleGet(ctx, req)
	case quicwire.OpIAMRoleList:
		return h.handleRoleList(ctx, req)
	case quicwire.OpIAMRoleAssign:
		return h.handleRoleAssign(ctx, req)
	case quicwire.OpIAMRoleRevoke:
		return h.handleRoleRevoke(ctx, req)
	case quicwire.OpIAMRoleDelete:
		return h.handleRoleDelete(ctx, req)

	// Group operations
	case quicwire.OpIAMGroupCreate:
		return h.handleGroupCreate(ctx, req)
	case quicwire.OpIAMGroupGet:
		return h.handleGroupGet(ctx, req)
	case quicwire.OpIAMGroupList:
		return h.handleGroupList(ctx, req)
	case quicwire.OpIAMGroupDelete:
		return h.handleGroupDelete(ctx, req)
	case quicwire.OpIAMGroupAddMember:
		return h.handleGroupAddMember(ctx, req)
	case quicwire.OpIAMGroupRemoveMember:
		return h.handleGroupRemoveMember(ctx, req)

	// Authorization operations
	case quicwire.OpIAMCheckPermission:
		return h.handleCheckPermission(ctx, req)

	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown IAM operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// IAMCreateUserRequest represents a user creation request
type IAMCreateUserRequest struct {
	TenantID   string            `codec:"tenant_id"`
	Email      string            `codec:"email"`
	Username   string            `codec:"username"`
	Name       string            `codec:"name"`
	Roles      []string          `codec:"roles"`
	Groups     []string          `codec:"groups"`
	Attributes map[string]string `codec:"attributes"`
}

// IAMUpdateUserRequest represents a user update request
type IAMUpdateUserRequest struct {
	TenantID   string            `codec:"tenant_id"`
	UserID     string            `codec:"user_id"`
	Email      string            `codec:"email"`
	Username   string            `codec:"username"`
	Name       string            `codec:"name"`
	Roles      []string          `codec:"roles"`
	Groups     []string          `codec:"groups"`
	Attributes map[string]string `codec:"attributes"`
}

// IAMGetUserRequest represents a user get request
type IAMGetUserRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
}

// IAMDeleteUserRequest represents a user deletion request
type IAMDeleteUserRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
}

// IAMListRequest represents a generic list request with pagination
type IAMListRequest struct {
	TenantID string `codec:"tenant_id"`
	Limit    int32  `codec:"limit"`
	Offset   int32  `codec:"offset"`
	Filter   string `codec:"filter"`
}

// IAMUserInfo contains user information
type IAMUserInfo struct {
	ID          string            `codec:"id"`
	TenantID    string            `codec:"tenant_id"`
	Email       string            `codec:"email"`
	Username    string            `codec:"username"`
	Name        string            `codec:"name"`
	Roles       []string          `codec:"roles"`
	Groups      []string          `codec:"groups"`
	Attributes  map[string]string `codec:"attributes"`
	MFAVerified bool              `codec:"mfa_verified"`
	CreatedAt   int64             `codec:"created_at"`
	UpdatedAt   int64             `codec:"updated_at"`
	LastAuth    int64             `codec:"last_auth"`
}

// IAMUserResponse represents a user operation response
type IAMUserResponse struct {
	User      *IAMUserInfo `codec:"user"`
	Timestamp int64        `codec:"timestamp"`
}

// IAMUserListResponse represents a user list response
type IAMUserListResponse struct {
	Users     []*IAMUserInfo `codec:"users"`
	Total     int64          `codec:"total"`
	Limit     int32          `codec:"limit"`
	Offset    int32          `codec:"offset"`
	Timestamp int64          `codec:"timestamp"`
}

// IAMCreateRoleRequest represents a role creation request
type IAMCreateRoleRequest struct {
	TenantID    string   `codec:"tenant_id"`
	ID          string   `codec:"id"`
	Name        string   `codec:"name"`
	Description string   `codec:"description"`
	Permissions []string `codec:"permissions"`
}

// IAMUpdateRoleRequest represents a role update request
type IAMUpdateRoleRequest struct {
	TenantID    string   `codec:"tenant_id"`
	RoleID      string   `codec:"role_id"`
	Name        string   `codec:"name"`
	Description string   `codec:"description"`
	Permissions []string `codec:"permissions"`
}

// IAMGetRoleRequest represents a role get request
type IAMGetRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	RoleID   string `codec:"role_id"`
}

// IAMDeleteRoleRequest represents a role deletion request
type IAMDeleteRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	RoleID   string `codec:"role_id"`
}

// IAMAssignRoleRequest represents a role assignment request
type IAMAssignRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
	RoleID   string `codec:"role_id"`
}

// IAMRevokeRoleRequest represents a role revocation request
type IAMRevokeRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
	RoleID   string `codec:"role_id"`
}

// IAMRoleInfo contains role information
type IAMRoleInfo struct {
	ID          string   `codec:"id"`
	TenantID    string   `codec:"tenant_id"`
	Name        string   `codec:"name"`
	Description string   `codec:"description"`
	Permissions []string `codec:"permissions"`
	CreatedAt   int64    `codec:"created_at"`
	UpdatedAt   int64    `codec:"updated_at"`
}

// IAMRoleResponse represents a role operation response
type IAMRoleResponse struct {
	Role      *IAMRoleInfo `codec:"role"`
	Timestamp int64        `codec:"timestamp"`
}

// IAMRoleListResponse represents a role list response
type IAMRoleListResponse struct {
	Roles     []*IAMRoleInfo `codec:"roles"`
	Total     int64          `codec:"total"`
	Limit     int32          `codec:"limit"`
	Offset    int32          `codec:"offset"`
	Timestamp int64          `codec:"timestamp"`
}

// IAMCreateGroupRequest represents a group creation request
type IAMCreateGroupRequest struct {
	TenantID    string `codec:"tenant_id"`
	ID          string `codec:"id"`
	Name        string `codec:"name"`
	Description string `codec:"description"`
}

// IAMUpdateGroupRequest represents a group update request
type IAMUpdateGroupRequest struct {
	TenantID    string `codec:"tenant_id"`
	GroupID     string `codec:"group_id"`
	Name        string `codec:"name"`
	Description string `codec:"description"`
}

// IAMGetGroupRequest represents a group get request
type IAMGetGroupRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
}

// IAMDeleteGroupRequest represents a group deletion request
type IAMDeleteGroupRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
}

// IAMGroupMemberRequest represents a group membership request
type IAMGroupMemberRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
	UserID   string `codec:"user_id"`
}

// IAMGroupInfo contains group information
type IAMGroupInfo struct {
	ID          string   `codec:"id"`
	TenantID    string   `codec:"tenant_id"`
	Name        string   `codec:"name"`
	Description string   `codec:"description"`
	Members     []string `codec:"members"`
	CreatedAt   int64    `codec:"created_at"`
	UpdatedAt   int64    `codec:"updated_at"`
}

// IAMGroupResponse represents a group operation response
type IAMGroupResponse struct {
	Group     *IAMGroupInfo `codec:"group"`
	Timestamp int64         `codec:"timestamp"`
}

// IAMGroupListResponse represents a group list response
type IAMGroupListResponse struct {
	Groups    []*IAMGroupInfo `codec:"groups"`
	Total     int64           `codec:"total"`
	Limit     int32           `codec:"limit"`
	Offset    int32           `codec:"offset"`
	Timestamp int64           `codec:"timestamp"`
}

// IAMCheckPermissionRequest represents a permission check request
type IAMCheckPermissionRequest struct {
	TenantID  string            `codec:"tenant_id"`
	SubjectID string            `codec:"subject_id"`
	Resource  string            `codec:"resource"`
	Action    string            `codec:"action"`
	Context   map[string]string `codec:"context"`
}

// IAMCheckPermissionResponse represents a permission check response
type IAMCheckPermissionResponse struct {
	Allowed   bool   `codec:"allowed"`
	Reason    string `codec:"reason"`
	Timestamp int64  `codec:"timestamp"`
}

// IAMSuccessResponse represents a generic success response
type IAMSuccessResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// User Handler Methods
// =============================================================================

// handleUserCreate creates a new IAM user
func (h *IAMHandler) handleUserCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var createReq IAMCreateUserRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if createReq.Email == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingEmail)
	}

	user, err := h.service.CreateUser(ctx, createReq.TenantID, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create user")
		return h.iamErrorResponse(err)
	}

	resp := &IAMUserResponse{
		User:      user,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUserGet retrieves an IAM user by ID
func (h *IAMHandler) handleUserGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var getReq IAMGetUserRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if getReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	user, err := h.service.GetUser(ctx, getReq.TenantID, getReq.UserID)
	if err != nil {
		h.logger.Error(err, "failed to get user")
		return h.iamErrorResponse(err)
	}

	resp := &IAMUserResponse{
		User:      user,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUserList lists IAM users
func (h *IAMHandler) handleUserList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var listReq IAMListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	// Apply defaults
	if listReq.Limit <= 0 {
		listReq.Limit = iamDefaultLimit
	}
	if listReq.Limit > iamMaxLimit {
		listReq.Limit = iamMaxLimit
	}

	users, err := h.service.ListUsers(ctx, listReq.TenantID, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list users")
		return h.iamErrorResponse(err)
	}

	users.Timestamp = time.Now().Unix()

	payload, err := quicwire.EncodePayload(users)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUserUpdate updates an IAM user
func (h *IAMHandler) handleUserUpdate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var updateReq IAMUpdateUserRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if updateReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if updateReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	user, err := h.service.UpdateUser(ctx, updateReq.TenantID, updateReq.UserID, &updateReq)
	if err != nil {
		h.logger.Error(err, "failed to update user")
		return h.iamErrorResponse(err)
	}

	resp := &IAMUserResponse{
		User:      user,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUserDelete deletes an IAM user
func (h *IAMHandler) handleUserDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var deleteReq IAMDeleteUserRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if deleteReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	if err := h.service.DeleteUser(ctx, deleteReq.TenantID, deleteReq.UserID); err != nil {
		h.logger.Error(err, "failed to delete user")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "user deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Role Handler Methods
// =============================================================================

// handleRoleCreate creates a new IAM role
func (h *IAMHandler) handleRoleCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var createReq IAMCreateRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingName)
	}

	role, err := h.service.CreateRole(ctx, createReq.TenantID, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create role")
		return h.iamErrorResponse(err)
	}

	resp := &IAMRoleResponse{
		Role:      role,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRoleGet retrieves an IAM role by ID
func (h *IAMHandler) handleRoleGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var getReq IAMGetRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if getReq.RoleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingRoleID)
	}

	role, err := h.service.GetRole(ctx, getReq.TenantID, getReq.RoleID)
	if err != nil {
		h.logger.Error(err, "failed to get role")
		return h.iamErrorResponse(err)
	}

	resp := &IAMRoleResponse{
		Role:      role,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRoleList lists IAM roles
func (h *IAMHandler) handleRoleList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var listReq IAMListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	// Apply defaults
	if listReq.Limit <= 0 {
		listReq.Limit = iamDefaultLimit
	}
	if listReq.Limit > iamMaxLimit {
		listReq.Limit = iamMaxLimit
	}

	roles, err := h.service.ListRoles(ctx, listReq.TenantID, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list roles")
		return h.iamErrorResponse(err)
	}

	roles.Timestamp = time.Now().Unix()

	payload, err := quicwire.EncodePayload(roles)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRoleDelete deletes an IAM role
func (h *IAMHandler) handleRoleDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var deleteReq IAMDeleteRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if deleteReq.RoleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingRoleID)
	}

	if err := h.service.DeleteRole(ctx, deleteReq.TenantID, deleteReq.RoleID); err != nil {
		h.logger.Error(err, "failed to delete role")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "role deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRoleAssign assigns a role to a user
func (h *IAMHandler) handleRoleAssign(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var assignReq IAMAssignRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &assignReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if assignReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if assignReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	if assignReq.RoleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingRoleID)
	}

	if err := h.service.AssignRole(ctx, assignReq.TenantID, assignReq.UserID, assignReq.RoleID); err != nil {
		h.logger.Error(err, "failed to assign role")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "role assigned successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRoleRevoke revokes a role from a user
func (h *IAMHandler) handleRoleRevoke(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var revokeReq IAMRevokeRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &revokeReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if revokeReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if revokeReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	if revokeReq.RoleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingRoleID)
	}

	if err := h.service.RevokeRole(ctx, revokeReq.TenantID, revokeReq.UserID, revokeReq.RoleID); err != nil {
		h.logger.Error(err, "failed to revoke role")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "role revoked successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Group Handler Methods
// =============================================================================

// handleGroupCreate creates a new IAM group
func (h *IAMHandler) handleGroupCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var createReq IAMCreateGroupRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingName)
	}

	group, err := h.service.CreateGroup(ctx, createReq.TenantID, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create group")
		return h.iamErrorResponse(err)
	}

	resp := &IAMGroupResponse{
		Group:     group,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGroupGet retrieves an IAM group by ID
func (h *IAMHandler) handleGroupGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var getReq IAMGetGroupRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if getReq.GroupID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingGroupID)
	}

	group, err := h.service.GetGroup(ctx, getReq.TenantID, getReq.GroupID)
	if err != nil {
		h.logger.Error(err, "failed to get group")
		return h.iamErrorResponse(err)
	}

	resp := &IAMGroupResponse{
		Group:     group,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGroupList lists IAM groups
func (h *IAMHandler) handleGroupList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var listReq IAMListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	// Apply defaults
	if listReq.Limit <= 0 {
		listReq.Limit = iamDefaultLimit
	}
	if listReq.Limit > iamMaxLimit {
		listReq.Limit = iamMaxLimit
	}

	groups, err := h.service.ListGroups(ctx, listReq.TenantID, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list groups")
		return h.iamErrorResponse(err)
	}

	groups.Timestamp = time.Now().Unix()

	payload, err := quicwire.EncodePayload(groups)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGroupDelete deletes an IAM group
func (h *IAMHandler) handleGroupDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var deleteReq IAMDeleteGroupRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if deleteReq.GroupID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingGroupID)
	}

	if err := h.service.DeleteGroup(ctx, deleteReq.TenantID, deleteReq.GroupID); err != nil {
		h.logger.Error(err, "failed to delete group")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "group deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGroupAddMember adds a user to a group
func (h *IAMHandler) handleGroupAddMember(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var memberReq IAMGroupMemberRequest
	if err := quicwire.DecodePayload(req.Payload, &memberReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if memberReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if memberReq.GroupID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingGroupID)
	}

	if memberReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	if err := h.service.AddGroupMember(ctx, memberReq.TenantID, memberReq.GroupID, memberReq.UserID); err != nil {
		h.logger.Error(err, "failed to add group member")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "member added successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGroupRemoveMember removes a user from a group
func (h *IAMHandler) handleGroupRemoveMember(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var memberReq IAMGroupMemberRequest
	if err := quicwire.DecodePayload(req.Payload, &memberReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if memberReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if memberReq.GroupID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingGroupID)
	}

	if memberReq.UserID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingUserID)
	}

	if err := h.service.RemoveGroupMember(ctx, memberReq.TenantID, memberReq.GroupID, memberReq.UserID); err != nil {
		h.logger.Error(err, "failed to remove group member")
		return h.iamErrorResponse(err)
	}

	resp := &IAMSuccessResponse{
		Success:   true,
		Message:   "member removed successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Authorization Handler Methods
// =============================================================================

// handleCheckPermission checks if a subject has permission for an action
func (h *IAMHandler) handleCheckPermission(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrIAMServiceNotAvailable)
	}

	var checkReq IAMCheckPermissionRequest
	if err := quicwire.DecodePayload(req.Payload, &checkReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrIAMDecodingFailed{Cause: err})
	}

	if checkReq.TenantID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingTenantID)
	}

	if checkReq.SubjectID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingSubjectID)
	}

	if checkReq.Resource == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingResource)
	}

	if checkReq.Action == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrIAMMissingAction)
	}

	result, err := h.service.CheckPermission(ctx, &checkReq)
	if err != nil {
		h.logger.Error(err, "failed to check permission")
		return h.iamErrorResponse(err)
	}

	result.Timestamp = time.Now().Unix()

	payload, err := quicwire.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrIAMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// errorResponse creates an error response with the given status and error
func (h *IAMHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// iamErrorResponse maps IAM errors to appropriate status codes
func (h *IAMHandler) iamErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, ErrIAMUserNotFound{}):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrIAMRoleNotFound{}):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrIAMGroupNotFound{}):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrIAMUserAlreadyExists{}):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ErrIAMRoleAlreadyExists{}):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ErrIAMGroupAlreadyExists{}):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ErrIAMPermissionDenied{}):
		status = quicwire.StatusPermissionDenied
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// IAM Error Types
// =============================================================================

// ErrIAMEncodingFailed represents an encoding failure error
type ErrIAMEncodingFailed struct {
	Cause error
}

func (e ErrIAMEncodingFailed) Error() string {
	return "failed to encode IAM payload: " + e.Cause.Error()
}

func (e ErrIAMEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrIAMDecodingFailed represents a decoding failure error
type ErrIAMDecodingFailed struct {
	Cause error
}

func (e ErrIAMDecodingFailed) Error() string {
	return "failed to decode IAM payload: " + e.Cause.Error()
}

func (e ErrIAMDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrIAMOperationFailed represents an IAM operation failure
type ErrIAMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrIAMOperationFailed) Error() string {
	return "IAM operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrIAMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrIAMUserNotFound represents a user not found error
type ErrIAMUserNotFound struct{}

func (e ErrIAMUserNotFound) Error() string {
	return "user not found"
}

func (e ErrIAMUserNotFound) Is(target error) bool {
	_, ok := target.(ErrIAMUserNotFound)
	return ok
}

// ErrIAMRoleNotFound represents a role not found error
type ErrIAMRoleNotFound struct{}

func (e ErrIAMRoleNotFound) Error() string {
	return "role not found"
}

func (e ErrIAMRoleNotFound) Is(target error) bool {
	_, ok := target.(ErrIAMRoleNotFound)
	return ok
}

// ErrIAMGroupNotFound represents a group not found error
type ErrIAMGroupNotFound struct{}

func (e ErrIAMGroupNotFound) Error() string {
	return "group not found"
}

func (e ErrIAMGroupNotFound) Is(target error) bool {
	_, ok := target.(ErrIAMGroupNotFound)
	return ok
}

// ErrIAMUserAlreadyExists represents a user already exists error
type ErrIAMUserAlreadyExists struct{}

func (e ErrIAMUserAlreadyExists) Error() string {
	return "user already exists"
}

func (e ErrIAMUserAlreadyExists) Is(target error) bool {
	_, ok := target.(ErrIAMUserAlreadyExists)
	return ok
}

// ErrIAMRoleAlreadyExists represents a role already exists error
type ErrIAMRoleAlreadyExists struct{}

func (e ErrIAMRoleAlreadyExists) Error() string {
	return "role already exists"
}

func (e ErrIAMRoleAlreadyExists) Is(target error) bool {
	_, ok := target.(ErrIAMRoleAlreadyExists)
	return ok
}

// ErrIAMGroupAlreadyExists represents a group already exists error
type ErrIAMGroupAlreadyExists struct{}

func (e ErrIAMGroupAlreadyExists) Error() string {
	return "group already exists"
}

func (e ErrIAMGroupAlreadyExists) Is(target error) bool {
	_, ok := target.(ErrIAMGroupAlreadyExists)
	return ok
}

// ErrIAMPermissionDenied represents a permission denied error
type ErrIAMPermissionDenied struct{}

func (e ErrIAMPermissionDenied) Error() string {
	return "permission denied"
}

func (e ErrIAMPermissionDenied) Is(target error) bool {
	_, ok := target.(ErrIAMPermissionDenied)
	return ok
}
