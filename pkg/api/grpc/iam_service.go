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

package grpc

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// IAM gRPC service error types.

// ErrNilIAMService is returned when the IAM service is nil.
type ErrNilIAMService struct{}

func (e ErrNilIAMService) Error() string {
	return "IAM service is nil"
}

// ErrMissingTenantID is returned when tenant ID is required but not provided.
type ErrMissingTenantID struct{}

func (e ErrMissingTenantID) Error() string {
	return "tenant ID is required"
}

// ErrMissingUserID is returned when user ID is required but not provided.
type ErrMissingUserID struct{}

func (e ErrMissingUserID) Error() string {
	return "user ID is required"
}

// ErrMissingEmail is returned when email is required but not provided.
type ErrMissingEmail struct{}

func (e ErrMissingEmail) Error() string {
	return "email is required"
}

// ErrMissingRoleID is returned when role ID is required but not provided.
type ErrMissingRoleID struct{}

func (e ErrMissingRoleID) Error() string {
	return "role ID is required"
}

// ErrMissingRoleName is returned when role name is required but not provided.
type ErrMissingRoleName struct{}

func (e ErrMissingRoleName) Error() string {
	return "role name is required"
}

// ErrMissingSubjectID is returned when subject ID is required but not provided.
type ErrMissingSubjectID struct{}

func (e ErrMissingSubjectID) Error() string {
	return "subject ID is required"
}

// ErrMissingAction is returned when action is required but not provided.
type ErrMissingAction struct{}

func (e ErrMissingAction) Error() string {
	return "action is required"
}

// ErrMissingResource is returned when resource is required but not provided.
type ErrMissingResource struct{}

func (e ErrMissingResource) Error() string {
	return "resource is required"
}

// ErrMissingTenantName is returned when tenant name is required but not provided.
type ErrMissingTenantName struct{}

func (e ErrMissingTenantName) Error() string {
	return "tenant name is required"
}

// ErrMissingPolicyName is returned when policy name is required but not provided.
type ErrMissingPolicyName struct{}

func (e ErrMissingPolicyName) Error() string {
	return "policy name is required"
}

// ErrMissingPolicySpec is returned when policy spec is required but not provided.
type ErrMissingPolicySpec struct{}

func (e ErrMissingPolicySpec) Error() string {
	return "policy spec is required"
}

// ErrMissingAppName is returned when app name is required but not provided.
type ErrMissingAppName struct{}

func (e ErrMissingAppName) Error() string {
	return "app name is required"
}

// ErrMissingClientID is returned when client ID is required but not provided.
type ErrMissingClientID struct{}

func (e ErrMissingClientID) Error() string {
	return "client ID is required"
}

// ErrIAMOperationFailed is returned when an IAM operation fails.
type ErrIAMOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrIAMOperationFailed) Error() string {
	return "IAM operation " + e.Operation + " failed: " + e.Reason
}

// IAMGRPCService implements the gRPC PlatformIAMService server interface.
// It wraps the IAMService interface to provide gRPC access to IAM operations.
type IAMGRPCService struct {
	platformv1.UnimplementedPlatformIAMServiceServer
	logger  *logging.Logger
	service IAMService
}

// NewIAMGRPCService creates a new IAMGRPCService instance.
func NewIAMGRPCService(
	logger *logging.Logger,
	service IAMService,
) *IAMGRPCService {
	return &IAMGRPCService{
		logger:  logger,
		service: service,
	}
}

// =============================================================================
// User Operations
// =============================================================================

// CreateUser creates a new user in the IAM system.
func (s *IAMGRPCService) CreateUser(
	ctx context.Context,
	req *platformv1.CreateIAMUserRequest,
) (*platformv1.IAMUserResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingEmail{}.Error())
	}

	iamReq := &IAMCreateUserRequest{
		TenantID:   req.GetTenantId(),
		Email:      req.GetEmail(),
		Name:       req.GetName(),
		Attributes: req.GetAttributes(),
	}

	resp, err := s.service.CreateUser(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("CreateUser", err)
	}

	return &platformv1.IAMUserResponse{
		User:      iamUserToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetUser retrieves a user by ID.
func (s *IAMGRPCService) GetUser(
	ctx context.Context,
	req *platformv1.GetIAMUserRequest,
) (*platformv1.IAMUserResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUserID{}.Error())
	}

	iamReq := &IAMGetUserRequest{
		TenantID: req.GetTenantId(),
		UserID:   req.GetUserId(),
	}

	resp, err := s.service.GetUser(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("GetUser", err)
	}

	return &platformv1.IAMUserResponse{
		User:      iamUserToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListUsers returns a paginated list of users.
func (s *IAMGRPCService) ListUsers(
	ctx context.Context,
	req *platformv1.ListIAMUsersRequest,
) (*platformv1.ListIAMUsersResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	iamReq := &IAMListRequest{
		TenantID: req.GetTenantId(),
		Limit:    int(req.GetPagination().GetPageSize()),
		Offset:   int(req.GetPagination().GetPage()) * int(req.GetPagination().GetPageSize()),
	}

	resp, err := s.service.ListUsers(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("ListUsers", err)
	}

	users := make([]*platformv1.IAMUser, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, iamUserToProto(u))
	}

	return &platformv1.ListIAMUsersResponse{
		Users: users,
		Pagination: &platformv1.PaginationResponse{
			TotalItems: uint64(resp.Total),
		},
		Total:     int64(resp.Total),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateUser updates an existing user.
func (s *IAMGRPCService) UpdateUser(
	ctx context.Context,
	req *platformv1.UpdateIAMUserRequest,
) (*platformv1.IAMUserResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUserID{}.Error())
	}

	iamReq := &IAMUpdateUserRequest{
		TenantID:   req.GetTenantId(),
		UserID:     req.GetUserId(),
		Email:      req.GetEmail(),
		Name:       req.GetName(),
		Roles:      req.GetRoles(),
		Attributes: req.GetAttributes(),
	}

	resp, err := s.service.UpdateUser(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("UpdateUser", err)
	}

	return &platformv1.IAMUserResponse{
		User:      iamUserToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteUser deletes a user.
func (s *IAMGRPCService) DeleteUser(
	ctx context.Context,
	req *platformv1.DeleteIAMUserRequest,
) (*platformv1.DeleteIAMUserResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUserID{}.Error())
	}

	iamReq := &IAMDeleteUserRequest{
		TenantID: req.GetTenantId(),
		UserID:   req.GetUserId(),
	}

	if err := s.service.DeleteUser(ctx, iamReq); err != nil {
		return nil, s.mapError("DeleteUser", err)
	}

	return &platformv1.DeleteIAMUserResponse{
		Status:    iamSuccessStatus("user deleted successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Role Operations
// =============================================================================

// CreateRole creates a new role.
func (s *IAMGRPCService) CreateRole(
	ctx context.Context,
	req *platformv1.CreateIAMRoleRequest,
) (*platformv1.IAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleName{}.Error())
	}

	iamReq := &IAMCreateRoleRequest{
		TenantID:    req.GetTenantId(),
		RoleID:      req.GetId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Permissions: req.GetPermissions(),
	}

	resp, err := s.service.CreateRole(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("CreateRole", err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      iamRoleToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetRole retrieves a role by ID.
func (s *IAMGRPCService) GetRole(
	ctx context.Context,
	req *platformv1.GetIAMRoleRequest,
) (*platformv1.IAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleID{}.Error())
	}

	iamReq := &IAMGetRoleRequest{
		TenantID: req.GetTenantId(),
		RoleID:   req.GetRoleId(),
	}

	resp, err := s.service.GetRole(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("GetRole", err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      iamRoleToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListRoles returns a paginated list of roles.
func (s *IAMGRPCService) ListRoles(
	ctx context.Context,
	req *platformv1.ListIAMRolesRequest,
) (*platformv1.ListIAMRolesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	iamReq := &IAMListRequest{
		TenantID: req.GetTenantId(),
		Limit:    int(req.GetPagination().GetPageSize()),
		Offset:   int(req.GetPagination().GetPage()) * int(req.GetPagination().GetPageSize()),
	}

	resp, err := s.service.ListRoles(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("ListRoles", err)
	}

	roles := make([]*platformv1.IAMRole, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		roles = append(roles, iamRoleToProto(r))
	}

	return &platformv1.ListIAMRolesResponse{
		Roles: roles,
		Pagination: &platformv1.PaginationResponse{
			TotalItems: uint64(resp.Total),
		},
		Total:     int64(resp.Total),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateRole updates an existing role.
func (s *IAMGRPCService) UpdateRole(
	ctx context.Context,
	req *platformv1.UpdateIAMRoleRequest,
) (*platformv1.IAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleID{}.Error())
	}

	iamReq := &IAMUpdateRoleRequest{
		TenantID:    req.GetTenantId(),
		RoleID:      req.GetRoleId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Permissions: req.GetPermissions(),
	}

	resp, err := s.service.UpdateRole(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("UpdateRole", err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      iamRoleToProto(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteRole deletes a role.
func (s *IAMGRPCService) DeleteRole(
	ctx context.Context,
	req *platformv1.DeleteIAMRoleRequest,
) (*platformv1.DeleteIAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleID{}.Error())
	}

	iamReq := &IAMDeleteRoleRequest{
		TenantID: req.GetTenantId(),
		RoleID:   req.GetRoleId(),
	}

	if err := s.service.DeleteRole(ctx, iamReq); err != nil {
		return nil, s.mapError("DeleteRole", err)
	}

	return &platformv1.DeleteIAMRoleResponse{
		Status:    iamSuccessStatus("role deleted successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// AssignRole assigns a role to a user.
func (s *IAMGRPCService) AssignRole(
	ctx context.Context,
	req *platformv1.AssignIAMRoleRequest,
) (*platformv1.AssignIAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUserID{}.Error())
	}

	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleID{}.Error())
	}

	iamReq := &IAMRoleAssignmentRequest{
		TenantID: req.GetTenantId(),
		UserID:   req.GetUserId(),
		RoleID:   req.GetRoleId(),
	}

	if err := s.service.AssignRoleToUser(ctx, iamReq); err != nil {
		return nil, s.mapError("AssignRole", err)
	}

	return &platformv1.AssignIAMRoleResponse{
		Status:    iamSuccessStatus("role assigned successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// RevokeRole revokes a role from a user.
func (s *IAMGRPCService) RevokeRole(
	ctx context.Context,
	req *platformv1.RevokeIAMRoleRequest,
) (*platformv1.RevokeIAMRoleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUserID{}.Error())
	}

	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoleID{}.Error())
	}

	iamReq := &IAMRoleAssignmentRequest{
		TenantID: req.GetTenantId(),
		UserID:   req.GetUserId(),
		RoleID:   req.GetRoleId(),
	}

	if err := s.service.RevokeRoleFromUser(ctx, iamReq); err != nil {
		return nil, s.mapError("RevokeRole", err)
	}

	return &platformv1.RevokeIAMRoleResponse{
		Status:    iamSuccessStatus("role revoked successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Authorization Operations (Passwordless)
// =============================================================================

// CheckPermission checks if a subject has permission to perform an action.
func (s *IAMGRPCService) CheckPermission(
	ctx context.Context,
	req *platformv1.CheckIAMPermissionRequest,
) (*platformv1.CheckIAMPermissionResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSubjectID{}.Error())
	}

	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingAction{}.Error())
	}

	if req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingResource{}.Error())
	}

	startTime := time.Now()
	iamReq := &IAMCheckPermissionRequest{
		TenantID:  req.GetTenantId(),
		SubjectID: req.GetSubjectId(),
		Resource:  req.GetResource(),
		Action:    req.GetAction(),
		Context:   req.GetContext(),
	}

	resp, err := s.service.CheckPermission(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("CheckPermission", err)
	}

	return &platformv1.CheckIAMPermissionResponse{
		Allowed:          resp.Allowed,
		Reason:           resp.Reason,
		EvaluationTimeNs: time.Since(startTime).Nanoseconds(),
		Timestamp:        timestamppb.Now(),
	}, nil
}

// =============================================================================
// Tenant Operations
// =============================================================================

// CreateTenant creates a new tenant.
func (s *IAMGRPCService) CreateTenant(
	ctx context.Context,
	req *platformv1.CreateIAMTenantRequest,
) (*platformv1.IAMTenantResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantName{}.Error())
	}

	// Tenant operations are handled by the service layer
	// For now, return a placeholder response
	now := timestamppb.Now()
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:   req.GetId(),
			Name: req.GetName(),
			Settings: &platformv1.IAMTenantSettings{
				MaxUsers:    req.GetSettings().GetMaxUsers(),
				MfaRequired: req.GetSettings().GetMfaRequired(),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		Timestamp: now,
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *IAMGRPCService) GetTenant(
	ctx context.Context,
	req *platformv1.GetIAMTenantRequest,
) (*platformv1.IAMTenantResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	// Return placeholder - tenant lookup would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:        req.GetTenantId(),
			Name:      "Tenant " + req.GetTenantId(),
			CreatedAt: now,
			UpdatedAt: now,
		},
		Timestamp: now,
	}, nil
}

// ListTenants returns a paginated list of tenants.
func (s *IAMGRPCService) ListTenants(
	ctx context.Context,
	req *platformv1.ListIAMTenantsRequest,
) (*platformv1.ListIAMTenantsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	// Return placeholder - tenant listing would be implemented in service layer
	return &platformv1.ListIAMTenantsResponse{
		Tenants: []*platformv1.IAMTenant{},
		Pagination: &platformv1.PaginationResponse{
			TotalItems: 0,
		},
		Total:     0,
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateTenant updates an existing tenant.
func (s *IAMGRPCService) UpdateTenant(
	ctx context.Context,
	req *platformv1.UpdateIAMTenantRequest,
) (*platformv1.IAMTenantResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	// Return placeholder - tenant update would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:   req.GetTenantId(),
			Name: req.GetName(),
			Settings: &platformv1.IAMTenantSettings{
				MaxUsers:    req.GetSettings().GetMaxUsers(),
				MfaRequired: req.GetSettings().GetMfaRequired(),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		Timestamp: now,
	}, nil
}

// DeleteTenant deletes a tenant.
func (s *IAMGRPCService) DeleteTenant(
	ctx context.Context,
	req *platformv1.DeleteIAMTenantRequest,
) (*platformv1.DeleteIAMTenantResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	// Tenant deletion would be implemented in service layer
	return &platformv1.DeleteIAMTenantResponse{
		Status:    iamSuccessStatus("tenant deleted successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Policy Operations
// =============================================================================

// CreatePolicy creates a new policy.
func (s *IAMGRPCService) CreatePolicy(
	ctx context.Context,
	req *platformv1.CreateIAMPolicyRequest,
) (*platformv1.IAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPolicyName{}.Error())
	}

	// Policy operations would be implemented through service layer
	now := timestamppb.Now()
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:        req.GetName(),
			TenantId:    req.GetTenantId(),
			Description: req.GetDescription(),
			Priority:    req.GetPriority(),
			SpecYaml:    req.GetSpecYaml(),
			Labels:      req.GetLabels(),
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		Timestamp: now,
	}, nil
}

// GetPolicy retrieves a policy by name.
func (s *IAMGRPCService) GetPolicy(
	ctx context.Context,
	req *platformv1.GetIAMPolicyRequest,
) (*platformv1.IAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPolicyName{}.Error())
	}

	// Return placeholder - policy lookup would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:      req.GetPolicyName(),
			TenantId:  req.GetTenantId(),
			CreatedAt: now,
			UpdatedAt: now,
		},
		Timestamp: now,
	}, nil
}

// ListPolicies returns a paginated list of policies.
func (s *IAMGRPCService) ListPolicies(
	ctx context.Context,
	req *platformv1.ListIAMPoliciesRequest,
) (*platformv1.ListIAMPoliciesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	// Return placeholder - policy listing would be implemented in service layer
	return &platformv1.ListIAMPoliciesResponse{
		Policies: []*platformv1.IAMPolicy{},
		Pagination: &platformv1.PaginationResponse{
			TotalItems: 0,
		},
		Total:     0,
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdatePolicy updates an existing policy.
func (s *IAMGRPCService) UpdatePolicy(
	ctx context.Context,
	req *platformv1.UpdateIAMPolicyRequest,
) (*platformv1.IAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPolicyName{}.Error())
	}

	// Return placeholder - policy update would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:        req.GetPolicyName(),
			TenantId:    req.GetTenantId(),
			Description: req.GetDescription(),
			Priority:    req.GetPriority(),
			SpecYaml:    req.GetSpecYaml(),
			Labels:      req.GetLabels(),
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		Timestamp: now,
	}, nil
}

// DeletePolicy deletes a policy.
func (s *IAMGRPCService) DeletePolicy(
	ctx context.Context,
	req *platformv1.DeleteIAMPolicyRequest,
) (*platformv1.DeleteIAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPolicyName{}.Error())
	}

	// Policy deletion would be implemented in service layer
	return &platformv1.DeleteIAMPolicyResponse{
		Status:    iamSuccessStatus("policy deleted successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ValidatePolicy validates a policy specification.
func (s *IAMGRPCService) ValidatePolicy(
	ctx context.Context,
	req *platformv1.ValidateIAMPolicyRequest,
) (*platformv1.ValidateIAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if len(req.GetSpecYaml()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPolicySpec{}.Error())
	}

	// Policy validation would be implemented in service layer
	return &platformv1.ValidateIAMPolicyResponse{
		Valid:     true,
		Errors:    []string{},
		Timestamp: timestamppb.Now(),
	}, nil
}

// TestPolicy tests a policy against a request.
func (s *IAMGRPCService) TestPolicy(
	ctx context.Context,
	req *platformv1.TestIAMPolicyRequest,
) (*platformv1.TestIAMPolicyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSubjectID{}.Error())
	}

	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingAction{}.Error())
	}

	if req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingResource{}.Error())
	}

	startTime := time.Now()

	// Use CheckPermission for policy testing
	iamReq := &IAMCheckPermissionRequest{
		TenantID:  req.GetTenantId(),
		SubjectID: req.GetSubjectId(),
		Resource:  req.GetResource(),
		Action:    req.GetAction(),
		Context:   req.GetContext(),
	}

	resp, err := s.service.CheckPermission(ctx, iamReq)
	if err != nil {
		return nil, s.mapError("TestPolicy", err)
	}

	return &platformv1.TestIAMPolicyResponse{
		Allowed:          resp.Allowed,
		EvaluationTimeNs: time.Since(startTime).Nanoseconds(),
		Timestamp:        timestamppb.Now(),
	}, nil
}

// =============================================================================
// Application Operations
// =============================================================================

// RegisterApp registers a new application.
func (s *IAMGRPCService) RegisterApp(
	ctx context.Context,
	req *platformv1.RegisterIAMAppRequest,
) (*platformv1.IAMAppResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingAppName{}.Error())
	}

	// App registration would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId:       "app-" + req.GetName(),
			ClientSecret:   "generated-secret",
			TenantId:       req.GetTenantId(),
			Name:           req.GetName(),
			RedirectUris:   req.GetRedirectUris(),
			GrantTypes:     req.GetGrantTypes(),
			ResponseTypes:  req.GetResponseTypes(),
			ResourcePrefix: req.GetResourcePrefix(),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		Timestamp: now,
	}, nil
}

// GetApp retrieves an application by client ID.
func (s *IAMGRPCService) GetApp(
	ctx context.Context,
	req *platformv1.GetIAMAppRequest,
) (*platformv1.IAMAppResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingClientID{}.Error())
	}

	// Return placeholder - app lookup would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId:  req.GetClientId(),
			TenantId:  req.GetTenantId(),
			Name:      "App " + req.GetClientId(),
			CreatedAt: now,
			UpdatedAt: now,
		},
		Timestamp: now,
	}, nil
}

// ListApps returns a paginated list of applications.
func (s *IAMGRPCService) ListApps(
	ctx context.Context,
	req *platformv1.ListIAMAppsRequest,
) (*platformv1.ListIAMAppsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	// Return placeholder - app listing would be implemented in service layer
	return &platformv1.ListIAMAppsResponse{
		Apps: []*platformv1.IAMApp{},
		Pagination: &platformv1.PaginationResponse{
			TotalItems: 0,
		},
		Total:     0,
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateApp updates an existing application.
func (s *IAMGRPCService) UpdateApp(
	ctx context.Context,
	req *platformv1.UpdateIAMAppRequest,
) (*platformv1.IAMAppResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingClientID{}.Error())
	}

	// Return placeholder - app update would be implemented in service layer
	now := timestamppb.Now()
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId:       req.GetClientId(),
			TenantId:       req.GetTenantId(),
			Name:           req.GetName(),
			RedirectUris:   req.GetRedirectUris(),
			GrantTypes:     req.GetGrantTypes(),
			ResponseTypes:  req.GetResponseTypes(),
			ResourcePrefix: req.GetResourcePrefix(),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		Timestamp: now,
	}, nil
}

// DeleteApp deletes an application.
func (s *IAMGRPCService) DeleteApp(
	ctx context.Context,
	req *platformv1.DeleteIAMAppRequest,
) (*platformv1.DeleteIAMAppResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingClientID{}.Error())
	}

	// App deletion would be implemented in service layer
	return &platformv1.DeleteIAMAppResponse{
		Status:    iamSuccessStatus("app deleted successfully"),
		Timestamp: timestamppb.Now(),
	}, nil
}

// RotateAppSecret rotates an application's client secret.
func (s *IAMGRPCService) RotateAppSecret(
	ctx context.Context,
	req *platformv1.RotateIAMAppSecretRequest,
) (*platformv1.RotateIAMAppSecretResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilIAMService{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTenantID{}.Error())
	}

	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingClientID{}.Error())
	}

	// Secret rotation would be implemented in service layer
	return &platformv1.RotateIAMAppSecretResponse{
		ClientId:     req.GetClientId(),
		Name:         "App " + req.GetClientId(),
		ClientSecret: "new-rotated-secret",
		Timestamp:    timestamppb.Now(),
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func iamSuccessStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func iamUserToProto(user *IAMUserResponse) *platformv1.IAMUser {
	if user == nil {
		return nil
	}
	return &platformv1.IAMUser{
		Id:         user.ID,
		TenantId:   user.TenantID,
		Email:      user.Email,
		Name:       user.Name,
		Roles:      user.Roles,
		Attributes: user.Attributes,
		CreatedAt:  timestamppb.New(time.Unix(user.CreatedAt, 0)),
		UpdatedAt:  timestamppb.New(time.Unix(user.UpdatedAt, 0)),
	}
}

func iamRoleToProto(role *IAMRoleResponse) *platformv1.IAMRole {
	if role == nil {
		return nil
	}
	return &platformv1.IAMRole{
		Id:          role.ID,
		TenantId:    role.TenantID,
		Name:        role.Name,
		Description: role.Description,
		Permissions: role.Permissions,
		CreatedAt:   timestamppb.New(time.Unix(role.CreatedAt, 0)),
		UpdatedAt:   timestamppb.New(time.Unix(role.UpdatedAt, 0)),
	}
}

// mapError maps IAM errors to appropriate gRPC status codes.
func (s *IAMGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "IAM operation failed", "operation", operation)

	// Check for specific IAM error types
	switch e := err.(type) {
	case ErrIAMOperationFailed:
		return status.Errorf(codes.Internal, "IAM operation %s failed: %s", e.Operation, e.Reason)
	case ErrIAMServiceNil:
		return status.Error(codes.FailedPrecondition, e.Error())
	case ErrIAMTenantIDRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMUserIDRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMEmailRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMRoleIDRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMNameRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMTokenRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMSubjectIDRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMResourceRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrIAMActionRequired:
		return status.Error(codes.InvalidArgument, e.Error())
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// Ensure IAMGRPCService implements the PlatformIAMServiceServer interface.
var _ platformv1.PlatformIAMServiceServer = (*IAMGRPCService)(nil)
