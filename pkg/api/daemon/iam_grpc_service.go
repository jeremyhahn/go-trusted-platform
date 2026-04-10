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

// iam_grpc_service.go implements the Platform IAM gRPC service.
//
// This file provides the gRPC protocol adapter for IAM operations, translating
// between the platform's protobuf API and the underlying QuicBaaS IAM service.
// It implements the PlatformIAMServiceServer interface defined in the platform
// protobuf definitions.
//
// # Supported Operations
//
// User Management:
//   - CreateUser: Create a new user in a tenant
//   - GetUser: Retrieve user by ID
//   - ListUsers: List users with pagination and filtering
//   - UpdateUser: Update user properties
//   - DeleteUser: Remove a user
//
// Role Management:
//   - CreateRole: Create a new role with permissions
//   - GetRole: Retrieve role by ID
//   - ListRoles: List roles with pagination
//   - UpdateRole: Update role properties and permissions
//   - DeleteRole: Remove a role
//   - AssignRole: Assign a role to a user
//   - RevokeRole: Remove a role from a user
//
// Group Management:
//   - CreateGroup: Create a new group
//   - GetGroup: Retrieve group by ID
//   - ListGroups: List groups with pagination
//   - UpdateGroup: Update group properties
//   - DeleteGroup: Remove a group
//   - AddGroupMember: Add a user to a group
//   - RemoveGroupMember: Remove a user from a group
//
// Tenant Management:
//   - CreateTenant: Create a new tenant (organization)
//   - GetTenant: Retrieve tenant by ID
//   - ListTenants: List all tenants
//   - UpdateTenant: Update tenant properties
//   - DeleteTenant: Remove a tenant
//
// Policy Management:
//   - CreatePolicy: Create a new authorization policy
//   - GetPolicy: Retrieve policy by name
//   - ListPolicies: List policies with pagination
//   - UpdatePolicy: Update policy specification
//   - DeletePolicy: Remove a policy
//   - ValidatePolicy: Validate policy syntax
//   - TestPolicy: Test policy against simulated request
//
// Application Management:
//   - RegisterApp: Register a new OAuth application
//   - GetApp: Retrieve application by client ID
//   - ListApps: List applications with pagination
//   - UpdateApp: Update application properties
//   - DeleteApp: Remove an application
//   - RotateAppSecret: Generate new client secret
//
// Authorization:
//   - CheckPermission: Evaluate if subject can perform action on resource
//
// # Error Handling
//
// All methods return gRPC status errors with appropriate codes:
//   - codes.InvalidArgument: Missing or invalid parameters
//   - codes.NotFound: Resource not found
//   - codes.FailedPrecondition: Service not available
//   - codes.Internal: Unexpected server errors
//   - codes.Unimplemented: Feature not yet supported
//
// # Thread Safety
//
// IAMGRPCService is safe for concurrent use. All state is immutable after
// construction, and the underlying gRPC clients handle connection pooling.

package daemon

import (
	"context"
	"log/slog"
	"time"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// iamDefaultPageSize is the default number of items returned in list operations.
	iamDefaultPageSize int32 = 50

	// iamMaxPageSize is the maximum number of items that can be requested in a single
	// list operation to prevent excessive resource consumption.
	iamMaxPageSize int32 = 1000

	// iamRequestTimeout is the maximum duration for a single IAM operation before
	// the request is cancelled. This prevents long-running operations from blocking
	// resources indefinitely.
	iamRequestTimeout = 30 * time.Second
)

// IAMGRPCService implements the Platform IAM gRPC service (PlatformIAMServiceServer).
//
// It acts as a protocol adapter between the platform's gRPC API and the QuicBaaS
// IAM service, handling type conversion, validation, pagination, and error mapping.
// The service delegates actual IAM operations to the QuicBaaS IAM and PEP clients.
//
// Example usage:
//
//	iamService := daemon.NewIAMGRPCService(logger, iamClient, pepClient)
//	platformv1.RegisterPlatformIAMServiceServer(grpcServer, iamService)
type IAMGRPCService struct {
	platformv1.UnimplementedPlatformIAMServiceServer

	logger    *slog.Logger
	iamClient iampb.IAMServiceClient
	pepClient iampb.PEPServiceClient
}

// NewIAMGRPCService creates a new IAM gRPC service instance.
//
// Parameters:
//   - logger: Structured logger for operation logging and error reporting
//   - iamClient: QuicBaaS IAM service client for user, role, group, tenant,
//     policy, and application operations
//   - pepClient: QuicBaaS PEP (Policy Enforcement Point) client for authorization
//     checks
//
// The iamClient and pepClient may be nil if the corresponding functionality
// is not available. Methods will return FailedPrecondition errors when called
// without the required client.
func NewIAMGRPCService(
	logger *slog.Logger,
	iamClient iampb.IAMServiceClient,
	pepClient iampb.PEPServiceClient,
) *IAMGRPCService {
	return &IAMGRPCService{
		logger:    logger,
		iamClient: iamClient,
		pepClient: pepClient,
	}
}

// =============================================================================
// User Operations
// =============================================================================

// CreateUser creates a new user in the IAM system.
//
// The user is created within the specified tenant. The email address must be
// unique within the tenant and serves as the primary identifier for authentication.
// Optional roles and groups can be assigned during creation.
//
// Required fields: tenant_id, email
// Optional fields: name, roles, groups, attributes
//
// Returns ErrIAMMissingParameter if required fields are missing.
func (s *IAMGRPCService) CreateUser(ctx context.Context, req *platformv1.CreateIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "email"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.CreateUserRequest{
		TenantId:   req.GetTenantId(),
		Email:      req.GetEmail(),
		Name:       req.GetName(),
		Roles:      req.GetRoles(),
		Groups:     req.GetGroups(),
		Attributes: req.GetAttributes(),
	}

	resp, err := s.iamClient.CreateUser(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to create user", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMUserResponse{
		User:      s.dragonUserToPlatformUser(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetUser retrieves a user by ID.
//
// Returns the user details including roles, groups, and custom attributes.
// Returns NotFound if the user does not exist in the specified tenant.
//
// Required fields: tenant_id, user_id
func (s *IAMGRPCService) GetUser(ctx context.Context, req *platformv1.GetIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetUserRequest{
		TenantId: req.GetTenantId(),
		UserId:   req.GetUserId(),
	}

	resp, err := s.iamClient.GetUser(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get user", "error", err, "tenant_id", req.GetTenantId(), "user_id", req.GetUserId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMUserResponse{
		User:      s.dragonUserToPlatformUser(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListUsers returns a paginated list of users.
//
// Supports filtering by email, role, or group. Pagination is controlled via
// the PaginationRequest with page number and page size. Default page size is 50,
// maximum is 1000.
//
// Required fields: tenant_id
// Optional fields: pagination, email_filter, role_filter, group_filter
func (s *IAMGRPCService) ListUsers(ctx context.Context, req *platformv1.ListIAMUsersRequest) (*platformv1.ListIAMUsersResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListUsersRequest{
		TenantId: req.GetTenantId(),
		Limit:    limit,
		Offset:   offset,
		Email:    req.GetEmailFilter(),
		Role:     req.GetRoleFilter(),
		Group:    req.GetGroupFilter(),
	}

	resp, err := s.iamClient.ListUsers(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list users", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	users := make([]*platformv1.IAMUser, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		users = append(users, s.dragonUserToPlatformUser(u))
	}

	return &platformv1.ListIAMUsersResponse{
		Users: users,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateUser updates an existing user.
//
// All provided fields will replace existing values. To preserve existing values
// for a field, omit it from the request or provide the current value.
//
// Required fields: tenant_id, user_id
// Optional fields: email, name, roles, groups, attributes
func (s *IAMGRPCService) UpdateUser(ctx context.Context, req *platformv1.UpdateIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.UpdateUserRequest{
		TenantId:   req.GetTenantId(),
		UserId:     req.GetUserId(),
		Email:      req.GetEmail(),
		Name:       req.GetName(),
		Roles:      req.GetRoles(),
		Groups:     req.GetGroups(),
		Attributes: req.GetAttributes(),
	}

	resp, err := s.iamClient.UpdateUser(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update user", "error", err, "tenant_id", req.GetTenantId(), "user_id", req.GetUserId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMUserResponse{
		User:      s.dragonUserToPlatformUser(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteUser deletes a user.
//
// This operation is irreversible. The user will be removed from all groups
// and have all role assignments revoked as part of the deletion.
//
// Required fields: tenant_id, user_id
func (s *IAMGRPCService) DeleteUser(ctx context.Context, req *platformv1.DeleteIAMUserRequest) (*platformv1.DeleteIAMUserResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeleteUserRequest{
		TenantId: req.GetTenantId(),
		UserId:   req.GetUserId(),
	}

	resp, err := s.iamClient.DeleteUser(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete user", "error", err, "tenant_id", req.GetTenantId(), "user_id", req.GetUserId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMUserResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "user deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Role Operations
// =============================================================================

// CreateRole creates a new role in the IAM system.
//
// Roles define sets of permissions that can be assigned to users. Permissions
// follow the format "resource:action" (e.g., "users:read", "policies:*").
//
// Required fields: tenant_id, id or name
// Optional fields: description, permissions
func (s *IAMGRPCService) CreateRole(ctx context.Context, req *platformv1.CreateIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetId() == "" && req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "id or name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.CreateRoleRequest{
		TenantId:    req.GetTenantId(),
		Id:          req.GetId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Permissions: req.GetPermissions(),
	}

	resp, err := s.iamClient.CreateRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to create role", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      s.dragonRoleToPlatformRole(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetRole retrieves a role by ID.
//
// Returns the role details including name, description, and permissions.
// Returns NotFound if the role does not exist in the specified tenant.
//
// Required fields: tenant_id, role_id
func (s *IAMGRPCService) GetRole(ctx context.Context, req *platformv1.GetIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "role_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetRoleRequest{
		TenantId: req.GetTenantId(),
		RoleId:   req.GetRoleId(),
	}

	resp, err := s.iamClient.GetRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get role", "error", err, "tenant_id", req.GetTenantId(), "role_id", req.GetRoleId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      s.dragonRoleToPlatformRole(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListRoles returns a paginated list of roles.
//
// Required fields: tenant_id
// Optional fields: pagination
func (s *IAMGRPCService) ListRoles(ctx context.Context, req *platformv1.ListIAMRolesRequest) (*platformv1.ListIAMRolesResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListRolesRequest{
		TenantId: req.GetTenantId(),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := s.iamClient.ListRoles(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list roles", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	roles := make([]*platformv1.IAMRole, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		roles = append(roles, s.dragonRoleToPlatformRole(r))
	}

	return &platformv1.ListIAMRolesResponse{
		Roles: roles,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateRole updates an existing role.
//
// Updates to permissions take effect immediately for all users with this role.
//
// Required fields: tenant_id, role_id
// Optional fields: name, description, permissions
func (s *IAMGRPCService) UpdateRole(ctx context.Context, req *platformv1.UpdateIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "role_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.UpdateRoleRequest{
		TenantId:    req.GetTenantId(),
		RoleId:      req.GetRoleId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Permissions: req.GetPermissions(),
	}

	resp, err := s.iamClient.UpdateRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update role", "error", err, "tenant_id", req.GetTenantId(), "role_id", req.GetRoleId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMRoleResponse{
		Role:      s.dragonRoleToPlatformRole(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteRole deletes a role.
//
// This operation is irreversible. Users with this role will lose the associated
// permissions immediately upon deletion.
//
// Required fields: tenant_id, role_id
func (s *IAMGRPCService) DeleteRole(ctx context.Context, req *platformv1.DeleteIAMRoleRequest) (*platformv1.DeleteIAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "role_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeleteRoleRequest{
		TenantId: req.GetTenantId(),
		RoleId:   req.GetRoleId(),
	}

	resp, err := s.iamClient.DeleteRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete role", "error", err, "tenant_id", req.GetTenantId(), "role_id", req.GetRoleId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMRoleResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "role deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// AssignRole assigns a role to a user.
//
// The user immediately gains all permissions defined by the role.
//
// Required fields: tenant_id, user_id, role_id
func (s *IAMGRPCService) AssignRole(ctx context.Context, req *platformv1.AssignIAMRoleRequest) (*platformv1.AssignIAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "role_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.AssignRoleRequest{
		TenantId: req.GetTenantId(),
		UserId:   req.GetUserId(),
		Role:     req.GetRoleId(),
	}

	resp, err := s.iamClient.AssignRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to assign role", "error", err, "tenant_id", req.GetTenantId(), "user_id", req.GetUserId(), "role_id", req.GetRoleId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.AssignIAMRoleResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "role assigned successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// RevokeRole revokes a role from a user.
//
// The user immediately loses all permissions defined by the role.
//
// Required fields: tenant_id, user_id, role_id
func (s *IAMGRPCService) RevokeRole(ctx context.Context, req *platformv1.RevokeIAMRoleRequest) (*platformv1.RevokeIAMRoleResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "role_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.RevokeRoleRequest{
		TenantId: req.GetTenantId(),
		UserId:   req.GetUserId(),
		Role:     req.GetRoleId(),
	}

	resp, err := s.iamClient.RevokeRole(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to revoke role", "error", err, "tenant_id", req.GetTenantId(), "user_id", req.GetUserId(), "role_id", req.GetRoleId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.RevokeIAMRoleResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "role revoked successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Group Operations
// =============================================================================

// CreateGroup creates a new group in the IAM system.
//
// Groups provide logical organization of users and can be used in policy
// conditions for group-based access control.
//
// Required fields: tenant_id, id or name
// Optional fields: description
func (s *IAMGRPCService) CreateGroup(ctx context.Context, req *platformv1.CreateIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetId() == "" && req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "id or name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.CreateGroupRequest{
		TenantId:    req.GetTenantId(),
		Id:          req.GetId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
	}

	resp, err := s.iamClient.CreateGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to create group", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMGroupResponse{
		Group:     s.dragonGroupToPlatformGroup(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetGroup retrieves a group by ID.
//
// Returns the group details including name, description, and member list.
// Returns NotFound if the group does not exist in the specified tenant.
//
// Required fields: tenant_id, group_id
func (s *IAMGRPCService) GetGroup(ctx context.Context, req *platformv1.GetIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "group_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetGroupRequest{
		TenantId: req.GetTenantId(),
		GroupId:  req.GetGroupId(),
	}

	resp, err := s.iamClient.GetGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get group", "error", err, "tenant_id", req.GetTenantId(), "group_id", req.GetGroupId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMGroupResponse{
		Group:     s.dragonGroupToPlatformGroup(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListGroups returns a paginated list of groups.
//
// Required fields: tenant_id
// Optional fields: pagination
func (s *IAMGRPCService) ListGroups(ctx context.Context, req *platformv1.ListIAMGroupsRequest) (*platformv1.ListIAMGroupsResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListGroupsRequest{
		TenantId: req.GetTenantId(),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := s.iamClient.ListGroups(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list groups", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	groups := make([]*platformv1.IAMGroup, 0, len(resp.GetGroups()))
	for _, g := range resp.GetGroups() {
		groups = append(groups, s.dragonGroupToPlatformGroup(g))
	}

	return &platformv1.ListIAMGroupsResponse{
		Groups: groups,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateGroup updates an existing group.
//
// Required fields: tenant_id, group_id
// Optional fields: name, description
func (s *IAMGRPCService) UpdateGroup(ctx context.Context, req *platformv1.UpdateIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "group_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.UpdateGroupRequest{
		TenantId:    req.GetTenantId(),
		GroupId:     req.GetGroupId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
	}

	resp, err := s.iamClient.UpdateGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update group", "error", err, "tenant_id", req.GetTenantId(), "group_id", req.GetGroupId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMGroupResponse{
		Group:     s.dragonGroupToPlatformGroup(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteGroup deletes a group.
//
// This operation is irreversible. All users will be removed from the group
// as part of the deletion.
//
// Required fields: tenant_id, group_id
func (s *IAMGRPCService) DeleteGroup(ctx context.Context, req *platformv1.DeleteIAMGroupRequest) (*platformv1.DeleteIAMGroupResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "group_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeleteGroupRequest{
		TenantId: req.GetTenantId(),
		GroupId:  req.GetGroupId(),
	}

	resp, err := s.iamClient.DeleteGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete group", "error", err, "tenant_id", req.GetTenantId(), "group_id", req.GetGroupId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMGroupResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "group deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// AddGroupMember adds a member to a group.
//
// The user immediately becomes a member of the group and policies referencing
// this group will apply to them.
//
// Required fields: tenant_id, group_id, user_id
func (s *IAMGRPCService) AddGroupMember(ctx context.Context, req *platformv1.AddGroupMemberRequest) (*platformv1.AddGroupMemberResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "group_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.AddUserToGroupRequest{
		TenantId: req.GetTenantId(),
		GroupId:  req.GetGroupId(),
		UserId:   req.GetUserId(),
	}

	resp, err := s.iamClient.AddUserToGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to add group member", "error", err, "tenant_id", req.GetTenantId(), "group_id", req.GetGroupId(), "user_id", req.GetUserId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.AddGroupMemberResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "member added successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// RemoveGroupMember removes a member from a group.
//
// The user immediately loses group membership and policies referencing this
// group will no longer apply to them.
//
// Required fields: tenant_id, group_id, user_id
func (s *IAMGRPCService) RemoveGroupMember(ctx context.Context, req *platformv1.RemoveGroupMemberRequest) (*platformv1.RemoveGroupMemberResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "group_id"}.Error())
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "user_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.RemoveUserFromGroupRequest{
		TenantId: req.GetTenantId(),
		GroupId:  req.GetGroupId(),
		UserId:   req.GetUserId(),
	}

	resp, err := s.iamClient.RemoveUserFromGroup(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to remove group member", "error", err, "tenant_id", req.GetTenantId(), "group_id", req.GetGroupId(), "user_id", req.GetUserId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.RemoveGroupMemberResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "member removed successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Authorization Operations
// =============================================================================

// CheckPermission checks if a subject has permission to perform an action on a resource.
//
// This is the Policy Enforcement Point (PEP) that evaluates authorization requests
// against the configured policies. The evaluation considers the subject's roles,
// groups, and attributes along with any contextual information provided.
//
// Required fields: tenant_id, subject_id, action, resource
// Optional fields: roles, groups, attributes, context
//
// Returns the authorization decision with details about the matched policy and rule.
func (s *IAMGRPCService) CheckPermission(ctx context.Context, req *platformv1.CheckIAMPermissionRequest) (*platformv1.CheckIAMPermissionResponse, error) {
	if s.pepClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "subject_id"}.Error())
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "action"}.Error())
	}
	if req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "resource"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	subject := &iampb.Subject{
		Id:         req.GetSubjectId(),
		TenantId:   req.GetTenantId(),
		Roles:      req.GetRoles(),
		Groups:     req.GetGroups(),
		Attributes: req.GetAttributes(),
	}

	// Use CheckRequest (not CheckPermissionRequest) as per go-quicbaas's API
	grpcReq := &iampb.CheckRequest{
		Subject:  subject,
		Action:   req.GetAction(),
		Resource: req.GetResource(),
		Context:  req.GetContext(),
	}

	// Use Check method (not CheckPermission) as per go-quicbaas's PEP API
	resp, err := s.pepClient.Check(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to check permission", "error", err, "tenant_id", req.GetTenantId(), "subject_id", req.GetSubjectId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.CheckIAMPermissionResponse{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
		Timestamp:        timestamppb.Now(),
	}, nil
}

// CreateToken creates a new access token.
//
// Note: This method is not implemented. Token creation is handled via OIDC
// flows using the Federation service.
func (s *IAMGRPCService) CreateToken(ctx context.Context, req *platformv1.CreateIAMTokenRequest) (*platformv1.CreateIAMTokenResponse, error) {
	// Token creation is handled via OIDC flows in go-quicbaas
	return nil, status.Error(codes.Unimplemented, "token creation should be performed via OIDC flows")
}

// RevokeToken revokes an access token.
//
// Note: This method is not implemented. Token revocation is handled via OIDC
// flows using the Federation service.
func (s *IAMGRPCService) RevokeToken(ctx context.Context, req *platformv1.RevokeIAMTokenRequest) (*platformv1.RevokeIAMTokenResponse, error) {
	// Token revocation is handled via OIDC flows in go-quicbaas
	return nil, status.Error(codes.Unimplemented, "token revocation should be performed via OIDC flows")
}

// VerifyToken verifies an access token.
//
// Note: This method is not implemented. Token verification is handled via OIDC
// flows using the Federation service.
func (s *IAMGRPCService) VerifyToken(ctx context.Context, req *platformv1.VerifyIAMTokenRequest) (*platformv1.VerifyIAMTokenResponse, error) {
	// Token verification is handled via OIDC flows in go-quicbaas
	return nil, status.Error(codes.Unimplemented, "token verification should be performed via OIDC flows")
}

// =============================================================================
// Tenant Operations
// =============================================================================

// CreateTenant creates a new tenant.
//
// Tenants represent isolated organizations within the platform. Each tenant
// has its own users, groups, roles, policies, and applications.
//
// Required fields: id
// Optional fields: name, settings
func (s *IAMGRPCService) CreateTenant(ctx context.Context, req *platformv1.CreateIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	var settings *iampb.TenantSettings
	if req.GetSettings() != nil {
		settings = &iampb.TenantSettings{
			MaxUsers:    req.GetSettings().GetMaxUsers(),
			MfaRequired: req.GetSettings().GetMfaRequired(),
		}
	}

	grpcReq := &iampb.CreateTenantRequest{
		Id:       req.GetId(),
		Name:     req.GetName(),
		Settings: settings,
	}

	resp, err := s.iamClient.CreateTenant(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to create tenant", "error", err, "tenant_id", req.GetId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMTenantResponse{
		Tenant:    s.dragonTenantToPlatformTenant(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetTenant retrieves a tenant by ID.
//
// Returns the tenant details including name and settings.
// Returns NotFound if the tenant does not exist.
//
// Required fields: tenant_id
func (s *IAMGRPCService) GetTenant(ctx context.Context, req *platformv1.GetIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetTenantRequest{
		Id: req.GetTenantId(),
	}

	resp, err := s.iamClient.GetTenant(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get tenant", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMTenantResponse{
		Tenant:    s.dragonTenantToPlatformTenant(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListTenants returns a paginated list of tenants.
//
// Optional fields: pagination
func (s *IAMGRPCService) ListTenants(ctx context.Context, req *platformv1.ListIAMTenantsRequest) (*platformv1.ListIAMTenantsResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListTenantsRequest{
		Limit:  limit,
		Offset: offset,
	}

	resp, err := s.iamClient.ListTenants(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list tenants", "error", err)
		return nil, s.convertGRPCError(err)
	}

	tenants := make([]*platformv1.IAMTenant, 0, len(resp.GetTenants()))
	for _, t := range resp.GetTenants() {
		tenants = append(tenants, s.dragonTenantToPlatformTenant(t))
	}

	return &platformv1.ListIAMTenantsResponse{
		Tenants: tenants,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateTenant updates an existing tenant.
//
// Required fields: tenant_id
// Optional fields: name, settings
func (s *IAMGRPCService) UpdateTenant(ctx context.Context, req *platformv1.UpdateIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	var settings *iampb.TenantSettings
	if req.GetSettings() != nil {
		settings = &iampb.TenantSettings{
			MaxUsers:    req.GetSettings().GetMaxUsers(),
			MfaRequired: req.GetSettings().GetMfaRequired(),
		}
	}

	grpcReq := &iampb.UpdateTenantRequest{
		Id:       req.GetTenantId(),
		Name:     req.GetName(),
		Settings: settings,
	}

	resp, err := s.iamClient.UpdateTenant(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update tenant", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMTenantResponse{
		Tenant:    s.dragonTenantToPlatformTenant(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteTenant deletes a tenant.
//
// This operation is irreversible. All users, groups, roles, policies, and
// applications within the tenant will be deleted.
//
// Required fields: tenant_id
func (s *IAMGRPCService) DeleteTenant(ctx context.Context, req *platformv1.DeleteIAMTenantRequest) (*platformv1.DeleteIAMTenantResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeleteTenantRequest{
		Id: req.GetTenantId(),
	}

	resp, err := s.iamClient.DeleteTenant(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete tenant", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMTenantResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "tenant deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Policy Operations
// =============================================================================

// CreatePolicy creates a new policy.
//
// Policies define authorization rules in YAML format. They specify conditions
// under which actions on resources are allowed or denied.
//
// Required fields: tenant_id, name, spec_yaml
// Optional fields: description, priority, labels
func (s *IAMGRPCService) CreatePolicy(ctx context.Context, req *platformv1.CreateIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "name"}.Error())
	}
	if len(req.GetSpecYaml()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "spec_yaml"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.CreatePolicyRequest{
		TenantId:    req.GetTenantId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Priority:    req.GetPriority(),
		SpecYaml:    req.GetSpecYaml(),
		Labels:      req.GetLabels(),
	}

	resp, err := s.iamClient.CreatePolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to create policy", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMPolicyResponse{
		Policy:    s.dragonPolicyToPlatformPolicy(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetPolicy retrieves a policy by name.
//
// Returns the policy details including the YAML specification.
// Returns NotFound if the policy does not exist in the specified tenant.
//
// Required fields: tenant_id, policy_name
func (s *IAMGRPCService) GetPolicy(ctx context.Context, req *platformv1.GetIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "policy_name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetPolicyRequest{
		TenantId:   req.GetTenantId(),
		PolicyName: req.GetPolicyName(),
	}

	resp, err := s.iamClient.GetPolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get policy", "error", err, "tenant_id", req.GetTenantId(), "policy_name", req.GetPolicyName())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMPolicyResponse{
		Policy:    s.dragonPolicyToPlatformPolicy(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListPolicies returns a paginated list of policies.
//
// Required fields: tenant_id
// Optional fields: pagination
func (s *IAMGRPCService) ListPolicies(ctx context.Context, req *platformv1.ListIAMPoliciesRequest) (*platformv1.ListIAMPoliciesResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListPoliciesRequest{
		TenantId: req.GetTenantId(),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := s.iamClient.ListPolicies(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list policies", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	policies := make([]*platformv1.IAMPolicy, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		policies = append(policies, s.dragonPolicyToPlatformPolicy(p))
	}

	return &platformv1.ListIAMPoliciesResponse{
		Policies: policies,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdatePolicy updates an existing policy.
//
// Policy updates take effect immediately for all authorization decisions.
//
// Required fields: tenant_id, policy_name
// Optional fields: description, priority, spec_yaml, labels
func (s *IAMGRPCService) UpdatePolicy(ctx context.Context, req *platformv1.UpdateIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "policy_name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.UpdatePolicyRequest{
		TenantId:    req.GetTenantId(),
		PolicyName:  req.GetPolicyName(),
		Description: req.GetDescription(),
		Priority:    req.GetPriority(),
		SpecYaml:    req.GetSpecYaml(),
		Labels:      req.GetLabels(),
	}

	resp, err := s.iamClient.UpdatePolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update policy", "error", err, "tenant_id", req.GetTenantId(), "policy_name", req.GetPolicyName())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMPolicyResponse{
		Policy:    s.dragonPolicyToPlatformPolicy(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeletePolicy deletes a policy.
//
// This operation is irreversible. Authorization decisions will no longer
// consider this policy after deletion.
//
// Required fields: tenant_id, policy_name
func (s *IAMGRPCService) DeletePolicy(ctx context.Context, req *platformv1.DeleteIAMPolicyRequest) (*platformv1.DeleteIAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetPolicyName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "policy_name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeletePolicyRequest{
		TenantId:   req.GetTenantId(),
		PolicyName: req.GetPolicyName(),
	}

	resp, err := s.iamClient.DeletePolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete policy", "error", err, "tenant_id", req.GetTenantId(), "policy_name", req.GetPolicyName())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMPolicyResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "policy deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// ValidatePolicy validates a policy specification.
//
// This method checks the policy YAML for syntax errors and semantic issues
// without creating the policy. Use this to validate policies before deployment.
//
// Required fields: tenant_id, spec_yaml
func (s *IAMGRPCService) ValidatePolicy(ctx context.Context, req *platformv1.ValidateIAMPolicyRequest) (*platformv1.ValidateIAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if len(req.GetSpecYaml()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "spec_yaml"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.ValidatePolicyRequest{
		TenantId: req.GetTenantId(),
		SpecYaml: req.GetSpecYaml(),
	}

	resp, err := s.iamClient.ValidatePolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to validate policy", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.ValidateIAMPolicyResponse{
		Valid:     resp.GetValid(),
		Errors:    resp.GetErrors(),
		Timestamp: timestamppb.Now(),
	}, nil
}

// TestPolicy tests a policy against a simulated request.
//
// This method evaluates all tenant policies against the provided subject,
// action, and resource without affecting real authorization. Use this to
// debug and verify policy behavior.
//
// Required fields: tenant_id, subject_id, action, resource
// Optional fields: roles, groups, attributes, context
func (s *IAMGRPCService) TestPolicy(ctx context.Context, req *platformv1.TestIAMPolicyRequest) (*platformv1.TestIAMPolicyResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "subject_id"}.Error())
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "action"}.Error())
	}
	if req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "resource"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	subject := &iampb.Subject{
		Id:         req.GetSubjectId(),
		TenantId:   req.GetTenantId(),
		Roles:      req.GetRoles(),
		Groups:     req.GetGroups(),
		Attributes: req.GetAttributes(),
	}

	grpcReq := &iampb.TestPolicyRequest{
		TenantId: req.GetTenantId(),
		Subject:  subject,
		Action:   req.GetAction(),
		Resource: req.GetResource(),
		Context:  req.GetContext(),
	}

	resp, err := s.iamClient.TestPolicy(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to test policy", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.TestIAMPolicyResponse{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
		Timestamp:        timestamppb.Now(),
	}, nil
}

// =============================================================================
// Application Operations
// =============================================================================

// RegisterApp registers a new application.
//
// Applications are OAuth clients that can authenticate users and request
// access tokens. Each application receives a client ID and client secret.
//
// Required fields: tenant_id, name
// Optional fields: redirect_uris, grant_types, response_types, resource_prefix
func (s *IAMGRPCService) RegisterApp(ctx context.Context, req *platformv1.RegisterIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "name"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.RegisterAppRequest{
		TenantId:       req.GetTenantId(),
		Name:           req.GetName(),
		RedirectUris:   req.GetRedirectUris(),
		GrantTypes:     req.GetGrantTypes(),
		ResponseTypes:  req.GetResponseTypes(),
		ResourcePrefix: req.GetResourcePrefix(),
	}

	resp, err := s.iamClient.RegisterApp(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to register app", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMAppResponse{
		App:       s.dragonAppToPlatformApp(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetApp retrieves an application by client ID.
//
// Returns the application details. Note that the client secret is not returned
// after initial registration for security reasons.
//
// Required fields: tenant_id, client_id
func (s *IAMGRPCService) GetApp(ctx context.Context, req *platformv1.GetIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "client_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.GetAppRequest{
		TenantId: req.GetTenantId(),
		ClientId: req.GetClientId(),
	}

	resp, err := s.iamClient.GetApp(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to get app", "error", err, "tenant_id", req.GetTenantId(), "client_id", req.GetClientId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMAppResponse{
		App:       s.dragonAppToPlatformApp(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListApps returns a paginated list of applications.
//
// Required fields: tenant_id
// Optional fields: pagination
func (s *IAMGRPCService) ListApps(ctx context.Context, req *platformv1.ListIAMAppsRequest) (*platformv1.ListIAMAppsResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	limit, offset := s.getPagination(req.GetPagination())

	grpcReq := &iampb.ListAppsRequest{
		TenantId: req.GetTenantId(),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := s.iamClient.ListApps(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to list apps", "error", err, "tenant_id", req.GetTenantId())
		return nil, s.convertGRPCError(err)
	}

	apps := make([]*platformv1.IAMApp, 0, len(resp.GetApps()))
	for _, a := range resp.GetApps() {
		apps = append(apps, s.dragonAppToPlatformApp(a))
	}

	return &platformv1.ListIAMAppsResponse{
		Apps: apps,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalItems: uint64(resp.GetTotal()),
		},
		Total:     int64(resp.GetTotal()),
		Timestamp: timestamppb.Now(),
	}, nil
}

// UpdateApp updates an existing application.
//
// Required fields: tenant_id, client_id
// Optional fields: name, redirect_uris, grant_types, response_types, resource_prefix
func (s *IAMGRPCService) UpdateApp(ctx context.Context, req *platformv1.UpdateIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "client_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.UpdateAppRequest{
		TenantId:       req.GetTenantId(),
		ClientId:       req.GetClientId(),
		Name:           req.GetName(),
		RedirectUris:   req.GetRedirectUris(),
		GrantTypes:     req.GetGrantTypes(),
		ResponseTypes:  req.GetResponseTypes(),
		ResourcePrefix: req.GetResourcePrefix(),
	}

	resp, err := s.iamClient.UpdateApp(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to update app", "error", err, "tenant_id", req.GetTenantId(), "client_id", req.GetClientId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.IAMAppResponse{
		App:       s.dragonAppToPlatformApp(resp),
		Timestamp: timestamppb.Now(),
	}, nil
}

// DeleteApp deletes an application.
//
// This operation is irreversible. All tokens issued to this application will
// be invalidated.
//
// Required fields: tenant_id, client_id
func (s *IAMGRPCService) DeleteApp(ctx context.Context, req *platformv1.DeleteIAMAppRequest) (*platformv1.DeleteIAMAppResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "client_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.DeleteAppRequest{
		TenantId: req.GetTenantId(),
		ClientId: req.GetClientId(),
	}

	resp, err := s.iamClient.DeleteApp(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to delete app", "error", err, "tenant_id", req.GetTenantId(), "client_id", req.GetClientId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.DeleteIAMAppResponse{
		Status: &platformv1.Status{
			Success: resp.GetSuccess(),
			Message: "app deleted successfully",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// RotateAppSecret rotates the client secret for an application.
//
// A new client secret is generated and returned. The old secret is immediately
// invalidated. Store the new secret securely as it cannot be retrieved again.
//
// Required fields: tenant_id, client_id
func (s *IAMGRPCService) RotateAppSecret(ctx context.Context, req *platformv1.RotateIAMAppSecretRequest) (*platformv1.RotateIAMAppSecretResponse, error) {
	if s.iamClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrIAMServiceNotAvailable{}.Error())
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "tenant_id"}.Error())
	}
	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrIAMMissingParameter{Parameter: "client_id"}.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	grpcReq := &iampb.RotateAppSecretRequest{
		TenantId: req.GetTenantId(),
		ClientId: req.GetClientId(),
	}

	resp, err := s.iamClient.RotateAppSecret(ctx, grpcReq)
	if err != nil {
		s.logger.Error("failed to rotate app secret", "error", err, "tenant_id", req.GetTenantId(), "client_id", req.GetClientId())
		return nil, s.convertGRPCError(err)
	}

	return &platformv1.RotateIAMAppSecretResponse{
		ClientId:     resp.GetClientId(),
		Name:         resp.GetName(),
		ClientSecret: resp.GetClientSecret(),
		Timestamp:    timestamppb.Now(),
	}, nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// getPagination extracts and validates pagination parameters from the request.
//
// If pagination is not specified, returns default values. Enforces the maximum
// page size limit to prevent excessive resource consumption.
func (s *IAMGRPCService) getPagination(req *platformv1.PaginationRequest) (limit int32, offset int32) {
	limit = iamDefaultPageSize
	offset = 0

	if req != nil {
		if req.GetPageSize() > 0 {
			limit = int32(req.GetPageSize())
			if limit > iamMaxPageSize {
				limit = iamMaxPageSize
			}
		}
		if req.GetPage() > 0 {
			offset = int32((req.GetPage() - 1)) * limit
		}
	}

	return limit, offset
}

// convertGRPCError converts gRPC status errors to the appropriate response.
//
// If the error is already a gRPC status, it preserves the code and message.
// Otherwise, it wraps the error as an Internal error.
func (s *IAMGRPCService) convertGRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return status.Error(codes.Internal, err.Error())
	}
	return status.Error(st.Code(), st.Message())
}

// dragonUserToPlatformUser converts a QuicBaaS user to a platform user.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonUserToPlatformUser(u *iampb.User) *platformv1.IAMUser {
	if u == nil {
		return nil
	}
	return &platformv1.IAMUser{
		Id:          u.GetId(),
		TenantId:    u.GetTenantId(),
		Email:       u.GetEmail(),
		Name:        u.GetName(),
		Roles:       u.GetRoles(),
		Groups:      u.GetGroups(),
		Attributes:  u.GetAttributes(),
		MfaVerified: u.GetMfaVerified(),
		CreatedAt:   u.GetCreatedAt(),
		UpdatedAt:   u.GetUpdatedAt(),
		LastAuth:    u.GetLastAuth(),
	}
}

// dragonRoleToPlatformRole converts a QuicBaaS role to a platform role.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonRoleToPlatformRole(r *iampb.Role) *platformv1.IAMRole {
	if r == nil {
		return nil
	}
	return &platformv1.IAMRole{
		Id:          r.GetId(),
		TenantId:    r.GetTenantId(),
		Name:        r.GetName(),
		Description: r.GetDescription(),
		Permissions: r.GetPermissions(),
		CreatedAt:   r.GetCreatedAt(),
		UpdatedAt:   r.GetUpdatedAt(),
	}
}

// dragonGroupToPlatformGroup converts a QuicBaaS group to a platform group.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonGroupToPlatformGroup(g *iampb.Group) *platformv1.IAMGroup {
	if g == nil {
		return nil
	}
	return &platformv1.IAMGroup{
		Id:          g.GetId(),
		TenantId:    g.GetTenantId(),
		Name:        g.GetName(),
		Description: g.GetDescription(),
		Members:     g.GetMembers(),
		CreatedAt:   g.GetCreatedAt(),
		UpdatedAt:   g.GetUpdatedAt(),
	}
}

// dragonTenantToPlatformTenant converts a QuicBaaS tenant to a platform tenant.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonTenantToPlatformTenant(t *iampb.Tenant) *platformv1.IAMTenant {
	if t == nil {
		return nil
	}
	tenant := &platformv1.IAMTenant{
		Id:        t.GetId(),
		Name:      t.GetName(),
		CreatedAt: t.GetCreatedAt(),
		UpdatedAt: t.GetUpdatedAt(),
	}
	if t.GetSettings() != nil {
		tenant.Settings = &platformv1.IAMTenantSettings{
			MaxUsers:    t.GetSettings().GetMaxUsers(),
			MfaRequired: t.GetSettings().GetMfaRequired(),
		}
	}
	return tenant
}

// dragonPolicyToPlatformPolicy converts a QuicBaaS policy to a platform policy.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonPolicyToPlatformPolicy(p *iampb.Policy) *platformv1.IAMPolicy {
	if p == nil {
		return nil
	}
	return &platformv1.IAMPolicy{
		Name:        p.GetName(),
		TenantId:    p.GetTenantId(),
		Description: p.GetDescription(),
		Priority:    p.GetPriority(),
		SpecYaml:    p.GetSpecYaml(),
		Labels:      p.GetLabels(),
		CreatedAt:   p.GetCreatedAt(),
		UpdatedAt:   p.GetUpdatedAt(),
	}
}

// dragonAppToPlatformApp converts a QuicBaaS application to a platform application.
//
// Returns nil if the input is nil, enabling safe chaining.
func (s *IAMGRPCService) dragonAppToPlatformApp(a *iampb.Application) *platformv1.IAMApp {
	if a == nil {
		return nil
	}
	return &platformv1.IAMApp{
		ClientId:       a.GetClientId(),
		ClientSecret:   a.GetClientSecret(),
		TenantId:       a.GetTenantId(),
		Name:           a.GetName(),
		RedirectUris:   a.GetRedirectUris(),
		GrantTypes:     a.GetGrantTypes(),
		ResponseTypes:  a.GetResponseTypes(),
		ResourcePrefix: a.GetResourcePrefix(),
		CreatedAt:      a.GetCreatedAt(),
		UpdatedAt:      a.GetUpdatedAt(),
	}
}
