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

//go:build integration

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// listReplyJSON decodes the protojson list replies the REST API writes,
// ignoring fields newer than this suite.
var listReplyJSON = protojson.UnmarshalOptions{DiscardUnknown: true}

// decodeListReply decodes an IAM list reply (the items, pagination, total
// and timestamp, camelCase protojson) into reply.
func decodeListReply(operation string, body []byte, reply proto.Message) error {
	if err := listReplyJSON.Unmarshal(body, reply); err != nil {
		return &RESTAdapterError{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}
	return nil
}

// listWindow is the limit and offset a list reply's pagination describes:
// the page size, and the first item of the page it reports.
func listWindow(pagination *pb.PaginationResponse) (limit, offset int32) {
	limit = int32(pagination.GetPageSize())
	if pagination.GetPage() > 1 {
		offset = int32(pagination.GetPage()-1) * limit
	}
	return limit, offset
}

// RESTAdapterError represents an error from the REST adapter
type RESTAdapterError struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e *RESTAdapterError) Error() string {
	return fmt.Sprintf("REST adapter error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// RESTAdapter implements IAMCommands using REST API
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		endpoint: GetRESTEndpoint(),
		client:   helpers.NewAdminHTTPClient(0),
	}
}

// Setup prepares the adapter for testing
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   helpers.SetupProbeFailure(err),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request and returns the response body
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &RESTAdapterError{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// userResponse represents the REST API user response structure
type userResponse struct {
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

func (r *userResponse) toUser() *User {
	return &User{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Email:       r.Email,
		Name:        r.Name,
		Roles:       r.Roles,
		Groups:      r.Groups,
		Attributes:  r.Attributes,
		MFAVerified: r.MFAVerified,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		LastAuth:    r.LastAuth,
	}
}

// groupResponse represents the REST API group response structure
type groupResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Members     []string   `json:"members,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func (r *groupResponse) toGroup() *Group {
	return &Group{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		Members:     r.Members,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// roleResponse represents the REST API role response structure
type roleResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func (r *roleResponse) toRole() *Role {
	return &Role{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// successResponse represents a generic success response
type successResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ============================================================================
// User CRUD Operations
// ============================================================================

// createUserRequest represents the request body for creating a user
type createUserRequest struct {
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// CreateUser creates a new user
func (a *RESTAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users", opts.TenantID)

	reqBody := createUserRequest{
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateUser",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateUserResult{User: resp.toUser()}, nil
}

// GetUser retrieves a user by ID
func (a *RESTAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users/%s", opts.TenantID, opts.UserID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetUser",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetUserResult{User: resp.toUser()}, nil
}

// updateUserRequest represents the request body for updating a user
type updateUserRequest struct {
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpdateUser updates an existing user
func (a *RESTAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users/%s", opts.TenantID, opts.UserID)

	reqBody := updateUserRequest{
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	}

	body, err := a.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateUser",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateUserResult{User: resp.toUser()}, nil
}

// DeleteUser removes a user
func (a *RESTAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users/%s", opts.TenantID, opts.UserID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "DeleteUser",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &DeleteUserResult{Success: resp.Success}, nil
}

// ListUsers lists all users with optional filtering
func (a *RESTAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users", opts.TenantID)

	params := ""
	if opts.Email != "" {
		params += fmt.Sprintf("&email=%s", opts.Email)
	}
	if opts.Role != "" {
		params += fmt.Sprintf("&role=%s", opts.Role)
	}
	if opts.Group != "" {
		params += fmt.Sprintf("&group=%s", opts.Group)
	}
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:]
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pb.ListIAMUsersResponse
	if err := decodeListReply("ListUsers", body, &resp); err != nil {
		return nil, err
	}

	limit, offset := listWindow(resp.GetPagination())
	result := &ListUsersResult{
		Users:  make([]*User, 0, len(resp.GetUsers())),
		Total:  resp.GetTotal(),
		Limit:  limit,
		Offset: offset,
	}
	for _, u := range resp.GetUsers() {
		result.Users = append(result.Users, protoToUser(u))
	}

	return result, nil
}

// ============================================================================
// User Role Operations
// ============================================================================

// AssignRole assigns a role to a user
func (a *RESTAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users/%s/roles/%s", opts.TenantID, opts.UserID, opts.RoleID)

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "AssignRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &AssignRoleResult{Success: resp.Success}, nil
}

// RevokeRole revokes a role from a user
func (a *RESTAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/users/%s/roles/%s", opts.TenantID, opts.UserID, opts.RoleID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "RevokeRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &RevokeRoleResult{Success: resp.Success}, nil
}

// ============================================================================
// Group CRUD Operations
// ============================================================================

// createGroupRequest represents the request body for creating a group
type createGroupRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// CreateGroup creates a new group
func (a *RESTAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups", opts.TenantID)

	reqBody := createGroupRequest{
		ID:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp groupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateGroup",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateGroupResult{Group: resp.toGroup()}, nil
}

// GetGroup retrieves a group by ID
func (a *RESTAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups/%s", opts.TenantID, opts.GroupID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp groupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetGroup",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetGroupResult{Group: resp.toGroup()}, nil
}

// updateGroupRequest represents the request body for updating a group
type updateGroupRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateGroup updates an existing group
func (a *RESTAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups/%s", opts.TenantID, opts.GroupID)

	reqBody := updateGroupRequest{
		Name:        opts.Name,
		Description: opts.Description,
	}

	body, err := a.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp groupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateGroup",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateGroupResult{Group: resp.toGroup()}, nil
}

// DeleteGroup removes a group
func (a *RESTAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups/%s", opts.TenantID, opts.GroupID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "DeleteGroup",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &DeleteGroupResult{Success: resp.Success}, nil
}

// ListGroups lists all groups with optional filtering
func (a *RESTAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups", opts.TenantID)

	params := ""
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:]
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pb.ListIAMGroupsResponse
	if err := decodeListReply("ListGroups", body, &resp); err != nil {
		return nil, err
	}

	limit, offset := listWindow(resp.GetPagination())
	result := &ListGroupsResult{
		Groups: make([]*Group, 0, len(resp.GetGroups())),
		Total:  resp.GetTotal(),
		Limit:  limit,
		Offset: offset,
	}
	for _, g := range resp.GetGroups() {
		result.Groups = append(result.Groups, protoToGroup(g))
	}

	return result, nil
}

// ============================================================================
// Group Membership Operations
// ============================================================================

// AddMember adds a user to a group
func (a *RESTAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups/%s/members/%s", opts.TenantID, opts.GroupID, opts.UserID)

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "AddMember",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &AddMemberResult{Success: resp.Success}, nil
}

// RemoveMember removes a user from a group
func (a *RESTAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/groups/%s/members/%s", opts.TenantID, opts.GroupID, opts.UserID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "RemoveMember",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &RemoveMemberResult{Success: resp.Success}, nil
}

// ============================================================================
// Role CRUD Operations
// ============================================================================

// createRoleRequest represents the request body for creating a role
type createRoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// CreateRole creates a new role
func (a *RESTAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/roles", opts.TenantID)

	reqBody := createRoleRequest{
		ID:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp roleResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateRoleResult{Role: resp.toRole()}, nil
}

// GetRole retrieves a role by ID
func (a *RESTAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/roles/%s", opts.TenantID, opts.RoleID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp roleResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetRoleResult{Role: resp.toRole()}, nil
}

// updateRoleRequest represents the request body for updating a role
type updateRoleRequest struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateRole updates an existing role
func (a *RESTAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/roles/%s", opts.TenantID, opts.RoleID)

	reqBody := updateRoleRequest{
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	body, err := a.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp roleResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateRoleResult{Role: resp.toRole()}, nil
}

// DeleteRole removes a role
func (a *RESTAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/roles/%s", opts.TenantID, opts.RoleID)

	body, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp successResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "DeleteRole",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &DeleteRoleResult{Success: resp.Success}, nil
}

// ListRoles lists all roles with optional filtering
func (a *RESTAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/roles", opts.TenantID)

	params := ""
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:]
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pb.ListIAMRolesResponse
	if err := decodeListReply("ListRoles", body, &resp); err != nil {
		return nil, err
	}

	limit, offset := listWindow(resp.GetPagination())
	result := &ListRolesResult{
		Roles:  make([]*Role, 0, len(resp.GetRoles())),
		Total:  resp.GetTotal(),
		Limit:  limit,
		Offset: offset,
	}
	for _, r := range resp.GetRoles() {
		result.Roles = append(result.Roles, protoToRole(r))
	}

	return result, nil
}

// ============================================================================
// Permission Operations
// ============================================================================

// checkPermissionRequest represents the request body for checking a permission
type checkPermissionRequest struct {
	SubjectID  string            `json:"subject_id"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Context    map[string]string `json:"context,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// checkPermissionResponse represents the response for checking a permission
type checkPermissionResponse struct {
	Allowed          bool   `json:"allowed"`
	MatchedPolicy    string `json:"matched_policy,omitempty"`
	MatchedRule      string `json:"matched_rule,omitempty"`
	EvaluationTimeNs int64  `json:"evaluation_time_ns,omitempty"`
}

// CheckPermission checks if a subject has permission for an action on a resource
func (a *RESTAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	path := fmt.Sprintf("/api/v1/iam/tenants/%s/policies/test", opts.TenantID)

	reqBody := checkPermissionRequest{
		SubjectID:  opts.SubjectID,
		Action:     opts.Action,
		Resource:   opts.Resource,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Context:    opts.Context,
		Attributes: opts.Attributes,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp checkPermissionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CheckPermission",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CheckPermissionResult{
		Allowed:          resp.Allowed,
		MatchedPolicy:    resp.MatchedPolicy,
		MatchedRule:      resp.MatchedRule,
		EvaluationTimeNs: resp.EvaluationTimeNs,
	}, nil
}

// Verify RESTAdapter implements IAMCommands
var _ IAMCommands = (*RESTAdapter)(nil)
