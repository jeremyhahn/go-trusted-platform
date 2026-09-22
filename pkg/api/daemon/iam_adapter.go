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

// iam_adapter.go provides in-process adapters for IAM gRPC services.
//
// These adapters implement the gRPC client interfaces (IAMServiceClient,
// PEPServiceClient) by delegating directly to the corresponding server
// implementations. This enables local, in-process communication without
// the overhead of actual gRPC transport.
//
// Use these adapters when the IAM service runs in the same process as the
// REST API layer, avoiding unnecessary network round-trips while maintaining
// the same interface contracts.

package daemon

import (
	"context"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"google.golang.org/grpc"
)

// IAMServiceClientAdapter implements iampb.IAMServiceClient by delegating
// to an iampb.IAMServiceServer implementation in-process.
//
// This adapter enables REST handlers to use the same IAMServiceClient interface
// they would use with a remote gRPC client, but without network overhead.
// The gRPC CallOptions are ignored since there's no actual gRPC transport.
type IAMServiceClientAdapter struct {
	server iampb.IAMServiceServer
}

// NewIAMServiceClientAdapter creates a new in-process IAM service client adapter.
//
// Parameters:
//   - server: The IAMServiceServer implementation to delegate calls to
//
// Returns:
//
//	An iampb.IAMServiceClient that delegates to the provided server
func NewIAMServiceClientAdapter(server iampb.IAMServiceServer) iampb.IAMServiceClient {
	return &IAMServiceClientAdapter{server: server}
}

// =============================================================================
// Tenant Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreateTenant(ctx context.Context, in *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	return a.server.CreateTenant(ctx, in)
}

func (a *IAMServiceClientAdapter) GetTenant(ctx context.Context, in *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	return a.server.GetTenant(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateTenant(ctx context.Context, in *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	return a.server.UpdateTenant(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteTenant(ctx context.Context, in *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
	return a.server.DeleteTenant(ctx, in)
}

func (a *IAMServiceClientAdapter) ListTenants(ctx context.Context, in *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
	return a.server.ListTenants(ctx, in)
}

// =============================================================================
// User Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreateUser(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	return a.server.CreateUser(ctx, in)
}

func (a *IAMServiceClientAdapter) GetUser(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	return a.server.GetUser(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateUser(ctx context.Context, in *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	return a.server.UpdateUser(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteUser(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
	return a.server.DeleteUser(ctx, in)
}

func (a *IAMServiceClientAdapter) ListUsers(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
	return a.server.ListUsers(ctx, in)
}

// =============================================================================
// Group Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreateGroup(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	return a.server.CreateGroup(ctx, in)
}

func (a *IAMServiceClientAdapter) GetGroup(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	return a.server.GetGroup(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateGroup(ctx context.Context, in *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	return a.server.UpdateGroup(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteGroup(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
	return a.server.DeleteGroup(ctx, in)
}

func (a *IAMServiceClientAdapter) ListGroups(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
	return a.server.ListGroups(ctx, in)
}

func (a *IAMServiceClientAdapter) AddUserToGroup(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
	return a.server.AddUserToGroup(ctx, in)
}

func (a *IAMServiceClientAdapter) RemoveUserFromGroup(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
	return a.server.RemoveUserFromGroup(ctx, in)
}

// =============================================================================
// Role Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreateRole(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	return a.server.CreateRole(ctx, in)
}

func (a *IAMServiceClientAdapter) GetRole(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	return a.server.GetRole(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateRole(ctx context.Context, in *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	return a.server.UpdateRole(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteRole(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
	return a.server.DeleteRole(ctx, in)
}

func (a *IAMServiceClientAdapter) ListRoles(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
	return a.server.ListRoles(ctx, in)
}

func (a *IAMServiceClientAdapter) AssignRole(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
	return a.server.AssignRole(ctx, in)
}

func (a *IAMServiceClientAdapter) RevokeRole(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
	return a.server.RevokeRole(ctx, in)
}

// =============================================================================
// Application (OAuth Client) Operations
// =============================================================================

func (a *IAMServiceClientAdapter) RegisterApp(ctx context.Context, in *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	return a.server.RegisterApp(ctx, in)
}

func (a *IAMServiceClientAdapter) GetApp(ctx context.Context, in *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	return a.server.GetApp(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateApp(ctx context.Context, in *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	return a.server.UpdateApp(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteApp(ctx context.Context, in *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
	return a.server.DeleteApp(ctx, in)
}

func (a *IAMServiceClientAdapter) ListApps(ctx context.Context, in *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
	return a.server.ListApps(ctx, in)
}

func (a *IAMServiceClientAdapter) RotateAppSecret(ctx context.Context, in *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	return a.server.RotateAppSecret(ctx, in)
}

// =============================================================================
// Policy Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreatePolicy(ctx context.Context, in *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	return a.server.CreatePolicy(ctx, in)
}

func (a *IAMServiceClientAdapter) GetPolicy(ctx context.Context, in *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	return a.server.GetPolicy(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdatePolicy(ctx context.Context, in *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	return a.server.UpdatePolicy(ctx, in)
}

func (a *IAMServiceClientAdapter) DeletePolicy(ctx context.Context, in *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
	return a.server.DeletePolicy(ctx, in)
}

func (a *IAMServiceClientAdapter) ListPolicies(ctx context.Context, in *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
	return a.server.ListPolicies(ctx, in)
}

func (a *IAMServiceClientAdapter) ValidatePolicy(ctx context.Context, in *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
	return a.server.ValidatePolicy(ctx, in)
}

func (a *IAMServiceClientAdapter) TestPolicy(ctx context.Context, in *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
	return a.server.TestPolicy(ctx, in)
}

// =============================================================================
// Delegated Administration Operations
// =============================================================================

func (a *IAMServiceClientAdapter) CreateAdminAssignment(ctx context.Context, in *iampb.CreateAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return a.server.CreateAdminAssignment(ctx, in)
}

func (a *IAMServiceClientAdapter) GetAdminAssignment(ctx context.Context, in *iampb.GetAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return a.server.GetAdminAssignment(ctx, in)
}

func (a *IAMServiceClientAdapter) UpdateAdminAssignment(ctx context.Context, in *iampb.UpdateAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return a.server.UpdateAdminAssignment(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteAdminAssignment(ctx context.Context, in *iampb.DeleteAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.DeleteAdminAssignmentResponse, error) {
	return a.server.DeleteAdminAssignment(ctx, in)
}

func (a *IAMServiceClientAdapter) ListAdminAssignments(ctx context.Context, in *iampb.ListAdminAssignmentsRequest, opts ...grpc.CallOption) (*iampb.AdminAssignmentList, error) {
	return a.server.ListAdminAssignments(ctx, in)
}

func (a *IAMServiceClientAdapter) CheckAdminPermission(ctx context.Context, in *iampb.CheckAdminPermissionRequest, opts ...grpc.CallOption) (*iampb.CheckAdminPermissionResponse, error) {
	return a.server.CheckAdminPermission(ctx, in)
}

func (a *IAMServiceClientAdapter) StartImpersonation(ctx context.Context, in *iampb.StartImpersonationRequest, opts ...grpc.CallOption) (*iampb.ImpersonationSession, error) {
	return a.server.StartImpersonation(ctx, in)
}

func (a *IAMServiceClientAdapter) EndImpersonation(ctx context.Context, in *iampb.EndImpersonationRequest, opts ...grpc.CallOption) (*iampb.EndImpersonationResponse, error) {
	return a.server.EndImpersonation(ctx, in)
}

func (a *IAMServiceClientAdapter) GetActiveImpersonations(ctx context.Context, in *iampb.GetActiveImpersonationsRequest, opts ...grpc.CallOption) (*iampb.ImpersonationSessionList, error) {
	return a.server.GetActiveImpersonations(ctx, in)
}

// =============================================================================
// GDPR Consent Management Operations
// =============================================================================

func (a *IAMServiceClientAdapter) GrantConsent(ctx context.Context, in *iampb.GrantConsentRequest, opts ...grpc.CallOption) (*iampb.Consent, error) {
	return a.server.GrantConsent(ctx, in)
}

func (a *IAMServiceClientAdapter) WithdrawConsent(ctx context.Context, in *iampb.WithdrawConsentRequest, opts ...grpc.CallOption) (*iampb.WithdrawConsentResponse, error) {
	return a.server.WithdrawConsent(ctx, in)
}

func (a *IAMServiceClientAdapter) GetConsent(ctx context.Context, in *iampb.GetConsentRequest, opts ...grpc.CallOption) (*iampb.Consent, error) {
	return a.server.GetConsent(ctx, in)
}

func (a *IAMServiceClientAdapter) ListUserConsents(ctx context.Context, in *iampb.ListUserConsentsRequest, opts ...grpc.CallOption) (*iampb.ConsentList, error) {
	return a.server.ListUserConsents(ctx, in)
}

// =============================================================================
// GDPR Data Export Operations
// =============================================================================

func (a *IAMServiceClientAdapter) RequestExport(ctx context.Context, in *iampb.RequestExportRequest, opts ...grpc.CallOption) (*iampb.DataExportRequest, error) {
	return a.server.RequestExport(ctx, in)
}

func (a *IAMServiceClientAdapter) GetExportStatus(ctx context.Context, in *iampb.GetExportStatusRequest, opts ...grpc.CallOption) (*iampb.DataExportRequest, error) {
	return a.server.GetExportStatus(ctx, in)
}

func (a *IAMServiceClientAdapter) GenerateExport(ctx context.Context, in *iampb.GenerateExportRequest, opts ...grpc.CallOption) (*iampb.UserDataExport, error) {
	return a.server.GenerateExport(ctx, in)
}

// =============================================================================
// GDPR Data Deletion Operations
// =============================================================================

func (a *IAMServiceClientAdapter) RequestDeletion(ctx context.Context, in *iampb.RequestDeletionRequest, opts ...grpc.CallOption) (*iampb.DataDeletionRequest, error) {
	return a.server.RequestDeletion(ctx, in)
}

func (a *IAMServiceClientAdapter) CancelDeletion(ctx context.Context, in *iampb.CancelDeletionRequest, opts ...grpc.CallOption) (*iampb.CancelDeletionResponse, error) {
	return a.server.CancelDeletion(ctx, in)
}

func (a *IAMServiceClientAdapter) ProcessDeletion(ctx context.Context, in *iampb.ProcessDeletionRequest, opts ...grpc.CallOption) (*iampb.DeletionSummary, error) {
	return a.server.ProcessDeletion(ctx, in)
}

func (a *IAMServiceClientAdapter) GetDeletionStatus(ctx context.Context, in *iampb.GetDeletionStatusRequest, opts ...grpc.CallOption) (*iampb.DataDeletionRequest, error) {
	return a.server.GetDeletionStatus(ctx, in)
}

// =============================================================================
// PEP Service Client Adapter (Server-based)
// =============================================================================

// PEPServiceClientAdapter implements iampb.PEPServiceClient by delegating
// to an iampb.PEPServiceServer implementation in-process.
//
// This adapter enables REST handlers to use the same PEPServiceClient interface
// they would use with a remote gRPC client, but without network overhead.
// The gRPC CallOptions are ignored since there's no actual gRPC transport.
type PEPServiceClientAdapter struct {
	server iampb.PEPServiceServer
}

// NewPEPServiceClientAdapter creates a new in-process PEP service client adapter.
//
// Parameters:
//   - server: The PEPServiceServer implementation to delegate calls to
//
// Returns:
//
//	An iampb.PEPServiceClient that delegates to the provided server
func NewPEPServiceClientAdapter(server iampb.PEPServiceServer) iampb.PEPServiceClient {
	return &PEPServiceClientAdapter{server: server}
}

func (a *PEPServiceClientAdapter) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
	return a.server.Check(ctx, in)
}

func (a *PEPServiceClientAdapter) CheckBatch(ctx context.Context, in *iampb.CheckBatchRequest, opts ...grpc.CallOption) (*iampb.CheckBatchResponse, error) {
	return a.server.CheckBatch(ctx, in)
}

// Subscribe is a streaming RPC that cannot be easily adapted in-process.
// For the REST API layer, this method is not used. If needed, implement
// a custom solution using channels.
func (a *PEPServiceClientAdapter) Subscribe(ctx context.Context, in *iampb.SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[iampb.PolicyUpdate], error) {
	// Streaming RPCs are not supported by the in-process adapter.
	// The REST API layer does not use this method.
	return nil, ErrStreamingNotSupported{}
}

// ErrStreamingNotSupported is returned when a streaming RPC is called
// on an in-process adapter that doesn't support it.
type ErrStreamingNotSupported struct{}

func (e ErrStreamingNotSupported) Error() string {
	return "streaming RPCs are not supported by in-process adapters"
}

// =============================================================================
// SDK PEP Client Adapter
// =============================================================================

// SDKPEPClientAdapter implements iampb.PEPServiceClient by delegating
// to the QuicBaaS SDK's IAMPEPClient (iam.PEPClient) implementation.
//
// This adapter converts between the SDK types and the protobuf types,
// enabling in-process authorization checks using the SDK client without
// requiring a gRPC server.
//
// Use this adapter when you have the SDK PEP client (from IAMService.PEP())
// and need to provide an iampb.PEPServiceClient interface.
type SDKPEPClientAdapter struct {
	client quicbaassdk.IAMPEPClient
}

// NewSDKPEPClientAdapter creates a new adapter that wraps the SDK PEP client.
//
// Parameters:
//   - client: The QuicBaaS SDK's IAMPEPClient implementation
//
// Returns:
//
//	An iampb.PEPServiceClient that delegates to the SDK client, or nil if client is nil
func NewSDKPEPClientAdapter(client quicbaassdk.IAMPEPClient) iampb.PEPServiceClient {
	if client == nil {
		return nil
	}
	return &SDKPEPClientAdapter{client: client}
}

// Check performs a single authorization check by converting the protobuf request
// to SDK format, calling the SDK client, and converting the response back.
func (a *SDKPEPClientAdapter) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
	if a.client == nil {
		return nil, ErrPEPClientNotAvailable{}
	}

	// Convert protobuf request to SDK request
	sdkReq := convertProtoCheckRequestToSDK(in)

	// Call the SDK client
	sdkResp, err := a.client.Check(ctx, sdkReq)
	if err != nil {
		return nil, err
	}

	// Convert SDK response to protobuf response
	return convertSDKCheckResponseToProto(sdkResp), nil
}

// CheckBatch performs multiple authorization checks. The SDK's CheckBatchRequest
// has a different structure (list of individual requests) compared to the protobuf
// version (single subject, single action, multiple resources).
func (a *SDKPEPClientAdapter) CheckBatch(ctx context.Context, in *iampb.CheckBatchRequest, opts ...grpc.CallOption) (*iampb.CheckBatchResponse, error) {
	if a.client == nil {
		return nil, ErrPEPClientNotAvailable{}
	}

	// Convert protobuf request to SDK request
	// The protobuf CheckBatchRequest has subject, action, and multiple resources
	// We need to create individual check requests for each resource
	sdkReq := convertProtoCheckBatchRequestToSDK(in)

	// Call the SDK client
	sdkResp, err := a.client.CheckBatch(ctx, sdkReq)
	if err != nil {
		return nil, err
	}

	// Convert SDK response to protobuf response
	return convertSDKCheckBatchResponseToProto(sdkResp), nil
}

// Subscribe is a streaming RPC that is not supported by the SDK adapter.
func (a *SDKPEPClientAdapter) Subscribe(ctx context.Context, in *iampb.SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[iampb.PolicyUpdate], error) {
	return nil, ErrStreamingNotSupported{}
}

// ErrPEPClientNotAvailable is returned when the PEP client is nil.
type ErrPEPClientNotAvailable struct{}

func (e ErrPEPClientNotAvailable) Error() string {
	return "PEP client is not available"
}

// =============================================================================
// Type Conversion Functions
// =============================================================================

// convertProtoCheckRequestToSDK converts a protobuf CheckRequest to SDK CheckRequest.
func convertProtoCheckRequestToSDK(in *iampb.CheckRequest) *sdkiam.CheckRequest {
	if in == nil {
		return nil
	}

	// Convert subject
	subject := sdkiam.CheckSubject{}
	if in.Subject != nil {
		subject.ID = in.Subject.Id
		subject.TenantID = in.Subject.TenantId
		subject.Roles = in.Subject.Roles
		subject.Groups = in.Subject.Groups
		// Convert attributes from map[string]string to map[string]interface{}
		if in.Subject.Attributes != nil {
			subject.Attributes = make(map[string]interface{}, len(in.Subject.Attributes))
			for k, v := range in.Subject.Attributes {
				subject.Attributes[k] = v
			}
		}
	}

	// Convert context from map[string]string to map[string]interface{}
	var reqContext map[string]interface{}
	if in.Context != nil {
		reqContext = make(map[string]interface{}, len(in.Context))
		for k, v := range in.Context {
			reqContext[k] = v
		}
	}

	return &sdkiam.CheckRequest{
		Subject:  subject,
		Action:   in.Action,
		Resource: in.Resource,
		Context:  reqContext,
	}
}

// convertSDKCheckResponseToProto converts an SDK CheckResponse to protobuf CheckResponse.
func convertSDKCheckResponseToProto(in *sdkiam.CheckResponse) *iampb.CheckResponse {
	if in == nil {
		return nil
	}

	return &iampb.CheckResponse{
		Allowed:          in.Allowed,
		MatchedPolicy:    in.MatchedPolicy,
		MatchedRule:      in.MatchedRule,
		EvaluationTimeNs: in.EvaluationTimeNs,
	}
}

// convertProtoCheckBatchRequestToSDK converts a protobuf CheckBatchRequest to SDK CheckBatchRequest.
// The protobuf version has a single subject/action with multiple resources,
// while the SDK version has a list of individual requests.
func convertProtoCheckBatchRequestToSDK(in *iampb.CheckBatchRequest) *sdkiam.CheckBatchRequest {
	if in == nil {
		return nil
	}

	// Convert subject
	subject := sdkiam.CheckSubject{}
	if in.Subject != nil {
		subject.ID = in.Subject.Id
		subject.TenantID = in.Subject.TenantId
		subject.Roles = in.Subject.Roles
		subject.Groups = in.Subject.Groups
		if in.Subject.Attributes != nil {
			subject.Attributes = make(map[string]interface{}, len(in.Subject.Attributes))
			for k, v := range in.Subject.Attributes {
				subject.Attributes[k] = v
			}
		}
	}

	// Convert context from map[string]string to map[string]interface{}
	var reqContext map[string]interface{}
	if in.Context != nil {
		reqContext = make(map[string]interface{}, len(in.Context))
		for k, v := range in.Context {
			reqContext[k] = v
		}
	}

	// Create individual requests for each resource
	requests := make([]sdkiam.CheckRequest, len(in.Resources))
	for i, resource := range in.Resources {
		requests[i] = sdkiam.CheckRequest{
			Subject:  subject,
			Action:   in.Action,
			Resource: resource,
			Context:  reqContext,
		}
	}

	return &sdkiam.CheckBatchRequest{
		Requests: requests,
	}
}

// convertSDKCheckBatchResponseToProto converts an SDK CheckBatchResponse to protobuf CheckBatchResponse.
// The SDK version has detailed results per request, while the protobuf version
// only has a list of boolean results.
func convertSDKCheckBatchResponseToProto(in *sdkiam.CheckBatchResponse) *iampb.CheckBatchResponse {
	if in == nil {
		return nil
	}

	// Extract boolean results from the detailed SDK response
	results := make([]bool, len(in.Results))
	for i, result := range in.Results {
		results[i] = result.Allowed
	}

	return &iampb.CheckBatchResponse{
		Results:          results,
		EvaluationTimeNs: in.TotalEvaluationTimeNs,
	}
}

// WebAuthn credential administration. These delegate to the in-process
// server exactly as every other verb on this adapter does; the adapter's
// whole purpose is to let a REST handler hold an IAMServiceClient without a
// network hop. DeleteWebAuthnCredential arrived with go-quicbaas v0.8.0 —
// the interface gained it, so the adapter implements it rather than leaving
// a hole that would fail at the type assertion.
func (a *IAMServiceClientAdapter) ListWebAuthnCredentials(ctx context.Context, in *iampb.ListWebAuthnCredentialsRequest, opts ...grpc.CallOption) (*iampb.ListWebAuthnCredentialsResponse, error) {
	return a.server.ListWebAuthnCredentials(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteWebAuthnCredential(ctx context.Context, in *iampb.DeleteWebAuthnCredentialRequest, opts ...grpc.CallOption) (*iampb.DeleteWebAuthnCredentialResponse, error) {
	return a.server.DeleteWebAuthnCredential(ctx, in)
}

func (a *IAMServiceClientAdapter) DeleteWebAuthnCredentials(ctx context.Context, in *iampb.DeleteWebAuthnCredentialsRequest, opts ...grpc.CallOption) (*iampb.DeleteWebAuthnCredentialsResponse, error) {
	return a.server.DeleteWebAuthnCredentials(ctx, in)
}

func (a *IAMServiceClientAdapter) ReconcileRoles(ctx context.Context, in *iampb.ReconcileRolesRequest, opts ...grpc.CallOption) (*iampb.ReconcileRolesResponse, error) {
	return a.server.ReconcileRoles(ctx, in)
}
