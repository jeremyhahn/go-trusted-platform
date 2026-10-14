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

// This file implements IAM (Identity and Access Management) operations for the
// QUIC protocol transport layer. QUIC provides low-latency, multiplexed streams
// with built-in TLS 1.3, making it ideal for mobile and high-performance clients.
//
// # Wire contract
//
// The canonical QUIC wire contract for the IAM surface is the platform.v1
// protobuf request/response messages themselves. The SDK QUIC transport maps
// each /platform.v1.PlatformIAMService/* RPC onto an OpIAM* opcode and hands the
// generated pb request struct straight to the payload codec (keyed on exact Go
// field names); the daemon decodes into the same pb message type and delegates
// to the shared *IAMGRPCService, giving the QUIC transport identical semantics
// to gRPC. Before this convergence the daemon decoded flat local structs whose
// Go field names diverged from the pb Go field names (TenantID vs TenantId,
// UserID vs UserId) and which lacked fields entirely (CreateIAMUserRequest.Roles
// / Groups), silently dropping them on the wire. Those flat structs are gone.
//
// # Supported Operations
//
// User / Role management and CheckPermission delegate to the shared
// *IAMGRPCService (pb wire).
//
// Authentication (OpIAMAuthenticate) remains daemon-native on the QUICIAMService
// Authenticate seam because it is not part of the PlatformIAMService gRPC
// surface.
//
// Token operations (OpIAMTokenCreate/Revoke/Verify) return StatusNotImplemented
// for parity with the gRPC delegate, which returns codes.Unimplemented: token
// issuance/verification is handled via OIDC flows in go-quicbaas, not the IAM
// service.

package daemon

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// QUICIAMService defines the daemon-native IAM seam reached over QUIC. Only
// Authenticate remains here: every other IAM operation is part of the
// PlatformIAMService gRPC surface and is served through the shared
// *IAMGRPCService delegate. Authenticate is retained because it is not exposed
// by that gRPC surface.
type QUICIAMService interface {
	// Authenticate validates user credentials and returns authentication tokens.
	// Supports username/password, and optionally TOTP or certificate-based
	// authentication.
	Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error)
}

// =============================================================================
// IAM Authentication Request/Response Types (daemon-native)
// =============================================================================

// AuthenticateRequest contains the parameters for user authentication.
// Used to validate user credentials and obtain authentication tokens.
//
// Fields:
//   - TenantID: Optional. The tenant context for authentication.
//   - Username: Required. The username or email to authenticate.
//   - Password: Required. The user's password.
//   - TOTPCode: Optional. Time-based one-time password for MFA.
//   - Certificate: Optional. Client certificate for certificate-based auth.
type AuthenticateRequest struct {
	TenantID    string `codec:"tenant_id"`
	Username    string `codec:"username"`
	Password    string `codec:"password" secret:"true"`
	TOTPCode    string `codec:"totp_code"`
	Certificate string `codec:"certificate"`
}

// AuthenticateResponse contains the result of a successful authentication.
// Includes access and refresh tokens for subsequent API calls.
//
// Fields:
//   - UserID: The authenticated user's unique identifier.
//   - TenantID: The tenant the user belongs to.
//   - AccessToken: JWT or opaque token for API authorization.
//   - RefreshToken: Token for obtaining new access tokens.
//   - ExpiresIn: Seconds until the access token expires.
//   - TokenType: The token type, typically "Bearer".
//   - Timestamp: Unix timestamp of this response.
type AuthenticateResponse struct {
	UserID       string `codec:"user_id"`
	TenantID     string `codec:"tenant_id"`
	AccessToken  string `codec:"access_token" secret:"true"`
	RefreshToken string `codec:"refresh_token" secret:"true"`
	ExpiresIn    int64  `codec:"expires_in"`
	TokenType    string `codec:"token_type"`
	Timestamp    int64  `codec:"timestamp"`
}

// ErrIAMTokenViaOIDC is returned for the IAM token opcodes, which are
// wire-mapped but delegate to OIDC flows rather than the IAM service. It mirrors
// the gRPC delegate's codes.Unimplemented for these operations.
type ErrIAMTokenViaOIDC struct {
	Op string
}

func (e ErrIAMTokenViaOIDC) Error() string {
	return "iam token " + e.Op + " is handled via OIDC flows, not the IAM service"
}

// =============================================================================
// QUIC Handler Methods
// =============================================================================

// handleIAMOperation routes IAM-related QUIC requests to the appropriate
// handler. Authentication is served daemon-native; token operations return
// StatusNotImplemented for OIDC parity; every other operation delegates to the
// shared *IAMGRPCService (pb wire).
func (h *QUICServiceHandler) handleIAMOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	switch req.Opcode {
	// Authentication is not part of the PlatformIAMService gRPC surface.
	case quicwire.OpIAMAuthenticate:
		return h.handleIAMAuthenticate(ctx, req)

	// Token issue and revocation are handled via OIDC flows; the gRPC delegate
	// returns codes.Unimplemented, so QUIC returns StatusNotImplemented for
	// parity whether or not the delegate is wired.
	case quicwire.OpIAMTokenCreate:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrIAMTokenViaOIDC{Op: iamTokenOpCreate})
	case quicwire.OpIAMTokenRevoke:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrIAMTokenViaOIDC{Op: iamTokenOpRevoke})
	}

	// All remaining operations delegate to the shared pb gRPC service.
	if h.iamGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "iam"})
	}

	switch req.Opcode {
	// User operations
	case quicwire.OpIAMUserCreate:
		return h.handleIAMUserCreate(ctx, req)
	case quicwire.OpIAMUserDelete:
		return h.handleIAMUserDelete(ctx, req)
	case quicwire.OpIAMUserGet:
		return h.handleIAMUserGet(ctx, req)
	case quicwire.OpIAMUserList:
		return h.handleIAMUserList(ctx, req)
	case quicwire.OpIAMUserUpdate:
		return h.handleIAMUserUpdate(ctx, req)

	// Role operations
	case quicwire.OpIAMRoleCreate:
		return h.handleIAMRoleCreate(ctx, req)
	case quicwire.OpIAMRoleDelete:
		return h.handleIAMRoleDelete(ctx, req)
	case quicwire.OpIAMRoleGet:
		return h.handleIAMRoleGet(ctx, req)
	case quicwire.OpIAMRoleList:
		return h.handleIAMRoleList(ctx, req)
	case quicwire.OpIAMRoleAssign:
		return h.handleIAMRoleAssign(ctx, req)
	case quicwire.OpIAMRoleRevoke:
		return h.handleIAMRoleRevoke(ctx, req)

	// Permission operations
	case quicwire.OpIAMCheckPermission:
		return h.handleIAMCheckPermission(ctx, req)

	// Token operations
	case quicwire.OpIAMTokenVerify:
		return h.handleIAMTokenVerify(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// User Operation Handlers
// =============================================================================

// handleIAMUserCreate creates a new IAM user. The pb request carries Roles and
// TenantId that the former flat struct dropped.
func (h *QUICServiceHandler) handleIAMUserCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.CreateIAMUserRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.CreateUser(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMUserCreate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMUserDelete deletes an IAM user.
func (h *QUICServiceHandler) handleIAMUserDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.DeleteIAMUserRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.DeleteUser(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMUserDelete", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMUserGet retrieves an IAM user by ID.
func (h *QUICServiceHandler) handleIAMUserGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.GetIAMUserRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.GetUser(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMUserGet", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMUserList returns a paginated list of IAM users. The list payload is
// optional.
func (h *QUICServiceHandler) handleIAMUserList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.ListIAMUsersRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.iamGRPC.ListUsers(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMUserList", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMUserUpdate updates an existing IAM user.
func (h *QUICServiceHandler) handleIAMUserUpdate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.UpdateIAMUserRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.UpdateUser(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMUserUpdate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// =============================================================================
// Role Operation Handlers
// =============================================================================

// handleIAMRoleCreate creates a new IAM role.
func (h *QUICServiceHandler) handleIAMRoleCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.CreateIAMRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.CreateRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleCreate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleDelete deletes an IAM role.
func (h *QUICServiceHandler) handleIAMRoleDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.DeleteIAMRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.DeleteRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleDelete", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleGet retrieves an IAM role by ID.
func (h *QUICServiceHandler) handleIAMRoleGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.GetIAMRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.GetRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleGet", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleList returns a paginated list of IAM roles. The list payload is
// optional.
func (h *QUICServiceHandler) handleIAMRoleList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.ListIAMRolesRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.iamGRPC.ListRoles(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleList", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleAssign assigns a role to a user.
func (h *QUICServiceHandler) handleIAMRoleAssign(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.AssignIAMRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.AssignRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleAssign", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleRevoke revokes a role from a user.
func (h *QUICServiceHandler) handleIAMRoleRevoke(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.RevokeIAMRoleRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.RevokeRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleRevoke", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// =============================================================================
// Permission Operation Handlers
// =============================================================================

// handleIAMCheckPermission evaluates an authorization request.
func (h *QUICServiceHandler) handleIAMCheckPermission(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.CheckIAMPermissionRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.CheckPermission(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMCheckPermission", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMTokenVerify delegates to IAMGRPCService.VerifyToken, so QUIC
// answers a token exactly as gRPC does.
func (h *QUICServiceHandler) handleIAMTokenVerify(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pbReq platformv1.VerifyIAMTokenRequest
	if err := quicwire.DecodePayload(req.Payload, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.VerifyToken(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTokenVerify", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// =============================================================================
// Authentication Operation Handlers (daemon-native)
// =============================================================================

// handleIAMAuthenticate authenticates a user with their credentials. This
// operation is not part of the PlatformIAMService gRPC surface, so it is served
// through the daemon-native QUICIAMService seam.
func (h *QUICServiceHandler) handleIAMAuthenticate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.iamService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "iam"})
	}

	var authReq AuthenticateRequest
	if err := quicwire.DecodePayload(req.Payload, &authReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if authReq.Username == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "username"})
	}
	if authReq.Password == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "password"})
	}

	result, err := h.iamService.Authenticate(ctx, &authReq)
	if err != nil {
		h.logger.Error(err, "failed to authenticate user", "username", authReq.Username)
		return h.errorResponse(quicwire.StatusUnauthorized, ErrQUICOperationFailed{Op: "IAMAuthenticate", Cause: err})
	}

	payload, err := quicwire.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}
