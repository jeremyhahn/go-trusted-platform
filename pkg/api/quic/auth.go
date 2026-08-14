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
)

// =============================================================================
// Error Types
// =============================================================================

// ErrAuthValidatorNotConfigured is returned when no token validator is available.
type ErrAuthValidatorNotConfigured struct{}

func (e ErrAuthValidatorNotConfigured) Error() string {
	return "OIDC token validator not configured"
}

// ErrMissingToken is returned when no token is present in the request.
type ErrMissingToken struct{}

func (e ErrMissingToken) Error() string {
	return "missing authentication token"
}

// ErrTokenValidationFailed is returned when token validation fails.
type ErrTokenValidationFailed struct {
	Cause error
}

func (e ErrTokenValidationFailed) Error() string {
	if e.Cause != nil {
		return "token validation failed: " + e.Cause.Error()
	}
	return "token validation failed"
}

func (e ErrTokenValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrPermissionDenied is returned when the user lacks permission.
type ErrPermissionDenied struct {
	Resource string
	Action   string
}

func (e ErrPermissionDenied) Error() string {
	return "permission denied: " + e.Action + " on " + e.Resource
}

// =============================================================================
// Token Validator Interface
// =============================================================================

// TokenValidator validates authentication tokens.
// This interface allows for different token validation implementations
// (e.g., QuicBaaS OIDC provider, local JWT validation, etc.).
type TokenValidator interface {
	// ValidateToken validates a token and returns whether it's valid.
	ValidateToken(ctx context.Context, token string) (bool, error)
}

// AuthorizationChecker checks if an authenticated user has permission for an action.
type AuthorizationChecker interface {
	// CheckPermission checks if the subject has permission for the given resource and action.
	CheckPermission(ctx context.Context, subject, resource, action string) (bool, error)
}

// =============================================================================
// Token Context Key
// =============================================================================

// tokenContextKey is the context key for the validated token.
type tokenContextKey struct{}

// ContextWithToken adds a validated token to the context.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext extracts the validated token from the context.
func TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenContextKey{}).(string)
	return token, ok
}

// =============================================================================
// Auth Middleware
// =============================================================================

// AuthMiddleware provides authentication and authorization for QUIC handlers.
type AuthMiddleware struct {
	tokenValidator TokenValidator
	authzChecker   AuthorizationChecker
	skipOpcodes    map[byte]bool
	requireAuth    bool
}

// AuthMiddlewareOption configures the auth middleware.
type AuthMiddlewareOption func(*AuthMiddleware)

// WithQUICTokenValidator sets the token validator.
func WithQUICTokenValidator(v TokenValidator) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.tokenValidator = v
	}
}

// WithQUICAuthorizationChecker sets the authorization checker.
func WithQUICAuthorizationChecker(c AuthorizationChecker) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.authzChecker = c
	}
}

// WithQUICSkipOpcodes sets opcodes that don't require authentication.
func WithQUICSkipOpcodes(opcodes ...byte) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		for _, op := range opcodes {
			m.skipOpcodes[op] = true
		}
	}
}

// WithQUICRequireAuth sets whether authentication is required.
func WithQUICRequireAuth(require bool) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.requireAuth = require
	}
}

// NewAuthMiddleware creates a new auth middleware.
func NewAuthMiddleware(opts ...AuthMiddlewareOption) *AuthMiddleware {
	m := &AuthMiddleware{
		skipOpcodes: make(map[byte]bool),
		requireAuth: true, // Default to requiring auth
	}

	// Default: skip health check opcodes
	m.skipOpcodes[OpHealth] = true
	m.skipOpcodes[OpLiveness] = true
	m.skipOpcodes[OpReadiness] = true

	for _, opt := range opts {
		opt(m)
	}
	return m
}

// AuthenticateRequest validates the token in a request.
// Returns the validated token, or an error response if authentication fails.
func (m *AuthMiddleware) AuthenticateRequest(ctx context.Context, req *Request) (context.Context, *Response) {
	// Skip authentication for certain opcodes
	if m.skipOpcodes[req.Opcode] {
		return ctx, nil
	}

	// If no validator configured, handle based on requireAuth setting
	if m.tokenValidator == nil {
		if m.requireAuth {
			return ctx, &Response{
				Status:  StatusUnavailable,
				Payload: []byte(ErrAuthValidatorNotConfigured{}.Error()),
			}
		}
		return ctx, nil
	}

	// Check for token
	if req.Token == "" {
		return ctx, &Response{
			Status:  StatusUnauthorized,
			Payload: []byte(ErrMissingToken{}.Error()),
		}
	}

	// Prefer the platform-token (claims) path when the validator supports it:
	// validate the framed bearer token, project scp -> RBAC / tenant_id -> RLS,
	// and stash the AuthorizedContext for AuthorizeRequest and downstream
	// handlers. QUIC has no DPoP frame, so this is always a bearer validation.
	//
	// requiredPerm="" routes through the validator's scope-free path: the
	// opcode's required scope is only resolved later in AuthorizeRequest,
	// which enforces it against the stored AuthorizedContext. Online
	// liveness/revocation is still enforced here on every request. QUIC has
	// no DPoP frame, so the proof / htm / htu inputs are empty.
	if cv, ok := m.tokenValidator.(ClaimsTokenValidator); ok {
		authCtx, err := cv.AuthorizeToken(ctx, req.Token, "", "", "", "")
		if err != nil {
			return ctx, &Response{
				Status:  StatusUnauthorized,
				Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
			}
		}
		ctx = ContextWithAuthorizedContext(ctx, authCtx)
		return ContextWithToken(ctx, req.Token), nil
	}

	// Validate token (legacy bool-only path)
	valid, err := m.tokenValidator.ValidateToken(ctx, req.Token)
	if err != nil {
		return ctx, &Response{
			Status:  StatusUnauthorized,
			Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
		}
	}
	if !valid {
		return ctx, &Response{
			Status:  StatusUnauthorized,
			Payload: []byte("invalid token"),
		}
	}

	// Add validated token to context
	return ContextWithToken(ctx, req.Token), nil
}

// AuthorizeRequest checks if the authenticated user has permission for the operation.
// This should be called after AuthenticateRequest.
func (m *AuthMiddleware) AuthorizeRequest(ctx context.Context, req *Request, resource, action string) *Response {
	// Skip authorization for certain opcodes
	if m.skipOpcodes[req.Opcode] {
		return nil
	}

	// When the request was validated via the platform-token (claims) path, an
	// AuthorizedContext is present: enforce scp -> RBAC against it directly
	// (the resource/action pair projects to the "<svc>.<verb>" scope). This is
	// the canonical authorization path for broker-issued tokens.
	if authCtx, ok := AuthorizedContextFromContext(ctx); ok {
		scope := scopeForOperation(resource, action)
		if scope == "" {
			return nil
		}
		if err := authCtx.RequireScope(scope); err != nil {
			return &Response{
				Status:  StatusPermissionDenied,
				Payload: []byte(ErrPermissionDenied{Resource: resource, Action: action}.Error()),
			}
		}
		return nil
	}

	// If no authorization checker, allow (legacy path)
	if m.authzChecker == nil {
		return nil
	}

	// Get token from context
	token, ok := TokenFromContext(ctx)
	if !ok {
		return &Response{
			Status:  StatusUnauthorized,
			Payload: []byte("no authenticated session"),
		}
	}

	// Check permission
	allowed, err := m.authzChecker.CheckPermission(ctx, token, resource, action)
	if err != nil {
		return &Response{
			Status:  StatusInternalError,
			Payload: []byte("authorization check failed: " + err.Error()),
		}
	}
	if !allowed {
		return &Response{
			Status:  StatusPermissionDenied,
			Payload: []byte(ErrPermissionDenied{Resource: resource, Action: action}.Error()),
		}
	}

	return nil
}

// =============================================================================
// Opcode to Permission Mapping
// =============================================================================

// OpcodePermission maps an opcode to its required permission.
type OpcodePermission struct {
	Resource string
	Action   string
}

// DefaultOpcodePermissions returns the default permission mappings for QUIC opcodes.
// Returns nil for opcodes that don't require authorization (health checks, etc.).
func DefaultOpcodePermissions() map[byte]*OpcodePermission {
	return map[byte]*OpcodePermission{
		// Health - no permission required
		OpHealth:    nil,
		OpLiveness:  nil,
		OpReadiness: nil,

		// vTPM operations
		OpVTPMCreate:    {Resource: "vtpm", Action: "write"},
		OpVTPMDelete:    {Resource: "vtpm", Action: "delete"},
		OpVTPMStart:     {Resource: "vtpm", Action: "write"},
		OpVTPMStop:      {Resource: "vtpm", Action: "write"},
		OpVTPMGetState:  {Resource: "vtpm", Action: "read"},
		OpVTPMList:      {Resource: "vtpm", Action: "read"},
		OpVTPMGetEK:     {Resource: "vtpm", Action: "read"},
		OpVTPMGetAK:     {Resource: "vtpm", Action: "read"},
		OpVTPMCreateAK:  {Resource: "vtpm", Action: "write"},
		OpVTPMQuote:     {Resource: "vtpm", Action: "read"},
		OpVTPMExtendPCR: {Resource: "vtpm", Action: "write"},
		OpVTPMReadPCR:   {Resource: "vtpm", Action: "read"},
		OpVTPMSeal:      {Resource: "vtpm", Action: "write"},
		OpVTPMUnseal:    {Resource: "vtpm", Action: "read"},

		// DNS operations
		OpDNSAddRecord:    {Resource: "dns", Action: "write"},
		OpDNSDeleteRecord: {Resource: "dns", Action: "delete"},
		OpDNSUpdateRecord: {Resource: "dns", Action: "write"},
		OpDNSGetRecord:    {Resource: "dns", Action: "read"},
		OpDNSListRecords:  {Resource: "dns", Action: "read"},
		OpDNSAddZone:      {Resource: "dns", Action: "write"},
		OpDNSDeleteZone:   {Resource: "dns", Action: "delete"},
		OpDNSGetZone:      {Resource: "dns", Action: "read"},
		OpDNSListZones:    {Resource: "dns", Action: "read"},
		OpDNSResolve:      {Resource: "dns", Action: "read"},

		// Device operations
		OpDeviceRegister:   {Resource: "device", Action: "write"},
		OpDeviceUnregister: {Resource: "device", Action: "delete"},
		OpDeviceGet:        {Resource: "device", Action: "read"},
		OpDeviceList:       {Resource: "device", Action: "read"},
		OpDeviceUpdate:     {Resource: "device", Action: "write"},
		OpDeviceAttest:     {Resource: "device", Action: "read"},

		// SDN operations
		OpSDNGetPortState: {Resource: "sdn", Action: "read"},
		OpSDNSetPortState: {Resource: "sdn", Action: "write"},
		OpSDNListPorts:    {Resource: "sdn", Action: "read"},
		OpSDNApplyPolicy:  {Resource: "sdn", Action: "write"},
		OpSDNGetPolicy:    {Resource: "sdn", Action: "read"},
		OpSDNListPolicies: {Resource: "sdn", Action: "read"},
		OpSDNListBridges:  {Resource: "sdn", Action: "read"},
		OpSDNCreateBridge: {Resource: "sdn", Action: "write"},
		OpSDNDeleteBridge: {Resource: "sdn", Action: "delete"},
		OpSDNCreatePort:   {Resource: "sdn", Action: "write"},
		OpSDNDeletePort:   {Resource: "sdn", Action: "delete"},
		OpSDNDeletePolicy: {Resource: "sdn", Action: "delete"},

		// KMS operations
		OpKMSGenerateKey: {Resource: "kms", Action: "write"},
		OpKMSImportKey:   {Resource: "kms", Action: "write"},
		OpKMSGetKey:      {Resource: "kms", Action: "read"},
		OpKMSListKeys:    {Resource: "kms", Action: "read"},
		OpKMSDeleteKey:   {Resource: "kms", Action: "delete"},
		OpKMSRotateKey:   {Resource: "kms", Action: "write"},
		OpKMSEncrypt:     {Resource: "kms", Action: "write"},
		OpKMSDecrypt:     {Resource: "kms", Action: "read"},
		OpKMSSign:        {Resource: "kms", Action: "write"},
		OpKMSVerify:      {Resource: "kms", Action: "read"},

		// IAM operations
		OpIAMUserCreate: {Resource: "iam", Action: "write"},
		OpIAMUserDelete: {Resource: "iam", Action: "delete"},
		OpIAMUserGet:    {Resource: "iam", Action: "read"},
		OpIAMUserList:   {Resource: "iam", Action: "read"},
		OpIAMUserUpdate: {Resource: "iam", Action: "write"},
		OpIAMRoleCreate: {Resource: "iam", Action: "write"},
		OpIAMRoleDelete: {Resource: "iam", Action: "delete"},
		OpIAMRoleGet:    {Resource: "iam", Action: "read"},
		OpIAMRoleList:   {Resource: "iam", Action: "read"},

		// NTP (time synchronization). The category opcode multiplexes
		// read (status, sources) and write (step) sub-operations in
		// payload[0], which this opcode-level catalog cannot
		// distinguish, so it records the floor scope every NTP caller
		// needs. Per-operation scope enforcement lives in the gRPC
		// method catalog (pkg/api/grpc/method_permissions.go) and the
		// MCP tool catalog, which is where ntp:write is required for
		// the manual step.
		OpNTPCategory: {Resource: "ntp", Action: "read"},

		// CA operations
		OpCAInfo:   {Resource: "ca", Action: "read"},
		OpCAIssue:  {Resource: "ca", Action: "write"},
		OpCARevoke: {Resource: "ca", Action: "write"},
		OpCARenew:  {Resource: "ca", Action: "write"},
		OpCAGet:    {Resource: "ca", Action: "read"},
		OpCAList:   {Resource: "ca", Action: "read"},
	}
}
