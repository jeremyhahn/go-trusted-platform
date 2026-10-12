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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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
	m.skipOpcodes[quicwire.OpHealth] = true
	m.skipOpcodes[quicwire.OpLiveness] = true
	m.skipOpcodes[quicwire.OpReadiness] = true

	for _, opt := range opts {
		opt(m)
	}
	return m
}

// AuthenticateRequest validates the token in a request.
// Returns the validated token, or an error response if authentication fails.
func (m *AuthMiddleware) AuthenticateRequest(ctx context.Context, req *quicwire.Request) (context.Context, *quicwire.Response) {
	// Skip authentication for certain opcodes
	if m.skipOpcodes[req.Opcode] {
		return ctx, nil
	}

	// If no validator configured, handle based on requireAuth setting
	if m.tokenValidator == nil {
		if m.requireAuth {
			return ctx, &quicwire.Response{
				Status:  quicwire.StatusUnavailable,
				Payload: []byte(ErrAuthValidatorNotConfigured{}.Error()),
			}
		}
		return ctx, nil
	}

	// Check for token
	if req.Token == "" {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
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
			return ctx, &quicwire.Response{
				Status:  quicwire.StatusUnauthorized,
				Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
			}
		}
		ctx = ContextWithAuthorizedContext(ctx, authCtx)
		return ContextWithToken(ctx, req.Token), nil
	}

	// Validate token (legacy bool-only path)
	valid, err := m.tokenValidator.ValidateToken(ctx, req.Token)
	if err != nil {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
		}
	}
	if !valid {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte("invalid token"),
		}
	}

	// Add validated token to context
	return ContextWithToken(ctx, req.Token), nil
}

// AuthorizeRequest checks if the authenticated user has permission for the operation.
// This should be called after AuthenticateRequest.
func (m *AuthMiddleware) AuthorizeRequest(ctx context.Context, req *quicwire.Request, resource, action string) *quicwire.Response {
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
			return &quicwire.Response{
				Status:  quicwire.StatusPermissionDenied,
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
		return &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte("no authenticated session"),
		}
	}

	// Check permission
	allowed, err := m.authzChecker.CheckPermission(ctx, token, resource, action)
	if err != nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInternalError,
			Payload: []byte("authorization check failed: " + err.Error()),
		}
	}
	if !allowed {
		return &quicwire.Response{
			Status:  quicwire.StatusPermissionDenied,
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
		quicwire.OpHealth:    nil,
		quicwire.OpLiveness:  nil,
		quicwire.OpReadiness: nil,

		// vTPM operations
		quicwire.OpVTPMCreate:    {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMDelete:    {Resource: "vtpm", Action: "delete"},
		quicwire.OpVTPMStart:     {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMStop:      {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMGetState:  {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMList:      {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMGetEK:     {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMGetAK:     {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMCreateAK:  {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMQuote:     {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMExtendPCR: {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMReadPCR:   {Resource: "vtpm", Action: "read"},
		quicwire.OpVTPMSeal:      {Resource: "vtpm", Action: "write"},
		quicwire.OpVTPMUnseal:    {Resource: "vtpm", Action: "read"},

		// DNS operations
		quicwire.OpDNSAddRecord:    {Resource: "dns", Action: "write"},
		quicwire.OpDNSDeleteRecord: {Resource: "dns", Action: "delete"},
		quicwire.OpDNSUpdateRecord: {Resource: "dns", Action: "write"},
		quicwire.OpDNSGetRecord:    {Resource: "dns", Action: "read"},
		quicwire.OpDNSListRecords:  {Resource: "dns", Action: "read"},
		quicwire.OpDNSAddZone:      {Resource: "dns", Action: "write"},
		quicwire.OpDNSDeleteZone:   {Resource: "dns", Action: "delete"},
		quicwire.OpDNSGetZone:      {Resource: "dns", Action: "read"},
		quicwire.OpDNSListZones:    {Resource: "dns", Action: "read"},
		quicwire.OpDNSResolve:      {Resource: "dns", Action: "read"},

		// Device operations
		quicwire.OpDeviceRegister:   {Resource: "device", Action: "write"},
		quicwire.OpDeviceUnregister: {Resource: "device", Action: "delete"},
		quicwire.OpDeviceGet:        {Resource: "device", Action: "read"},
		quicwire.OpDeviceList:       {Resource: "device", Action: "read"},
		quicwire.OpDeviceUpdate:     {Resource: "device", Action: "write"},
		quicwire.OpDeviceAttest:     {Resource: "device", Action: "read"},

		// SDN operations
		quicwire.OpSDNGetPortState: {Resource: "sdn", Action: "read"},
		quicwire.OpSDNSetPortState: {Resource: "sdn", Action: "write"},
		quicwire.OpSDNListPorts:    {Resource: "sdn", Action: "read"},
		quicwire.OpSDNApplyPolicy:  {Resource: "sdn", Action: "write"},
		quicwire.OpSDNGetPolicy:    {Resource: "sdn", Action: "read"},
		quicwire.OpSDNListPolicies: {Resource: "sdn", Action: "read"},
		quicwire.OpSDNListBridges:  {Resource: "sdn", Action: "read"},
		quicwire.OpSDNCreateBridge: {Resource: "sdn", Action: "write"},
		quicwire.OpSDNDeleteBridge: {Resource: "sdn", Action: "delete"},
		quicwire.OpSDNCreatePort:   {Resource: "sdn", Action: "write"},
		quicwire.OpSDNDeletePort:   {Resource: "sdn", Action: "delete"},
		quicwire.OpSDNDeletePolicy: {Resource: "sdn", Action: "delete"},

		// KMS operations
		quicwire.OpKMSGenerateKey: {Resource: "kms", Action: "write"},
		quicwire.OpKMSImportKey:   {Resource: "kms", Action: "write"},
		quicwire.OpKMSGetKey:      {Resource: "kms", Action: "read"},
		quicwire.OpKMSListKeys:    {Resource: "kms", Action: "read"},
		quicwire.OpKMSDeleteKey:   {Resource: "kms", Action: "delete"},
		quicwire.OpKMSRotateKey:   {Resource: "kms", Action: "write"},
		quicwire.OpKMSEncrypt:     {Resource: "kms", Action: "write"},
		quicwire.OpKMSDecrypt:     {Resource: "kms", Action: "read"},
		quicwire.OpKMSSign:        {Resource: "kms", Action: "write"},
		quicwire.OpKMSVerify:      {Resource: "kms", Action: "read"},

		// IAM operations
		quicwire.OpIAMUserCreate: {Resource: "iam", Action: "write"},
		quicwire.OpIAMUserDelete: {Resource: "iam", Action: "delete"},
		quicwire.OpIAMUserGet:    {Resource: "iam", Action: "read"},
		quicwire.OpIAMUserList:   {Resource: "iam", Action: "read"},
		quicwire.OpIAMUserUpdate: {Resource: "iam", Action: "write"},
		quicwire.OpIAMRoleCreate: {Resource: "iam", Action: "write"},
		quicwire.OpIAMRoleDelete: {Resource: "iam", Action: "delete"},
		quicwire.OpIAMRoleGet:    {Resource: "iam", Action: "read"},
		quicwire.OpIAMRoleList:   {Resource: "iam", Action: "read"},

		// NTP (time synchronization). The category opcode multiplexes
		// read (status, sources) and write (step) sub-operations in
		// payload[0], which this opcode-level catalog cannot
		// distinguish, so it records the floor scope every NTP caller
		// needs. Per-operation scope enforcement lives in the gRPC
		// method catalog (pkg/api/grpc/method_permissions.go) and the
		// MCP tool catalog, which is where ntp:write is required for
		// the manual step.
		quicwire.OpNTPCategory: {Resource: "ntp", Action: "read"},

		// CA operations
		quicwire.OpCAInfo:   {Resource: "ca", Action: "read"},
		quicwire.OpCAIssue:  {Resource: "ca", Action: "write"},
		quicwire.OpCARevoke: {Resource: "ca", Action: "write"},
		quicwire.OpCARenew:  {Resource: "ca", Action: "write"},
		quicwire.OpCAGet:    {Resource: "ca", Action: "read"},
		quicwire.OpCAList:   {Resource: "ca", Action: "read"},
	}
}
