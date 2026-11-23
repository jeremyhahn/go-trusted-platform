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

package daemon

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// eabPageCollectSize is the page size used when walking the full
// credential store for unfiltered list requests.
const eabPageCollectSize = 100

// EABGRPCService implements the platform.v1 EABService backed by the
// canonical eab.Service (External Account Binding credential management
// for ACME device enrollment, RFC 8555 §7.3.4). The same instance backs
// the gRPC TCP, gRPC UDS, QUIC (via the provisioning category EAB
// sub-opcodes) and webservice REST (/api/v1/eab) surfaces, so every
// transport shares identical semantics and error mapping.
type EABGRPCService struct {
	platformv1.UnimplementedEABServiceServer

	service  EABServicer
	delivery EABDeliveryServicer
	logger   *logging.Logger

	// pepClient, when set, makes the IAM authorisation decision for the
	// tenant-scoped EAB operations (docs/SPEC.md line 125). Without it the
	// service falls back to the caller-tenant equality check.
	pepClient quicbaassdk.IAMPEPClient

	// users resolves an mTLS certificate identity to its stored IAM user
	// and roles before the PEP check: the PEP projects the supplied subject
	// into RBAC as is and does not hydrate roles from the subject ID.
	users eabUserDirectory
}

// eabUserDirectory is the part of the SDK IAM UserClient the EAB service
// uses to resolve an mTLS caller to its stored IAM user.
type eabUserDirectory interface {
	Get(ctx context.Context, tenantID, userID string) (*sdkiam.User, error)
	GetByEmail(ctx context.Context, tenantID, email string) (*sdkiam.User, error)
	FindByUsername(ctx context.Context, tenantID, username string) (*sdkiam.User, error)
}

// SetPEPClient wires the IAM PEP client that authorises tenant-scoped EAB
// operations. A nil client refuses every tenant-scoped call.
func (s *EABGRPCService) SetPEPClient(c quicbaassdk.IAMPEPClient) {
	s.pepClient = c
}

// SetUserClient wires the IAM user directory that resolves mTLS callers to
// their stored user and roles. With a PEP configured and no directory, an
// mTLS caller is refused rather than checked without its roles.
func (s *EABGRPCService) SetUserClient(c eabUserDirectory) {
	s.users = c
}

// eabCaller is the authenticated caller of a tenant-scoped EAB operation.
// identity is set for an mTLS certificate caller, on gRPC or on QUIC, whose
// IAM user and roles are not yet resolved.
type eabCaller struct {
	id       string
	tenantID string
	roles    []string
	identity *auth.Identity
}

// resolveEABMTLSCaller resolves an mTLS certificate identity to its stored
// IAM user in the identity's tenant: by the resolved user ID when the
// interceptor set one, else by the email SAN, else by the CN as username.
// A missing user, or one stored in another tenant, is refused.
func (s *EABGRPCService) resolveEABMTLSCaller(ctx context.Context, caller eabCaller) (eabCaller, error) {
	identity := caller.identity
	denied := status.Error(codes.PermissionDenied, ErrIAMTenantForbidden{Requested: caller.tenantID}.Error())
	if s.users == nil {
		return eabCaller{}, status.Error(codes.Unavailable, "caller identity resolution unavailable")
	}
	var (
		user *sdkiam.User
		err  error
	)
	switch {
	case identity.UserID != "":
		user, err = s.users.Get(ctx, identity.TenantID, identity.UserID)
	case identity.Email != "":
		user, err = s.users.GetByEmail(ctx, identity.TenantID, identity.Email)
	case identity.Name != "":
		user, err = s.users.FindByUsername(ctx, identity.TenantID, identity.Name)
	case identity.ID != "":
		user, err = s.users.FindByUsername(ctx, identity.TenantID, identity.ID)
	default:
		return eabCaller{}, denied
	}
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			return eabCaller{}, denied
		}
		if s.logger != nil {
			s.logger.Error(err, "eab grpc: caller identity lookup failed", "tenant_id", identity.TenantID)
		}
		return eabCaller{}, status.Error(codes.Unavailable, "caller identity resolution unavailable")
	}
	if user == nil || user.ID == "" || user.TenantID != identity.TenantID {
		return eabCaller{}, denied
	}
	return eabCaller{id: user.ID, tenantID: user.TenantID, roles: user.Roles}, nil
}

// eabCallerFromContext returns the authenticated caller, or false for an
// unbound local caller. It reads every caller source callerTenant reads, in
// the same order: the gRPC, QUIC and MCP AuthorizedContext, the QUIC legacy
// principal, the REST platform token and IAM session, then the mTLS
// identity. Token callers keep their subject, tenant and roles. Only a QUIC
// or MCP peer-certificate context, which mtlsPeerAuthenticator stores as an
// operator-scoped AuthorizedContext with no roles and no bearer token in ctx,
// carries its identity so it is resolved through IAM the same way as a
// certificate caller on gRPC.
func eabCallerFromContext(ctx context.Context) (eabCaller, bool) {
	tokenCaller := func(authCtx *platformtoken.AuthorizedContext) eabCaller {
		return eabCaller{id: authCtx.Subject, tenantID: authCtx.TenantID, roles: authCtx.Roles}
	}
	if authCtx, ok := grpcapi.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return tokenCaller(authCtx), true
	}
	if authCtx, ok := quic.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		if _, hasToken := quic.TokenFromContext(ctx); !hasToken && isMTLSPeerAuthorizedContext(authCtx) {
			return certificateCaller(authCtx), true
		}
		return tokenCaller(authCtx), true
	}
	if p, ok := quic.LegacyPrincipalFromContext(ctx); ok {
		return tokenCaller(p), true
	}
	if authCtx, ok := mcp.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		if mcp.TokenFromContext(ctx) == "" && isMTLSPeerAuthorizedContext(authCtx) {
			return certificateCaller(authCtx), true
		}
		return tokenCaller(authCtx), true
	}
	if authCtx, ok := iammw.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return tokenCaller(authCtx), true
	}
	if session, ok := iammw.GetSessionFromContext(ctx); ok && session != nil {
		return eabCaller{id: session.UserID(), tenantID: session.TenantID(), roles: session.Roles()}, true
	}
	if identity := IdentityFromContext(ctx); identity != nil {
		id := identity.UserID
		if id == "" {
			id = identity.ID
		}
		return eabCaller{id: id, tenantID: identity.TenantID, identity: identity}, true
	}
	return eabCaller{}, false
}

// certificateCaller is the caller of a QUIC or MCP peer-certificate context:
// its identity is resolved through IAM before the PEP is asked.
func certificateCaller(authCtx *platformtoken.AuthorizedContext) eabCaller {
	identity := &auth.Identity{ID: authCtx.Subject, Name: authCtx.Username, TenantID: authCtx.TenantID}
	// The mTLS adapter takes the certificate identity from the email
	// SAN by default; carry it as Email so resolution tries it first.
	if strings.Contains(authCtx.Subject, "@") {
		identity.Email = authCtx.Subject
	}
	return eabCaller{id: authCtx.Subject, tenantID: authCtx.TenantID, identity: identity}
}

// isMTLSPeerAuthorizedContext reports whether authCtx has the shape
// mtlsPeerAuthenticator builds for a client certificate: exactly the operator
// scope and no roles. The shape alone does not prove a certificate, since a
// bearer token can be minted with it; callers also check that ctx carries no
// bearer token.
func isMTLSPeerAuthorizedContext(authCtx *platformtoken.AuthorizedContext) bool {
	return len(authCtx.Roles) == 0 && len(authCtx.Scopes) == 1 && authCtx.Scopes[0] == mtlsOperatorScope
}

// authorizeEABTenant authorises a tenant-scoped EAB operation. A bound caller
// must carry a tenant and must name one tenant (the empty tenant spans every
// tenant's store). With a PEP configured the IAM decision is final, with the
// request tenant in CheckRequest.TenantID and the caller's OU tenant in the
// subject, so policy can grant cross-tenant access (docs/SPEC.md line 125).
// action is "read" or "write": the authorizer joins it with the "eab"
// resource into the granted eab:read / eab:write permission.
// Without a PEP every call is refused: tenant equality alone is not an
// authorization decision (docs/SPEC.md line 109). A caller with no tenant
// binding goes to authorizeUnboundCaller, which admits only an
// authenticated Unix peer the PEP allows for the method's registered eab
// permission; a context with no peer credentials is refused.
func (s *EABGRPCService) authorizeEABTenant(ctx context.Context, requestTenant, action string) error {
	caller, bound := eabCallerFromContext(ctx)
	if !bound {
		return authorizeUnboundCaller(ctx, s.pepClient, requestTenant)
	}
	if caller.tenantID == "" || requestTenant == "" {
		return status.Error(codes.PermissionDenied, ErrIAMTenantForbidden{Requested: requestTenant}.Error())
	}
	if s.pepClient == nil {
		return status.Error(codes.PermissionDenied, ErrPEPClientNotAvailable{}.Error())
	}
	if caller.identity != nil {
		resolved, err := s.resolveEABMTLSCaller(ctx, caller)
		if err != nil {
			return err
		}
		caller = resolved
	}
	resp, err := s.pepClient.Check(ctx, &sdkiam.CheckRequest{
		Subject: sdkiam.CheckSubject{
			ID:       caller.id,
			TenantID: caller.tenantID,
			Roles:    caller.roles,
		},
		Action:   action,
		Resource: "eab",
		TenantID: requestTenant,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Error(err, "eab grpc: permission check failed", "tenant_id", requestTenant, "action", action)
		}
		return status.Error(codes.Unavailable, "authorization decision unavailable")
	}
	if resp == nil || !resp.Allowed {
		return status.Error(codes.PermissionDenied, ErrIAMTenantForbidden{Requested: requestTenant}.Error())
	}
	return nil
}

// NewEABGRPCService creates a new EAB gRPC service instance. The backing
// service and delivery handler may be nil when the platform is not
// QuicBaaS-backed; every RPC then returns a typed Unavailable error via
// the requireService / requireDelivery guards instead of panicking.
func NewEABGRPCService(logger *logging.Logger, service EABServicer, delivery EABDeliveryServicer) *EABGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &EABGRPCService{
		logger:   logger,
		service:  service,
		delivery: delivery,
	}
}

// requireService returns a typed Unavailable error when the backing EAB
// credential service is not configured.
func (s *EABGRPCService) requireService() error {
	if s.service == nil {
		return status.Error(codes.Unavailable, ErrEABNotConfigured{}.Error())
	}
	return nil
}

// requireDelivery returns a typed Unavailable error when the QR/URL
// delivery handler is not configured.
func (s *EABGRPCService) requireDelivery() error {
	if s.delivery == nil {
		return status.Error(codes.Unavailable, ErrEABDeliveryNotConfigured{}.Error())
	}
	return nil
}

// =============================================================================
// Error Mapping
// =============================================================================

// eabErrorMatchers maps typed pkg/eab errors to gRPC status codes,
// reusing the ordered matcher-table machinery shared with the config
// delivery service. First match wins; unknown errors map to Internal.
var eabErrorMatchers = []configDeliveryErrorMatcher{
	matchConfigDeliveryError[eab.ErrCredentialNotFound](codes.NotFound),
	matchConfigDeliveryError[eab.ErrInvalidProfileID](codes.InvalidArgument),
	matchConfigDeliveryError[eab.ErrInvalidTenantID](codes.InvalidArgument),
	matchConfigDeliveryError[eab.ErrInvalidExpiresAt](codes.InvalidArgument),
	matchConfigDeliveryError[eab.ErrInvalidCredential](codes.InvalidArgument),
	matchConfigDeliveryError[eab.ErrCredentialExpired](codes.FailedPrecondition),
	matchConfigDeliveryError[eab.ErrCredentialRevoked](codes.FailedPrecondition),
	matchConfigDeliveryError[eab.ErrCredentialAlreadyUsed](codes.FailedPrecondition),
	matchConfigDeliveryError[eab.ErrKeyGenerationFailed](codes.Internal),
	matchConfigDeliveryError[eab.ErrQRCodeGenerationFailed](codes.Internal),
}

// errEABNegativeExpiry refuses a create request whose expires_in_seconds
// is negative; a negative duration must never yield a non-expiring
// credential.
var errEABNegativeExpiry = eab.ErrInvalidExpiresAt{Reason: "expiration duration cannot be negative"}

// eabErrorToStatus maps a typed eab error to a gRPC status error using
// the eabErrorMatchers table.
func eabErrorToStatus(err error) error {
	return configDeliveryErrorToStatus(err, eabErrorMatchers)
}

// =============================================================================
// Converters
// =============================================================================

// eabStatusToPb maps domain credential statuses onto the platform.v1
// enum with O(1) lookup.
var eabStatusToPb = map[eab.Status]platformv1.EABCredentialStatus{
	eab.StatusActive:  platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
	eab.StatusRevoked: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
	eab.StatusExpired: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED,
	eab.StatusUsed:    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,
}

// pbStatusToEAB maps the platform.v1 enum back onto domain credential
// statuses with O(1) lookup. Unspecified has no domain equivalent and is
// intentionally absent (callers treat missing as "no filter").
var pbStatusToEAB = map[platformv1.EABCredentialStatus]eab.Status{
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE:  eab.StatusActive,
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED: eab.StatusRevoked,
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED: eab.StatusExpired,
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED:    eab.StatusUsed,
}

// eabCredentialToPb converts a domain credential to its protobuf
// representation. The HMAC key is included (base64url, no padding) only
// when includeHMACKey is true — i.e. on create — per RFC 8555 §7.3.4.
func eabCredentialToPb(cred *eab.Credential, includeHMACKey bool) *platformv1.EABCredential {
	if cred == nil {
		return nil
	}
	pb := &platformv1.EABCredential{
		Id:        cred.ID,
		KeyId:     cred.KeyID,
		ProfileId: cred.ProfileID,
		TenantId:  cred.TenantID,
		Status:    eabStatusToPb[cred.Status],
	}
	if includeHMACKey {
		pb.HmacKey = base64.RawURLEncoding.EncodeToString(cred.HMACKey)
	}
	if !cred.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(cred.CreatedAt)
	}
	if !cred.ExpiresAt.IsZero() {
		pb.ExpiresAt = timestamppb.New(cred.ExpiresAt)
	}
	if !cred.UsedAt.IsZero() {
		pb.UsedAt = timestamppb.New(cred.UsedAt)
	}
	return pb
}

// =============================================================================
// RPCs
// =============================================================================

// CreateCredential creates a new EAB credential for device enrollment.
// The response includes the HMAC key — the only time it is ever
// returned — per RFC 8555 §7.3.4.
func (s *EABGRPCService) CreateCredential(
	ctx context.Context,
	req *platformv1.CreateEABCredentialRequest,
) (*platformv1.CreateEABCredentialResponse, error) {
	ctx = withOperationMethod(ctx, "/platform.v1.EABService/CreateCredential")
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if err := s.authorizeEABTenant(ctx, req.GetTenantId(), "write"); err != nil {
		return nil, err
	}

	params := eab.GenerateParams{
		ProfileID:  req.GetProfileId(),
		TenantID:   req.GetTenantId(),
		HMACKeyLen: int(req.GetHmacKeyLength()),
	}
	if secs := req.GetExpiresInSeconds(); secs > 0 {
		params.ExpiresIn = time.Duration(secs) * time.Second
	} else if secs < 0 {
		return nil, status.Error(codes.InvalidArgument, errEABNegativeExpiry.Error())
	}

	cred, err := s.service.Generate(ctx, params)
	if err != nil {
		s.logger.Error(err, "eab grpc: create credential failed")
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.CreateEABCredentialResponse{
		Credential: eabCredentialToPb(cred, true),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// GetCredential retrieves an EAB credential by its ID. The HMAC key is
// never included.
func (s *EABGRPCService) GetCredential(
	ctx context.Context,
	req *platformv1.GetEABCredentialRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	cred, err := s.service.Get(ctx, req.GetCredentialId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.GetEABCredentialResponse{
		Credential: eabCredentialToPb(cred, false),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// GetCredentialByKeyID retrieves an EAB credential by its KeyID. The
// HMAC key is never included.
func (s *EABGRPCService) GetCredentialByKeyID(
	ctx context.Context,
	req *platformv1.GetEABCredentialByKeyIDRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	cred, err := s.service.GetByKeyID(ctx, req.GetKeyId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.GetEABCredentialResponse{
		Credential: eabCredentialToPb(cred, false),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// ListCredentials returns EAB credentials with optional filtering. The
// filter cascade is: profile_id (then tenant_id refines), tenant_id, or
// the full store when both are empty. status_filter and active_only
// refine the result; pagination is applied last so pagination totals
// reflect the filtered set. HMAC keys are never included.
func (s *EABGRPCService) ListCredentials(
	ctx context.Context,
	req *platformv1.ListEABCredentialsRequest,
) (*platformv1.ListEABCredentialsResponse, error) {
	ctx = withOperationMethod(ctx, "/platform.v1.EABService/ListCredentials")
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if err := s.authorizeEABTenant(ctx, req.GetTenantId(), "read"); err != nil {
		return nil, err
	}

	creds, err := collectEABCredentials(ctx, s.service, req.GetProfileId(), req.GetTenantId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	statusFilter, hasStatusFilter := pbStatusToEAB[req.GetStatusFilter()]
	filtered := filterEABCredentials(creds, eabCredentialFilter{
		status:     statusFilter,
		byStatus:   hasStatusFilter,
		activeOnly: req.GetActiveOnly(),
	})
	if err := sortEABCredentials(filtered, req.GetPagination()); err != nil {
		return nil, err
	}
	pageCreds, pagination := paginatePage(filtered, req.GetPagination())

	pbCreds := make([]*platformv1.EABCredential, 0, len(pageCreds))
	for _, cred := range pageCreds {
		pbCreds = append(pbCreds, eabCredentialToPb(cred, false))
	}

	return &platformv1.ListEABCredentialsResponse{
		Credentials: pbCreds,
		Pagination:  pagination,
		Total:       int64(len(filtered)),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// collectEABCredentials resolves the base credential set for a list
// request using the narrowest available index. The gRPC and MCP surfaces
// share it so both list the same credentials for the same filters.
func collectEABCredentials(
	ctx context.Context,
	svc EABServicer,
	profileID uint64,
	tenantID string,
) ([]*eab.Credential, error) {
	switch {
	case profileID > 0:
		creds, err := svc.ListByProfile(ctx, profileID)
		if err != nil {
			return nil, err
		}
		// A tenant filter on top of a profile listing must never leak
		// another tenant's credentials.
		if tenantID != "" {
			scoped := make([]*eab.Credential, 0, len(creds))
			for _, cred := range creds {
				if cred.TenantID == tenantID {
					scoped = append(scoped, cred)
				}
			}
			return scoped, nil
		}
		return creds, nil

	case tenantID != "":
		return svc.ListByTenant(ctx, tenantID)

	default:
		return eabCollectAll(ctx, svc)
	}
}

// eabCredentialFilter is the status and active-only refinement of a list
// request, decoded from the pb enum (gRPC) or the status name (MCP).
type eabCredentialFilter struct {
	status     eab.Status
	byStatus   bool
	activeOnly bool
}

// filterEABCredentials applies the status and active-only refinements to
// a credential set.
func filterEABCredentials(creds []*eab.Credential, filter eabCredentialFilter) []*eab.Credential {
	if !filter.byStatus && !filter.activeOnly {
		return creds
	}
	filtered := make([]*eab.Credential, 0, len(creds))
	for _, cred := range creds {
		if filter.byStatus && cred.Status != filter.status {
			continue
		}
		if filter.activeOnly && !cred.IsValid() {
			continue
		}
		filtered = append(filtered, cred)
	}
	return filtered
}

// eabCredentialOrders are the sort_by fields an EAB list accepts. When
// sort_by is empty the set is ordered by id ascending (stable default; the
// ascending flag is only meaningful alongside an explicit sort_by because the
// pb bool defaults to false).
var eabCredentialOrders = pageOrder[*eab.Credential]{
	"":   eabCredentialByID,
	"id": eabCredentialByID,
	"created_at": func(a, b *eab.Credential) bool {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return a.ID < b.ID
		}
		return a.CreatedAt.Before(b.CreatedAt)
	},
}

// eabCredentialByID orders credentials by id.
func eabCredentialByID(a, b *eab.Credential) bool { return a.ID < b.ID }

// sortEABCredentials orders a credential set deterministically by the
// request's sort_by field. A field not in eabCredentialOrders is rejected as
// InvalidArgument so callers get a clear contract instead of silently
// unsorted results.
func sortEABCredentials(creds []*eab.Credential, pagination *platformv1.PaginationRequest) error {
	if !sortPage(creds, pagination, eabCredentialOrders) {
		return status.Error(codes.InvalidArgument,
			ErrEABUnsupportedSortField{Field: pagination.GetSortBy()}.Error())
	}
	return nil
}

// RevokeCredential marks an EAB credential as revoked. The revoker_id is
// recorded in the audit log; the credential store itself does not track
// the revoking principal.
func (s *EABGRPCService) RevokeCredential(
	ctx context.Context,
	req *platformv1.RevokeEABCredentialRequest,
) (*platformv1.RevokeEABCredentialResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	if err := s.service.Revoke(ctx, req.GetCredentialId()); err != nil {
		return nil, eabErrorToStatus(err)
	}
	s.logger.Info("eab credential revoked",
		"credential_id", req.GetCredentialId(),
		"revoker_id", req.GetRevokerId())

	return &platformv1.RevokeEABCredentialResponse{
		Status:    &platformv1.Status{Success: true, Message: "credential revoked"},
		Timestamp: timestamppb.Now(),
	}, nil
}

// ValidateCredential checks whether a (KeyID, HMAC key) pair is valid
// for use. Validation failures are reported in-band (valid=false plus
// error_message) rather than as an RPC error, matching the REST and MCP
// surfaces; only transport-level problems (nil service, malformed
// base64) surface as gRPC errors.
func (s *EABGRPCService) ValidateCredential(
	ctx context.Context,
	req *platformv1.ValidateEABCredentialRequest,
) (*platformv1.ValidateEABCredentialResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	hmacKey, err := decodeEABHMACKey(req.GetHmacKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cred, err := s.service.Validate(ctx, req.GetKeyId(), hmacKey)
	if err != nil {
		return &platformv1.ValidateEABCredentialResponse{
			Valid:        false,
			ErrorMessage: err.Error(),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	return &platformv1.ValidateEABCredentialResponse{
		Valid:      true,
		Credential: eabCredentialToPb(cred, false),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// DeleteCredential permanently removes an EAB credential.
func (s *EABGRPCService) DeleteCredential(
	ctx context.Context,
	req *platformv1.DeleteEABCredentialRequest,
) (*platformv1.DeleteEABCredentialResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	if err := s.service.Delete(ctx, req.GetCredentialId()); err != nil {
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.DeleteEABCredentialResponse{
		Status:    &platformv1.Status{Success: true, Message: "credential deleted"},
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetCredentialQRCode generates a PNG QR code image containing the
// credential payload for device delivery.
func (s *EABGRPCService) GetCredentialQRCode(
	ctx context.Context,
	req *platformv1.GetEABCredentialQRCodeRequest,
) (*platformv1.GetEABCredentialQRCodeResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if err := s.requireDelivery(); err != nil {
		return nil, err
	}
	if req.GetSize() < 0 {
		return nil, status.Error(codes.InvalidArgument,
			ErrEABInvalidQRCodeSize{Size: int(req.GetSize())}.Error())
	}

	cred, err := s.service.Get(ctx, req.GetCredentialId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	png, err := s.delivery.ToQRCodeSized(cred, int(req.GetSize()))
	if err != nil {
		s.logger.Error(err, "eab grpc: QR code generation failed",
			"credential_id", req.GetCredentialId())
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.GetEABCredentialQRCodeResponse{
		QrCode:      png,
		ContentType: "image/png",
		Timestamp:   timestamppb.Now(),
	}, nil
}

// GetEnrollmentURL generates an enrollment URL with the credential
// embedded as query parameters.
func (s *EABGRPCService) GetEnrollmentURL(
	ctx context.Context,
	req *platformv1.GetEABEnrollmentURLRequest,
) (*platformv1.GetEABEnrollmentURLResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if err := s.requireDelivery(); err != nil {
		return nil, err
	}

	cred, err := s.service.Get(ctx, req.GetCredentialId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	var url string
	if path := req.GetPath(); path != "" {
		url, err = s.delivery.ToURLWithPath(cred, path)
	} else {
		url, err = s.delivery.ToURL(cred)
	}
	if err != nil {
		s.logger.Error(err, "eab grpc: enrollment URL generation failed",
			"credential_id", req.GetCredentialId())
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.GetEABEnrollmentURLResponse{
		Url:       url,
		Timestamp: timestamppb.Now(),
	}, nil
}

// MarkCredentialUsed marks a credential as used after successful ACME
// enrollment.
func (s *EABGRPCService) MarkCredentialUsed(
	ctx context.Context,
	req *platformv1.MarkEABCredentialUsedRequest,
) (*platformv1.MarkEABCredentialUsedResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	if err := s.service.MarkUsed(ctx, req.GetCredentialId()); err != nil {
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.MarkEABCredentialUsedResponse{
		Status:    &platformv1.Status{Success: true, Message: "credential marked used"},
		Timestamp: timestamppb.Now(),
	}, nil
}

// CleanupExpiredCredentials removes expired credentials. When tenant_id
// is set only that tenant's expired credentials are deleted; otherwise
// the store-wide cleanup runs.
func (s *EABGRPCService) CleanupExpiredCredentials(
	ctx context.Context,
	req *platformv1.CleanupExpiredEABCredentialsRequest,
) (*platformv1.CleanupExpiredEABCredentialsResponse, error) {
	ctx = withOperationMethod(ctx, "/platform.v1.EABService/CleanupExpiredCredentials")
	if err := s.requireService(); err != nil {
		return nil, err
	}
	// A tenant-bound caller must name a tenant the IAM decision allows; the
	// empty tenant (every tenant's expired credentials) is open only to an
	// unbound Unix peer the PEP allows eab:write.
	if err := s.authorizeEABTenant(ctx, req.GetTenantId(), "write"); err != nil {
		return nil, err
	}

	deleted, err := cleanupExpiredEABCredentials(ctx, s.service, req.GetTenantId())
	if err != nil {
		return nil, eabErrorToStatus(err)
	}

	return &platformv1.CleanupExpiredEABCredentialsResponse{
		DeletedCount: int32(deleted),
		Status:       &platformv1.Status{Success: true, Message: "expired credentials removed"},
		Timestamp:    timestamppb.Now(),
	}, nil
}

// cleanupExpiredEABCredentials deletes the expired credentials of one
// tenant, or of every tenant when tenantID is empty, and returns how many
// it deleted. The gRPC and MCP surfaces share it so a tenant-scoped
// cleanup never touches another tenant's credentials on either.
func cleanupExpiredEABCredentials(ctx context.Context, svc EABServicer, tenantID string) (int, error) {
	if tenantID == "" {
		return svc.CleanupExpired(ctx)
	}
	creds, err := svc.ListByTenant(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, cred := range creds {
		if cred.Status != eab.StatusExpired && !cred.IsExpired() {
			continue
		}
		if err := svc.Delete(ctx, cred.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

// Ensure EABGRPCService implements the generated server interface.
var _ platformv1.EABServiceServer = (*EABGRPCService)(nil)
