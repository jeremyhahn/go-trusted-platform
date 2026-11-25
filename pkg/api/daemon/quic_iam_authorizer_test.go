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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	sdkrest "github.com/jeremyhahn/go-quicbaas/sdk/go/transport/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
)

// fakeQuicBaaSTokenService answers ValidateToken with a fixed response.
type fakeQuicBaaSTokenService struct {
	resp *quicbaas.ValidateTokenResponse
	err  error
}

func (f fakeQuicBaaSTokenService) ValidateToken(context.Context, *quicbaas.ValidateTokenRequest) (*quicbaas.ValidateTokenResponse, error) {
	return f.resp, f.err
}

// rejectingJWTVerifier refuses every token.
type rejectingJWTVerifier struct{}

func (rejectingJWTVerifier) VerifyTokenClaims(string) (*jwt.TokenClaims, error) {
	return nil, jwt.ErrInvalidToken
}

func TestNewIAMTokenAuthorizer_RequiresValidatorAndPEP(t *testing.T) {
	_, err := newIAMTokenAuthorizer(nil, &mockSDKPEPClient{})
	var invalid ErrInvalidConfig
	assert.True(t, errors.As(err, &invalid), "error is %T, want ErrInvalidConfig", err)

	_, err = newIAMTokenAuthorizer(newGRPCTokenValidator(nil, nil), nil)
	assert.ErrorIs(t, err, ErrPEPClientNotAvailable{})
}

func TestGRPCTokenValidator_ResolvePrincipal(t *testing.T) {
	t.Run("platform JWT names user, tenant and roles", func(t *testing.T) {
		v := newGRPCTokenValidator(nil, nil)
		v.SetJWTVerifier(rejectingJWTVerifier{})
		v.SetJWTVerifier(alwaysValidJWTVerifier{claims: jwt.TokenClaims{UserIDStr: "7", TenantID: "acme", Roles: []string{"admin"}}})

		p, err := v.ResolvePrincipal(context.Background(), "jwt")
		require.NoError(t, err)
		assert.Equal(t, &tokenPrincipal{Subject: "7", TenantID: "acme", Roles: []string{"admin"}}, p)
	})
	t.Run("registered subject is the fallback user id", func(t *testing.T) {
		claims := jwt.TokenClaims{TenantID: "acme"}
		claims.Subject = "9"
		v := newGRPCTokenValidator(nil, nil)
		v.SetJWTVerifier(alwaysValidJWTVerifier{claims: claims})

		p, err := v.ResolvePrincipal(context.Background(), "jwt")
		require.NoError(t, err)
		assert.Equal(t, "9", p.Subject)
	})
	t.Run("QuicBaaS token has no tenant", func(t *testing.T) {
		v := newGRPCTokenValidator(fakeQuicBaaSTokenService{resp: &quicbaas.ValidateTokenResponse{
			Valid: true, UserID: "u1", Roles: []string{"viewer"},
		}}, nil)

		p, err := v.ResolvePrincipal(context.Background(), "opaque")
		require.NoError(t, err)
		assert.Equal(t, &tokenPrincipal{Subject: "u1", Roles: []string{"viewer"}}, p)
	})
	t.Run("invalid QuicBaaS token is refused", func(t *testing.T) {
		v := newGRPCTokenValidator(fakeQuicBaaSTokenService{resp: &quicbaas.ValidateTokenResponse{Valid: false}}, nil)

		_, err := v.ResolvePrincipal(context.Background(), "opaque")
		var want ErrTokenValidationFailed
		assert.True(t, errors.As(err, &want), "error is %T", err)
	})
	t.Run("no verifier accepts and no QuicBaaS service", func(t *testing.T) {
		v := newGRPCTokenValidator(nil, nil)
		v.SetJWTVerifier(rejectingJWTVerifier{})

		_, err := v.ResolvePrincipal(context.Background(), "jwt")
		assert.ErrorIs(t, err, ErrQuicBaaSServiceUnavailable{})
	})
}

func TestIAMTokenAuthorizer_CheckPermission_Errors(t *testing.T) {
	validator := newGRPCTokenValidator(nil, nil)
	validator.SetJWTVerifier(alwaysValidJWTVerifier{claims: jwt.TokenClaims{UserIDStr: "7", TenantID: "acme"}})

	t.Run("PEP failure is a typed error, not a decision", func(t *testing.T) {
		pepErr := errors.New("pep unreachable")
		authz, err := newIAMTokenAuthorizer(validator, &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, pepErr
		}})
		require.NoError(t, err)

		allowed, err := authz.CheckPermission(context.Background(), "jwt", "kms", "read")
		assert.False(t, allowed)
		var want ErrIAMPermissionCheckFailed
		require.True(t, errors.As(err, &want), "error is %T", err)
		assert.ErrorIs(t, err, pepErr)
	})
	t.Run("unresolvable token is an error", func(t *testing.T) {
		rejecting := newGRPCTokenValidator(nil, nil)
		rejecting.SetJWTVerifier(rejectingJWTVerifier{})
		authz, err := newIAMTokenAuthorizer(rejecting, &mockSDKPEPClient{})
		require.NoError(t, err)

		allowed, err := authz.CheckPermission(context.Background(), "jwt", "kms", "read")
		assert.False(t, allowed)
		assert.Error(t, err)
	})
	t.Run("empty permission is refused before the PEP", func(t *testing.T) {
		asked := false
		authz, err := newIAMTokenAuthorizer(validator, &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			asked = true
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}})
		require.NoError(t, err)

		allowed, err := authz.CheckPermission(context.Background(), "jwt", "kms", "")
		assert.False(t, allowed)
		var want ErrEmptyPermission
		require.True(t, errors.As(err, &want), "error is %T", err)
		assert.False(t, asked, "the PEP must not be asked about an empty permission")
	})
	t.Run("nil PEP response denies", func(t *testing.T) {
		authz, err := newIAMTokenAuthorizer(validator, &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, nil
		}})
		require.NoError(t, err)

		allowed, err := authz.CheckPermission(context.Background(), "jwt", "kms", "read")
		require.NoError(t, err)
		assert.False(t, allowed)
	})
}

// TestIAMTokenAuthorizer_CheckPermission_CarriesTheTokenTenant pins that a
// token caller's PEP check carries the token's tenant both as the subject's
// tenant and as the request's TenantID (docs/SPEC.md:123, PR #2082 Codex
// round 3).
func TestIAMTokenAuthorizer_CheckPermission_CarriesTheTokenTenant(t *testing.T) {
	validator := newGRPCTokenValidator(nil, nil)
	validator.SetJWTVerifier(alwaysValidJWTVerifier{claims: jwt.TokenClaims{UserIDStr: "7", TenantID: "acme", Roles: []string{"kms-operator"}}})

	var asked []*sdkiam.CheckRequest
	authz, err := newIAMTokenAuthorizer(validator, pepGrantingRole("kms-operator", "kms", "delete", &asked))
	require.NoError(t, err)

	allowed, err := authz.CheckPermission(context.Background(), "jwt", "kms", "delete")
	require.NoError(t, err)
	assert.True(t, allowed)
	require.Len(t, asked, 1)
	assert.Equal(t, "acme", asked[0].TenantID, "the PEP request carries the token's tenant (docs/SPEC.md:123)")
	assert.Equal(t, "acme", asked[0].Subject.TenantID)
}

func TestErrPEPClientNotAvailable_Error(t *testing.T) {
	err := ErrPEPClientNotAvailable{}
	if err.Error() != "PEP client is not available" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// storedUsersIAM is an IAM client whose user lookups follow the pinned
// go-quicbaas SDK v0.12.0-alpha: users are tenant-scoped, Get answers only
// numeric Snowflake IDs (the store's ParseUserID refuses anything else as
// not found), List returns the tenant's stored users, and GetByEmail and
// FindByUsername fail whatever is stored, as the SDK's gRPC and REST/HTTP3
// transports do. Every other IAM method is the embedded nil interface and
// panics if called.
type storedUsersIAM struct {
	quicbaassdk.IAMClient
	users  []*sdkiam.User
	getErr error
	// listIgnoresTenant, when set, makes List return every stored user, of
	// any tenant: a server that does not scope its answer to the tenant.
	listIgnoresTenant bool
}

// iamStoringAnyUser is an IAM client that holds the testutil client
// certificate's user (CN test-client in tenant O "Test Platform Client",
// pkg/testutil/tls.go), with no roles, as stored user 1001.
func iamStoringAnyUser() *storedUsersIAM {
	return &storedUsersIAM{users: []*sdkiam.User{{ID: "1001", TenantID: "Test Platform Client", Username: "test-client"}}}
}

func (c *storedUsersIAM) User() sdkiam.UserClient { return storedUsers{client: c} }

type storedUsers struct {
	sdkiam.UserClient
	client *storedUsersIAM
}

var (
	errStoredUserNotFound     = errors.New("user not found")
	errPinnedSDKUnimplemented = errors.New("unimplemented: the pinned SDK transports do not serve this lookup")
)

func (u storedUsers) find(tenantID string, match func(*sdkiam.User) bool) (*sdkiam.User, error) {
	if u.client.getErr != nil {
		return nil, u.client.getErr
	}
	for _, user := range u.client.users {
		if user.TenantID == tenantID && match(user) {
			return user, nil
		}
	}
	return nil, errStoredUserNotFound
}

func (u storedUsers) Get(_ context.Context, tenantID, userID string) (*sdkiam.User, error) {
	if _, err := strconv.ParseUint(userID, 10, 64); err != nil {
		return nil, errStoredUserNotFound
	}
	return u.find(tenantID, func(user *sdkiam.User) bool { return user.ID == userID })
}

func (u storedUsers) GetByEmail(context.Context, string, string) (*sdkiam.User, error) {
	return nil, errPinnedSDKUnimplemented
}

func (u storedUsers) FindByUsername(context.Context, string, string) (*sdkiam.User, error) {
	return nil, errPinnedSDKUnimplemented
}

func (u storedUsers) List(_ context.Context, tenantID string, _ *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
	if u.client.getErr != nil {
		return nil, u.client.getErr
	}
	resp := &sdkiam.ListUsersResponse{}
	for _, user := range u.client.users {
		if u.client.listIgnoresTenant || user.TenantID == tenantID {
			resp.Users = append(resp.Users, *user)
		}
	}
	return resp, nil
}

// pepGrantingRole is a PEP that allows resource:action only when the Check
// carries role, the way the RBAC authorizer behind the real PEP resolves
// permissions from the subject's supplied roles. It records every request.
func pepGrantingRole(role, resource, action string, asked *[]*sdkiam.CheckRequest) *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		*asked = append(*asked, req)
		if req.Resource != resource || req.Action != action {
			return &sdkiam.CheckResponse{Allowed: false}, nil
		}
		for _, r := range req.Subject.Roles {
			if r == role {
				return &sdkiam.CheckResponse{Allowed: true}, nil
			}
		}
		return &sdkiam.CheckResponse{Allowed: false}, nil
	}}
}

// A certificate principal carries only subject and tenant. Its role grants
// are the stored IAM user's, resolved in its tenant before the PEP is asked
// (#2016, PR #2082 Codex round 1 P1): without them the RBAC chain resolves
// no permission and denies every certificate caller.
func TestIAMTokenAuthorizer_CheckPeerPermission_ResolvesStoredRoles(t *testing.T) {
	t.Parallel()
	// The mTLS adapter sets Subject to the certificate's email SAN, else its
	// CN: never the stored user's numeric ID.
	emailPeer := &platformtoken.AuthorizedContext{Subject: "ops@acme.example", TenantID: "acme"}
	cnPeer := &platformtoken.AuthorizedContext{Subject: "admin", TenantID: "acme"}
	operator := &sdkiam.User{ID: "7301", TenantID: "acme", Email: "ops@acme.example", Roles: []string{"kms-operator"}}
	admin := &sdkiam.User{ID: "7302", TenantID: "acme", Username: "admin", Roles: []string{"kms-operator"}}

	t.Run("email SAN resolves to the stored user and its roles", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{operator, admin}},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), emailPeer, "kms", "delete")
		require.NoError(t, err)
		assert.True(t, allowed)
		require.Len(t, asked, 1)
		assert.Equal(t, "7301", asked[0].Subject.ID, "the PEP decides on the canonical user ID")
		assert.Equal(t, "acme", asked[0].Subject.TenantID)
		assert.Equal(t, []string{"kms-operator"}, asked[0].Subject.Roles)
		assert.Equal(t, "acme", asked[0].TenantID, "the PEP request carries the certificate's tenant (docs/SPEC.md:123)")
	})
	t.Run("CN resolves to the stored user by username", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{operator, admin}},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), cnPeer, "kms", "delete")
		require.NoError(t, err)
		assert.True(t, allowed)
		require.Len(t, asked, 1)
		assert.Equal(t, "7302", asked[0].Subject.ID)
		assert.Equal(t, []string{"kms-operator"}, asked[0].Subject.Roles)
		assert.Equal(t, "acme", asked[0].TenantID, "the PEP request carries the certificate's tenant (docs/SPEC.md:123)")
	})
	t.Run("mixed-case email SAN resolves to the normalized stored email", func(t *testing.T) {
		// The IAM store keeps every email lowercased and trimmed; the
		// certificate's SAN keeps the case it was issued with.
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{operator, admin}},
		}
		peer := &platformtoken.AuthorizedContext{Subject: "Ops@ACME.Example", TenantID: "acme"}
		allowed, err := authz.CheckPeerPermission(context.Background(), peer, "kms", "delete")
		require.NoError(t, err)
		assert.True(t, allowed, "a mixed-case email SAN resolves its stored user")
		require.Len(t, asked, 1)
		assert.Equal(t, "7301", asked[0].Subject.ID)
		assert.Equal(t, []string{"kms-operator"}, asked[0].Subject.Roles)
		assert.Equal(t, "acme", asked[0].TenantID, "the PEP request carries the certificate's tenant (docs/SPEC.md:123)")
	})
	t.Run("stored user without the role is denied", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{
				{ID: "7301", TenantID: "acme", Email: "ops@acme.example"},
			}},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), emailPeer, "kms", "delete")
		require.NoError(t, err)
		assert.False(t, allowed)
	})
	t.Run("unknown subject is denied without a PEP call", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{operator, admin}},
		}
		peer := &platformtoken.AuthorizedContext{Subject: "stranger@acme.example", TenantID: "acme"}
		allowed, err := authz.CheckPeerPermission(context.Background(), peer, "kms", "delete")
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Empty(t, asked)
	})
	t.Run("user stored in another tenant is denied", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{
				{ID: "7301", TenantID: "other", Email: "ops@acme.example", Roles: []string{"kms-operator"}},
				{ID: "7302", TenantID: "other", Username: "admin", Roles: []string{"kms-operator"}},
			}},
		}
		for _, peer := range []*platformtoken.AuthorizedContext{emailPeer, cnPeer} {
			allowed, err := authz.CheckPeerPermission(context.Background(), peer, "kms", "delete")
			require.NoError(t, err)
			assert.False(t, allowed)
		}
		assert.Empty(t, asked, "a principal with no stored user never reaches the PEP")
	})
	t.Run("lookup returning a user of another tenant is denied", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{listIgnoresTenant: true, users: []*sdkiam.User{
				{ID: "7301", TenantID: "other", Email: "ops@acme.example", Roles: []string{"kms-operator"}},
			}},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), emailPeer, "kms", "delete")
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Empty(t, asked)
	})
	t.Run("two stored users with the same username are denied", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{users: []*sdkiam.User{
				{ID: "7302", TenantID: "acme", Username: "admin", Roles: []string{"kms-operator"}},
				{ID: "7303", TenantID: "acme", Username: "admin", Roles: []string{"kms-operator"}},
			}},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), cnPeer, "kms", "delete")
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Empty(t, asked, "an ambiguous certificate subject never reaches the PEP")
	})
	t.Run("lookup error is a denial without an error", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: &storedUsersIAM{getErr: errors.New("iam store unreachable: secret detail")},
		}
		allowed, err := authz.CheckPeerPermission(context.Background(), emailPeer, "kms", "delete")
		assert.NoError(t, err)
		assert.False(t, allowed)
		assert.Empty(t, asked)
	})
	t.Run("no IAM client is a denial", func(t *testing.T) {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{pep: pepGrantingRole("kms-operator", "kms", "delete", &asked)}
		allowed, err := authz.CheckPeerPermission(context.Background(), emailPeer, "kms", "delete")
		assert.NoError(t, err)
		assert.False(t, allowed)
		assert.Empty(t, asked)
	})
}

// TestIAMTokenAuthorizer_CheckPeerPermission_ResolvesThroughPinnedRESTTransport
// drives certificate-user resolution through the pinned SDK's real REST
// transport adapter against a server answering the pinned server's
// ListUsers shape, so a lookup the SDK does not carry end to end fails here.
func TestIAMTokenAuthorizer_CheckPeerPermission_ResolvesThroughPinnedRESTTransport(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/tenants/acme/users" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"users":[`+
			`{"id":"7301","tenant_id":"acme","email":"ops@acme.example","username":"ops","roles":["kms-operator"]},`+
			`{"id":"7302","tenant_id":"acme","email":"admin@acme.example","username":"admin","roles":["kms-operator"]}`+
			`],"limit":100,"offset":0}`)
	}))
	t.Cleanup(srv.Close)
	tr, err := sdkrest.New(&sdktransport.Config{Address: srv.URL, Timeout: 5 * time.Second})
	require.NoError(t, err)

	for _, tc := range []struct {
		subject string
		wantID  string
	}{
		{subject: "ops@acme.example", wantID: "7301"},
		{subject: "admin", wantID: "7302"},
	} {
		var asked []*sdkiam.CheckRequest
		authz := &iamTokenAuthorizer{
			pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
			iam: sdkiam.NewClient(tr),
		}
		peer := &platformtoken.AuthorizedContext{Subject: tc.subject, TenantID: "acme"}
		allowed, err := authz.CheckPeerPermission(context.Background(), peer, "kms", "delete")
		require.NoError(t, err, tc.subject)
		assert.True(t, allowed, "%s resolves through the pinned REST transport", tc.subject)
		require.Len(t, asked, 1, tc.subject)
		assert.Equal(t, tc.wantID, asked[0].Subject.ID, tc.subject)
		assert.Equal(t, []string{"kms-operator"}, asked[0].Subject.Roles, tc.subject)
		assert.Equal(t, "acme", asked[0].TenantID, tc.subject)
	}

	var asked []*sdkiam.CheckRequest
	authz := &iamTokenAuthorizer{
		pep: pepGrantingRole("kms-operator", "kms", "delete", &asked),
		iam: sdkiam.NewClient(tr),
	}
	stranger := &platformtoken.AuthorizedContext{Subject: "stranger@acme.example", TenantID: "acme"}
	allowed, err := authz.CheckPeerPermission(context.Background(), stranger, "kms", "delete")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Empty(t, asked, "an absent certificate subject never reaches the PEP")
}

// mockSDKPEPClient is an sdkiam.PEPClient whose answers the test supplies.
type mockSDKPEPClient struct {
	checkFunc      func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error)
	checkBatchFunc func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error)
}

func (m *mockSDKPEPClient) Check(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx, req)
	}
	return &sdkiam.CheckResponse{}, nil
}

func (m *mockSDKPEPClient) CheckBatch(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	if m.checkBatchFunc != nil {
		return m.checkBatchFunc(ctx, req)
	}
	return &sdkiam.CheckBatchResponse{}, nil
}
