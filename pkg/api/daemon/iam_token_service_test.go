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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	platformiam "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

// tokenRefusal is the text every transport carries when it refuses to issue
// or revoke a token.
const tokenRefusal = "is handled via OIDC flows, not the IAM service"

// revokedSubject is the subject subjectLiveness reports revoked.
const revokedSubject = "mallory"

// subjectLiveness is the liveness authority of the broker: it reports
// revokedSubject's tokens inactive, or fails when err is set.
type subjectLiveness struct {
	err error
}

func (l subjectLiveness) CheckLiveness(_ context.Context, _ string, claims *platformtoken.Claims) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	return claims.Subject != revokedSubject, nil
}

// errLivenessUnreachable stands for a liveness authority that cannot be
// reached.
type errLivenessUnreachable struct{}

func (errLivenessUnreachable) Error() string { return "liveness authority unreachable" }

// iamTokenFixture is a broker issuer key, a validator that trusts it with a
// liveness authority, and the token service built on that validator.
type iamTokenFixture struct {
	key     *ptIssuerKey
	tokens  *IAMTokenService
	expires time.Time
}

func newIAMTokenFixture(t *testing.T) *iamTokenFixture {
	t.Helper()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	validator.liveness = subjectLiveness{}
	return &iamTokenFixture{
		key:     key,
		tokens:  newIAMTokenService(selectIAMTokenVerifier(validator, nil, nil)),
		expires: time.Now().Add(10 * time.Minute).Truncate(time.Second),
	}
}

// validToken is alice's token in tenant-1 granting iam:read.
func (f *iamTokenFixture) validToken(t *testing.T) string {
	return f.key.signExpiring(t, "alice", "tenant-1", []string{"iam:read"}, f.expires)
}

// rejectedTokens are tokens the validator must answer valid: false for, by
// the reason it must give.
func (f *iamTokenFixture) rejectedTokens(t *testing.T) map[IAMTokenReason]string {
	return map[IAMTokenReason]string{
		IAMTokenExpired:      f.key.signExpiring(t, "alice", "tenant-1", nil, time.Now().Add(-time.Hour)),
		IAMTokenBadSignature: newPTIssuerKey(t).sign(t, "alice", "tenant-1", nil),
		IAMTokenRevoked:      f.key.sign(t, revokedSubject, "tenant-1", nil),
		IAMTokenMalformed:    "not-a-jwt",
	}
}

// TestIAMTokenServiceVerify: the service answers valid with the token's
// claims for a good token and valid: false with the reason for each failing
// one, against a broker key minted in memory.
func TestIAMTokenServiceVerify(t *testing.T) {
	f := newIAMTokenFixture(t)
	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		got, err := f.tokens.Verify(ctx, f.validToken(t))
		require.NoError(t, err)
		assert.True(t, got.Valid)
		assert.Empty(t, got.Reason)
		require.NotNil(t, got.Claims)
		assert.Equal(t, "alice", got.Claims.Subject)
		assert.Equal(t, "tenant-1", got.Claims.TenantID)
		assert.Equal(t, []string{"iam:read"}, got.Claims.Scopes)
		assert.Equal(t, f.expires.Unix(), got.Claims.ExpiresAt)
	})

	for reason, token := range f.rejectedTokens(t) {
		t.Run(string(reason), func(t *testing.T) {
			got, err := f.tokens.Verify(ctx, token)
			require.NoError(t, err)
			assert.False(t, got.Valid)
			assert.Equal(t, reason, got.Reason)
			assert.Nil(t, got.Claims, "a rejected token carries no claims")
		})
	}
}

// TestIAMTokenServiceVerifyErrors: when the service cannot check a token it
// returns a typed error, never an answer, and never valid.
func TestIAMTokenServiceVerifyErrors(t *testing.T) {
	ctx := context.Background()
	f := newIAMTokenFixture(t)

	t.Run("empty token", func(t *testing.T) {
		for _, token := range []string{"", "   "} {
			got, err := f.tokens.Verify(ctx, token)
			assert.ErrorIs(t, err, ErrIAMMissingParameter{Parameter: "token"})
			assert.Nil(t, got)
		}
	})

	t.Run("no validator wired", func(t *testing.T) {
		unwired := map[string]*IAMTokenService{
			"nil verifier":      newIAMTokenService(nil),
			"nothing selected":  newIAMTokenService(selectIAMTokenVerifier(nil, nil, nil)),
			"nil token service": nil,
		}
		for name, svc := range unwired {
			got, err := svc.Verify(ctx, f.validToken(t))
			assert.ErrorIs(t, err, ErrIAMTokenVerifierNotConfigured{}, name)
			assert.Nil(t, got, name)
		}
	})

	t.Run("liveness authority unreachable", func(t *testing.T) {
		validator := newSharedValidator(t, f.key.jwksHandler(t).URL, true)
		validator.liveness = subjectLiveness{err: errLivenessUnreachable{}}

		got, err := newIAMTokenService(validator).Verify(ctx, f.validToken(t))
		var failed ErrTokenValidationFailed
		require.ErrorAs(t, err, &failed)
		assert.ErrorIs(t, err, errLivenessUnreachable{})
		assert.Nil(t, got)
	})
}

// TestIAMTokenServiceRefusesIssueAndRevoke: the SDK IAM client can neither
// issue nor revoke a token, so the service refuses both, wired or not.
func TestIAMTokenServiceRefusesIssueAndRevoke(t *testing.T) {
	for name, svc := range map[string]*IAMTokenService{
		"wired":   newIAMTokenFixture(t).tokens,
		"unwired": nil,
	} {
		assert.Equal(t, ErrIAMTokenViaOIDC{Op: iamTokenOpCreate}, svc.Create(), name)
		assert.Equal(t, ErrIAMTokenViaOIDC{Op: iamTokenOpRevoke}, svc.Revoke(), name)
	}
}

// TestSelectIAMTokenVerifier: the broker validator wins, then the gRPC and
// QUIC local validators; with none the selection is a nil interface.
func TestSelectIAMTokenVerifier(t *testing.T) {
	shared := &platformTokenValidator{}
	grpcValidator := newGRPCTokenValidator(nil, nil)
	quicValidator := newGRPCTokenValidator(nil, nil)

	assert.Same(t, shared, selectIAMTokenVerifier(shared, grpcValidator, quicValidator))
	assert.Same(t, grpcValidator, selectIAMTokenVerifier(nil, grpcValidator, quicValidator))
	assert.Same(t, quicValidator, selectIAMTokenVerifier(nil, nil, quicValidator))
	assert.Nil(t, selectIAMTokenVerifier(nil, nil, nil))
}

// TestIAMTokenVerifierForMTLS covers the mTLS deployment: certificates
// authenticate callers, so no transport builds a token validator, yet IAM
// VerifyToken still answers the tokens the daemon's issuers mint.
func TestIAMTokenVerifierForMTLS(t *testing.T) {
	t.Run("a transport validator wins", func(t *testing.T) {
		shared := &platformTokenValidator{}
		config := failClosedConfig()
		config.App = &app.App{}
		config.PlatformJWTVerifier = alwaysValidJWTVerifier{}

		assert.Same(t, shared, iamTokenVerifierFor(config, logging.DefaultLogger(), shared, nil, nil))
	})

	t.Run("mTLS falls back to the platform JWT verifier", func(t *testing.T) {
		config := failClosedConfig()
		config.EnableMTLS = true
		config.App = &app.App{}
		config.PlatformJWTVerifier = alwaysValidJWTVerifier{claims: jwt.TokenClaims{
			UserIDStr: "42", TenantID: "acme",
		}}

		tokens := newIAMTokenService(iamTokenVerifierFor(config, logging.DefaultLogger(), nil, nil, nil))
		verification, err := tokens.Verify(context.Background(), "platform-jwt")
		require.NoError(t, err)
		assert.True(t, verification.Valid)
		require.NotNil(t, verification.Claims)
		assert.Equal(t, "acme", verification.Claims.TenantID)
	})

	t.Run("no issuer leaves the service unconfigured", func(t *testing.T) {
		config := failClosedConfig()
		config.EnableMTLS = true

		assert.Nil(t, iamTokenVerifierFor(config, logging.DefaultLogger(), nil, nil, nil))
		_, err := newIAMTokenService(iamTokenVerifierFor(config, logging.DefaultLogger(), nil, nil, nil)).
			Verify(context.Background(), "platform-jwt")
		assert.ErrorAs(t, err, &ErrIAMTokenVerifierNotConfigured{})
	})
}

// ecJWTVerifier verifies platform JWTs the way the platform JWT service does:
// an ES256 signature over jwt.TokenClaims, with golang-jwt's expiry check.
type ecJWTVerifier struct {
	pub *ecdsa.PublicKey
}

func (v ecJWTVerifier) VerifyTokenClaims(token string) (*jwt.TokenClaims, error) {
	claims := &jwt.TokenClaims{}
	_, err := gojwt.ParseWithClaims(token, claims, func(*gojwt.Token) (interface{}, error) {
		return v.pub, nil
	}, gojwt.WithValidMethods([]string{gojwt.SigningMethodES256.Alg()}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// signPlatformJWT mints a platform JWT for user 7 in acme expiring at exp.
func signPlatformJWT(t *testing.T, priv *ecdsa.PrivateKey, exp time.Time) string {
	t.Helper()
	token, err := gojwt.NewWithClaims(gojwt.SigningMethodES256, &jwt.TokenClaims{
		UserIDStr:        "7",
		TenantID:         "acme",
		Roles:            []string{"admin"},
		RegisteredClaims: gojwt.RegisteredClaims{ExpiresAt: gojwt.NewNumericDate(exp)},
	}).SignedString(priv)
	require.NoError(t, err)
	return token
}

// TestIAMTokenServiceVerifyLocalValidator: without the broker validator the
// service verifies through the gRPC validator, the platform JWT verifiers
// first and QuicBaaS second, as request authentication does.
func TestIAMTokenServiceVerifyLocalValidator(t *testing.T) {
	ctx := context.Background()
	trusted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	untrusted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	quicbaasValid := fakeQuicBaaSTokenService{resp: &quicbaas.ValidateTokenResponse{
		Valid: true, UserID: "u1", Roles: []string{"viewer"}, ExpiresAt: expires.Unix(),
	}}

	service := func(quicbaasService quicbaas.ServiceInterface) *IAMTokenService {
		v := newGRPCTokenValidator(quicbaasService, nil)
		v.SetJWTVerifier(ecJWTVerifier{pub: &trusted.PublicKey})
		return newIAMTokenService(selectIAMTokenVerifier(nil, v, nil))
	}

	t.Run("valid platform JWT", func(t *testing.T) {
		got, err := service(nil).Verify(ctx, signPlatformJWT(t, trusted, expires))
		require.NoError(t, err)
		require.True(t, got.Valid)
		assert.Equal(t, &IAMTokenClaims{Subject: "7", TenantID: "acme", Roles: []string{"admin"}, ExpiresAt: expires.Unix()}, got.Claims)
	})

	t.Run("expired platform JWT is expired even when QuicBaaS would accept", func(t *testing.T) {
		got, err := service(quicbaasValid).Verify(ctx, signPlatformJWT(t, trusted, time.Now().Add(-time.Hour)))
		require.NoError(t, err)
		assert.False(t, got.Valid)
		assert.Equal(t, IAMTokenExpired, got.Reason)
	})

	t.Run("JWT from an untrusted key without QuicBaaS", func(t *testing.T) {
		got, err := service(nil).Verify(ctx, signPlatformJWT(t, untrusted, expires))
		require.NoError(t, err)
		assert.False(t, got.Valid)
		assert.Equal(t, IAMTokenBadSignature, got.Reason)
	})

	t.Run("malformed token without QuicBaaS", func(t *testing.T) {
		got, err := service(nil).Verify(ctx, "not-a-jwt")
		require.NoError(t, err)
		assert.False(t, got.Valid)
		assert.Equal(t, IAMTokenMalformed, got.Reason)
	})

	t.Run("QuicBaaS-minted token", func(t *testing.T) {
		got, err := service(quicbaasValid).Verify(ctx, "opaque-quicbaas-token")
		require.NoError(t, err)
		require.True(t, got.Valid)
		assert.Equal(t, &IAMTokenClaims{Subject: "u1", Roles: []string{"viewer"}, ExpiresAt: expires.Unix()}, got.Claims)
	})

	t.Run("QuicBaaS rejection", func(t *testing.T) {
		rejecting := fakeQuicBaaSTokenService{resp: &quicbaas.ValidateTokenResponse{Valid: false}}
		got, err := service(rejecting).Verify(ctx, "opaque-quicbaas-token")
		require.NoError(t, err)
		assert.False(t, got.Valid)
		assert.Equal(t, IAMTokenRejected, got.Reason)
	})

	t.Run("QuicBaaS refusing the token as unauthorized is a rejection", func(t *testing.T) {
		refusing := fakeQuicBaaSTokenService{err: sdkerrors.NewUnauthorized("ValidateToken", "invalid token")}
		got, err := service(refusing).Verify(ctx, "not-a-jwt")
		require.NoError(t, err)
		assert.False(t, got.Valid)
		assert.Equal(t, IAMTokenRejected, got.Reason)
	})

	t.Run("QuicBaaS unreachable is no answer", func(t *testing.T) {
		got, err := service(fakeQuicBaaSTokenService{err: errLivenessUnreachable{}}).Verify(ctx, "opaque-quicbaas-token")
		require.Error(t, err)
		assert.Nil(t, got)
	})

	t.Run("no verifier and no QuicBaaS", func(t *testing.T) {
		v := newGRPCTokenValidator(nil, nil)
		got, err := newIAMTokenService(v).Verify(ctx, "any-token")
		assert.ErrorIs(t, err, ErrIAMTokenVerifierNotConfigured{})
		assert.Nil(t, got)
	})
}

// TestIAMGRPCServiceTokenStatusCodes: the gRPC service maps the token
// service's errors to status codes: a blank token is InvalidArgument, an
// unwired verifier Unavailable, and issue and revoke Unimplemented.
func TestIAMGRPCServiceTokenStatusCodes(t *testing.T) {
	ctx := context.Background()
	wired := NewIAMGRPCService(slog.Default(), nil, nil)
	wired.SetTokenService(newIAMTokenFixture(t).tokens)
	unwired := NewIAMGRPCService(slog.Default(), nil, nil)

	_, err := wired.VerifyToken(ctx, &platformv1.VerifyIAMTokenRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	resp, err := unwired.VerifyToken(ctx, &platformv1.VerifyIAMTokenRequest{Token: "header.payload.signature"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Nil(t, resp, "an unwired verifier must never answer")

	for _, svc := range []*IAMGRPCService{wired, unwired} {
		created, err := svc.CreateToken(ctx, &platformv1.CreateIAMTokenRequest{TenantId: "tenant-1", UserId: "alice"})
		assert.Equal(t, codes.Unimplemented, status.Code(err))
		assert.Nil(t, created)
		revoked, err := svc.RevokeToken(ctx, &platformv1.RevokeIAMTokenRequest{TokenId: "token-1"})
		assert.Equal(t, codes.Unimplemented, status.Code(err))
		assert.Nil(t, revoked)
	}
}

// iamTokenTransport opens an SDK IAM client over one transport to the
// daemon's IAM service, whose token operations run on tokens.
type iamTokenTransport func(t *testing.T, svc *IAMGRPCService, tokens *IAMTokenService) *platformiam.Client

func iamTokenTransports() map[string]iamTokenTransport {
	return map[string]iamTokenTransport{
		"gRPC":     iamTokenGRPCClient,
		"QUIC":     iamTokenQUICClient,
		"MCP":      iamTokenMCPClient,
		"embedded": iamTokenEmbeddedClient,
	}
}

func iamClient(conn grpc.ClientConnInterface) *platformiam.Client {
	return platformiam.NewClientFromGRPC(platformv1.NewPlatformIAMServiceClient(conn))
}

func iamTokenGRPCClient(t *testing.T, svc *IAMGRPCService, _ *IAMTokenService) *platformiam.Client {
	tlsBundle := testutil.GenerateTestTLSBundle(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPCServices(t, lis, func(srv grpc.ServiceRegistrar) {
		platformv1.RegisterPlatformIAMServiceServer(srv, svc)
	}, grpc.Creds(credentials.NewTLS(tlsBundle.ServerTLSConfig())))
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(tlsBundle.ClientTLSConfig()),
	))
	return iamClient(connection(t, adapter, err))
}

// iamTokenQUICClient grants iam:read for verify and iam:write so that issue
// and revoke reach the refusal rather than a scope denial.
func iamTokenQUICClient(t *testing.T, svc *IAMGRPCService, _ *IAMTokenService) *platformiam.Client {
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"iam:read", "iam:write"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	handler.SetIAMGRPCService(svc)
	return iamClient(serveQUIC(t, testutil.GenerateTestTLSBundle(t), handler))
}

func iamTokenMCPClient(t *testing.T, _ *IAMGRPCService, tokens *IAMTokenService) *platformiam.Client {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{IAMTokens: tokens})
	srv := httptest.NewServer(mcpToolBridge(t, mcp.NewToolRegistry(provider, logging.DefaultLogger())))
	t.Cleanup(srv.Close)
	adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
	return iamClient(connection(t, adapter, err))
}

func iamTokenEmbeddedClient(t *testing.T, svc *IAMGRPCService, _ *IAMTokenService) *platformiam.Client {
	adapter, err := embedded.New(&embedded.ServiceRegistry{IAM: svc})
	return iamClient(connection(t, adapter, err))
}

// TestIAMTokenParity: the same token gets the same answer through the SDK
// over gRPC, QUIC, MCP and the embedded transport, because all of them call
// IAMTokenService.Verify; and none of them issues or revokes a token.
func TestIAMTokenParity(t *testing.T) {
	f := newIAMTokenFixture(t)
	svc := NewIAMGRPCService(slog.Default(), nil, nil)
	svc.SetTokenService(f.tokens)
	ctx := context.Background()

	for name, open := range iamTokenTransports() {
		t.Run(name, func(t *testing.T) {
			client := open(t, svc, f.tokens)

			got, err := client.VerifyToken(ctx, f.validToken(t))
			require.NoError(t, err)
			assert.True(t, got.GetValid())
			assert.Empty(t, got.GetReason())
			assert.Equal(t, "alice", got.GetUserId())
			assert.Equal(t, "tenant-1", got.GetTenantId())
			assert.Equal(t, []string{"iam:read"}, got.GetScopes())
			assert.Equal(t, f.expires.Unix(), got.GetExpiresAt())

			for reason, token := range f.rejectedTokens(t) {
				got, err := client.VerifyToken(ctx, token)
				require.NoError(t, err, reason)
				assert.False(t, got.GetValid(), reason)
				assert.Equal(t, string(reason), got.GetReason())
				assert.Empty(t, got.GetUserId(), reason)
			}
		})
	}
}

// TestIAMTokenRefusalParity: no transport issues or revokes a token; each
// carries the token service's refusal. The SDK's MCP wire client retries every
// error one second apart, so over MCP the refusal is asserted at the tool
// registry the MCP server runs.
func TestIAMTokenRefusalParity(t *testing.T) {
	f := newIAMTokenFixture(t)
	svc := NewIAMGRPCService(slog.Default(), nil, nil)
	svc.SetTokenService(f.tokens)
	ctx := context.Background()

	transports := iamTokenTransports()
	delete(transports, "MCP")
	for name, open := range transports {
		t.Run(name, func(t *testing.T) {
			client := open(t, svc, f.tokens)

			created, err := client.CreateToken(ctx, &platformv1.CreateIAMTokenRequest{TenantId: "tenant-1", UserId: "alice"})
			assert.ErrorContains(t, err, tokenRefusal)
			assert.Nil(t, created)
			assert.ErrorContains(t, client.RevokeToken(ctx, "token-1", ""), tokenRefusal)
		})
	}

	t.Run("MCP", func(t *testing.T) {
		registry := mcp.NewToolRegistry(
			NewMCPServiceProvider(&MCPServiceProviderConfig{IAMTokens: f.tokens}), logging.DefaultLogger())

		created, err := registry.ExecuteTool(ctx, "iam_create_token",
			map[string]interface{}{"tenant_id": "tenant-1", "user_id": "alice"})
		assert.ErrorIs(t, err, ErrIAMTokenViaOIDC{Op: iamTokenOpCreate})
		assert.Nil(t, created)

		revoked, err := registry.ExecuteTool(ctx, "iam_revoke_token", map[string]interface{}{"token_id": "token-1"})
		assert.ErrorIs(t, err, ErrIAMTokenViaOIDC{Op: iamTokenOpRevoke})
		assert.Nil(t, revoked, "a refused revocation must not report success")
	})
}

// TestIAMVerifyTokenToolErrors: the MCP tool returns the service's typed
// errors for a blank token and for a daemon with no validator wired, and
// never answers valid.
func TestIAMVerifyTokenToolErrors(t *testing.T) {
	f := newIAMTokenFixture(t)
	ctx := context.Background()
	registryFor := func(tokens *IAMTokenService) *mcp.ToolRegistry {
		return mcp.NewToolRegistry(
			NewMCPServiceProvider(&MCPServiceProviderConfig{IAMTokens: tokens}), logging.DefaultLogger())
	}

	t.Run("empty token", func(t *testing.T) {
		got, err := registryFor(f.tokens).ExecuteTool(ctx, "iam_verify_token", map[string]interface{}{"token": "   "})
		assert.ErrorIs(t, err, ErrIAMMissingParameter{Parameter: "token"})
		assert.Nil(t, got)
	})

	t.Run("no validator wired", func(t *testing.T) {
		got, err := registryFor(nil).ExecuteTool(ctx, "iam_verify_token",
			map[string]interface{}{"token": f.validToken(t)})
		assert.ErrorIs(t, err, ErrIAMTokenVerifierNotConfigured{})
		assert.Nil(t, got)
	})
}
