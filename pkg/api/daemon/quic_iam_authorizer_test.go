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
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
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

func TestErrPEPClientNotAvailable_Error(t *testing.T) {
	err := ErrPEPClientNotAvailable{}
	if err.Error() != "PEP client is not available" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
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
