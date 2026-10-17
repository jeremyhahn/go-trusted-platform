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
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	secrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

const scopeSystemTenant = "platform"

// countingSecretsClient answers every secrets call the adapter makes and
// counts the calls, which is what reaches the SDK's system namespace.
type countingSecretsClient struct {
	extSecretsClientMock
	calls atomic.Int32
}

func (c *countingSecretsClient) Store(context.Context, *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	c.calls.Add(1)
	return &secrets.StoreSecretResponse{Version: 1}, nil
}

func (c *countingSecretsClient) Get(_ context.Context, path string, _ ...secrets.GetOption) (*secrets.Secret, error) {
	c.calls.Add(1)
	return &secrets.Secret{Path: path, Data: map[string]interface{}{"_raw": []byte("hunter2")}, Version: 1}, nil
}

func (c *countingSecretsClient) List(context.Context, string) (*secrets.ListSecretsResponse, error) {
	c.calls.Add(1)
	return &secrets.ListSecretsResponse{}, nil
}

func (c *countingSecretsClient) Delete(context.Context, string) error {
	c.calls.Add(1)
	return nil
}

func (c *countingSecretsClient) SetRotationPolicy(context.Context, *secrets.SetRotationPolicyRequest) error {
	c.calls.Add(1)
	return nil
}

func (c *countingSecretsClient) GetRotationPolicy(context.Context, string) (*secrets.RotationPolicy, error) {
	c.calls.Add(1)
	return &secrets.RotationPolicy{Enabled: true}, nil
}

// secretsAdapterCalls invokes every SecretsServerAdapter method once.
func secretsAdapterCalls(adapter *SecretsServerAdapter) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"StoreSecret": func(ctx context.Context) error {
			_, err := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: "db/password", Data: []byte("x")})
			return err
		},
		"GetSecret": func(ctx context.Context) error {
			_, err := adapter.GetSecret(ctx, &pb.GetSecretRequest{SecretId: "db/password"})
			return err
		},
		"ListSecrets": func(ctx context.Context) error {
			_, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{})
			return err
		},
		"DeleteSecret": func(ctx context.Context) error {
			_, err := adapter.DeleteSecret(ctx, &pb.DeleteSecretRequest{SecretId: "db/password"})
			return err
		},
		"SetRotationPolicy": func(ctx context.Context) error {
			_, err := adapter.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{
				SecretId: "db/password", Policy: &pb.SecretRotationPolicy{Enabled: true},
			})
			return err
		},
		"GetRotationPolicy": func(ctx context.Context) error {
			_, err := adapter.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: "db/password"})
			return err
		},
	}
}

func newScopedSecretsAdapter() (*SecretsServerAdapter, *countingSecretsClient) {
	client := &countingSecretsClient{}
	adapter := NewSecretsServerAdapter(client, slog.Default())
	adapter.SetSystemTenant(scopeSystemTenant)
	return adapter, client
}

func grpcTenantContext(tenantID string) context.Context {
	return grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

func unixIdentityContext(tenantID string) context.Context {
	return context.WithValue(context.Background(), ContextKeyIdentity, &auth.Identity{ID: "operator", TenantID: tenantID})
}

func TestSecretsServerAdapter_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	transports := map[string]func(string) context.Context{
		"gRPC": grpcTenantContext,
		"Unix": unixIdentityContext,
	}
	for transport, tenantContext := range transports {
		adapter, client := newScopedSecretsAdapter()
		for method, call := range secretsAdapterCalls(adapter) {
			err := call(tenantContext("tenant-a"))
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s %s", transport, method)
			var refused tenant.ErrSystemScopeOnly
			assert.True(t, errors.As(err, &refused), "%s %s: %v", transport, method, err)
		}
		assert.Zero(t, client.calls.Load(), "%s: a tenant-bound caller reached the SDK", transport)
	}
}

func TestSecretsServerAdapter_SystemAndUnboundCallersReachTheSDK(t *testing.T) {
	t.Parallel()
	callers := map[string]context.Context{
		"gRPC system tenant": grpcTenantContext(scopeSystemTenant),
		"Unix system tenant": unixIdentityContext(scopeSystemTenant),
		"unbound operator":   context.Background(),
	}
	for name, ctx := range callers {
		adapter, client := newScopedSecretsAdapter()
		calls := secretsAdapterCalls(adapter)
		for method, call := range calls {
			assert.NoError(t, call(ctx), "%s %s", name, method)
		}
		assert.Equal(t, int32(len(calls)), client.calls.Load(), name)
	}
}

func TestKMSService_SetSystemTenant_ReachesTheSecretsAdapter(t *testing.T) {
	t.Parallel()
	client := &countingSecretsClient{}
	svc := &KMSService{secretsServer: NewSecretsServerAdapter(client, slog.Default())}
	svc.SetSystemTenant(scopeSystemTenant)

	_, err := svc.secretsServer.GetSecret(grpcTenantContext("tenant-a"), &pb.GetSecretRequest{SecretId: "db/password"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Zero(t, client.calls.Load())
}

// countingMCPSecrets is the MCP secrets service; every call is counted.
func countingMCPSecrets(calls *atomic.Int32) *lifecycleSecretsServiceMock {
	return &lifecycleSecretsServiceMock{
		storeSecretFunc: func(context.Context, *service.StoreSecretRequest) (*service.StoreSecretResponse, error) {
			calls.Add(1)
			return &service.StoreSecretResponse{SecretID: "db/password", Version: 1}, nil
		},
		getSecretFunc: func(context.Context, *service.GetSecretRequest) (*service.GetSecretResponse, error) {
			calls.Add(1)
			return &service.GetSecretResponse{SecretID: "db/password", Data: []byte("hunter2")}, nil
		},
		listSecretsFunc: func(context.Context, *service.ListSecretsRequest) (*service.ListSecretsResponse, error) {
			calls.Add(1)
			return &service.ListSecretsResponse{}, nil
		},
		deleteSecretFunc: func(context.Context, *service.DeleteSecretRequest) (*service.DeleteSecretResponse, error) {
			calls.Add(1)
			return &service.DeleteSecretResponse{}, nil
		},
		setRotationPolicyFunc: func(context.Context, *service.SetRotationPolicyRequest) (*service.SetRotationPolicyResponse, error) {
			calls.Add(1)
			return &service.SetRotationPolicyResponse{}, nil
		},
		getRotationPolicyFunc: func(context.Context, *service.GetRotationPolicyRequest) (*service.GetRotationPolicyResponse, error) {
			calls.Add(1)
			return &service.GetRotationPolicyResponse{}, nil
		},
	}
}

// mcpSecretsCalls invokes every MCP secrets tool method once.
func mcpSecretsCalls(provider *MCPServiceProvider) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"SecretStore": func(ctx context.Context) error {
			_, err := provider.SecretStore(ctx, &mcp.SecretStoreRequest{SecretID: "db/password", Data: []byte("x")})
			return err
		},
		"SecretGet": func(ctx context.Context) error {
			_, err := provider.SecretGet(ctx, "db/password", 0)
			return err
		},
		"SecretList": func(ctx context.Context) error {
			_, err := provider.SecretList(ctx, 10)
			return err
		},
		"SecretDelete": func(ctx context.Context) error {
			return provider.SecretDelete(ctx, "db/password")
		},
		"SecretSetRotationPolicy": func(ctx context.Context) error {
			_, err := provider.SecretSetRotationPolicy(ctx, &mcp.SecretSetRotationPolicyRequest{SecretID: "db/password", Enabled: true})
			return err
		},
		"SecretGetRotationPolicy": func(ctx context.Context) error {
			_, err := provider.SecretGetRotationPolicy(ctx, "db/password")
			return err
		},
	}
}

func newScopedMCPProvider(calls *atomic.Int32) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		SecretsService:   countingMCPSecrets(calls),
		PlatformTenantID: scopeSystemTenant,
		Logger:           slog.Default(),
	})
}

func mcpTenantContext(tenantID string) context.Context {
	return mcp.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

func TestMCPServiceProvider_Secrets_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := newScopedMCPProvider(&calls)
	for method, call := range mcpSecretsCalls(provider) {
		err := call(mcpTenantContext("tenant-a"))
		assert.Equal(t, codes.PermissionDenied, status.Code(err), method)
		var refused tenant.ErrSystemScopeOnly
		assert.True(t, errors.As(err, &refused), "%s: %v", method, err)
	}
	assert.Zero(t, calls.Load(), "a tenant-bound MCP caller reached the SDK")
}

func TestMCPServiceProvider_Secrets_SystemCallerReachesTheSDK(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := newScopedMCPProvider(&calls)
	methods := mcpSecretsCalls(provider)
	for method, call := range methods {
		require.NoError(t, call(mcpTenantContext(scopeSystemTenant)), method)
	}
	assert.Equal(t, int32(len(methods)), calls.Load())
}

func TestMCPServiceProvider_Secrets_NoServiceIsUnavailable(t *testing.T) {
	t.Parallel()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{PlatformTenantID: scopeSystemTenant, Logger: slog.Default()})
	_, err := provider.SecretGet(mcpTenantContext(scopeSystemTenant), "db/password", 0)
	var unavailable ErrServiceNotAvailable
	assert.True(t, errors.As(err, &unavailable), "%v", err)
}

func TestRequireSystemScopeContext(t *testing.T) {
	t.Parallel()
	assert.NoError(t, requireSystemScopeContext(context.Background(), scopeSystemTenant))
	assert.NoError(t, requireSystemScopeContext(grpcTenantContext(scopeSystemTenant), scopeSystemTenant))
	assert.NoError(t, requireSystemScopeContext(unixIdentityContext(""), scopeSystemTenant))

	err := requireSystemScopeContext(mcpTenantContext("tenant-a"), scopeSystemTenant)
	assert.Equal(t, tenant.ErrSystemScopeOnly{TenantID: "tenant-a"}, err)
}
