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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// The tripwire clients embed a nil SDK client, so any call that reaches the
// SDK panics. A refusal test that sees the panic has caught a tenant-bound
// caller reaching the system namespace.
type tripwireKMSClient struct{ quicbaas.KMSClient }

type tripwireCryptoClient struct{ quicbaas.CryptoClient }

type tripwireDEKClient struct{ dekclient.Client }

type tripwireMCPKMS struct{ service.KMSService }

type tripwireMCPCrypto struct{ service.CryptoService }

var (
	contextType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType   = reflect.TypeOf((*error)(nil)).Elem()
)

// contextEntryPoints returns a call for every exported method of target whose
// first parameter is a context.Context and whose last result is an error and
// whose name has the prefix, so an entry point added later is covered without
// editing the test. Every further argument is a zero value; a pointer is an
// empty request.
func contextEntryPoints(target any, prefix string) map[string]func(context.Context) error {
	calls := make(map[string]func(context.Context) error)
	value := reflect.ValueOf(target)
	for i := 0; i < value.NumMethod(); i++ {
		name := value.Type().Method(i).Name
		method := value.Method(i)
		signature := method.Type()
		if !strings.HasPrefix(name, prefix) || signature.NumIn() == 0 || signature.In(0) != contextType {
			continue
		}
		if signature.NumOut() == 0 || signature.Out(signature.NumOut()-1) != errorType {
			continue
		}
		calls[name] = func(ctx context.Context) error {
			args := []reflect.Value{reflect.ValueOf(ctx)}
			for j := 1; j < signature.NumIn(); j++ {
				args = append(args, zeroArgument(signature.In(j)))
			}
			results := method.Call(args)
			last := results[len(results)-1]
			if last.IsNil() {
				return nil
			}
			return last.Interface().(error)
		}
	}
	return calls
}

func zeroArgument(argType reflect.Type) reflect.Value {
	if argType.Kind() == reflect.Pointer {
		return reflect.New(argType.Elem())
	}
	return reflect.Zero(argType)
}

// assertEveryEntryPointRefused calls each entry point as a tenant-bound caller
// and asserts the shared refusal: tenant.ErrSystemScopeOnly, PermissionDenied,
// and no call into the SDK.
func assertEveryEntryPointRefused(t *testing.T, label string, calls map[string]func(context.Context) error, ctx context.Context) {
	t.Helper()
	for name, call := range calls {
		var err error
		require.NotPanics(t, func() { err = call(ctx) }, "%s %s: a tenant-bound caller reached the SDK", label, name)
		if isGeneratedUnimplementedStub(err, name) {
			continue
		}
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s %s: %v", label, name, err)
		var refused tenant.ErrSystemScopeOnly
		if assert.True(t, errors.As(err, &refused), "%s %s: %v", label, name, err) {
			assert.Equal(t, "tenant-a", refused.TenantID, "%s %s", label, name)
		}
	}
}

// isGeneratedUnimplementedStub reports the answer of a method promoted from
// an embedded pb.Unimplemented*Server: it serves nothing and reaches no SDK
// (the tripwire would have panicked), so there is no namespace to refuse.
func isGeneratedUnimplementedStub(err error, method string) bool {
	answer, ok := status.FromError(err)
	return ok && answer.Code() == codes.Unimplemented && answer.Message() == "method "+method+" not implemented"
}

func newTripwireKMSAdapters() (*KMSServerAdapter, *CryptoServerAdapter, *DEKServerAdapter) {
	kmsAdapter := NewKMSServerAdapter(tripwireKMSClient{}, slog.Default())
	cryptoAdapter := NewCryptoServerAdapter(tripwireCryptoClient{}, slog.Default())
	dekAdapter := NewDEKServerAdapter(tripwireDEKClient{}, slog.Default())
	kmsAdapter.SetSystemTenant(scopeSystemTenant)
	cryptoAdapter.SetSystemTenant(scopeSystemTenant)
	dekAdapter.SetSystemTenant(scopeSystemTenant)
	return kmsAdapter, cryptoAdapter, dekAdapter
}

func TestKMSCryptoDEKAdapters_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	transports := map[string]func(string) context.Context{
		"gRPC": grpcTenantContext,
		"Unix": unixIdentityContext,
	}
	kmsAdapter, cryptoAdapter, dekAdapter := newTripwireKMSAdapters()
	adapters := map[string]any{"KMS": kmsAdapter, "Crypto": cryptoAdapter, "DEK": dekAdapter}
	for transport, tenantContext := range transports {
		for adapterName, adapter := range adapters {
			calls := contextEntryPoints(adapter, "")
			require.NotEmpty(t, calls, adapterName)
			assertEveryEntryPointRefused(t, transport+" "+adapterName, calls, tenantContext("tenant-a"))
		}
	}
	assert.Contains(t, contextEntryPoints(kmsAdapter, ""), "GenerateKey")
	assert.Contains(t, contextEntryPoints(cryptoAdapter, ""), "Encrypt")
	assert.Contains(t, contextEntryPoints(dekAdapter, ""), "CreateDEK")
}

func TestKMSCryptoDEKAdapters_SystemAndUnboundCallersReachTheSDK(t *testing.T) {
	t.Parallel()
	callers := map[string]context.Context{
		"gRPC system tenant": grpcTenantContext(scopeSystemTenant),
		"Unix system tenant": unixIdentityContext(scopeSystemTenant),
		"unbound operator":   context.Background(),
	}
	for name, ctx := range callers {
		kmsAdapter := NewKMSServerAdapter(&platformMockKMSClient{}, slog.Default())
		kmsAdapter.SetSystemTenant(scopeSystemTenant)
		_, err := kmsAdapter.ListKeys(ctx, &pb.ListKeysRequest{})
		assert.NoError(t, err, "%s KMS", name)

		cryptoAdapter := NewCryptoServerAdapter(&platformMockCryptoClient{}, slog.Default())
		cryptoAdapter.SetSystemTenant(scopeSystemTenant)
		_, err = cryptoAdapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: "key-1", Plaintext: []byte("data")})
		assert.NoError(t, err, "%s Crypto", name)

		dekAdapter := NewDEKServerAdapter(&fakeDEKClient{}, slog.Default())
		dekAdapter.SetSystemTenant(scopeSystemTenant)
		_, err = dekAdapter.ListDEKs(ctx, &pb.ListDEKsRequest{})
		assert.NoError(t, err, "%s DEK", name)
	}
}

func TestKMSCryptoDEKAdapters_NoClientIsUnavailable(t *testing.T) {
	t.Parallel()
	adapters := map[string]any{
		"KMS":    NewKMSServerAdapter(nil, slog.Default()),
		"Crypto": NewCryptoServerAdapter(nil, slog.Default()),
		"DEK":    NewDEKServerAdapter(nil, slog.Default()),
	}
	for adapterName, adapter := range adapters {
		for name, call := range contextEntryPoints(adapter, "") {
			err := call(grpcTenantContext("tenant-a"))
			if isGeneratedUnimplementedStub(err, name) {
				continue
			}
			assert.Equal(t, codes.Unavailable, status.Code(err), "%s %s", adapterName, name)
		}
	}
}

func TestKMSService_SetSystemTenant_ReachesTheCryptoAndDEKAdapters(t *testing.T) {
	t.Parallel()
	svc := &KMSService{
		kmsAdapter:   NewKMSServerAdapter(tripwireKMSClient{}, slog.Default()),
		cryptoServer: NewCryptoServerAdapter(tripwireCryptoClient{}, slog.Default()),
		dekServer:    NewDEKServerAdapter(tripwireDEKClient{}, slog.Default()),
	}
	svc.SetSystemTenant(scopeSystemTenant)

	ctx := grpcTenantContext("tenant-a")
	assertEveryEntryPointRefused(t, "KMS", map[string]func(context.Context) error{
		"GenerateKey": func(ctx context.Context) error {
			_, err := svc.kmsAdapter.GenerateKey(ctx, &pb.GenerateKeyRequest{})
			return err
		},
		"Encrypt": func(ctx context.Context) error {
			_, err := svc.cryptoServer.Encrypt(ctx, &pb.CryptoEncryptRequest{})
			return err
		},
		"CreateDEK": func(ctx context.Context) error {
			_, err := svc.dekServer.CreateDEK(ctx, &pb.CreateDEKRequest{})
			return err
		},
	}, ctx)
}

func TestPlatformKMSBackend_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	backend := newTestPlatformKMSBackend(tripwireKMSClient{}, tripwireCryptoClient{})
	backend.SetSystemTenant(scopeSystemTenant)

	calls := contextEntryPoints(backend, "")
	require.Contains(t, calls, "GenerateKey")
	require.Contains(t, calls, "Encrypt")
	require.Contains(t, calls, "BackendStatus")
	transports := map[string]func(string) context.Context{
		"gRPC": grpcTenantContext,
		"Unix": unixIdentityContext,
	}
	for transport, tenantContext := range transports {
		assertEveryEntryPointRefused(t, transport+" platform KMS", calls, tenantContext("tenant-a"))
	}
}

func TestPlatformKMSBackend_SystemAndUnboundCallersReachTheSDK(t *testing.T) {
	t.Parallel()
	callers := map[string]context.Context{
		"gRPC system tenant": grpcTenantContext(scopeSystemTenant),
		"unbound operator":   context.Background(),
	}
	for name, ctx := range callers {
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		backend.SetSystemTenant(scopeSystemTenant)
		_, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{})
		assert.NoError(t, err, "%s ListKeys", name)
		_, err = backend.GenerateRandom(ctx, &grpcapi.KMSGenerateRandomRequest{NumBytes: 16})
		assert.NoError(t, err, "%s GenerateRandom", name)
	}
}

func TestMCPServiceProvider_KMSAndCrypto_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService:       tripwireMCPKMS{},
		CryptoService:    tripwireMCPCrypto{},
		PlatformTenantID: scopeSystemTenant,
		Logger:           slog.Default(),
	})
	calls := contextEntryPoints(provider, "KMS")
	require.Contains(t, calls, "KMSCreateKey")
	require.Contains(t, calls, "KMSEncrypt")
	require.Contains(t, calls, "KMSBackendStatus")
	assertEveryEntryPointRefused(t, "MCP", calls, mcpTenantContext("tenant-a"))
}

func TestMCPServiceProvider_KMSAndCrypto_SystemCallerReachesTheSDK(t *testing.T) {
	t.Parallel()
	generate := func(_ context.Context, req *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
		return &service.GenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService:       &mockKMSServiceForMCPTests{},
		CryptoService:    &mockCryptoServiceForMCPTests{generateRandomFunc: generate},
		PlatformTenantID: scopeSystemTenant,
		Logger:           slog.Default(),
	})
	for name, ctx := range map[string]context.Context{
		"system tenant":    mcpTenantContext(scopeSystemTenant),
		"unbound operator": context.Background(),
	} {
		_, err := provider.KMSListKeys(ctx, 10, 0)
		assert.NoError(t, err, "%s KMSListKeys", name)
		random, err := provider.KMSGenerateRandom(ctx, 16)
		assert.NoError(t, err, "%s KMSGenerateRandom", name)
		assert.Len(t, random, 16, name)
	}
}

func TestMCPServiceProvider_KMSAndCrypto_NoServiceIsUnavailable(t *testing.T) {
	t.Parallel()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{PlatformTenantID: scopeSystemTenant, Logger: slog.Default()})
	for name, call := range contextEntryPoints(provider, "KMS") {
		var unavailable ErrServiceNotAvailable
		assert.True(t, errors.As(call(mcpTenantContext("tenant-a")), &unavailable), name)
	}
}
