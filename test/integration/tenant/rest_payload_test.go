//go:build integration

package tenant

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	wstenant "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDecodePayload(t *testing.T) {
	type tenantDoc struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	t.Run("enveloped body decodes its payload", func(t *testing.T) {
		var got tenantDoc
		body := []byte(`{"code":200,"success":true,"payload":{"id":"t-1","name":"acme"}}`)
		require.NoError(t, decodePayload(body, &got))
		require.Equal(t, tenantDoc{ID: "t-1", Name: "acme"}, got)
	})

	t.Run("enveloped array decodes its payload", func(t *testing.T) {
		var got []tenantDoc
		body := []byte(`{"code":200,"success":true,"payload":[{"id":"t-1"},{"id":"t-2"}]}`)
		require.NoError(t, decodePayload(body, &got))
		require.Len(t, got, 2)
		require.Equal(t, "t-2", got[1].ID)
	})

	t.Run("bare object decodes as is", func(t *testing.T) {
		var got tenantDoc
		require.NoError(t, decodePayload([]byte(`{"id":"t-1","name":"acme"}`), &got))
		require.Equal(t, tenantDoc{ID: "t-1", Name: "acme"}, got)
	})

	t.Run("bare array decodes as is", func(t *testing.T) {
		var got []tenantDoc
		require.NoError(t, decodePayload([]byte(` [{"id":"t-1"}]`), &got))
		require.Len(t, got, 1)
		require.Equal(t, "t-1", got[0].ID)
	})

	t.Run("empty body yields no payload", func(t *testing.T) {
		payload, err := unwrapPayload([]byte(" \n"))
		require.NoError(t, err)
		require.Nil(t, payload)
		got := tenantDoc{ID: "unchanged"}
		require.NoError(t, decodePayload(nil, &got))
		require.Equal(t, "unchanged", got.ID)
	})

	t.Run("malformed body fails", func(t *testing.T) {
		var got tenantDoc
		require.Error(t, decodePayload([]byte(`{"id":`), &got))
	})
}

// webserviceTenantServer answers the tenant service calls the REST adapter
// makes with fixed, known values.
type webserviceTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
}

func knownTenant() *platformv1.Tenant {
	return &platformv1.Tenant{Id: "t-known", Name: "acme", DisplayName: "Acme Corp"}
}

func (webserviceTenantServer) CreateTenant(context.Context, *platformv1.CreateTenantRequest) (*platformv1.CreateTenantResponse, error) {
	return &platformv1.CreateTenantResponse{Tenant: knownTenant()}, nil
}

func (webserviceTenantServer) GetTenant(context.Context, *platformv1.GetTenantRequest) (*platformv1.GetTenantResponse, error) {
	return &platformv1.GetTenantResponse{Tenant: knownTenant()}, nil
}

func (webserviceTenantServer) GetTenantByName(context.Context, *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {
	return &platformv1.GetTenantByNameResponse{Tenant: knownTenant()}, nil
}

func (webserviceTenantServer) UpdateTenant(context.Context, *platformv1.UpdateTenantRequest) (*platformv1.UpdateTenantResponse, error) {
	return &platformv1.UpdateTenantResponse{Tenant: knownTenant()}, nil
}

func (webserviceTenantServer) CheckQuota(context.Context, *platformv1.CheckQuotaRequest) (*platformv1.CheckQuotaResponse, error) {
	return &platformv1.CheckQuotaResponse{
		TenantId:  "t-known",
		Resource:  "vcpu",
		Amount:    4,
		Available: true,
		Message:   "within quota",
	}, nil
}

func knownComputeQuota() *platformv1.ComputeQuota {
	return &platformv1.ComputeQuota{MaxVms: 10, MaxContainers: 20, MaxVcpus: 32, MaxMemoryMb: 65536}
}

func knownNetworkQuota() *platformv1.NetworkQuota {
	return &platformv1.NetworkQuota{MaxBridges: 3, MaxPorts: 48, MaxBandwidthMbps: 1000}
}

func knownStorageQuota() *platformv1.StorageQuota {
	return &platformv1.StorageQuota{MaxVolumesGb: 500, MaxSnapshots: 25}
}

func (webserviceTenantServer) GetQuotas(context.Context, *platformv1.GetQuotasRequest) (*platformv1.GetQuotasResponse, error) {
	return &platformv1.GetQuotasResponse{
		TenantId: "t-known",
		Compute:  knownComputeQuota(),
		Network:  knownNetworkQuota(),
		Storage:  knownStorageQuota(),
	}, nil
}

// UpdateQuotas accepts only the known quotas, so a request body the
// webservice cannot decode into UpdateQuotasRequest fails the round trip.
func (webserviceTenantServer) UpdateQuotas(_ context.Context, req *platformv1.UpdateQuotasRequest) (*platformv1.UpdateQuotasResponse, error) {
	if req.GetTenantId() != "t-known" ||
		!proto.Equal(req.GetCompute(), knownComputeQuota()) ||
		!proto.Equal(req.GetNetwork(), knownNetworkQuota()) ||
		!proto.Equal(req.GetStorage(), knownStorageQuota()) {
		return nil, status.Errorf(codes.InvalidArgument, "unexpected quotas: %v", req)
	}
	return &platformv1.UpdateQuotasResponse{}, nil
}

func (webserviceTenantServer) GetUsage(context.Context, *platformv1.GetUsageRequest) (*platformv1.GetUsageResponse, error) {
	return &platformv1.GetUsageResponse{Usage: &platformv1.TenantUsage{
		TenantId:      "t-known",
		Vms:           2,
		Containers:    5,
		Vcpus:         8,
		MemoryMb:      16384,
		DiskGb:        120,
		Bridges:       1,
		Ports:         6,
		BandwidthMbps: 250,
		Volumes:       4,
		Snapshots:     3,
	}}, nil
}

func (webserviceTenantServer) GetTenantBarrierStatus(context.Context, *platformv1.GetTenantBarrierStatusRequest) (*platformv1.GetTenantBarrierStatusResponse, error) {
	return &platformv1.GetTenantBarrierStatusResponse{BarrierStatus: &platformv1.TenantBarrierStatus{
		TenantId:       "t-known",
		Sealed:         true,
		Initialized:    true,
		Strategy:       "tpm",
		HardwareBacked: true,
	}}, nil
}

// TestRESTAdapter_WebserviceResponses drives the adapter against the real
// webservice tenant router, so both its paths and its decoding of the
// camelCase protobuf replies are checked against what the handlers write.
func TestRESTAdapter_WebserviceResponses(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	pass := func(h http.Handler) http.Handler { return h }
	tr, err := wstenant.NewTenantRouter(logger, webserviceTenantServer{}, response.NewResponseWriter(logger, nil), wstenant.Authorization{
		RequireOwnTenantOrSystem:     pass,
		RequireSystemTenant:          pass,
		RequireOwnTenantNameOrSystem: pass,
	})
	require.NoError(t, err)
	parent := mux.NewRouter()
	tr.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	srv := httptest.NewServer(parent)
	t.Cleanup(srv.Close)

	a := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
	ctx := context.Background()

	requireKnownTenant := func(t *testing.T, got *TenantData) {
		t.Helper()
		require.NotNil(t, got)
		require.Equal(t, "t-known", got.ID)
		require.Equal(t, "acme", got.Name)
		require.Equal(t, "Acme Corp", got.DisplayName)
	}

	t.Run("CreateTenant", func(t *testing.T) {
		res, err := a.CreateTenant(ctx, CreateTenantOptions{Name: "acme"})
		require.NoError(t, err)
		requireKnownTenant(t, res.Tenant)
	})

	t.Run("GetTenant", func(t *testing.T) {
		res, err := a.GetTenant(ctx, GetTenantOptions{TenantID: "t-known"})
		require.NoError(t, err)
		requireKnownTenant(t, res.Tenant)
	})

	t.Run("GetTenantByName", func(t *testing.T) {
		res, err := a.GetTenantByName(ctx, GetTenantByNameOptions{Name: "acme"})
		require.NoError(t, err)
		requireKnownTenant(t, res.Tenant)
	})

	t.Run("UpdateTenant", func(t *testing.T) {
		display := "Acme Corp"
		res, err := a.UpdateTenant(ctx, UpdateTenantOptions{TenantID: "t-known", DisplayName: &display})
		require.NoError(t, err)
		requireKnownTenant(t, res.Tenant)
	})

	t.Run("CheckQuota", func(t *testing.T) {
		res, err := a.CheckQuota(ctx, CheckQuotaOptions{TenantID: "t-known", Resource: "vcpu", Amount: 4})
		require.NoError(t, err)
		require.Equal(t, &CheckQuotaResult{
			TenantID: "t-known",
			Resource: "vcpu",
			Amount:   4,
			Allowed:  true,
			Message:  "within quota",
		}, res)
	})

	knownCompute := &ComputeQuotaData{MaxVMs: 10, MaxContainers: 20, MaxVCPUs: 32, MaxMemoryMB: 65536}
	knownNetwork := &NetworkQuotaData{MaxBridges: 3, MaxPorts: 48, MaxBandwidthMbps: 1000}
	knownStorage := &StorageQuotaData{MaxVolumesGB: 500, MaxSnapshots: 25}

	t.Run("GetQuotas", func(t *testing.T) {
		res, err := a.GetQuotas(ctx, GetQuotasOptions{TenantID: "t-known"})
		require.NoError(t, err)
		require.Equal(t, &GetQuotasResult{
			TenantID: "t-known",
			Compute:  knownCompute,
			Network:  knownNetwork,
			Storage:  knownStorage,
		}, res)
	})

	t.Run("UpdateQuotas", func(t *testing.T) {
		res, err := a.UpdateQuotas(ctx, UpdateQuotasOptions{
			TenantID: "t-known",
			Compute:  &ComputeQuotaUpdate{MaxVMs: 10, MaxContainers: 20, MaxVCPUs: 32, MaxMemoryMB: 65536},
			Network:  &NetworkQuotaUpdate{MaxBridges: 3, MaxPorts: 48, MaxBandwidthMbps: 1000},
			Storage:  &StorageQuotaUpdate{MaxVolumesGB: 500, MaxSnapshots: 25},
		})
		require.NoError(t, err)
		require.Equal(t, &UpdateQuotasResult{
			TenantID: "t-known",
			Compute:  knownCompute,
			Network:  knownNetwork,
			Storage:  knownStorage,
		}, res)
	})

	t.Run("GetUsage", func(t *testing.T) {
		res, err := a.GetUsage(ctx, GetUsageOptions{TenantID: "t-known"})
		require.NoError(t, err)
		require.Equal(t, &GetUsageResult{
			TenantID:      "t-known",
			VMs:           2,
			Containers:    5,
			VCPUs:         8,
			MemoryMB:      16384,
			DiskGB:        120,
			Bridges:       1,
			Ports:         6,
			BandwidthMbps: 250,
			Volumes:       4,
			Snapshots:     3,
		}, res)
	})

	t.Run("TenantBarrierStatus", func(t *testing.T) {
		res, err := a.TenantBarrierStatus(ctx, TenantBarrierStatusOptions{TenantID: "t-known"})
		require.NoError(t, err)
		require.Equal(t, &TenantBarrierStatusResult{
			TenantID:       "t-known",
			Sealed:         true,
			Initialized:    true,
			Strategy:       "tpm",
			HardwareBacked: true,
		}, res)
	})
}
