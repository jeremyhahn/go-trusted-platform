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
	"strings"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// iamTenantOnlyClient serves only the tenant sub-client; the IAM category
// never reaches any other part of the IAM client.
type iamTenantOnlyClient struct {
	quicbaassdk.IAMClient
	tenants quicbaassdk.IAMTenantClient
}

// mockIAMClientForTenant is an in-memory quicbaassdk.IAMTenantClient.
type mockIAMClientForTenant struct {
	mu      sync.RWMutex
	tenants map[string]*sdkiam.Tenant
}

func newMockIAMClientForTenant() *mockIAMClientForTenant {
	return &mockIAMClientForTenant{
		tenants: make(map[string]*sdkiam.Tenant),
	}
}

// Reconcile satisfies tenant.RoleReconciler; these tests do not inspect roles.
func (m *mockIAMClientForTenant) Reconcile(_ context.Context, tenantID string) (*sdkiam.ReconcileRolesResponse, error) {
	return &sdkiam.ReconcileRolesResponse{TenantID: tenantID}, nil
}

func (m *mockIAMClientForTenant) Create(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := req.ID
	if id == "" {
		id = req.Name + "-id"
	}

	t := &sdkiam.Tenant{
		ID:   id,
		Name: req.Name,
	}

	m.tenants[t.ID] = t
	return t, nil
}

func (m *mockIAMClientForTenant) Get(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return t, nil
}

func (m *mockIAMClientForTenant) List(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]sdkiam.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, *t)
	}

	return &sdkiam.ListTenantsResponse{
		Tenants:    tenants,
		Pagination: sdkiam.PaginationInfo{TotalCount: len(tenants)},
	}, nil
}

func (m *mockIAMClientForTenant) Update(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}

	if req.DisplayName != "" {
		t.DisplayName = req.DisplayName
	}
	return t, nil
}

func (m *mockIAMClientForTenant) Delete(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tenants, tenantID)
	return nil
}

func (c iamTenantOnlyClient) Tenant() quicbaassdk.IAMTenantClient {
	return c.tenants
}

// newIAMCategoryHandler builds a QUIC handler whose IAM delegate is backed by
// an in-memory tenant store. No platform TenantService is wired, so a request
// that strayed onto the platform tenancy path would fail as unavailable.
func newIAMCategoryHandler() *QUICServiceHandler {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	client := iamTenantOnlyClient{tenants: newMockIAMClientForTenant()}
	handler.SetIAMGRPCService(NewIAMGRPCService(logger.Slog(), client, nil))
	return handler
}

// iamCategoryRequest builds an OpIAMCategory request: the sub-opcode followed
// by the encoded platform.v1 message, as the SDK adapter sends it.
func iamCategoryRequest(t *testing.T, sub byte, msg any) *quicwire.Request {
	t.Helper()
	body, err := quicwire.EncodePayload(msg)
	if err != nil {
		t.Fatalf("encode %T: %v", msg, err)
	}
	return &quicwire.Request{Opcode: quicwire.OpIAMCategory, Payload: append([]byte{sub}, body...)}
}

func TestQUICIAMCategoryManagesIAMTenantRecords(t *testing.T) {
	handler := newIAMCategoryHandler()
	ctx := context.Background()

	resp := handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantCreate,
		&platformv1.CreateIAMTenantRequest{Id: "acme", Name: "Acme"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("create: status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}
	var created platformv1.IAMTenantResponse
	if err := quicwire.DecodePayload(resp.Payload, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.GetTenant().GetId() != "acme" {
		t.Fatalf("created tenant = %+v, want id acme", created.GetTenant())
	}

	resp = handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantGet,
		&platformv1.GetIAMTenantRequest{TenantId: "acme"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("get: status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}

	resp = handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantUpdate,
		&platformv1.UpdateIAMTenantRequest{TenantId: "acme", Name: "Acme Corp"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("update: status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}

	resp = handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantList,
		&platformv1.ListIAMTenantsRequest{}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("list: status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}
	var listed platformv1.ListIAMTenantsResponse
	if err := quicwire.DecodePayload(resp.Payload, &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.GetTenants()) != 1 {
		t.Fatalf("listed %d tenants, want 1", len(listed.GetTenants()))
	}

	resp = handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantDelete,
		&platformv1.DeleteIAMTenantRequest{TenantId: "acme"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("delete: status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}

	resp = handler.HandleRequest(ctx, iamCategoryRequest(t, quicwire.IAMSubTenantGet,
		&platformv1.GetIAMTenantRequest{TenantId: "acme"}))
	if resp.Status != quicwire.StatusNotFound {
		t.Fatalf("get after delete: status = 0x%02x, want NotFound", resp.Status)
	}
}

func TestQUICIAMCategoryRejectsBadRequests(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		handler *QUICServiceHandler
		payload []byte
		want    byte
	}{
		{"no iam service", newTestQUICServiceHandler(logging.DefaultLogger()), []byte{quicwire.IAMSubTenantList}, quicwire.StatusUnavailable},
		{"missing sub-opcode", newIAMCategoryHandler(), nil, quicwire.StatusInvalidRequest},
		// The authorization guard refuses an unclassified sub-opcode before
		// dispatch; TestQUICIAMCategoryHandlerRejectsUnknownSub covers the
		// handler's own refusal.
		{"unknown sub-opcode", newIAMCategoryHandler(), []byte{0x7F}, quicwire.StatusPermissionDenied},
		{"undecodable body", newIAMCategoryHandler(), []byte{quicwire.IAMSubTenantCreate, 0xC1}, quicwire.StatusInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpIAMCategory, Payload: tc.payload})
			if resp.Status != tc.want {
				t.Fatalf("status = 0x%02x, want 0x%02x (payload %q)", resp.Status, tc.want, resp.Payload)
			}
		})
	}
}

func TestQUICIAMCategoryHandlerRejectsUnknownSub(t *testing.T) {
	handler := newIAMCategoryHandler()
	resp := handler.handleIAMCategory(context.Background(), &quicwire.Request{Opcode: quicwire.OpIAMCategory, Payload: []byte{0x7F}})
	if resp.Status != quicwire.StatusNotImplemented {
		t.Fatalf("status = 0x%02x, want StatusNotImplemented", resp.Status)
	}
}

// TestQUICIAMCategoryCreateRequiresID shows the delegate's validation reaches
// the QUIC caller: the IAM service, not the platform TenantService, judged it.
func TestQUICIAMCategoryCreateRequiresID(t *testing.T) {
	handler := newIAMCategoryHandler()
	resp := handler.HandleRequest(context.Background(), iamCategoryRequest(t, quicwire.IAMSubTenantCreate,
		&platformv1.CreateIAMTenantRequest{Name: "Acme"}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("status = 0x%02x, want InvalidArgument (payload %q)", resp.Status, resp.Payload)
	}
	if !strings.Contains(string(resp.Payload), "IAMTenantCreate") {
		t.Fatalf("payload %q does not name the IAM tenant operation", resp.Payload)
	}
}
