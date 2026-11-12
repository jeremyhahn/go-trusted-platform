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
	"errors"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The MCP EAB tools and the gRPC EABService answer the same input with the
// same result and the same error class (#304). Each test drives both
// surfaces over one in-memory eab fake.

// eabParityFixture is one fake store reached through both surfaces.
type eabParityFixture struct {
	grpc *EABGRPCService
	mcp  *MCPServiceProvider
	svc  *fakeEABService
}

func newEABParityFixture() eabParityFixture {
	grpcService, svc, del := newEABGRPCFixture()
	return eabParityFixture{grpc: grpcService, mcp: newEABProvider(svc, del), svc: svc}
}

// seedEABCredential stores one credential of tenantID with the given status.
func seedEABCredential(t *testing.T, svc *fakeEABService, tenantID string, credStatus eab.Status) *eab.Credential {
	t.Helper()
	cred, err := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: tenantID})
	if err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	cred.Status = credStatus
	return cred
}

func TestEABParity_ErrorClass(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		arrange func(f eabParityFixture)
		grpc    func(f eabParityFixture) error
		mcp     func(f eabParityFixture) error
		want    codes.Code
	}{
		{
			name: "create negative expiry",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
					ProfileId: 1, TenantId: "t", ExpiresInSeconds: -60,
				})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABCreateCredential(ctx, 1, "t", -60, 0)
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name:    "create invalid tenant",
			arrange: func(f eabParityFixture) { f.svc.errGenerate = eab.ErrInvalidTenantID{} },
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
					ProfileId: 1, ExpiresInSeconds: 3600,
				})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABCreateCredential(ctx, 1, "", 3600, 0)
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "create missing expiry",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
					ProfileId: 1, TenantId: "t",
				})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABCreateCredential(ctx, 1, "t", 0, 0)
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "get not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: 404})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABGetCredential(ctx, 404)
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "get by key id not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{KeyId: "nope"})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABGetCredentialByKeyID(ctx, "nope")
				return err
			},
			want: codes.NotFound,
		},
		{
			name:    "list invalid tenant",
			arrange: func(f eabParityFixture) { f.svc.errListByTenant = eab.ErrInvalidTenantID{TenantID: "t"} },
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: "t"})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t"})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "revoke not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{CredentialId: 404})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABRevokeCredential(ctx, 404, 0)
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "validate undecodable hmac",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{
					KeyId: "k", HmacKey: "!!!not-base64!!!",
				})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABValidateCredential(ctx, "k", "!!!not-base64!!!")
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "delete not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{CredentialId: 404})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABDeleteCredential(ctx, 404)
				return err
			},
			want: codes.NotFound,
		},
		{
			name:    "mark used on a revoked credential",
			arrange: func(f eabParityFixture) { f.svc.errMarkUsed = eab.ErrCredentialRevoked{ID: 1} },
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{CredentialId: 1})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABMarkCredentialUsed(ctx, 1)
				return err
			},
			want: codes.FailedPrecondition,
		},
		{
			name:    "cleanup store failure",
			arrange: func(f eabParityFixture) { f.svc.errCleanupExpired = errors.New("store down") },
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABCleanupExpiredCredentials(ctx, "")
				return err
			},
			want: codes.Internal,
		},
		{
			name: "qr negative size",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{CredentialId: 1, Size: -1})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABGetCredentialQRCode(ctx, 1, -1)
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "qr not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{CredentialId: 404})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABGetCredentialQRCode(ctx, 404, 0)
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "enrollment url not found",
			grpc: func(f eabParityFixture) error {
				_, err := f.grpc.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{CredentialId: 404})
				return err
			},
			mcp: func(f eabParityFixture) error {
				_, err := f.mcp.EABGetEnrollmentURL(ctx, 404, "")
				return err
			},
			want: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newEABParityFixture()
			if tc.arrange != nil {
				tc.arrange(f)
			}
			if got := status.Code(tc.grpc(f)); got != tc.want {
				t.Fatalf("gRPC class = %v, want %v", got, tc.want)
			}
			if got := status.Code(tc.mcp(f)); got != tc.want {
				t.Errorf("MCP class = %v, want %v (the gRPC class)", got, tc.want)
			}
		})
	}
}

func TestEABParity_NotConfiguredIsUnavailable(t *testing.T) {
	ctx := context.Background()
	grpcService := NewEABGRPCService(nil, nil, nil)
	provider := newEABProvider(nil, nil)

	_, grpcErr := grpcService.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: 1})
	_, mcpErr := provider.EABGetCredential(ctx, 1)
	if status.Code(grpcErr) != codes.Unavailable || status.Code(mcpErr) != codes.Unavailable {
		t.Fatalf("classes gRPC=%v MCP=%v, want Unavailable on both", status.Code(grpcErr), status.Code(mcpErr))
	}
	var notConfigured ErrEABNotConfigured
	if !errors.As(mcpErr, &notConfigured) {
		t.Errorf("MCP error %v does not wrap ErrEABNotConfigured", mcpErr)
	}

	provider = newEABProvider(newFakeEABService(), nil)
	_, mcpErr = provider.EABGetEnrollmentURL(ctx, 1, "")
	if status.Code(mcpErr) != codes.Unavailable {
		t.Errorf("MCP class without delivery = %v, want Unavailable", status.Code(mcpErr))
	}
}

func TestEABParity_UnknownStatusFilterRefused(t *testing.T) {
	f := newEABParityFixture()
	seedEABCredential(t, f.svc, "t", eab.StatusActive)

	_, err := f.mcp.EABListCredentials(context.Background(), mcp.EABListParams{Status: "bogus"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("class = %v, want InvalidArgument", status.Code(err))
	}
	var unsupported ErrEABUnsupportedStatusFilter
	if !errors.As(err, &unsupported) || unsupported.Status != "bogus" {
		t.Errorf("error %v is not ErrEABUnsupportedStatusFilter{bogus}", err)
	}
}

// mcpCredentialIDs returns the id of each credential in an MCP list answer.
func mcpCredentialIDs(t *testing.T, result interface{}) []string {
	t.Helper()
	creds := result.(map[string]interface{})["credentials"].([]map[string]interface{})
	ids := make([]string, 0, len(creds))
	for _, c := range creds {
		ids = append(ids, c["id"].(string))
	}
	return ids
}

func grpcCredentialIDs(creds []*platformv1.EABCredential) []string {
	ids := make([]string, 0, len(creds))
	for _, c := range creds {
		ids = append(ids, strconv.FormatUint(c.GetId(), 10))
	}
	return ids
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEABParity_ListAnswer(t *testing.T) {
	ctx := context.Background()
	f := newEABParityFixture()
	for i := 0; i < 6; i++ {
		seedEABCredential(t, f.svc, "t", eab.StatusActive)
	}
	seedEABCredential(t, f.svc, "t", eab.StatusRevoked)
	seedEABCredential(t, f.svc, "other", eab.StatusActive)

	cases := []struct {
		name string
		grpc *platformv1.ListEABCredentialsRequest
		mcp  mcp.EABListParams
	}{
		{"whole store", &platformv1.ListEABCredentialsRequest{}, mcp.EABListParams{}},
		{"one tenant", &platformv1.ListEABCredentialsRequest{TenantId: "t"}, mcp.EABListParams{TenantID: "t"}},
		{
			"status filter",
			&platformv1.ListEABCredentialsRequest{StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED},
			mcp.EABListParams{Status: "revoked"},
		},
		{
			"second page",
			&platformv1.ListEABCredentialsRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 3}},
			mcp.EABListParams{Page: 2, PageSize: 3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grpcResp, err := f.grpc.ListCredentials(ctx, tc.grpc)
			if err != nil {
				t.Fatalf("gRPC: %v", err)
			}
			mcpResult, err := f.mcp.EABListCredentials(ctx, tc.mcp)
			if err != nil {
				t.Fatalf("MCP: %v", err)
			}
			want := grpcCredentialIDs(grpcResp.GetCredentials())
			if got := mcpCredentialIDs(t, mcpResult); !sameIDs(got, want) {
				t.Errorf("MCP ids = %v, gRPC ids = %v", got, want)
			}
			if total := mcpResult.(map[string]interface{})["total"].(int); int64(total) != grpcResp.GetTotal() {
				t.Errorf("MCP total = %d, gRPC total = %d", total, grpcResp.GetTotal())
			}
		})
	}
}

func TestEABParity_ReadAnswers(t *testing.T) {
	ctx := context.Background()
	f := newEABParityFixture()
	cred := seedEABCredential(t, f.svc, "t", eab.StatusActive)

	grpcGet, err := f.grpc.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: cred.ID})
	if err != nil {
		t.Fatalf("gRPC get: %v", err)
	}
	mcpGet, err := f.mcp.EABGetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("MCP get: %v", err)
	}
	got := mcpGet.(map[string]interface{})
	want := grpcGet.GetCredential()
	if got["id"] != strconv.FormatUint(want.GetId(), 10) || got["key_id"] != want.GetKeyId() ||
		got["tenant_id"] != want.GetTenantId() || pbStatusToEAB[want.GetStatus()].String() != got["status"] {
		t.Errorf("MCP get %v differs from gRPC get %v", got, want)
	}
	if _, leaked := got["hmac_key"]; leaked || want.GetHmacKey() != "" {
		t.Error("get must not return the HMAC key on either surface")
	}

	hmacKey := base64.RawURLEncoding.EncodeToString(cred.HMACKey)
	grpcValid, err := f.grpc.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{KeyId: "missing", HmacKey: hmacKey})
	if err != nil {
		t.Fatalf("gRPC validate: %v", err)
	}
	mcpValid, err := f.mcp.EABValidateCredential(ctx, "missing", hmacKey)
	if err != nil {
		t.Fatalf("MCP validate: %v", err)
	}
	valid := mcpValid.(map[string]interface{})
	if valid["valid"] != grpcValid.GetValid() || valid["error_message"] != grpcValid.GetErrorMessage() {
		t.Errorf("MCP validate %v differs from gRPC validate %v", valid, grpcValid)
	}

	grpcQR, err := f.grpc.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{CredentialId: cred.ID})
	if err != nil {
		t.Fatalf("gRPC qr: %v", err)
	}
	mcpQR, err := f.mcp.EABGetCredentialQRCode(ctx, cred.ID, 0)
	if err != nil {
		t.Fatalf("MCP qr: %v", err)
	}
	if mcpQR.(map[string]interface{})["qr_code"] != base64.StdEncoding.EncodeToString(grpcQR.GetQrCode()) {
		t.Error("MCP QR payload differs from the gRPC one")
	}

	grpcURL, err := f.grpc.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{CredentialId: cred.ID})
	if err != nil {
		t.Fatalf("gRPC url: %v", err)
	}
	mcpURL, err := f.mcp.EABGetEnrollmentURL(ctx, cred.ID, "")
	if err != nil {
		t.Fatalf("MCP url: %v", err)
	}
	if mcpURL.(map[string]interface{})["url"] != grpcURL.GetUrl() {
		t.Error("MCP enrollment URL differs from the gRPC one")
	}
}

func TestEABParity_TenantScopedCleanup(t *testing.T) {
	ctx := context.Background()
	seed := func(f eabParityFixture) *eab.Credential {
		seedEABCredential(t, f.svc, "a", eab.StatusExpired)
		seedEABCredential(t, f.svc, "a", eab.StatusActive)
		return seedEABCredential(t, f.svc, "b", eab.StatusExpired)
	}

	viaGRPC := newEABParityFixture()
	otherGRPC := seed(viaGRPC)
	grpcResp, err := viaGRPC.grpc.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "a"})
	if err != nil {
		t.Fatalf("gRPC cleanup: %v", err)
	}

	viaMCP := newEABParityFixture()
	otherMCP := seed(viaMCP)
	mcpResult, err := viaMCP.mcp.EABCleanupExpiredCredentials(ctx, "a")
	if err != nil {
		t.Fatalf("MCP cleanup: %v", err)
	}

	if got := mcpResult.(map[string]interface{})["deleted_count"].(int); int64(got) != int64(grpcResp.GetDeletedCount()) {
		t.Errorf("MCP deleted %d, gRPC deleted %d", got, grpcResp.GetDeletedCount())
	}
	if len(viaMCP.svc.byID) != len(viaGRPC.svc.byID) {
		t.Errorf("MCP left %d credentials, gRPC left %d", len(viaMCP.svc.byID), len(viaGRPC.svc.byID))
	}
	if _, kept := viaGRPC.svc.byID[otherGRPC.ID]; !kept {
		t.Error("gRPC tenant-a cleanup deleted tenant-b's credential")
	}
	if _, kept := viaMCP.svc.byID[otherMCP.ID]; !kept {
		t.Error("MCP tenant-a cleanup deleted tenant-b's credential")
	}
}
