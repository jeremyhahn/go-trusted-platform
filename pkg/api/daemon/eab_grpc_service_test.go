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
	"testing"
	"time"

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
)

// newEABGRPCFixture builds an EABGRPCService against the shared fake
// servicer + delivery.
func newEABGRPCFixture() (*EABGRPCService, *fakeEABService, *fakeEABDelivery) {
	svc := newFakeEABService()
	del := &fakeEABDelivery{
		qrPayload:   []byte{0x89, 0x50, 0x4e, 0x47},
		url:         "https://acme.example/enroll?kid=x",
		urlWithPath: "https://acme.example/custom?kid=x",
	}
	return NewEABGRPCService(logging.DefaultLogger(), svc, del), svc, del
}

// sameTenantPEP is a decision point that allows a check only when the
// request tenant is the subject's own tenant, so tests of the caller-tenant
// rule run with a PEP wired (a nil PEP refuses every tenant-scoped call).
func sameTenantPEP() *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return &sdkiam.CheckResponse{Allowed: req.TenantID != "" && req.TenantID == req.Subject.TenantID}, nil
	}}
}

func TestNewEABGRPCService_NilLoggerDefaults(t *testing.T) {
	service := NewEABGRPCService(nil, nil, nil)
	if service == nil {
		t.Fatal("NewEABGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected default logger when nil supplied")
	}
}

// TestEABGRPCService_NilServiceReturnsUnavailable pins the requireService
// guard: every RPC on an unconfigured service must return a typed
// Unavailable status — never Unimplemented, never a panic.
func TestEABGRPCService_NilServiceReturnsUnavailable(t *testing.T) {
	service := NewEABGRPCService(logging.DefaultLogger(), nil, nil)
	ctx := context.Background()

	calls := []struct {
		name string
		fn   func() error
	}{
		{"CreateCredential", func() error {
			_, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{})
			return err
		}},
		{"GetCredential", func() error {
			_, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{})
			return err
		}},
		{"GetCredentialByKeyID", func() error {
			_, err := service.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{})
			return err
		}},
		{"ListCredentials", func() error {
			_, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{})
			return err
		}},
		{"RevokeCredential", func() error {
			_, err := service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{})
			return err
		}},
		{"ValidateCredential", func() error {
			_, err := service.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{})
			return err
		}},
		{"DeleteCredential", func() error {
			_, err := service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{})
			return err
		}},
		{"GetCredentialQRCode", func() error {
			_, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{})
			return err
		}},
		{"GetEnrollmentURL", func() error {
			_, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{})
			return err
		}},
		{"MarkCredentialUsed", func() error {
			_, err := service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{})
			return err
		}},
		{"CleanupExpiredCredentials", func() error {
			_, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{})
			return err
		}},
	}

	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatalf("%s: expected error with nil service", tc.name)
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("%s: expected gRPC status error, got %v", tc.name, err)
			}
			if st.Code() != codes.Unavailable {
				t.Errorf("%s: expected Unavailable, got %v", tc.name, st.Code())
			}
		})
	}
}

// TestEABGRPCService_NilDeliveryReturnsUnavailable pins the
// requireDelivery guard on the QR / URL RPCs.
func TestEABGRPCService_NilDeliveryReturnsUnavailable(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	service := NewEABGRPCService(logging.DefaultLogger(), svc, nil)
	ctx := context.Background()

	if _, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: cred.ID,
	}); status.Code(err) != codes.Unavailable {
		t.Errorf("QR: expected Unavailable, got %v", err)
	}
	if _, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: cred.ID,
	}); status.Code(err) != codes.Unavailable {
		t.Errorf("URL: expected Unavailable, got %v", err)
	}
}

func TestEABGRPCService_CreateCredential(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))

	resp, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId:        7,
		TenantId:         "tenant-1",
		ExpiresInSeconds: 3600,
		HmacKeyLength:    64,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := resp.GetCredential()
	if cred.GetId() == 0 {
		t.Error("expected non-zero credential id")
	}
	if cred.GetHmacKey() == "" {
		t.Error("expected hmac_key included on create per RFC 8555")
	}
	if cred.GetStatus() != platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE {
		t.Errorf("expected ACTIVE, got %v", cred.GetStatus())
	}
	if cred.GetCreatedAt() == nil || cred.GetExpiresAt() == nil {
		t.Error("expected created_at + expires_at timestamps")
	}
	if resp.GetTimestamp() == nil {
		t.Error("expected response timestamp")
	}
	if svc.lastGenerate.ExpiresIn != time.Hour || svc.lastGenerate.HMACKeyLen != 64 {
		t.Errorf("Generate params not threaded: %+v", svc.lastGenerate)
	}
	// The hmac_key wire form is base64url without padding.
	if _, decErr := base64.RawURLEncoding.DecodeString(cred.GetHmacKey()); decErr != nil {
		t.Errorf("hmac_key not raw-base64url: %v", decErr)
	}
}

func TestEABGRPCService_CreateCredential_Errors(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))

	// Negative expiry rejected up front.
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId:        1,
		TenantId:         "t",
		ExpiresInSeconds: -1,
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative expiry: expected InvalidArgument, got %v", err)
	}

	// Typed domain errors map through the matcher table.
	svc.errGenerate = eab.ErrInvalidProfileID{ProfileID: 0}
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		TenantId: "t",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid profile: expected InvalidArgument, got %v", err)
	}

	svc.errGenerate = eab.ErrKeyGenerationFailed{Cause: context.Canceled}
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId: 1,
		TenantId:  "t",
	}); status.Code(err) != codes.Internal {
		t.Errorf("keygen failure: expected Internal, got %v", err)
	}
}

func TestEABGRPCService_GetCredential(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: cred.ID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetCredential().GetId() != cred.ID {
		t.Errorf("id mismatch: %d", resp.GetCredential().GetId())
	}
	if resp.GetCredential().GetHmacKey() != "" {
		t.Error("Get must never include hmac_key")
	}
}

func TestEABGRPCService_GetCredential_NotFound(t *testing.T) {
	service, _, _ := newEABGRPCFixture()
	if _, err := service.GetCredential(context.Background(),
		&platformv1.GetEABCredentialRequest{CredentialId: 999}); status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestEABGRPCService_GetCredentialByKeyID(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.GetCredentialByKeyID(ctx,
		&platformv1.GetEABCredentialByKeyIDRequest{KeyId: cred.KeyID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetCredential().GetKeyId() != cred.KeyID {
		t.Errorf("key_id mismatch: %s", resp.GetCredential().GetKeyId())
	}

	if _, err := service.GetCredentialByKeyID(ctx,
		&platformv1.GetEABCredentialByKeyIDRequest{KeyId: "missing"}); status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestEABGRPCService_ListCredentials_FilterCascade(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t2"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 2, TenantID: "t1"})

	// Unfiltered over gRPC spans every tenant: no caller holds an IAM
	// decision for the empty tenant, so it is refused.
	if _, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unfiltered list: code = %v, want PermissionDenied", status.Code(err))
	}
	// The shared cascade still walks the full store for the MCP surface.
	all, err := collectEABCredentials(ctx, svc, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("unfiltered total = %d, want 3", len(all))
	}

	// By tenant.
	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: "t1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetTotal() != 2 {
		t.Errorf("tenant total = %d, want 2", resp.GetTotal())
	}

	// By profile, tenant refines.
	resp, err = service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		ProfileId: 1, TenantId: "t2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetTotal() != 1 {
		t.Errorf("profile+tenant total = %d, want 1", resp.GetTotal())
	}

	// HMAC keys never leak from list.
	for _, c := range resp.GetCredentials() {
		if c.GetHmacKey() != "" {
			t.Error("list leaked hmac_key")
		}
	}
}

func TestEABGRPCService_ListCredentials_StatusAndActiveFilters(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))
	c1, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_ = svc.Revoke(ctx, c1.ID)

	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:     "t1",
		StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetTotal() != 1 {
		t.Errorf("status filter total = %d, want 1", resp.GetTotal())
	}

	resp, err = service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		ActiveOnly: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetTotal() != 1 {
		t.Errorf("active_only total = %d, want 1", resp.GetTotal())
	}
}

func TestEABGRPCService_ListCredentials_Pagination(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))
	for i := 0; i < 5; i++ {
		_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	}

	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 2},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetCredentials()) != 2 {
		t.Errorf("page 2 size = %d, want 2", len(resp.GetCredentials()))
	}
	pg := resp.GetPagination()
	if pg.GetPage() != 2 || pg.GetPageSize() != 2 || pg.GetTotalPages() != 3 || pg.GetTotalItems() != 5 {
		t.Errorf("pagination = %+v, want page=2 size=2 pages=3 items=5", pg)
	}

	// Deterministic id-ascending ordering: page 2 holds ids 3 and 4.
	if resp.GetCredentials()[0].GetId() != 3 || resp.GetCredentials()[1].GetId() != 4 {
		t.Errorf("page 2 ids = %d,%d, want 3,4",
			resp.GetCredentials()[0].GetId(), resp.GetCredentials()[1].GetId())
	}

	// Out-of-range page: empty slice, totals intact.
	resp, err = service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		Pagination: &platformv1.PaginationRequest{Page: 9, PageSize: 2},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetCredentials()) != 0 || resp.GetPagination().GetTotalItems() != 5 {
		t.Errorf("out-of-range page: got %d creds, items=%d",
			len(resp.GetCredentials()), resp.GetPagination().GetTotalItems())
	}
}

func TestEABGRPCService_ListCredentials_SortOptions(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))
	for i := 0; i < 3; i++ {
		_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	}

	// Descending by id.
	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		Pagination: &platformv1.PaginationRequest{SortBy: "id", Ascending: false},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetCredentials()[0].GetId() != 3 {
		t.Errorf("descending sort first id = %d, want 3", resp.GetCredentials()[0].GetId())
	}

	// created_at ascending is stable (fake stamps identical times, falls
	// back to id ordering).
	resp, err = service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		Pagination: &platformv1.PaginationRequest{SortBy: "created_at", Ascending: true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetCredentials()[0].GetId() != 1 {
		t.Errorf("created_at sort first id = %d, want 1", resp.GetCredentials()[0].GetId())
	}

	// Unknown sort field: typed InvalidArgument.
	if _, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId:   "t1",
		Pagination: &platformv1.PaginationRequest{SortBy: "nope"},
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown sort field: expected InvalidArgument, got %v", err)
	}
}

func TestEABGRPCService_ListCredentials_PropagatesErrors(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))

	svc.errListByTenant = eab.ErrInvalidTenantID{TenantID: "x"}
	if _, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId: "x",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}

	svc.errListByTenant = nil
	svc.errPage = context.DeadlineExceeded
	if _, err := collectEABCredentials(ctx, svc, 0, ""); status.Code(eabErrorToStatus(err)) != codes.Internal {
		t.Errorf("expected Internal for unknown error, got %v", err)
	}
}

func TestEABGRPCService_RevokeCredential(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{
		CredentialId: cred.ID,
		RevokerId:    99,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
	if cred.Status != eab.StatusRevoked {
		t.Errorf("credential status = %v, want revoked", cred.Status)
	}

	if _, err := service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{
		CredentialId: 999,
	}); status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestEABGRPCService_ValidateCredential(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{
		KeyId:   cred.KeyID,
		HmacKey: base64.RawURLEncoding.EncodeToString(cred.HMACKey),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetValid() {
		t.Error("expected valid=true")
	}
	if resp.GetCredential().GetHmacKey() != "" {
		t.Error("validate must never include hmac_key")
	}
	if string(svc.lastValidateHMAC) != string(cred.HMACKey) {
		t.Error("decoded hmac not threaded to service")
	}
}

func TestEABGRPCService_ValidateCredential_Failures(t *testing.T) {
	service, _, _ := newEABGRPCFixture()
	ctx := context.Background()

	// Malformed base64: transport-level InvalidArgument.
	if _, err := service.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{
		KeyId:   "k",
		HmacKey: "!!!not-base64!!!",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad base64: expected InvalidArgument, got %v", err)
	}

	// Unknown credential: in-band valid=false, NOT an RPC error.
	resp, err := service.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{
		KeyId:   "missing",
		HmacKey: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetValid() {
		t.Error("expected valid=false")
	}
	if resp.GetErrorMessage() == "" {
		t.Error("expected error_message populated")
	}
}

func TestEABGRPCService_DeleteCredential(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{
		CredentialId: cred.ID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}

	if _, err := service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{
		CredentialId: cred.ID,
	}); status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound on second delete, got %v", err)
	}
}

func TestEABGRPCService_GetCredentialQRCode(t *testing.T) {
	service, svc, del := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: cred.ID,
		Size:         512,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetContentType() != "image/png" {
		t.Errorf("content_type = %q", resp.GetContentType())
	}
	if string(resp.GetQrCode()) != string(del.qrPayload) {
		t.Error("qr payload mismatch")
	}
	if del.lastSize != 512 {
		t.Errorf("requested size not threaded: %d", del.lastSize)
	}
}

func TestEABGRPCService_GetCredentialQRCode_Errors(t *testing.T) {
	service, svc, del := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	if _, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: cred.ID,
		Size:         -1,
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative size: expected InvalidArgument, got %v", err)
	}

	if _, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: 999,
	}); status.Code(err) != codes.NotFound {
		t.Errorf("missing credential: expected NotFound, got %v", err)
	}

	del.errQR = eab.ErrQRCodeGenerationFailed{Cause: context.Canceled}
	if _, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: cred.ID,
	}); status.Code(err) != codes.Internal {
		t.Errorf("qr failure: expected Internal, got %v", err)
	}
}

func TestEABGRPCService_GetEnrollmentURL(t *testing.T) {
	service, svc, del := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: cred.ID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetUrl() != del.url {
		t.Errorf("url = %q, want %q", resp.GetUrl(), del.url)
	}

	resp, err = service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: cred.ID,
		Path:         "/custom",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetUrl() != del.urlWithPath {
		t.Errorf("url = %q, want %q", resp.GetUrl(), del.urlWithPath)
	}
}

func TestEABGRPCService_GetEnrollmentURL_Errors(t *testing.T) {
	service, svc, del := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	if _, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: 999,
	}); status.Code(err) != codes.NotFound {
		t.Errorf("missing credential: expected NotFound, got %v", err)
	}

	del.errURL = eab.ErrInvalidCredential{Reason: "base URL not configured"}
	if _, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: cred.ID,
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("delivery failure: expected InvalidArgument, got %v", err)
	}
}

func TestEABGRPCService_MarkCredentialUsed(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	resp, err := service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{
		CredentialId: cred.ID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
	if cred.Status != eab.StatusUsed {
		t.Errorf("credential status = %v, want used", cred.Status)
	}

	if _, err := service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{
		CredentialId: 999,
	}); status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestEABGRPCService_CleanupExpiredCredentials(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))
	svc.cleanupCount = 4

	// Global cleanup over gRPC spans every tenant: no caller holds an IAM
	// decision for the empty tenant, so it is refused.
	if _, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("global cleanup: code = %v, want PermissionDenied", status.Code(err))
	}
	// The shared helper still delegates a global cleanup to CleanupExpired.
	deleted, err := cleanupExpiredEABCredentials(ctx, svc, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 4 {
		t.Errorf("deleted = %d, want 4", deleted)
	}

	// Tenant-scoped cleanup deletes only that tenant's expired creds.
	expired, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	otherTenant, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t2"})
	otherTenant.ExpiresAt = time.Now().Add(-time.Hour)

	resp, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{
		TenantId: "t1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetDeletedCount() != 1 {
		t.Errorf("tenant-scoped deleted_count = %d, want 1", resp.GetDeletedCount())
	}
	if _, getErr := svc.Get(ctx, otherTenant.ID); getErr != nil {
		t.Error("tenant-scoped cleanup must not touch other tenants")
	}
}

// TestEABGRPCService_CallerTenantBinding is SPEC row 125 (#2008): a
// tenant-bound caller may create, list and clean up EAB credentials only in
// its own tenant. Naming another tenant, or no tenant for the all-tenant
// cleanup, is refused with PermissionDenied before the service is reached.
func TestEABGRPCService_CallerTenantBinding(t *testing.T) {
	calls := map[string]func(*EABGRPCService, context.Context, string) error{
		"CreateCredential": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: tenantID})
			return err
		},
		"ListCredentials": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: tenantID})
			return err
		},
		"CleanupExpiredCredentials": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: tenantID})
			return err
		},
	}
	cases := []struct {
		name     string
		ctx      context.Context
		tenantID string
		wantCode codes.Code
	}{
		{name: "own tenant", ctx: tokenCallerContext("tenant-a"), tenantID: "tenant-a", wantCode: codes.OK},
		{name: "another tenant", ctx: tokenCallerContext("tenant-a"), tenantID: "tenant-b", wantCode: codes.PermissionDenied},
		{name: "every tenant", ctx: tokenCallerContext("tenant-a"), tenantID: "", wantCode: codes.PermissionDenied},
		{name: "unbound local caller", ctx: context.Background(), tenantID: "tenant-b", wantCode: codes.PermissionDenied},
		{name: "empty-tenant bound caller, every tenant", ctx: tokenCallerContext(""), tenantID: "", wantCode: codes.PermissionDenied},
		{name: "empty-tenant bound caller, named tenant", ctx: tokenCallerContext(""), tenantID: "tenant-a", wantCode: codes.PermissionDenied},
	}
	for method, call := range calls {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				service, svc, _ := newEABGRPCFixture()
				service.SetPEPClient(sameTenantPEP())
				err := call(service, tc.ctx, tc.tenantID)
				if got := status.Code(err); got != tc.wantCode {
					t.Fatalf("code = %v, want %v (err %v)", got, tc.wantCode, err)
				}
				if tc.wantCode == codes.PermissionDenied && svc.lastGenerate.TenantID != "" {
					t.Fatalf("refused create reached the service: %+v", svc.lastGenerate)
				}
			})
		}
	}
}

// TestEABGRPCService_PEPDecision drives the three tenant-scoped methods with a
// PEP configured: the PEP decision, not tenant equality, decides (SPEC row
// 125), so a policy-granted cross-tenant request passes and a denied
// own-tenant request is refused before the service is reached.
func TestEABGRPCService_PEPDecision(t *testing.T) {
	calls := map[string]struct {
		action string
		perm   string
		call   func(*EABGRPCService, context.Context, string) error
	}{
		"CreateCredential": {action: "write", perm: "eab:write", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: tenantID})
			return err
		}},
		"ListCredentials": {action: "read", perm: "eab:read", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: tenantID})
			return err
		}},
		"CleanupExpiredCredentials": {action: "write", perm: "eab:write", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: tenantID})
			return err
		}},
	}
	caller := grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{
		Subject:  "user-a",
		TenantID: "tenant-a",
		Roles:    []string{"eab-admin"},
	})
	cases := []struct {
		name      string
		ctx       context.Context
		tenantID  string
		allow     bool
		wantCode  codes.Code
		wantCheck bool
	}{
		{name: "allowed cross tenant", ctx: caller, tenantID: "tenant-b", allow: true, wantCode: codes.OK, wantCheck: true},
		{name: "denied own tenant", ctx: caller, tenantID: "tenant-a", allow: false, wantCode: codes.PermissionDenied, wantCheck: true},
		{name: "denied cross tenant", ctx: caller, tenantID: "tenant-b", allow: false, wantCode: codes.PermissionDenied, wantCheck: true},
		{name: "every tenant refused before the PEP", ctx: caller, tenantID: "", allow: true, wantCode: codes.PermissionDenied},
		{name: "empty-tenant caller refused before the PEP", ctx: tokenCallerContext(""), tenantID: "tenant-a", allow: true, wantCode: codes.PermissionDenied},
	}
	for method, m := range calls {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				service, svc, _ := newEABGRPCFixture()
				var got *sdkiam.CheckRequest
				service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
					got = req
					return &sdkiam.CheckResponse{Allowed: tc.allow}, nil
				}})
				err := m.call(service, tc.ctx, tc.tenantID)
				if code := status.Code(err); code != tc.wantCode {
					t.Fatalf("code = %v, want %v (err %v)", code, tc.wantCode, err)
				}
				if (got != nil) != tc.wantCheck {
					t.Fatalf("PEP checked = %v, want %v", got != nil, tc.wantCheck)
				}
				if got != nil {
					if got.TenantID != tc.tenantID || got.Subject.TenantID != "tenant-a" || got.Subject.ID != "user-a" || got.Action != m.action {
						t.Fatalf("check request = %+v", got)
					}
					// The RBAC authorizer joins resource and action into the
					// permission it looks up; it must be the granted one.
					if got.Resource != "eab" || got.Resource+":"+got.Action != m.perm {
						t.Fatalf("check permission = %q, want %q", got.Resource+":"+got.Action, m.perm)
					}
				}
				if tc.wantCode == codes.PermissionDenied && svc.lastGenerate.TenantID != "" {
					t.Fatalf("refused create reached the service: %+v", svc.lastGenerate)
				}
			})
		}
	}
}

// TestEABGRPCService_PEPError refuses the request when the PEP cannot decide.
func TestEABGRPCService_PEPError(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return nil, context.DeadlineExceeded
	}})
	_, err := service.CreateCredential(tokenCallerContext("tenant-a"), &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-a"})
	if status.Code(err) == codes.OK {
		t.Fatal("create passed with an undecided PEP")
	}
	if svc.lastGenerate.TenantID != "" {
		t.Fatalf("undecided create reached the service: %+v", svc.lastGenerate)
	}
}

// eabTenantCalls drives each tenant-scoped EAB method with the given
// caller and tenant, paired with the action its registered eab permission
// names (method_permissions.go).
var eabTenantCalls = []struct {
	method string
	action string
	call   func(*EABGRPCService, context.Context, string) error
}{
	{method: "CreateCredential", action: "write", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
		_, err := s.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: tenantID})
		return err
	}},
	{method: "ListCredentials", action: "read", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
		_, err := s.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: tenantID})
		return err
	}},
	{method: "CleanupExpiredCredentials", action: "write", call: func(s *EABGRPCService, ctx context.Context, tenantID string) error {
		_, err := s.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: tenantID})
		return err
	}},
}

// A bound caller on its own tenant is still refused when no decision point
// is wired: tenant equality alone is not an authorization decision.
func TestEABGRPCService_NoPEPRefusesBoundCaller(t *testing.T) {
	for _, tc := range eabTenantCalls {
		t.Run(tc.method, func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			err := tc.call(service, tokenCallerContext("tenant-a"), "tenant-a")
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", got, err)
			}
			if svc.lastGenerate.TenantID != "" {
				t.Fatalf("refused call reached the service: %+v", svc.lastGenerate)
			}
		})
	}
}

// A caller with no tenant binding is admitted only by the IAM decision on
// its authenticated peer and the method's registered eab permission.
func TestEABGRPCService_UnboundCallerDecidedByPEP(t *testing.T) {
	denyAll := func(seen *[]*sdkiam.CheckRequest) *mockSDKPEPClient {
		return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			*seen = append(*seen, req)
			return &sdkiam.CheckResponse{Allowed: false}, nil
		}}
	}
	for _, tc := range eabTenantCalls {
		t.Run(tc.method+"/no peer credentials", func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			var seen []*sdkiam.CheckRequest
			service.SetPEPClient(allowAllPEP(&seen))
			err := tc.call(service, context.Background(), "tenant-a")
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", got, err)
			}
			if len(seen) != 0 {
				t.Fatalf("PEP saw %d checks for a caller with no peer credentials", len(seen))
			}
			if svc.lastGenerate.TenantID != "" {
				t.Fatalf("refused call reached the service: %+v", svc.lastGenerate)
			}
		})
		t.Run(tc.method+"/unix operator allowed", func(t *testing.T) {
			service, _, _ := newEABGRPCFixture()
			var seen []*sdkiam.CheckRequest
			service.SetPEPClient(registeredPairPEP("eab", tc.action, &seen))
			if err := tc.call(service, unixOperatorContext(), "tenant-a"); err != nil {
				t.Fatalf("decided unix operator refused: %v", err)
			}
			if len(seen) != 1 {
				t.Fatalf("PEP checks = %d, want 1", len(seen))
			}
			if seen[0].Resource != "eab" || seen[0].Action != tc.action {
				t.Fatalf("check = %s:%s, want eab:%s", seen[0].Resource, seen[0].Action, tc.action)
			}
		})
		t.Run(tc.method+"/unix operator denied", func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			var seen []*sdkiam.CheckRequest
			service.SetPEPClient(denyAll(&seen))
			err := tc.call(service, unixOperatorContext(), "tenant-a")
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", got, err)
			}
			if len(seen) != 1 {
				t.Fatalf("PEP checks = %d, want 1", len(seen))
			}
			if svc.lastGenerate.TenantID != "" {
				t.Fatalf("denied call reached the service: %+v", svc.lastGenerate)
			}
		})
		t.Run(tc.method+"/unix operator no PEP", func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			err := tc.call(service, unixOperatorContext(), "tenant-a")
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", got, err)
			}
			if svc.lastGenerate.TenantID != "" {
				t.Fatalf("refused call reached the service: %+v", svc.lastGenerate)
			}
		})
	}
}

// eabUserStub is the IAM user directory the EAB service resolves mTLS
// callers against. Get answers only canonical numeric IDs, as the qrdb store
// does; a certificate email or CN must go through GetByEmail or
// FindByUsername.
type eabUserStub struct {
	users []*sdkiam.User
}

func (s *eabUserStub) Get(_ context.Context, tenantID, userID string) (*sdkiam.User, error) {
	for _, r := range userID {
		if r < '0' || r > '9' {
			return nil, sdkerrors.NewNotFound("get user", "not a canonical user id")
		}
	}
	for _, u := range s.users {
		if u.ID == userID && u.TenantID == tenantID {
			return u, nil
		}
	}
	return nil, sdkerrors.NewNotFound("get user", "no such user")
}

func (s *eabUserStub) GetByEmail(_ context.Context, tenantID, email string) (*sdkiam.User, error) {
	for _, u := range s.users {
		if u.Email == email && (u.TenantID == tenantID || tenantID == "") {
			return u, nil
		}
	}
	return nil, sdkerrors.NewNotFound("get user by email", "no such user")
}

func (s *eabUserStub) FindByUsername(_ context.Context, tenantID, username string) (*sdkiam.User, error) {
	for _, u := range s.users {
		if u.Username == username && (u.TenantID == tenantID || tenantID == "") {
			return u, nil
		}
	}
	return nil, sdkerrors.NewNotFound("find user", "no such user")
}

func TestEABGRPCService_MTLSCallerResolvesIAMUser(t *testing.T) {
	users := &eabUserStub{users: []*sdkiam.User{
		{ID: "1001", TenantID: "tenant-a", Username: "alice", Email: "alice@example.com", Roles: []string{"eab-admin"}},
		{ID: "1002", TenantID: "tenant-a", Username: "bob-cn", Email: "bob@example.com", Roles: []string{"eab-operator"}},
		{ID: "2001", TenantID: "tenant-b", Username: "mallory", Email: "mallory@example.com", Roles: []string{"eab-admin"}},
	}}
	mtls := func(id *auth.Identity) context.Context {
		return context.WithValue(context.Background(), ContextKeyIdentity, id)
	}
	cases := []struct {
		name      string
		identity  *auth.Identity
		wantCode  codes.Code
		wantID    string
		wantRoles []string
	}{
		{
			name:      "email SAN resolves to the stored admin",
			identity:  &auth.Identity{ID: "alice@example.com", Email: "alice@example.com", Name: "Alice", TenantID: "tenant-a"},
			wantCode:  codes.OK,
			wantID:    "1001",
			wantRoles: []string{"eab-admin"},
		},
		{
			name:      "CN resolves by username",
			identity:  &auth.Identity{ID: "bob-cn", Name: "bob-cn", TenantID: "tenant-a"},
			wantCode:  codes.OK,
			wantID:    "1002",
			wantRoles: []string{"eab-operator"},
		},
		{
			name:     "unknown subject denied without a PEP call",
			identity: &auth.Identity{ID: "nobody@example.com", Email: "nobody@example.com", Name: "nobody", TenantID: "tenant-a"},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "user of another tenant denied",
			identity: &auth.Identity{ID: "mallory@example.com", Email: "mallory@example.com", Name: "mallory", TenantID: "tenant-a"},
			wantCode: codes.PermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			service.SetUserClient(users)
			var got *sdkiam.CheckRequest
			service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				got = req
				allowed := req.Subject.ID == "1001" || req.Subject.ID == "1002"
				return &sdkiam.CheckResponse{Allowed: allowed && len(req.Subject.Roles) > 0}, nil
			}})
			_, err := service.CreateCredential(mtls(tc.identity), &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-a"})
			if code := status.Code(err); code != tc.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", code, tc.wantCode, err)
			}
			if tc.wantCode != codes.OK {
				if got != nil {
					t.Fatalf("PEP called for a refused caller: %+v", got)
				}
				if svc.lastGenerate.TenantID != "" {
					t.Fatalf("refused create reached the service: %+v", svc.lastGenerate)
				}
				return
			}
			if got == nil {
				t.Fatal("PEP not called")
			}
			if got.Subject.ID != tc.wantID || got.Subject.TenantID != "tenant-a" {
				t.Fatalf("subject = %+v, want ID %q in tenant-a", got.Subject, tc.wantID)
			}
			if len(got.Subject.Roles) != len(tc.wantRoles) || got.Subject.Roles[0] != tc.wantRoles[0] {
				t.Fatalf("subject roles = %v, want %v", got.Subject.Roles, tc.wantRoles)
			}
		})
	}
}

// TestEABGRPCService_QUICMTLSCallerResolvesIAMUser pins that a certificate
// caller on QUIC, which mtlsPeerAuthenticator turns into an AuthorizedContext
// with the operator scope and no roles, reaches the PEP as its stored IAM user
// and roles, the same as a certificate caller on gRPC. A QUIC bearer-token
// caller keeps its token subject and roles with no user lookup.
func TestEABGRPCService_QUICMTLSCallerResolvesIAMUser(t *testing.T) {
	users := &eabUserStub{users: []*sdkiam.User{
		{ID: "1001", TenantID: "tenant-a", Username: "alice", Email: "alice@example.com", Roles: []string{"eab-admin"}},
		{ID: "1002", TenantID: "tenant-a", Username: "bob-cn", Email: "bob@example.com", Roles: []string{"eab-operator"}},
	}}
	cases := []struct {
		name      string
		authCtx   *platformtoken.AuthorizedContext
		users     *eabUserStub
		wantCode  codes.Code
		wantID    string
		wantRoles []string
	}{
		{
			name:      "certificate CN resolves to the stored user",
			authCtx:   &platformtoken.AuthorizedContext{Subject: "bob-cn", Username: "bob-cn", TenantID: "tenant-a", Scopes: []string{mtlsOperatorScope}},
			users:     users,
			wantCode:  codes.OK,
			wantID:    "1002",
			wantRoles: []string{"eab-operator"},
		},
		{
			name:      "certificate email identity resolves by email when the CN differs",
			authCtx:   &platformtoken.AuthorizedContext{Subject: "alice@example.com", Username: "alice-cn", TenantID: "tenant-a", Scopes: []string{mtlsOperatorScope}},
			users:     users,
			wantCode:  codes.OK,
			wantID:    "1001",
			wantRoles: []string{"eab-admin"},
		},
		{
			name:     "unknown certificate CN denied without a PEP call",
			authCtx:  &platformtoken.AuthorizedContext{Subject: "nobody", Username: "nobody", TenantID: "tenant-a", Scopes: []string{mtlsOperatorScope}},
			users:    users,
			wantCode: codes.PermissionDenied,
		},
		{
			// An empty directory denies any lookup, so OK proves none was made.
			name:      "bearer token keeps its subject and roles",
			authCtx:   &platformtoken.AuthorizedContext{Subject: "tok-1", TenantID: "tenant-a", Scopes: []string{"eab:write"}, Roles: []string{"eab-admin"}},
			users:     &eabUserStub{},
			wantCode:  codes.OK,
			wantID:    "tok-1",
			wantRoles: []string{"eab-admin"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, svc, _ := newEABGRPCFixture()
			service.SetUserClient(tc.users)
			var got *sdkiam.CheckRequest
			service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				got = req
				return &sdkiam.CheckResponse{Allowed: len(req.Subject.Roles) > 0}, nil
			}})
			ctx := quic.ContextWithAuthorizedContext(context.Background(), tc.authCtx)
			_, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-a"})
			if code := status.Code(err); code != tc.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", code, tc.wantCode, err)
			}
			if tc.wantCode != codes.OK {
				if got != nil {
					t.Fatalf("PEP called for a refused caller: %+v", got)
				}
				if svc.lastGenerate.TenantID != "" {
					t.Fatalf("refused create reached the service: %+v", svc.lastGenerate)
				}
				return
			}
			if got == nil {
				t.Fatal("PEP not called")
			}
			if got.Subject.ID != tc.wantID || got.Subject.TenantID != "tenant-a" {
				t.Fatalf("subject = %+v, want ID %q in tenant-a", got.Subject, tc.wantID)
			}
			if len(got.Subject.Roles) != len(tc.wantRoles) || got.Subject.Roles[0] != tc.wantRoles[0] {
				t.Fatalf("subject roles = %v, want %v", got.Subject.Roles, tc.wantRoles)
			}
		})
	}
}

func TestEABGRPCService_MTLSCallerWithoutUserDirectory(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	called := false
	service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		called = true
		return &sdkiam.CheckResponse{Allowed: true}, nil
	}})
	ctx := context.WithValue(context.Background(), ContextKeyIdentity, &auth.Identity{ID: "alice@example.com", Email: "alice@example.com", TenantID: "tenant-a"})
	_, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-a"})
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (err %v)", code, err)
	}
	if called || svc.lastGenerate.TenantID != "" {
		t.Fatal("an unresolved mTLS caller reached the PEP or the service")
	}
}

// TestEABGRPCService_EveryBoundCallerSourceIsBound pins that every
// authenticated caller source callerTenant reads binds an EAB call to its
// tenant, so none of them passes as an unbound local caller.
func TestEABGRPCService_EveryBoundCallerSourceIsBound(t *testing.T) {
	calls := map[string]func(*EABGRPCService, context.Context, string) error{
		"CreateCredential": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: tenantID})
			return err
		},
		"ListCredentials": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: tenantID})
			return err
		},
		"CleanupExpiredCredentials": func(s *EABGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: tenantID})
			return err
		},
	}
	sources := map[string]func() context.Context{
		"QUIC legacy principal": func() context.Context {
			return quic.ContextWithLegacyPrincipal(context.Background(), &platformtoken.AuthorizedContext{Subject: "legacy-1", TenantID: "tenant-a"})
		},
		"REST platform token": func() context.Context {
			return iammw.SetAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Subject: "rest-1", TenantID: "tenant-a", Scopes: []string{"eab:write"}})
		},
		"REST session": func() context.Context {
			return iammw.SetSessionInContext(context.Background(), iammw.NewIAMSession(&sdkiam.User{ID: "u1", TenantID: "tenant-a"}))
		},
	}
	cases := []struct {
		name     string
		tenantID string
		wantCode codes.Code
	}{
		{name: "own tenant", tenantID: "tenant-a", wantCode: codes.OK},
		{name: "another tenant", tenantID: "tenant-b", wantCode: codes.PermissionDenied},
		{name: "every tenant", tenantID: "", wantCode: codes.PermissionDenied},
	}
	for method, call := range calls {
		for source, ctxFor := range sources {
			for _, tc := range cases {
				t.Run(method+"/"+source+"/"+tc.name, func(t *testing.T) {
					service, svc, _ := newEABGRPCFixture()
					service.SetPEPClient(sameTenantPEP())
					err := call(service, ctxFor(), tc.tenantID)
					if got := status.Code(err); got != tc.wantCode {
						t.Fatalf("code = %v, want %v (err %v)", got, tc.wantCode, err)
					}
					if tc.wantCode == codes.PermissionDenied && svc.lastGenerate.TenantID != "" {
						t.Fatalf("refused create reached the service: %+v", svc.lastGenerate)
					}
				})
			}
		}
	}
}

// TestEABGRPCService_WildcardBearerTokenIsNotACertificate pins that a bearer
// token carrying only the operator scope and no roles keeps its own subject:
// only a peer-certificate context, which has no token, is resolved through
// the IAM user directory.
func TestEABGRPCService_WildcardBearerTokenIsNotACertificate(t *testing.T) {
	authCtx := &platformtoken.AuthorizedContext{Subject: "tok-2", TenantID: "tenant-a", Scopes: []string{mtlsOperatorScope}}
	contexts := map[string]context.Context{
		"QUIC": quic.ContextWithToken(quic.ContextWithAuthorizedContext(context.Background(), authCtx), "bearer"),
		"MCP":  mcp.ContextWithToken(mcp.ContextWithAuthorizedContext(context.Background(), authCtx), "bearer"),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			service, _, _ := newEABGRPCFixture()
			// An empty directory denies any lookup, so OK proves none was made.
			service.SetUserClient(&eabUserStub{})
			var got *sdkiam.CheckRequest
			service.SetPEPClient(&mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				got = req
				return &sdkiam.CheckResponse{Allowed: true}, nil
			}})
			_, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-a"})
			if code := status.Code(err); code != codes.OK {
				t.Fatalf("code = %v, want OK (err %v)", code, err)
			}
			if got == nil {
				t.Fatal("PEP not called")
			}
			if got.Subject.ID != "tok-2" || got.Subject.TenantID != "tenant-a" {
				t.Fatalf("subject = %+v, want ID tok-2 in tenant-a", got.Subject)
			}
		})
	}
}

func TestEABGRPCService_CleanupExpiredCredentials_Errors(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := unixOperatorContext()
	service.SetPEPClient(allowAllPEP(nil))

	svc.errCleanupExpired = context.DeadlineExceeded
	if _, err := cleanupExpiredEABCredentials(ctx, svc, ""); status.Code(eabErrorToStatus(err)) != codes.Internal {
		t.Errorf("expected Internal, got %v", err)
	}

	svc.errCleanupExpired = nil
	svc.errListByTenant = eab.ErrInvalidTenantID{TenantID: "t1"}
	if _, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{
		TenantId: "t1",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

// TestEABCredentialToPb covers the converter happy path and zero-value
// handling.
func TestEABCredentialToPb(t *testing.T) {
	if eabCredentialToPb(nil, true) != nil {
		t.Error("nil credential must convert to nil")
	}

	cred := &eab.Credential{
		ID:        7,
		KeyID:     "k",
		HMACKey:   []byte{1, 2, 3},
		ProfileID: 9,
		TenantID:  "t",
		Status:    eab.StatusUsed,
		CreatedAt: time.Unix(1_700_000_000, 0),
		ExpiresAt: time.Unix(1_700_001_000, 0),
		UsedAt:    time.Unix(1_700_000_500, 0),
	}
	pb := eabCredentialToPb(cred, true)
	if pb.GetId() != 7 || pb.GetProfileId() != 9 || pb.GetTenantId() != "t" {
		t.Errorf("scalar fields mismatch: %+v", pb)
	}
	if pb.GetStatus() != platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED {
		t.Errorf("status = %v, want USED", pb.GetStatus())
	}
	if pb.GetHmacKey() == "" {
		t.Error("expected hmac_key when included")
	}
	if pb.GetCreatedAt().AsTime().Unix() != 1_700_000_000 ||
		pb.GetExpiresAt().AsTime().Unix() != 1_700_001_000 ||
		pb.GetUsedAt().AsTime().Unix() != 1_700_000_500 {
		t.Error("timestamps not converted")
	}

	// Zero timestamps stay nil; hmac excluded by default.
	minimal := eabCredentialToPb(&eab.Credential{ID: 1, Status: eab.StatusActive}, false)
	if minimal.GetHmacKey() != "" || minimal.GetCreatedAt() != nil ||
		minimal.GetExpiresAt() != nil || minimal.GetUsedAt() != nil {
		t.Errorf("zero-value handling broken: %+v", minimal)
	}
}

// TestEABStatusMapsAreInverse pins the two status maps as exact
// inverses so a new status can't be added to one side only.
func TestEABStatusMapsAreInverse(t *testing.T) {
	if len(eabStatusToPb) != len(pbStatusToEAB) {
		t.Fatalf("status map sizes differ: %d vs %d", len(eabStatusToPb), len(pbStatusToEAB))
	}
	for domain, pb := range eabStatusToPb {
		back, ok := pbStatusToEAB[pb]
		if !ok || back != domain {
			t.Errorf("status %v does not round-trip (pb=%v back=%v ok=%v)", domain, pb, back, ok)
		}
	}
}

// TestEABErrorMatchers verifies the full matcher table mapping.
func TestEABErrorMatchers(t *testing.T) {
	cases := []struct {
		err  error
		code codes.Code
	}{
		{eab.ErrCredentialNotFound{ID: 1}, codes.NotFound},
		{eab.ErrInvalidProfileID{ProfileID: 0}, codes.InvalidArgument},
		{eab.ErrInvalidTenantID{TenantID: ""}, codes.InvalidArgument},
		{eab.ErrInvalidExpiresAt{Reason: "x"}, codes.InvalidArgument},
		{eab.ErrInvalidCredential{Reason: "x"}, codes.InvalidArgument},
		{eab.ErrCredentialExpired{ID: 1}, codes.FailedPrecondition},
		{eab.ErrCredentialRevoked{ID: 1}, codes.FailedPrecondition},
		{eab.ErrCredentialAlreadyUsed{ID: 1}, codes.FailedPrecondition},
		{eab.ErrKeyGenerationFailed{Cause: context.Canceled}, codes.Internal},
		{eab.ErrQRCodeGenerationFailed{Cause: context.Canceled}, codes.Internal},
		{context.Canceled, codes.Internal},
	}
	for _, tc := range cases {
		if got := status.Code(eabErrorToStatus(tc.err)); got != tc.code {
			t.Errorf("%T -> %v, want %v", tc.err, got, tc.code)
		}
	}
}
