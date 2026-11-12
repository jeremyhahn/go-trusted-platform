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

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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
	ctx := context.Background()

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
	ctx := context.Background()

	// Negative expiry rejected up front.
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId:        1,
		TenantId:         "t",
		ExpiresInSeconds: -1,
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative expiry: expected InvalidArgument, got %v", err)
	}

	// A missing (zero) expiry is refused before Generate: no credential is
	// ever issued without an expiration.
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId: 1,
		TenantId:  "t",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing expiry: expected InvalidArgument, got %v", err)
	}
	if svc.lastGenerate.ProfileID != 0 {
		t.Errorf("missing expiry: Generate must not be reached, got %+v", svc.lastGenerate)
	}

	// Typed domain errors map through the matcher table.
	svc.errGenerate = eab.ErrInvalidProfileID{ProfileID: 0}
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		TenantId:         "t",
		ExpiresInSeconds: 3600,
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid profile: expected InvalidArgument, got %v", err)
	}

	svc.errGenerate = eab.ErrKeyGenerationFailed{Cause: context.Canceled}
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
		ProfileId:        1,
		TenantId:         "t",
		ExpiresInSeconds: 3600,
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
	ctx := context.Background()
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t2"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 2, TenantID: "t1"})

	// Unfiltered: full store via Page walk.
	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetTotal() != 3 {
		t.Errorf("unfiltered total = %d, want 3", resp.GetTotal())
	}

	// By tenant.
	resp, err = service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: "t1"})
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()

	svc.errListByTenant = eab.ErrInvalidTenantID{TenantID: "x"}
	if _, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{
		TenantId: "x",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}

	svc.errListByTenant = nil
	svc.errPage = context.DeadlineExceeded
	if _, err := service.ListCredentials(ctx,
		&platformv1.ListEABCredentialsRequest{}); status.Code(err) != codes.Internal {
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
	ctx := context.Background()
	svc.cleanupCount = 4

	// Global cleanup delegates to CleanupExpired.
	resp, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetDeletedCount() != 4 {
		t.Errorf("deleted_count = %d, want 4", resp.GetDeletedCount())
	}

	// Tenant-scoped cleanup deletes only that tenant's expired creds.
	expired, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	otherTenant, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t2"})
	otherTenant.ExpiresAt = time.Now().Add(-time.Hour)

	resp, err = service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{
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

func TestEABGRPCService_CleanupExpiredCredentials_Errors(t *testing.T) {
	service, svc, _ := newEABGRPCFixture()
	ctx := context.Background()

	svc.errCleanupExpired = context.DeadlineExceeded
	if _, err := service.CleanupExpiredCredentials(ctx,
		&platformv1.CleanupExpiredEABCredentialsRequest{}); status.Code(err) != codes.Internal {
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
