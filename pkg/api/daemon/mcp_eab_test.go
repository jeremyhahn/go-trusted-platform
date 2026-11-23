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
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeEABService implements EABServicer for in-memory testing. It records
// the most recent call for each method so tests can assert delegation.
type fakeEABService struct {
	// Stored credentials keyed by ID and KeyID.
	byID    map[uint64]*eab.Credential
	byKeyID map[string]*eab.Credential
	nextID  uint64

	// Last-call record for assertion.
	lastGenerate     eab.GenerateParams
	lastValidateHMAC []byte
	cleanupCount     int

	// Errors injected per method (zero = none).
	errGenerate       error
	errGet            error
	errGetByKeyID     error
	errListByProfile  error
	errListByTenant   error
	errRevoke         error
	errValidate       error
	errDelete         error
	errMarkUsed       error
	errCleanupExpired error
	errPage           error
}

func newFakeEABService() *fakeEABService {
	return &fakeEABService{
		byID:    map[uint64]*eab.Credential{},
		byKeyID: map[string]*eab.Credential{},
	}
}

func (f *fakeEABService) Generate(ctx context.Context, p eab.GenerateParams) (*eab.Credential, error) {
	f.lastGenerate = p
	if f.errGenerate != nil {
		return nil, f.errGenerate
	}
	f.nextID++
	cred := &eab.Credential{
		ID:        f.nextID,
		KeyID:     "key-" + string(rune('a'+f.nextID-1)),
		HMACKey:   []byte{0x01, 0x02, 0x03, 0x04},
		ProfileID: p.ProfileID,
		TenantID:  p.TenantID,
		Status:    eab.StatusActive,
		CreatedAt: time.Unix(1_700_000_000, 0),
	}
	if p.ExpiresIn > 0 {
		cred.ExpiresAt = cred.CreatedAt.Add(p.ExpiresIn)
	}
	f.byID[cred.ID] = cred
	f.byKeyID[cred.KeyID] = cred
	return cred, nil
}

func (f *fakeEABService) Get(ctx context.Context, id uint64) (*eab.Credential, error) {
	if f.errGet != nil {
		return nil, f.errGet
	}
	cred, ok := f.byID[id]
	if !ok {
		return nil, eab.ErrCredentialNotFound{ID: id}
	}
	return cred, nil
}

func (f *fakeEABService) GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error) {
	if f.errGetByKeyID != nil {
		return nil, f.errGetByKeyID
	}
	cred, ok := f.byKeyID[keyID]
	if !ok {
		return nil, eab.ErrCredentialNotFound{KeyID: keyID}
	}
	return cred, nil
}

func (f *fakeEABService) ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
	if f.errListByProfile != nil {
		return nil, f.errListByProfile
	}
	out := make([]*eab.Credential, 0)
	for _, c := range f.byID {
		if c.ProfileID == profileID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeEABService) ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
	if f.errListByTenant != nil {
		return nil, f.errListByTenant
	}
	out := make([]*eab.Credential, 0)
	for _, c := range f.byID {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeEABService) Revoke(ctx context.Context, id uint64) error {
	if f.errRevoke != nil {
		return f.errRevoke
	}
	cred, ok := f.byID[id]
	if !ok {
		return eab.ErrCredentialNotFound{ID: id}
	}
	cred.Status = eab.StatusRevoked
	return nil
}

func (f *fakeEABService) Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
	f.lastValidateHMAC = append([]byte(nil), hmacKey...)
	if f.errValidate != nil {
		return nil, f.errValidate
	}
	cred, ok := f.byKeyID[keyID]
	if !ok {
		return nil, eab.ErrCredentialNotFound{KeyID: keyID}
	}
	return cred, nil
}

func (f *fakeEABService) Delete(ctx context.Context, id uint64) error {
	if f.errDelete != nil {
		return f.errDelete
	}
	cred, ok := f.byID[id]
	if !ok {
		return eab.ErrCredentialNotFound{ID: id}
	}
	delete(f.byID, id)
	delete(f.byKeyID, cred.KeyID)
	return nil
}

func (f *fakeEABService) MarkUsed(ctx context.Context, id uint64) error {
	if f.errMarkUsed != nil {
		return f.errMarkUsed
	}
	cred, ok := f.byID[id]
	if !ok {
		return eab.ErrCredentialNotFound{ID: id}
	}
	cred.Status = eab.StatusUsed
	cred.UsedAt = time.Unix(1_700_000_100, 0)
	return nil
}

func (f *fakeEABService) CleanupExpired(ctx context.Context) (int, error) {
	if f.errCleanupExpired != nil {
		return 0, f.errCleanupExpired
	}
	return f.cleanupCount, nil
}

func (f *fakeEABService) Count(ctx context.Context) (int, error) {
	return len(f.byID), nil
}

func (f *fakeEABService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*eab.Credential], error) {
	if f.errPage != nil {
		return datastore.PageResult[*eab.Credential]{}, f.errPage
	}
	// Single-page store: return everything on page 1, nothing after.
	if query.Page > 1 {
		return datastore.PageResult[*eab.Credential]{Page: query.Page, PageSize: query.PageSize}, nil
	}
	out := make([]*eab.Credential, 0, len(f.byID))
	for _, c := range f.byID {
		out = append(out, c)
	}
	return datastore.PageResult[*eab.Credential]{
		Entities: out,
		Page:     1,
		PageSize: query.PageSize,
		Total:    len(out),
		HasMore:  false,
	}, nil
}

// fakeEABDelivery implements EABDeliveryServicer.
type fakeEABDelivery struct {
	qrPayload   []byte
	url         string
	urlWithPath string
	lastSize    int
	errQR       error
	errURL      error
	errURLPath  error
}

func (f *fakeEABDelivery) ToQRCode(_ *eab.Credential) ([]byte, error) {
	if f.errQR != nil {
		return nil, f.errQR
	}
	return f.qrPayload, nil
}

func (f *fakeEABDelivery) ToQRCodeSized(_ *eab.Credential, size int) ([]byte, error) {
	f.lastSize = size
	if f.errQR != nil {
		return nil, f.errQR
	}
	return f.qrPayload, nil
}

func (f *fakeEABDelivery) ToURL(_ *eab.Credential) (string, error) {
	if f.errURL != nil {
		return "", f.errURL
	}
	return f.url, nil
}

func (f *fakeEABDelivery) ToURLWithPath(_ *eab.Credential, _ string) (string, error) {
	if f.errURLPath != nil {
		return "", f.errURLPath
	}
	return f.urlWithPath, nil
}

// Compile-time interface checks.
var (
	_ EABServicer         = (*fakeEABService)(nil)
	_ EABDeliveryServicer = (*fakeEABDelivery)(nil)
	_ mcp.EABProvider     = (*MCPServiceProvider)(nil)
)

// =============================================================================
// Tests
// =============================================================================

func newEABProvider(svc EABServicer, del EABDeliveryServicer) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		EABService:  svc,
		EABDelivery: del,
	})
}

func TestEAB_NotConfigured(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	ctx := unixOperatorContext()

	checks := []struct {
		name string
		fn   func() (interface{}, error)
	}{
		{"create", func() (interface{}, error) {
			return p.EABCreateCredential(ctx, 1, "t", 0, 0)
		}},
		{"get", func() (interface{}, error) { return p.EABGetCredential(ctx, 1) }},
		{"get_by_key_id", func() (interface{}, error) { return p.EABGetCredentialByKeyID(ctx, "k") }},
		{"list", func() (interface{}, error) { return p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t"}) }},
		{"revoke", func() (interface{}, error) { return p.EABRevokeCredential(ctx, 1, 0) }},
		{"validate", func() (interface{}, error) { return p.EABValidateCredential(ctx, "k", "AAECAwQF") }},
		{"delete", func() (interface{}, error) { return p.EABDeleteCredential(ctx, 1) }},
		{"mark_used", func() (interface{}, error) { return p.EABMarkCredentialUsed(ctx, 1) }},
		{"cleanup", func() (interface{}, error) { return p.EABCleanupExpiredCredentials(ctx, "") }},
		{"qr", func() (interface{}, error) { return p.EABGetCredentialQRCode(ctx, 1, 256) }},
		{"url", func() (interface{}, error) { return p.EABGetEnrollmentURL(ctx, 1, "") }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn()
			if err == nil {
				t.Fatalf("%s: expected error when EAB service not configured", tc.name)
			}
			var notConfigured ErrEABNotConfigured
			if !errors.As(err, &notConfigured) {
				t.Errorf("%s: expected ErrEABNotConfigured, got %v", tc.name, err)
			}
		})
	}
}

func TestEAB_CreateCredential_HappyPath(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	ctx := unixOperatorContext()

	result, err := p.EABCreateCredential(ctx, 7, "tenant-1", 3600, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if id := m["id"].(string); id == "" || id == "0" {
		t.Errorf("expected non-zero decimal-string id, got %v", m["id"])
	}
	if m["hmac_key"] == nil {
		t.Error("expected hmac_key included on create per RFC 8555")
	}
	if m["status"] != eab.StatusActive.String() {
		t.Errorf("expected status active, got %v", m["status"])
	}
	if svc.lastGenerate.ProfileID != 7 || svc.lastGenerate.TenantID != "tenant-1" {
		t.Errorf("Generate args not threaded: %+v", svc.lastGenerate)
	}
	if svc.lastGenerate.ExpiresIn != time.Hour {
		t.Errorf("expected ExpiresIn=1h, got %v", svc.lastGenerate.ExpiresIn)
	}
	if svc.lastGenerate.HMACKeyLen != 64 {
		t.Errorf("expected HMACKeyLen=64, got %d", svc.lastGenerate.HMACKeyLen)
	}
}

func TestEAB_CreateCredential_NoExpiry(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	result, err := p.EABCreateCredential(unixOperatorContext(), 1, "t", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if _, has := m["expires_at"]; has {
		t.Error("expected no expires_at field when expiresInSeconds=0")
	}
	if svc.lastGenerate.ExpiresIn != 0 {
		t.Errorf("expected ExpiresIn=0, got %v", svc.lastGenerate.ExpiresIn)
	}
}

func TestEAB_CreateCredential_PropagatesError(t *testing.T) {
	svc := newFakeEABService()
	svc.errGenerate = eab.ErrInvalidProfileID{ProfileID: 0}
	p := newEABProvider(svc, nil)
	_, err := p.EABCreateCredential(unixOperatorContext(), 0, "", 0, 0)
	if err == nil {
		t.Fatal("expected error from underlying service")
	}
}

func TestEAB_GetCredential(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	result, err := p.EABGetCredential(unixOperatorContext(), cred.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["id"].(string) != strconv.FormatUint(cred.ID, 10) {
		t.Errorf("id mismatch: %v", m["id"])
	}
	if _, has := m["hmac_key"]; has {
		t.Error("Get should NOT include hmac_key")
	}
}

func TestEAB_GetCredential_NotFound(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	_, err := p.EABGetCredential(unixOperatorContext(), 99)
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_GetCredentialByKeyID(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	result, err := p.EABGetCredentialByKeyID(unixOperatorContext(), cred.KeyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["key_id"].(string) != cred.KeyID {
		t.Errorf("key_id mismatch: %v", m["key_id"])
	}

	_, err = p.EABGetCredentialByKeyID(unixOperatorContext(), "nope")
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_ListCredentials_ByTenant(t *testing.T) {
	svc := newFakeEABService()
	ctx := unixOperatorContext()
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 2, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 3, TenantID: "t2"})
	p := newEABProvider(svc, nil)

	result, err := p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"].(int) != 2 {
		t.Errorf("expected total=2 for t1, got %v", m["total"])
	}
}

func TestEAB_ListCredentials_AllTenantsViaPage(t *testing.T) {
	svc := newFakeEABService()
	ctx := unixOperatorContext()
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 2, TenantID: "t2"})
	p := newEABProvider(svc, nil)

	// Empty tenant + zero profile walks the paginated store.
	result, err := p.EABListCredentials(ctx, mcp.EABListParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"].(int) != 2 {
		t.Errorf("expected total=2 across tenants, got %v", m["total"])
	}
}

func TestEAB_ListCredentials_StatusAndPagination(t *testing.T) {
	svc := newFakeEABService()
	ctx := unixOperatorContext()
	c1, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_ = svc.Revoke(ctx, c1.ID)
	p := newEABProvider(svc, nil)

	result, err := p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1", Status: "revoked"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"].(int) != 1 {
		t.Errorf("expected status filter to keep 1, got %v", m["total"])
	}

	// page_size=1 with page=2 on a 2-element set returns 1 element and
	// reports the filtered total.
	result, err = p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1", Page: 2, PageSize: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m = result.(map[string]interface{})
	if m["total"].(int) != 2 {
		t.Errorf("expected total=2, got %v", m["total"])
	}
	if creds := m["credentials"].([]map[string]interface{}); len(creds) != 1 {
		t.Errorf("expected 1 credential on page 2, got %d", len(creds))
	}

	// Out-of-range page returns an empty slice.
	result, err = p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1", Page: 9, PageSize: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m = result.(map[string]interface{})
	if creds := m["credentials"].([]map[string]interface{}); len(creds) != 0 {
		t.Errorf("expected 0 credentials past the end, got %d", len(creds))
	}
}

func TestEAB_ListCredentials_PagePropagatesError(t *testing.T) {
	svc := newFakeEABService()
	svc.errPage = errors.New("storage down")
	p := newEABProvider(svc, nil)
	if _, err := p.EABListCredentials(unixOperatorContext(), mcp.EABListParams{}); err == nil {
		t.Fatal("expected error from page walk")
	}
}

func TestEAB_ListCredentials_ByProfileFiltersTenant(t *testing.T) {
	svc := newFakeEABService()
	ctx := unixOperatorContext()
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t2"})
	p := newEABProvider(svc, nil)

	// profile_id=1 is shared across tenants; ensure tenant filter applies.
	result, err := p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1", ProfileID: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"].(int) != 1 {
		t.Errorf("expected tenant filter to limit to 1, got %v", m["total"])
	}
}

func TestEAB_ListCredentials_ActiveOnlyFiltersExpired(t *testing.T) {
	svc := newFakeEABService()
	ctx := unixOperatorContext()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	// Force expiry in the past so IsValid() == false.
	cred.ExpiresAt = time.Now().Add(-time.Hour)
	p := newEABProvider(svc, nil)

	result, err := p.EABListCredentials(ctx, mcp.EABListParams{TenantID: "t1", ActiveOnly: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"].(int) != 0 {
		t.Errorf("expected active_only to drop expired, got total=%v", m["total"])
	}
}

func TestEAB_ListCredentials_PropagatesError(t *testing.T) {
	svc := newFakeEABService()
	svc.errListByTenant = errors.New("storage down")
	p := newEABProvider(svc, nil)
	if _, err := p.EABListCredentials(unixOperatorContext(), mcp.EABListParams{TenantID: "t1"}); err == nil {
		t.Fatal("expected error from underlying service")
	}
	svc.errListByTenant = nil
	svc.errListByProfile = errors.New("storage down")
	if _, err := p.EABListCredentials(unixOperatorContext(), mcp.EABListParams{TenantID: "t1", ProfileID: 1}); err == nil {
		t.Fatal("expected error from underlying service")
	}
}

func TestEAB_RevokeCredential(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	result, err := p.EABRevokeCredential(unixOperatorContext(), cred.ID, 99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["status"] != "revoked" {
		t.Errorf("expected status=revoked, got %v", m["status"])
	}
	if m["revoker_id"].(string) != "99" {
		t.Errorf("expected revoker_id=99, got %v", m["revoker_id"])
	}
	if cred.Status != eab.StatusRevoked {
		t.Errorf("expected credential to be revoked, got %v", cred.Status)
	}
}

func TestEAB_RevokeCredential_PropagatesError(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	_, err := p.EABRevokeCredential(unixOperatorContext(), 99, 0)
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_ValidateCredential_HappyPath(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	encoded := base64.RawURLEncoding.EncodeToString(cred.HMACKey)
	result, err := p.EABValidateCredential(unixOperatorContext(), cred.KeyID, encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["valid"].(bool) != true {
		t.Errorf("expected valid=true, got %v", m["valid"])
	}
	// Underlying service receives the decoded bytes.
	if string(svc.lastValidateHMAC) != string(cred.HMACKey) {
		t.Errorf("hmac decode mismatch: %v vs %v", svc.lastValidateHMAC, cred.HMACKey)
	}
}

func TestEAB_ValidateCredential_StdBase64(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	// Use std base64 (with padding) to confirm fallback decoders work.
	encoded := base64.StdEncoding.EncodeToString(cred.HMACKey)
	if _, err := p.EABValidateCredential(unixOperatorContext(), cred.KeyID, encoded); err != nil {
		t.Fatalf("unexpected error with std base64: %v", err)
	}
}

func TestEAB_ValidateCredential_BadBase64(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	_, err := p.EABValidateCredential(unixOperatorContext(), "k", "!!!not-base64!!!")
	var bad ErrEABInvalidHMACKey
	if !errors.As(err, &bad) {
		t.Errorf("expected ErrEABInvalidHMACKey, got %v", err)
	}
}

func TestEAB_ValidateCredential_NotFoundReturnsErrorMessage(t *testing.T) {
	svc := newFakeEABService()
	p := newEABProvider(svc, nil)
	encoded := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	result, err := p.EABValidateCredential(unixOperatorContext(), "missing", encoded)
	// Validation failures should return valid=false, not a Go error.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["valid"].(bool) != false {
		t.Errorf("expected valid=false for missing credential, got %v", m["valid"])
	}
	if m["error_message"] == "" {
		t.Error("expected error_message to be populated")
	}
}

func TestEAB_DeleteCredential(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	result, err := p.EABDeleteCredential(unixOperatorContext(), cred.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %v", m["status"])
	}

	_, err = p.EABDeleteCredential(unixOperatorContext(), 999)
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_MarkCredentialUsed(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)

	result, err := p.EABMarkCredentialUsed(unixOperatorContext(), cred.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["status"] != "used" {
		t.Errorf("expected status=used, got %v", m["status"])
	}
	if cred.Status != eab.StatusUsed {
		t.Errorf("expected credential to be marked used, got %v", cred.Status)
	}

	_, err = p.EABMarkCredentialUsed(unixOperatorContext(), 999)
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_CleanupExpiredCredentials(t *testing.T) {
	svc := newFakeEABService()
	svc.cleanupCount = 5
	p := newEABProvider(svc, nil)

	result, err := p.EABCleanupExpiredCredentials(unixOperatorContext(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["deleted_count"].(int) != 5 {
		t.Errorf("expected deleted_count=5 from the all-tenant cleanup, got %v", m["deleted_count"])
	}
}

func TestEAB_CleanupExpiredCredentials_PropagatesError(t *testing.T) {
	svc := newFakeEABService()
	svc.errCleanupExpired = errors.New("storage down")
	p := newEABProvider(svc, nil)
	if _, err := p.EABCleanupExpiredCredentials(unixOperatorContext(), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestEAB_GetCredentialQRCode_HappyPath(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	del := &fakeEABDelivery{qrPayload: []byte{0x89, 0x50, 0x4e, 0x47}}
	p := newEABProvider(svc, del)

	result, err := p.EABGetCredentialQRCode(unixOperatorContext(), cred.ID, 512)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if del.lastSize != 512 {
		t.Errorf("expected requested size threaded to delivery, got %d", del.lastSize)
	}
	m := result.(map[string]interface{})
	if m["content_type"].(string) != "image/png" {
		t.Errorf("expected content_type=image/png, got %v", m["content_type"])
	}
	encoded := m["qr_code"].(string)
	decoded, decErr := base64.StdEncoding.DecodeString(encoded)
	if decErr != nil {
		t.Fatalf("qr_code not valid base64: %v", decErr)
	}
	if string(decoded) != string(del.qrPayload) {
		t.Errorf("qr_code roundtrip mismatch")
	}
}

func TestEAB_GetCredentialQRCode_DeliveryNotConfigured(t *testing.T) {
	svc := newFakeEABService()
	_, _ = svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)
	_, err := p.EABGetCredentialQRCode(unixOperatorContext(), 1, 256)
	var notConfigured ErrEABDeliveryNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Errorf("expected ErrEABDeliveryNotConfigured, got %v", err)
	}
}

func TestEAB_GetCredentialQRCode_GetError(t *testing.T) {
	svc := newFakeEABService()
	del := &fakeEABDelivery{qrPayload: []byte{1}}
	p := newEABProvider(svc, del)
	_, err := p.EABGetCredentialQRCode(unixOperatorContext(), 999, 256)
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_GetCredentialQRCode_DeliveryError(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	del := &fakeEABDelivery{errQR: errors.New("png encode failed")}
	p := newEABProvider(svc, del)
	_, err := p.EABGetCredentialQRCode(unixOperatorContext(), cred.ID, 256)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEAB_GetEnrollmentURL_NoPath(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	del := &fakeEABDelivery{url: "https://acme.example/enroll?kid=x"}
	p := newEABProvider(svc, del)

	result, err := p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["url"].(string) != del.url {
		t.Errorf("url mismatch: %v", m["url"])
	}
}

func TestEAB_GetEnrollmentURL_WithPath(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	del := &fakeEABDelivery{urlWithPath: "https://acme.example/custom/path?kid=x"}
	p := newEABProvider(svc, del)

	result, err := p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, "/custom/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["url"].(string) != del.urlWithPath {
		t.Errorf("url mismatch: %v", m["url"])
	}
}

func TestEAB_GetEnrollmentURL_DeliveryNotConfigured(t *testing.T) {
	svc := newFakeEABService()
	_, _ = svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p := newEABProvider(svc, nil)
	_, err := p.EABGetEnrollmentURL(unixOperatorContext(), 1, "")
	var notConfigured ErrEABDeliveryNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Errorf("expected ErrEABDeliveryNotConfigured, got %v", err)
	}
}

func TestEAB_GetEnrollmentURL_GetError(t *testing.T) {
	svc := newFakeEABService()
	del := &fakeEABDelivery{url: "https://x"}
	p := newEABProvider(svc, del)
	_, err := p.EABGetEnrollmentURL(unixOperatorContext(), 999, "")
	var notFound eab.ErrCredentialNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestEAB_GetEnrollmentURL_DeliveryError(t *testing.T) {
	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	del := &fakeEABDelivery{errURL: errors.New("base url not configured")}
	p := newEABProvider(svc, del)
	_, err := p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, "")
	if err == nil {
		t.Fatal("expected error")
	}

	del.errURL = nil
	del.errURLPath = errors.New("bad path")
	_, err = p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, "/x")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEAB_SettersInjectAfterConstruction(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	if _, err := p.EABGetCredential(unixOperatorContext(), 1); err == nil {
		t.Fatal("expected ErrEABNotConfigured before SetEABService")
	}

	svc := newFakeEABService()
	cred, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "t"})
	p.SetEABService(svc)
	if _, err := p.EABGetCredential(unixOperatorContext(), cred.ID); err != nil {
		t.Errorf("expected success after SetEABService, got %v", err)
	}

	if _, err := p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, ""); err == nil {
		t.Fatal("expected ErrEABDeliveryNotConfigured before SetEABDelivery")
	}
	p.SetEABDelivery(&fakeEABDelivery{url: "https://x"})
	if _, err := p.EABGetEnrollmentURL(unixOperatorContext(), cred.ID, ""); err != nil {
		t.Errorf("expected success after SetEABDelivery, got %v", err)
	}
}

// TestEAB_CredentialJSON_OmitsZeroTimestamps verifies the helper
// formatter behaves correctly for credentials with zero values.
func TestEAB_CredentialJSON_OmitsZeroTimestamps(t *testing.T) {
	cred := &eab.Credential{
		ID:        1,
		KeyID:     "k",
		ProfileID: 1,
		TenantID:  "t",
		Status:    eab.StatusActive,
		CreatedAt: time.Unix(1_700_000_000, 0),
	}
	out := eabCredentialJSON(cred, false)
	if _, has := out["expires_at"]; has {
		t.Error("expected expires_at omitted when zero")
	}
	if _, has := out["used_at"]; has {
		t.Error("expected used_at omitted when zero")
	}
	if _, has := out["hmac_key"]; has {
		t.Error("expected hmac_key omitted when includeHMACKey=false")
	}
}

// TestEAB_CredentialJSON_NilReturnsNil verifies nil-safety.
func TestEAB_CredentialJSON_NilReturnsNil(t *testing.T) {
	if eabCredentialJSON(nil, true) != nil {
		t.Error("expected nil result for nil credential")
	}
}

// TestEAB_CredentialJSON_IncludesAllPopulatedFields covers the
// expires_at + used_at branches when the credential carries those
// timestamps, plus hmac_key inclusion on create.
func TestEAB_CredentialJSON_IncludesAllPopulatedFields(t *testing.T) {
	cred := &eab.Credential{
		ID:        7,
		KeyID:     "k",
		HMACKey:   []byte{0x01, 0x02},
		ProfileID: 1,
		TenantID:  "t",
		Status:    eab.StatusUsed,
		CreatedAt: time.Unix(1_700_000_000, 0),
		ExpiresAt: time.Unix(1_700_001_000, 0),
		UsedAt:    time.Unix(1_700_000_500, 0),
	}
	out := eabCredentialJSON(cred, true)
	if _, has := out["expires_at"]; !has {
		t.Error("expected expires_at populated")
	}
	if _, has := out["used_at"]; !has {
		t.Error("expected used_at populated")
	}
	if _, has := out["hmac_key"]; !has {
		t.Error("expected hmac_key on includeHMACKey=true")
	}
}

// TestEAB_DecodeHMACKey_RoundTripVariants verifies all four base64
// variants round-trip correctly.
func TestEAB_DecodeHMACKey_RoundTripVariants(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0xff}
	encoders := []struct {
		name  string
		encFn func([]byte) string
	}{
		{"raw_url", base64.RawURLEncoding.EncodeToString},
		{"url_padded", base64.URLEncoding.EncodeToString},
		{"raw_std", base64.RawStdEncoding.EncodeToString},
		{"std_padded", base64.StdEncoding.EncodeToString},
	}
	for _, e := range encoders {
		t.Run(e.name, func(t *testing.T) {
			decoded, err := decodeEABHMACKey(e.encFn(payload))
			if err != nil {
				t.Fatalf("%s: decode failed: %v", e.name, err)
			}
			if string(decoded) != string(payload) {
				t.Errorf("%s: roundtrip mismatch", e.name)
			}
		})
	}
}

func TestEAB_DecodeHMACKey_RejectsGarbage(t *testing.T) {
	if _, err := decodeEABHMACKey("!!!"); err == nil {
		t.Error("expected error for garbage input")
	}
}

// TestEAB_ErrorTypes verifies the typed error implementations expose
// the expected messages and unwrap behavior.
func TestEAB_ErrorTypes(t *testing.T) {
	if (ErrEABNotConfigured{}).Error() == "" {
		t.Error("ErrEABNotConfigured: empty message")
	}
	if (ErrEABDeliveryNotConfigured{}).Error() == "" {
		t.Error("ErrEABDeliveryNotConfigured: empty message")
	}
	cause := errors.New("boom")
	bad := ErrEABInvalidHMACKey{Cause: cause}
	if bad.Error() == "" {
		t.Error("ErrEABInvalidHMACKey: empty message")
	}
	if !errors.Is(bad, cause) {
		t.Error("ErrEABInvalidHMACKey: unwrap to cause failed")
	}
}

// TestEAB_CallerTenantIsEnforced pins #2008 on MCP: a tenant-bound caller
// cannot create, list, clean up or act on another tenant's EAB
// credentials, its own tenant works, and the unbound local operator keeps
// today's behaviour.
func TestEAB_CallerTenantIsEnforced(t *testing.T) {
	tenantA := mcp.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-a"})
	newFixture := func() (*MCPServiceProvider, *fakeEABService) {
		svc := newFakeEABService()
		return newEABProvider(svc, &fakeEABDelivery{qrPayload: []byte{1}, url: "https://acme.example/enroll"}), svc
	}
	denied := func(t *testing.T, what string, err error) {
		t.Helper()
		var failure ErrEABToolFailure
		if !errors.As(err, &failure) || failure.Class != codes.PermissionDenied {
			t.Errorf("%s: err = %v, want an ErrEABToolFailure of class PermissionDenied", what, err)
		}
	}
	ok := func(t *testing.T, what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}

	t.Run("create, list and cleanup naming another tenant", func(t *testing.T) {
		p, svc := newFixture()
		_, err := p.EABCreateCredential(tenantA, 1, "tenant-b", 0, 0)
		denied(t, "EABCreateCredential tenant-b", err)
		if len(svc.byID) != 0 {
			t.Error("EABCreateCredential for another tenant reached Generate")
		}
		_, err = p.EABListCredentials(tenantA, mcp.EABListParams{TenantID: "tenant-b"})
		denied(t, "EABListCredentials tenant-b", err)
		_, err = p.EABListCredentials(tenantA, mcp.EABListParams{ProfileID: 1})
		denied(t, "EABListCredentials profile without tenant", err)

		expired, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "tenant-b"})
		expired.ExpiresAt = time.Now().Add(-time.Hour)
		_, err = p.EABCleanupExpiredCredentials(tenantA, "tenant-b")
		denied(t, "EABCleanupExpiredCredentials tenant-b", err)
		_, err = p.EABCleanupExpiredCredentials(tenantA, "")
		denied(t, "EABCleanupExpiredCredentials empty tenant", err)
		if _, getErr := svc.Get(context.Background(), expired.ID); getErr != nil {
			t.Error("a refused cleanup deleted another tenant's credential")
		}
	})

	t.Run("credential-ID tools on another tenant's credential", func(t *testing.T) {
		p, svc := newFixture()
		other, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "tenant-b"})
		_, err := p.EABGetCredential(tenantA, other.ID)
		denied(t, "EABGetCredential", err)
		_, err = p.EABGetCredentialByKeyID(tenantA, other.KeyID)
		denied(t, "EABGetCredentialByKeyID", err)
		_, err = p.EABGetCredentialQRCode(tenantA, other.ID, 256)
		denied(t, "EABGetCredentialQRCode", err)
		_, err = p.EABGetEnrollmentURL(tenantA, other.ID, "")
		denied(t, "EABGetEnrollmentURL", err)
		_, err = p.EABRevokeCredential(tenantA, other.ID, 0)
		denied(t, "EABRevokeCredential", err)
		_, err = p.EABMarkCredentialUsed(tenantA, other.ID)
		denied(t, "EABMarkCredentialUsed", err)
		if other.Status != eab.StatusActive {
			t.Errorf("refused tools changed the credential status to %v", other.Status)
		}
		_, err = p.EABDeleteCredential(tenantA, other.ID)
		denied(t, "EABDeleteCredential", err)
		if _, getErr := svc.Get(context.Background(), other.ID); getErr != nil {
			t.Error("a refused EABDeleteCredential removed another tenant's credential")
		}
	})

	t.Run("own tenant succeeds", func(t *testing.T) {
		p, svc := newFixture()
		_, err := p.EABCreateCredential(tenantA, 1, "tenant-a", 0, 0)
		ok(t, "EABCreateCredential", err)
		own, _ := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "tenant-a"})
		_, err = p.EABListCredentials(tenantA, mcp.EABListParams{TenantID: "tenant-a"})
		ok(t, "EABListCredentials", err)
		_, err = p.EABListCredentials(tenantA, mcp.EABListParams{ProfileID: 1, TenantID: "tenant-a"})
		ok(t, "EABListCredentials profile+tenant", err)
		_, err = p.EABGetCredential(tenantA, own.ID)
		ok(t, "EABGetCredential", err)
		_, err = p.EABGetCredentialByKeyID(tenantA, own.KeyID)
		ok(t, "EABGetCredentialByKeyID", err)
		_, err = p.EABGetCredentialQRCode(tenantA, own.ID, 256)
		ok(t, "EABGetCredentialQRCode", err)
		_, err = p.EABGetEnrollmentURL(tenantA, own.ID, "")
		ok(t, "EABGetEnrollmentURL", err)
		_, err = p.EABMarkCredentialUsed(tenantA, own.ID)
		ok(t, "EABMarkCredentialUsed", err)
		_, err = p.EABRevokeCredential(tenantA, own.ID, 0)
		ok(t, "EABRevokeCredential", err)
		_, err = p.EABCleanupExpiredCredentials(tenantA, "tenant-a")
		ok(t, "EABCleanupExpiredCredentials", err)
		_, err = p.EABDeleteCredential(tenantA, own.ID)
		ok(t, "EABDeleteCredential", err)
	})

	t.Run("Unix-socket operator is unchanged", func(t *testing.T) {
		p, svc := newFixture()
		ctx := unixOperatorContext()
		other, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "tenant-b"})
		svc.cleanupCount = 2
		_, err := p.EABCreateCredential(ctx, 1, "tenant-b", 0, 0)
		ok(t, "EABCreateCredential", err)
		_, err = p.EABListCredentials(ctx, mcp.EABListParams{ProfileID: 1})
		ok(t, "EABListCredentials", err)
		_, err = p.EABGetCredential(ctx, other.ID)
		ok(t, "EABGetCredential", err)
		_, err = p.EABGetCredentialByKeyID(ctx, other.KeyID)
		ok(t, "EABGetCredentialByKeyID", err)
		_, err = p.EABGetCredentialQRCode(ctx, other.ID, 256)
		ok(t, "EABGetCredentialQRCode", err)
		_, err = p.EABGetEnrollmentURL(ctx, other.ID, "")
		ok(t, "EABGetEnrollmentURL", err)
		_, err = p.EABMarkCredentialUsed(ctx, other.ID)
		ok(t, "EABMarkCredentialUsed", err)
		_, err = p.EABRevokeCredential(ctx, other.ID, 0)
		ok(t, "EABRevokeCredential", err)
		result, err := p.EABCleanupExpiredCredentials(ctx, "")
		ok(t, "EABCleanupExpiredCredentials", err)
		if m, _ := result.(map[string]interface{}); m["deleted_count"] != 2 {
			t.Errorf("store-wide cleanup deleted_count = %v, want 2", m["deleted_count"])
		}
		_, err = p.EABDeleteCredential(ctx, other.ID)
		ok(t, "EABDeleteCredential", err)
	})
}
