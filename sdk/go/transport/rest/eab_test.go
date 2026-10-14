// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// captureEAB records the request the adapter emitted and answers with an
// empty success envelope.
type captureEAB struct {
	method string
	path   string
	query  url.Values
	body   map[string]interface{}
}

func eabAdapter(t *testing.T, payload string) (*Adapter, *captureEAB) {
	t.Helper()
	captured := &captureEAB{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		captured.body = nil
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&captured.body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":` + payload + `}`))
	})
	return a, captured
}

func TestEABREST_GetCredential_PathTemplated(t *testing.T) {
	a, captured := eabAdapter(t, `{}`)
	conn := a.Connection()

	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 42},
		&platformv1.GetEABCredentialResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodGet || captured.path != "/api/v1/eab/credentials/42" {
		t.Errorf("got %s %s, want GET /api/v1/eab/credentials/42", captured.method, captured.path)
	}
	if _, has := captured.body["credential_id"]; has {
		t.Errorf("body still contains credential_id: %v", captured.body)
	}
}

func TestEABREST_GetCredential_ZeroIDRejected(t *testing.T) {
	a, _ := eabAdapter(t, `{}`)
	conn := a.Connection()

	err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{},
		&platformv1.GetEABCredentialResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for zero credential_id, got %v", err)
	}
}

func TestEABREST_LifecycleRoutes(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		args       interface{}
		reply      interface{}
		wantMethod string
		wantPath   string
	}{
		{
			name:       "delete",
			method:     "/platform.v1.EABService/DeleteCredential",
			args:       &platformv1.DeleteEABCredentialRequest{CredentialId: 7},
			reply:      &platformv1.DeleteEABCredentialResponse{},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/eab/credentials/7",
		},
		{
			name:       "revoke",
			method:     "/platform.v1.EABService/RevokeCredential",
			args:       &platformv1.RevokeEABCredentialRequest{CredentialId: 7, RevokerId: 9},
			reply:      &platformv1.RevokeEABCredentialResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/eab/credentials/7/revoke",
		},
		{
			name:       "mark_used",
			method:     "/platform.v1.EABService/MarkCredentialUsed",
			args:       &platformv1.MarkEABCredentialUsedRequest{CredentialId: 7},
			reply:      &platformv1.MarkEABCredentialUsedResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/eab/credentials/7/used",
		},
		{
			name:       "get_by_key",
			method:     "/platform.v1.EABService/GetCredentialByKeyID",
			args:       &platformv1.GetEABCredentialByKeyIDRequest{KeyId: "abc/def"},
			reply:      &platformv1.GetEABCredentialResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/eab/credentials/key/abc/def",
		},
		{
			name:       "create_flat",
			method:     "/platform.v1.EABService/CreateCredential",
			args:       &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "t"},
			reply:      &platformv1.CreateEABCredentialResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/eab/credentials",
		},
		{
			name:       "validate_flat",
			method:     "/platform.v1.EABService/ValidateCredential",
			args:       &platformv1.ValidateEABCredentialRequest{KeyId: "k", HmacKey: "h"},
			reply:      &platformv1.ValidateEABCredentialResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/eab/credentials/validate",
		},
		{
			name:       "cleanup_flat",
			method:     "/platform.v1.EABService/CleanupExpiredCredentials",
			args:       &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "t"},
			reply:      &platformv1.CleanupExpiredEABCredentialsResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/eab/credentials/cleanup",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := eabAdapter(t, `{}`)
			conn := a.Connection()
			if err := conn.Invoke(context.Background(), tc.method, tc.args, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod || captured.path != tc.wantPath {
				t.Errorf("got %s %s, want %s %s",
					captured.method, captured.path, tc.wantMethod, tc.wantPath)
			}
		})
	}
}

func TestEABREST_QRCode_SizeQueryParam(t *testing.T) {
	a, captured := eabAdapter(t, `{}`)
	conn := a.Connection()

	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredentialQRCode",
		&platformv1.GetEABCredentialQRCodeRequest{CredentialId: 5, Size: 512},
		&platformv1.GetEABCredentialQRCodeResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.path != "/api/v1/eab/credentials/5/qrcode" {
		t.Errorf("path = %q", captured.path)
	}
	if captured.query.Get("size") != "512" {
		t.Errorf("size query = %q, want 512", captured.query.Get("size"))
	}

	// Zero size is omitted from the URL.
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredentialQRCode",
		&platformv1.GetEABCredentialQRCodeRequest{CredentialId: 5},
		&platformv1.GetEABCredentialQRCodeResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.query.Has("size") {
		t.Errorf("zero size must be omitted, got %q", captured.query.Get("size"))
	}
}

func TestEABREST_EnrollmentURL_PathQueryParam(t *testing.T) {
	a, captured := eabAdapter(t, `{}`)
	conn := a.Connection()

	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetEnrollmentURL",
		&platformv1.GetEABEnrollmentURLRequest{CredentialId: 5, Path: "/custom/enroll"},
		&platformv1.GetEABEnrollmentURLResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.path != "/api/v1/eab/credentials/5/url" {
		t.Errorf("path = %q", captured.path)
	}
	if captured.query.Get("path") != "/custom/enroll" {
		t.Errorf("path query = %q", captured.query.Get("path"))
	}
}

func TestEABREST_List_FilterQueryParams(t *testing.T) {
	a, captured := eabAdapter(t, `{}`)
	conn := a.Connection()

	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/ListCredentials",
		&platformv1.ListEABCredentialsRequest{
			TenantId:     "tenant-1",
			ProfileId:    7,
			ActiveOnly:   true,
			StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
			Pagination:   &platformv1.PaginationRequest{Page: 2, PageSize: 25},
		},
		&platformv1.ListEABCredentialsResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodGet || captured.path != "/api/v1/eab/credentials" {
		t.Errorf("got %s %s", captured.method, captured.path)
	}
	q := captured.query
	if q.Get("tenant_id") != "tenant-1" || q.Get("profile_id") != "7" ||
		q.Get("active_only") != "true" || q.Get("page") != "2" || q.Get("page_size") != "25" {
		t.Errorf("query params wrong: %v", q)
	}
	// Enum encodes as the proto enum value name; the server accepts both
	// forms (pkg/webservice/v1/rest/eab/handlers.go).
	if q.Get("status") != "EAB_CREDENTIAL_STATUS_REVOKED" {
		t.Errorf("status query = %q", q.Get("status"))
	}
}

func TestEABREST_List_ZeroFiltersOmitted(t *testing.T) {
	a, captured := eabAdapter(t, `{}`)
	conn := a.Connection()

	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/ListCredentials",
		&platformv1.ListEABCredentialsRequest{},
		&platformv1.ListEABCredentialsResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(captured.query) != 0 {
		t.Errorf("expected no query params for zero-valued request, got %v", captured.query)
	}
}

// TestEABREST_ResponseDecode verifies a protojson envelope payload
// decodes into the pb reply (uint64 ids as strings per protojson).
func TestEABREST_ResponseDecode(t *testing.T) {
	payload := `{"credential":{"id":"42","key_id":"key-a","profile_id":"7","tenant_id":"t","status":"EAB_CREDENTIAL_STATUS_ACTIVE"}}`
	a, _ := eabAdapter(t, payload)
	conn := a.Connection()

	reply := &platformv1.GetEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 42}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	cred := reply.GetCredential()
	if cred.GetId() != 42 || cred.GetKeyId() != "key-a" || cred.GetProfileId() != 7 ||
		cred.GetStatus() != platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE {
		t.Errorf("decode mismatch: %+v", cred)
	}
}
