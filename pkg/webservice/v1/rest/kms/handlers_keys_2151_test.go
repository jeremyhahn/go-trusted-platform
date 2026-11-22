package kms

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

// keys2151KMS records the generate and metadata-update requests the key
// handlers send and serves a fixed key list (#2151 Codex round 2).
type keys2151KMS struct {
	kmsclient.Client
	keys      []kmsclient.KeyInfo
	genReq    *kmsclient.GenerateKeyRequest
	importReq *kmsclient.ImportKeyRequest
	updateReq *kmsclient.UpdateKeyMetadataRequest
	updateErr error
}

func (f *keys2151KMS) ImportKey(_ context.Context, req *kmsclient.ImportKeyRequest) (*kmsclient.ImportKeyResponse, error) {
	f.importReq = req
	return &kmsclient.ImportKeyResponse{KeyID: "imp-1", Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *keys2151KMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.genReq = req
	return &kmsclient.GenerateKeyResponse{KeyID: "gen-1", Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *keys2151KMS) UpdateKeyMetadata(_ context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	f.updateReq = req
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return &kmsclient.KeyMetadataResponse{KeyID: req.KeyID}, nil
}

func (f *keys2151KMS) ListKeys(context.Context) (*kmsclient.ListKeysResponse, error) {
	return &kmsclient.ListKeysResponse{Keys: f.keys}, nil
}

func keys2151Handlers(f *keys2151KMS) *Handlers {
	return NewHandlers(logging.DefaultLogger(), f, nil, nil, nil, response.NewResponseWriter(logging.DefaultLogger(), nil))
}

func TestGenerateKey2151_RecordsDescriptionAndTags(t *testing.T) {
	t.Run("description and tags are recorded", func(t *testing.T) {
		f := &keys2151KMS{}
		w := covServe(keys2151Handlers(f).GenerateKey, covRequest(http.MethodPost, "/api/v1/kms/keys",
			`{"name":"k1","algorithm":"AES-256-GCM","description":"payroll","tags":{"team":"ops"}}`, nil))
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
		}
		if f.updateReq == nil {
			t.Fatal("UpdateKeyMetadata was not called: description and tags were dropped")
		}
		if f.updateReq.KeyID != "gen-1" || f.updateReq.Description != "payroll" || f.updateReq.Tags["team"] != "ops" {
			t.Fatalf("UpdateKeyMetadata request = %+v, want KeyID gen-1, Description payroll, Tags team=ops", f.updateReq)
		}
	})
	t.Run("no metadata, no update", func(t *testing.T) {
		f := &keys2151KMS{}
		w := covServe(keys2151Handlers(f).GenerateKey, covRequest(http.MethodPost, "/api/v1/kms/keys",
			`{"name":"k1","algorithm":"AES-256-GCM"}`, nil))
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
		}
		if f.updateReq != nil {
			t.Fatalf("UpdateKeyMetadata called with %+v, want no call", f.updateReq)
		}
	})
	t.Run("a metadata failure fails the request", func(t *testing.T) {
		f := &keys2151KMS{updateErr: errors.New("metadata store down")}
		w := covServe(keys2151Handlers(f).GenerateKey, covRequest(http.MethodPost, "/api/v1/kms/keys",
			`{"name":"k1","algorithm":"AES-256-GCM","description":"payroll"}`, nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", w.Code, w.Body.String())
		}
	})
}

type keys2151ListPayload struct {
	Keys []struct {
		KeyID string `json:"key_id"`
	} `json:"keys"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
	TotalCount int    `json:"total_count"`
}

func TestListKeys2151_FiltersAndPaginates(t *testing.T) {
	f := &keys2151KMS{keys: []kmsclient.KeyInfo{
		{KeyID: "c", Name: "c", Algorithm: kmsclient.AlgorithmRSA2048, Version: 1},
		{KeyID: "a", Name: "a", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
		{KeyID: "b", Name: "b", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
	}}
	h := keys2151Handlers(f)
	cases := []struct {
		query      string
		ids        []string
		nextCursor string
		hasMore    bool
		total      int
	}{
		{"", []string{"a", "b", "c"}, "", false, 3},
		{"?name=b", []string{"b"}, "", false, 1},
		{"?algorithm=aes-256-gcm", []string{"a", "b"}, "", false, 2},
		{"?limit=1", []string{"a"}, "1", true, 3},
		{"?limit=1&cursor=1", []string{"b"}, "2", true, 3},
	}
	for _, c := range cases {
		t.Run("query "+c.query, func(t *testing.T) {
			w := covServe(h.ListKeys, covRequest(http.MethodGet, "/api/v1/kms/keys"+c.query, "", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
			var got keys2151ListPayload
			decodeEnvelope(t, w, &got)
			ids := make([]string, 0, len(got.Keys))
			for _, k := range got.Keys {
				ids = append(ids, k.KeyID)
			}
			if len(ids) != len(c.ids) {
				t.Fatalf("keys = %v, want %v", ids, c.ids)
			}
			for i := range ids {
				if ids[i] != c.ids[i] {
					t.Fatalf("keys = %v, want %v", ids, c.ids)
				}
			}
			if got.NextCursor != c.nextCursor || got.HasMore != c.hasMore || got.TotalCount != c.total {
				t.Fatalf("next_cursor %q has_more %v total_count %d, want %q %v %d",
					got.NextCursor, got.HasMore, got.TotalCount, c.nextCursor, c.hasMore, c.total)
			}
		})
	}
	for _, q := range []string{"?owner=x", "?cursor=bad", "?cursor=-1", "?limit=abc"} {
		t.Run("bad query "+q, func(t *testing.T) {
			w := covServe(h.ListKeys, covRequest(http.MethodGet, "/api/v1/kms/keys"+q, "", nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
		})
	}
}

// TestListKeys2151_HugeLimitDoesNotOverflow pins the maximum-integer limit
// boundary: start+limit must not wrap negative and panic the slice (#2151
// Codex round 1).
func TestListKeys2151_HugeLimitDoesNotOverflow(t *testing.T) {
	f := &keys2151KMS{keys: []kmsclient.KeyInfo{
		{KeyID: "c", Name: "c", Algorithm: kmsclient.AlgorithmRSA2048, Version: 1},
		{KeyID: "a", Name: "a", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
		{KeyID: "b", Name: "b", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
	}}
	w := covServe(keys2151Handlers(f).ListKeys, covRequest(http.MethodGet,
		"/api/v1/kms/keys?cursor=1&limit=9223372036854775807", "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var got keys2151ListPayload
	decodeEnvelope(t, w, &got)
	if len(got.Keys) != 2 || got.Keys[0].KeyID != "b" || got.Keys[1].KeyID != "c" {
		t.Fatalf("keys = %+v, want [b c]", got.Keys)
	}
	if got.NextCursor != "" || got.HasMore || got.TotalCount != 3 {
		t.Fatalf("next_cursor %q has_more %v total_count %d, want \"\" false 3",
			got.NextCursor, got.HasMore, got.TotalCount)
	}
}

// TestGenerateKey2151_AcceptsTheFacadeKeySpec pins the facade's snake_case
// key_spec envelope on the mounted router (#2151 Codex round 2).
func TestGenerateKey2151_AcceptsTheFacadeKeySpec(t *testing.T) {
	f := &keys2151KMS{}
	w := covServe(keys2151Handlers(f).GenerateKey, covRequest(http.MethodPost, "/api/v1/kms/keys",
		`{"name":"k","key_spec":{"algorithm":"AES-256-GCM","usage":["ENCRYPT","DECRYPT"],"exportable":true,"deletion_protection":true}}`, nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
	}
	if f.genReq == nil {
		t.Fatal("GenerateKey was not called")
	}
	if f.genReq.Algorithm != kmsclient.AlgorithmAES256GCM || len(f.genReq.Usage) != 2 ||
		!f.genReq.Exportable || !f.genReq.DeletionProtection {
		t.Fatalf("GenerateKey request = %+v, want AES-256-GCM, two usages, exportable, deletion protection", f.genReq)
	}
}

// TestImportKey2151_AcceptsTheFacadeKeySpec pins the same envelope on import.
func TestImportKey2151_AcceptsTheFacadeKeySpec(t *testing.T) {
	f := &keys2151KMS{}
	w := covServe(keys2151Handlers(f).ImportKey, covRequest(http.MethodPost, "/api/v1/kms/keys/import",
		`{"name":"k","key_material":"AQID","key_spec":{"algorithm":"AES-256-GCM","usage":["ENCRYPT"]}}`, nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
	}
	if f.importReq == nil || f.importReq.Algorithm != kmsclient.AlgorithmAES256GCM || len(f.importReq.Usage) != 1 {
		t.Fatalf("ImportKey request = %+v, want AES-256-GCM with one usage", f.importReq)
	}
}
