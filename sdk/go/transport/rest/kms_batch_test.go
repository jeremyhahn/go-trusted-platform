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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestKMSExportKey_QueryCarriesEnumNumbers pins ExportKey to the daemon's
// GET /api/v1/kms/keys/{id}/export, which parses the wrapping algorithm and
// the format as integers, and reads the reply's numeric enums back.
func TestKMSExportKey_QueryCarriesEnumNumbers(t *testing.T) {
	a, captured := kmsAdapter(t, `{"key_id":"k1","format":2,"wrapping_key_id":"kek","wrapping_algorithm":1,`+
		`"wrapped_material":"`+b64("wrapped")+`","version":3,"timestamp":1700000000}`)

	resp := &platformv1.ExportKeyResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ExportKey_FullMethodName,
		&platformv1.ExportKeyRequest{
			KeyId:             "k1",
			WrappingKeyId:     "kek",
			WrappingAlgorithm: platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256,
			Format:            platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8,
			Version:           3,
		}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodGet || captured.path != "/api/v1/kms/keys/k1/export" {
		t.Fatalf("route = %s %s, want GET /api/v1/kms/keys/k1/export", captured.method, captured.path)
	}
	wantQuery := url.Values{
		"wrapping_key_id":    {"kek"},
		"wrapping_algorithm": {"1"},
		"format":             {"2"},
		"version":            {"3"},
	}
	if !reflect.DeepEqual(captured.query, wantQuery) {
		t.Fatalf("query = %v, want %v", captured.query, wantQuery)
	}

	want := &platformv1.ExportKeyResponse{
		Status:            &platformv1.Status{Success: true},
		KeyId:             "k1",
		Format:            platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8,
		WrappingKeyId:     "kek",
		WrappingAlgorithm: platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256,
		WrappedMaterial:   []byte("wrapped"),
		Version:           3,
		Timestamp:         1700000000,
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("reply = %v, want %v", resp, want)
	}
}

// TestKMSExportKey_UnsetOptionsAreOmitted: zero enums and version leave the
// query empty, so the server applies its defaults instead of reading "0".
func TestKMSExportKey_UnsetOptionsAreOmitted(t *testing.T) {
	a, captured := kmsAdapter(t, `{"key_id":"k1"}`)
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ExportKey_FullMethodName,
		&platformv1.ExportKeyRequest{KeyId: "k1"}, &platformv1.ExportKeyResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(captured.query) != 0 {
		t.Fatalf("query = %v, want none", captured.query)
	}
}

// TestKMSExportKey_EmptyKeyRefusedBeforeTheWire: the key is the path, so an
// empty one is InvalidArgument and nothing is sent.
func TestKMSExportKey_EmptyKeyRefusedBeforeTheWire(t *testing.T) {
	a, captured := kmsAdapter(t, `{}`)
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ExportKey_FullMethodName,
		&platformv1.ExportKeyRequest{}, &platformv1.ExportKeyResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
	}
	if captured.method != "" {
		t.Fatalf("request reached the server: %s %s", captured.method, captured.path)
	}
}

// TestKMSBatchEncrypt_ItemsCorrelateAndFailuresBecomeStatuses: the body keeps
// each item's id, and the reply's per-item error becomes a failed Status while
// successful items take the batch's key version.
func TestKMSBatchEncrypt_ItemsCorrelateAndFailuresBecomeStatuses(t *testing.T) {
	a, captured := kmsAdapter(t, `{"key_id":"k1","key_version":4,"results":[`+
		`{"item_id":"a","ciphertext":"`+b64("ct")+`","nonce":"`+b64("nn")+`"},`+
		`{"item_id":"b","error":"plaintext too large"}],`+
		`"success_count":1,"failure_count":1,"timestamp":1700000000}`)

	resp := &platformv1.BatchEncryptResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_BatchEncrypt_FullMethodName,
		&platformv1.BatchEncryptRequest{KeyId: "k1", Items: []*platformv1.BatchEncryptItem{
			{ItemId: "a", Plaintext: []byte("one"), Context: []byte("aad")},
			{ItemId: "b", Plaintext: []byte("two")},
		}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/kms/batch-encrypt" {
		t.Fatalf("route = %s %s, want POST /api/v1/kms/batch-encrypt", captured.method, captured.path)
	}
	wantBody := map[string]interface{}{"key_id": "k1", "items": []interface{}{
		map[string]interface{}{"item_id": "a", "plaintext": b64("one"), "context": b64("aad")},
		map[string]interface{}{"item_id": "b", "plaintext": b64("two")},
	}}
	if !reflect.DeepEqual(captured.body, wantBody) {
		t.Fatalf("body = %v, want %v", captured.body, wantBody)
	}

	want := &platformv1.BatchEncryptResponse{
		Status: &platformv1.Status{Success: true},
		KeyId:  "k1",
		Results: []*platformv1.BatchEncryptResultItem{
			{ItemId: "a", Status: &platformv1.Status{Success: true}, Ciphertext: []byte("ct"), Nonce: []byte("nn"), KeyVersion: 4},
			{ItemId: "b", Status: &platformv1.Status{Message: "plaintext too large"}},
		},
		SuccessCount: 1,
		FailureCount: 1,
		Timestamp:    1700000000,
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("reply = %v, want %v", resp, want)
	}
}

// TestKMSBatchDecrypt_ItemsCorrelateAndFailuresBecomeStatuses: as for
// encrypt, with the key version read per item.
func TestKMSBatchDecrypt_ItemsCorrelateAndFailuresBecomeStatuses(t *testing.T) {
	a, captured := kmsAdapter(t, `{"key_id":"k1","results":[`+
		`{"item_id":"a","plaintext":"`+b64("one")+`","key_version":2},`+
		`{"item_id":"b","error":"authentication failed"}],`+
		`"success_count":1,"failure_count":1,"timestamp":1700000000}`)

	resp := &platformv1.BatchDecryptResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_BatchDecrypt_FullMethodName,
		&platformv1.BatchDecryptRequest{KeyId: "k1", Items: []*platformv1.BatchDecryptItem{
			{ItemId: "a", Ciphertext: []byte("ct"), KeyVersion: 2},
			{ItemId: "b", Ciphertext: []byte("bad")},
		}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/kms/batch-decrypt" {
		t.Fatalf("route = %s %s, want POST /api/v1/kms/batch-decrypt", captured.method, captured.path)
	}
	wantBody := map[string]interface{}{"key_id": "k1", "items": []interface{}{
		map[string]interface{}{"item_id": "a", "ciphertext": b64("ct"), "key_version": float64(2)},
		map[string]interface{}{"item_id": "b", "ciphertext": b64("bad")},
	}}
	if !reflect.DeepEqual(captured.body, wantBody) {
		t.Fatalf("body = %v, want %v", captured.body, wantBody)
	}

	want := &platformv1.BatchDecryptResponse{
		Status: &platformv1.Status{Success: true},
		KeyId:  "k1",
		Results: []*platformv1.BatchDecryptResultItem{
			{ItemId: "a", Status: &platformv1.Status{Success: true}, Plaintext: []byte("one"), KeyVersion: 2},
			{ItemId: "b", Status: &platformv1.Status{Message: "authentication failed"}},
		},
		SuccessCount: 1,
		FailureCount: 1,
		Timestamp:    1700000000,
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("reply = %v, want %v", resp, want)
	}
}

// TestKMSRewrap_OneKeyIsSourceAndDestination: the proto rewraps under one
// key, so the route's source and destination are both the request's key, and
// the reply's versions land as source and target.
func TestKMSRewrap_OneKeyIsSourceAndDestination(t *testing.T) {
	a, captured := kmsAdapter(t, `{"source_key_id":"k1","destination_key_id":"k1","source_key_version":1,`+
		`"dest_key_version":2,"ciphertext":"`+b64("new")+`","nonce":"`+b64("nn")+`","timestamp":1700000000}`)

	resp := &platformv1.RewrapResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Rewrap_FullMethodName,
		&platformv1.RewrapRequest{KeyId: "k1", Ciphertext: []byte("old"), Context: []byte("aad"), Nonce: []byte("on")}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/kms/rewrap" {
		t.Fatalf("route = %s %s, want POST /api/v1/kms/rewrap", captured.method, captured.path)
	}
	wantBody := map[string]interface{}{
		"source_key_id": "k1", "destination_key_id": "k1", "ciphertext": b64("old"),
		"source_context": b64("aad"), "source_nonce": b64("on"),
	}
	if !reflect.DeepEqual(captured.body, wantBody) {
		t.Fatalf("body = %v, want %v", captured.body, wantBody)
	}

	want := &platformv1.RewrapResponse{
		Status:        &platformv1.Status{Success: true},
		KeyId:         "k1",
		SourceVersion: 1,
		TargetVersion: 2,
		Ciphertext:    []byte("new"),
		Nonce:         []byte("nn"),
		Timestamp:     1700000000,
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("reply = %v, want %v", resp, want)
	}
}

// TestKMSRewrap_SourceVersionRefusalIsInvalidArgument: a source version is
// sent, and the daemon's 400 refusal (the SDK rewrap takes no source
// version) reaches the caller as InvalidArgument rather than a silent rewrap
// of the current version.
func TestKMSRewrap_SourceVersionRefusalIsInvalidArgument(t *testing.T) {
	var sent map[string]interface{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":"rewrap of source version 1 is not supported"}`))
	})

	err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_Rewrap_FullMethodName,
		&platformv1.RewrapRequest{KeyId: "k1", Ciphertext: []byte("old"), SourceVersion: 1}, &platformv1.RewrapResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
	}
	if sent["source_key_version"] != float64(1) {
		t.Fatalf("source_key_version = %v, want 1", sent["source_key_version"])
	}
}

// TestKMSExportBatchRewrap_MalformedReplyIsAnError: a reply that is not the
// route's JSON is a typed decode error, never an empty success.
func TestKMSExportBatchRewrap_MalformedReplyIsAnError(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"ExportKey": func(raw []byte) error {
			_, err := decodeKMSExportKey(raw)
			return err
		},
		"BatchEncrypt": func(raw []byte) error {
			_, err := decodeKMSBatchEncrypt(raw)
			return err
		},
		"BatchDecrypt": func(raw []byte) error {
			_, err := decodeKMSBatchDecrypt(raw)
			return err
		},
		"Rewrap": func(raw []byte) error {
			_, err := decodeKMSRewrap(raw)
			return err
		},
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			var target ErrUnmarshalFailed
			if err := decode([]byte(`{"results":"not a list","wrapped_material":7,"ciphertext":7}`)); !errors.As(err, &target) {
				t.Fatalf("error = %T (%v), want ErrUnmarshalFailed", err, err)
			}
		})
	}
}

// TestEncodeEnumNumber renders a set enum as its number and the zero value as
// unset.
func TestEncodeEnumNumber(t *testing.T) {
	set := platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP.Number()
	if got := encodeEnumNumber(protoreflect.ValueOfEnum(set)); got != "5" {
		t.Fatalf("encodeEnumNumber(AES_KWP) = %q, want \"5\"", got)
	}
	if got := encodeEnumNumber(protoreflect.ValueOfEnum(0)); got != "" {
		t.Fatalf("encodeEnumNumber(0) = %q, want unset", got)
	}
}
