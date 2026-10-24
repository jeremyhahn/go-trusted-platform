package rest

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kmsServe sends one request through a router built on the KMS handlers.
func kmsServe(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// kmsErrorMessage decodes the ErrorResponse a KMS handler wrote.
func kmsErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, rec.Code, resp.Code, "the body carries the status it was sent with")
	return resp.Error
}

// kmsBase64Error is the error the handlers wrap for an undecodable field.
func kmsBase64Error(t *testing.T, field, value string) string {
	t.Helper()
	_, err := base64.StdEncoding.DecodeString(value)
	require.Error(t, err)
	return ErrInvalidBase64{Field: field, Cause: err}.Error()
}

func TestKMSAPIRest_NoServiceBatchAndRewrap(t *testing.T) {
	t.Parallel()
	router := mux.NewRouter()
	NewKMSHandlers(nil, slog.Default()).RegisterRoutes(router)

	for _, path := range []string{"/api/v1/kms/batch-encrypt", "/api/v1/kms/batch-decrypt", "/api/v1/kms/rewrap"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rec := kmsServe(router, http.MethodPost, path, "{}")
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Equal(t, ErrKMSServiceNotAvailable{}.Error(), kmsErrorMessage(t, rec))
		})
	}
}

// The router never yields an empty {id}; the handlers still refuse one when
// called directly, so a mis-registered route cannot reach the KMS with "".
func TestKMSAPIRest_EmptyKeyID(t *testing.T) {
	t.Parallel()
	svc := newMockKMSService()
	h, _ := setupKMSTestHandler(svc)

	handlers := map[string]http.HandlerFunc{
		"get":      h.handleGetKey,
		"delete":   h.handleDeleteKey,
		"rotate":   h.handleRotateKey,
		"export":   h.handleExportKey,
		"versions": h.handleGetKeyVersions,
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/", nil)
			req = mux.SetURLVars(req, map[string]string{"id": ""})
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrInvalidKeyID{}.Error(), kmsErrorMessage(t, rec))
		})
	}
	assert.Nil(t, svc.lastGetKeyReq, "no refused request reaches the KMS")
	assert.Nil(t, svc.lastExportKeyReq, "no refused request reaches the KMS")
}

func TestKMSAPIRest_MalformedBody(t *testing.T) {
	t.Parallel()
	_, router := setupKMSTestHandler(newMockKMSService())
	want := ErrKMSRequestBodyInvalid{Reason: "unexpected EOF"}.Error()

	paths := []string{
		"/api/v1/kms/keys/import",
		"/api/v1/kms/encrypt",
		"/api/v1/kms/decrypt",
		"/api/v1/kms/sign",
		"/api/v1/kms/verify",
		"/api/v1/kms/hash",
		"/api/v1/kms/hmac",
		"/api/v1/kms/random",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rec := kmsServe(router, http.MethodPost, path, "{")
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, want, kmsErrorMessage(t, rec))
		})
	}
}

func TestKMSAPIRest_BatchTooManyItems(t *testing.T) {
	t.Parallel()
	svc := newMockKMSService()
	_, router := setupKMSTestHandler(svc)
	want := ErrKMSBatchItemsTooMany{Count: kmsMaxBatchItems + 1, Max: kmsMaxBatchItems}.Error()
	item := base64.StdEncoding.EncodeToString([]byte("data"))

	t.Run("encrypt", func(t *testing.T) {
		t.Parallel()
		items := make([]KMSBatchEncryptItemRequest, kmsMaxBatchItems+1)
		for i := range items {
			items[i].Plaintext = item
		}
		body, err := json.Marshal(KMSBatchEncryptRequest{KeyID: "k", Items: items})
		require.NoError(t, err)

		rec := kmsServe(router, http.MethodPost, "/api/v1/kms/batch-encrypt", string(body))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, want, kmsErrorMessage(t, rec))
	})

	t.Run("decrypt", func(t *testing.T) {
		t.Parallel()
		items := make([]KMSBatchDecryptItemRequest, kmsMaxBatchItems+1)
		for i := range items {
			items[i].Ciphertext = item
		}
		body, err := json.Marshal(KMSBatchDecryptRequest{KeyID: "k", Items: items})
		require.NoError(t, err)

		rec := kmsServe(router, http.MethodPost, "/api/v1/kms/batch-decrypt", string(body))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, want, kmsErrorMessage(t, rec))
	})
}

func TestKMSAPIRest_BatchAtLimitAccepted(t *testing.T) {
	t.Parallel()
	svc := newMockKMSService()
	_, router := setupKMSTestHandler(svc)
	items := make([]KMSBatchEncryptItemRequest, kmsMaxBatchItems)
	for i := range items {
		items[i].Plaintext = base64.StdEncoding.EncodeToString([]byte("data"))
	}
	body, err := json.Marshal(KMSBatchEncryptRequest{KeyID: "k", Items: items})
	require.NoError(t, err)

	rec := kmsServe(router, http.MethodPost, "/api/v1/kms/batch-encrypt", string(body))

	assert.Equal(t, http.StatusOK, rec.Code, "exactly the maximum is allowed")
	require.NotNil(t, svc.lastBatchEncryptReq)
	assert.Len(t, svc.lastBatchEncryptReq.Items, kmsMaxBatchItems)
}

func TestKMSAPIRest_RewrapContexts(t *testing.T) {
	t.Parallel()
	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	const bad = "not-valid-base64!!!"

	refusals := []struct {
		name  string
		field string
		req   KMSRewrapRequest
	}{
		{"dest_context", "dest_context", KMSRewrapRequest{SourceKeyID: "s", DestinationKeyID: "d", Ciphertext: ciphertext, DestContext: bad}},
		{"source_nonce", "source_nonce", KMSRewrapRequest{SourceKeyID: "s", DestinationKeyID: "d", Ciphertext: ciphertext, SourceNonce: bad}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newMockKMSService()
			_, router := setupKMSTestHandler(svc)
			body, err := json.Marshal(tc.req)
			require.NoError(t, err)

			rec := kmsServe(router, http.MethodPost, "/api/v1/kms/rewrap", string(body))

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, kmsBase64Error(t, tc.field, bad), kmsErrorMessage(t, rec))
			assert.Nil(t, svc.lastRewrapReq, "a refused rewrap never reaches the KMS")
		})
	}

	t.Run("decoded contexts reach the KMS", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)
		body, err := json.Marshal(KMSRewrapRequest{
			SourceKeyID:      "s",
			DestinationKeyID: "d",
			Ciphertext:       ciphertext,
			SourceContext:    base64.StdEncoding.EncodeToString([]byte("src-aad")),
			DestContext:      base64.StdEncoding.EncodeToString([]byte("dst-aad")),
			SourceNonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		})
		require.NoError(t, err)

		rec := kmsServe(router, http.MethodPost, "/api/v1/kms/rewrap", string(body))

		assert.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, svc.lastRewrapReq)
		assert.Equal(t, []byte("src-aad"), svc.lastRewrapReq.SourceContext)
		assert.Equal(t, []byte("dst-aad"), svc.lastRewrapReq.DestContext)
		assert.Equal(t, []byte("nonce"), svc.lastRewrapReq.SourceNonce)
	})
}

func TestKMSAPIRest_ExportKeyWrappingAlgorithm(t *testing.T) {
	t.Parallel()
	svc := newMockKMSService()
	_, router := setupKMSTestHandler(svc)

	rec := kmsServe(router, http.MethodGet, "/api/v1/kms/keys/key-1/export?wrapping_key_id=wrap-1&wrapping_algorithm=3", "")

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, svc.lastExportKeyReq)
	assert.Equal(t, "key-1", svc.lastExportKeyReq.KeyID)
	assert.Equal(t, "wrap-1", svc.lastExportKeyReq.WrappingKeyID)
	assert.Equal(t, int32(3), svc.lastExportKeyReq.WrappingAlgorithm)
}

func TestKMSAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	t.Parallel()
	h, _ := setupKMSTestHandler(newMockKMSService())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
