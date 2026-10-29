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

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeOCIBackend is an in-memory OCIDistBackend for handler tests.
type fakeOCIBackend struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]fakeManifest
	failPut   error
	failList  error
}

type fakeManifest struct {
	mediaType string
	content   []byte
}

func newFakeOCIBackend() *fakeOCIBackend {
	return &fakeOCIBackend{
		blobs:     map[string][]byte{},
		manifests: map[string]fakeManifest{},
	}
}

func (f *fakeOCIBackend) PutBlob(_ context.Context, digest string, content []byte) error {
	if f.failPut != nil {
		return f.failPut
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[digest] = append([]byte(nil), content...)
	return nil
}

func (f *fakeOCIBackend) GetBlob(_ context.Context, digest string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blobs[digest]
	if !ok {
		return nil, &MessageError{Msg: "blob unknown"}
	}
	return b, nil
}

func (f *fakeOCIBackend) BlobExists(_ context.Context, digest string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.blobs[digest]
	return ok, nil
}

func (f *fakeOCIBackend) PutManifest(_ context.Context, name, reference, mediaType string, content []byte) (string, error) {
	if f.failPut != nil {
		return "", f.failPut
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[name+":"+reference] = fakeManifest{mediaType: mediaType, content: content}
	return manifestDigest(content), nil
}

func (f *fakeOCIBackend) GetManifest(_ context.Context, name, reference string) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.manifests[name+":"+reference]
	if !ok {
		return "", nil, &MessageError{Msg: "manifest unknown"}
	}
	return m.mediaType, m.content, nil
}

func (f *fakeOCIBackend) DeleteManifest(_ context.Context, name, reference string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.manifests[name+":"+reference]; !ok {
		return &MessageError{Msg: "manifest unknown"}
	}
	delete(f.manifests, name+":"+reference)
	return nil
}

func (f *fakeOCIBackend) ListRepositories(_ context.Context, _ int) ([]string, error) {
	if f.failList != nil {
		return nil, f.failList
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for k := range f.manifests {
		name, _, _ := strings.Cut(k, ":")
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

func (f *fakeOCIBackend) ListTags(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.manifests {
		n, tag, _ := strings.Cut(k, ":")
		if n == name {
			out = append(out, tag)
		}
	}
	if len(out) == 0 {
		return nil, &MessageError{Msg: "name unknown"}
	}
	return out, nil
}

// passGate is the identity gate: it admits everything, so handler tests
// exercise the handlers rather than the gate.
func passGate(next http.Handler) http.Handler { return next }

// denyGate refuses everything with 401, standing in for the operator chain.
func denyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

// recordingGate counts the requests that pass through it so a test can
// prove which gate a route is mounted behind.
type recordingGate struct {
	hits int
}

func (g *recordingGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.hits++
		next.ServeHTTP(w, r)
	})
}

func newTestRouter(t *testing.T, backend OCIDistBackend, gates OCIDistGates, limits OCIDistLimits) *mux.Router {
	t.Helper()
	root := mux.NewRouter()
	require.NoError(t, RegisterOCIDistRoutes(root, logging.DefaultLogger(), backend, gates, limits))
	return root
}

func openGates() OCIDistGates {
	return OCIDistGates{Read: passGate, Write: passGate}
}

func do(router http.Handler, method, target string, body []byte, header map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reader)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestRegisterOCIDistRoutes_RefusesNilBackend(t *testing.T) {
	err := RegisterOCIDistRoutes(mux.NewRouter(), logging.DefaultLogger(), nil, openGates(), OCIDistLimits{})
	var want *ErrOCIDistBackendRequired
	require.True(t, errors.As(err, &want), "got %v", err)
}

func TestRegisterOCIDistRoutes_RefusesMissingGate(t *testing.T) {
	cases := map[string]OCIDistGates{
		"no read gate":  {Write: passGate},
		"no write gate": {Read: passGate},
		"no gates":      {},
	}
	for name, gates := range cases {
		t.Run(name, func(t *testing.T) {
			err := RegisterOCIDistRoutes(mux.NewRouter(), logging.DefaultLogger(), newFakeOCIBackend(), gates, OCIDistLimits{})
			var want *ErrOCIDistGateRequired
			require.True(t, errors.As(err, &want), "got %v", err)
		})
	}
}

// TestRegisterOCIDistRoutes_EveryRouteIsBehindAGate walks the mounted table
// and proves each route answers through the read or the write gate — a
// route reachable through neither is the defect this issue is about.
func TestRegisterOCIDistRoutes_EveryRouteIsBehindAGate(t *testing.T) {
	router := newTestRouter(t, newFakeOCIBackend(), OCIDistGates{Read: denyGate, Write: denyGate}, OCIDistLimits{})

	var routes []string
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			routes = append(routes, m+" "+tmpl)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, routes)

	for _, route := range routes {
		method, tmpl, _ := strings.Cut(route, " ")
		target := strings.NewReplacer(
			"{name:.+}", "library/alpine",
			"{reference}", "latest",
			"{uuid}", "0123456789abcdef0123456789abcdef",
			"{digest}", sha256Of([]byte("x")),
		).Replace(tmpl)
		rec := do(router, method, target, []byte("x"), nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s reached its handler without passing a gate", route)
	}
}

// TestRegisterOCIDistRoutes_ReadAndWriteAreSplit proves pulls go through the
// read gate and pushes and deletes through the write gate.
func TestRegisterOCIDistRoutes_ReadAndWriteAreSplit(t *testing.T) {
	read := &recordingGate{}
	write := &recordingGate{}
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, OCIDistGates{Read: read.wrap, Write: write.wrap}, OCIDistLimits{})

	manifest := []byte(`{"schemaVersion":2}`)
	rec := do(router, http.MethodPut, "/v2/library/alpine/manifests/latest", manifest,
		map[string]string{"Content-Type": defaultManifestMediaType})
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, 0, read.hits)
	assert.Equal(t, 1, write.hits)

	rec = do(router, http.MethodGet, "/v2/library/alpine/manifests/latest", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, read.hits)
	assert.Equal(t, 1, write.hits)

	rec = do(router, http.MethodDelete, "/v2/library/alpine/manifests/latest", nil, nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, 2, write.hits)

	rec = do(router, http.MethodGet, "/v2/", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = do(router, http.MethodGet, "/v2/_catalog", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 3, read.hits)
}

func TestOCIDist_VersionCheck(t *testing.T) {
	router := newTestRouter(t, newFakeOCIBackend(), openGates(), OCIDistLimits{})
	rec := do(router, http.MethodGet, "/v2/", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "registry/2.0", rec.Header().Get("Docker-Distribution-API-Version"))
}

func TestOCIDist_ManifestRoundTrip(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{})
	manifest := []byte(`{"schemaVersion":2,"config":{}}`)

	rec := do(router, http.MethodPut, "/v2/apps/web/manifests/v1", manifest, nil)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, manifestDigest(manifest), rec.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, "/v2/apps/web/manifests/v1", rec.Header().Get("Location"))

	rec = do(router, http.MethodHead, "/v2/apps/web/manifests/v1", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, defaultManifestMediaType, rec.Header().Get("Content-Type"))

	rec = do(router, http.MethodGet, "/v2/apps/web/manifests/v1", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, manifest, rec.Body.Bytes())
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	rec = do(router, http.MethodGet, "/v2/apps/web/tags/list", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tags))
	assert.Equal(t, "apps/web", tags.Name)
	assert.Equal(t, []string{"v1"}, tags.Tags)

	rec = do(router, http.MethodGet, "/v2/_catalog", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"apps/web"`)

	rec = do(router, http.MethodDelete, "/v2/apps/web/manifests/v1", nil, nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	rec = do(router, http.MethodGet, "/v2/apps/web/manifests/v1", nil, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOCIDist_ManifestErrors(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{MaxManifestBytes: 32})

	t.Run("unknown manifest", func(t *testing.T) {
		rec := do(router, http.MethodHead, "/v2/apps/web/manifests/missing", nil, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		rec = do(router, http.MethodDelete, "/v2/apps/web/manifests/missing", nil, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		rec = do(router, http.MethodGet, "/v2/nothing/tags/list", nil, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("rejected media type", func(t *testing.T) {
		rec := do(router, http.MethodPut, "/v2/apps/web/manifests/v1", []byte("<html>"),
			map[string]string{"Content-Type": "text/html"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "MANIFEST_INVALID")
	})
	t.Run("oversized manifest is 413", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), 33)
		rec := do(router, http.MethodPut, "/v2/apps/web/manifests/v1", big, nil)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.Contains(t, rec.Body.String(), "MANIFEST_INVALID")
	})
	t.Run("backend failure is 500", func(t *testing.T) {
		backend.failPut = &MessageError{Msg: "disk full"}
		defer func() { backend.failPut = nil }()
		rec := do(router, http.MethodPut, "/v2/apps/web/manifests/v1", []byte(`{}`), nil)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
	t.Run("catalog backend failure is 500", func(t *testing.T) {
		backend.failList = &MessageError{Msg: "storage offline"}
		defer func() { backend.failList = nil }()
		rec := do(router, http.MethodGet, "/v2/_catalog", nil, nil)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "STORAGE_ERROR")
	})
}

func TestOCIDist_BlobMonolithicUpload(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{})
	blob := []byte("layer-bytes")
	digest := sha256Of(blob)

	rec := do(router, http.MethodPost, "/v2/apps/web/blobs/uploads/?digest="+digest, blob, nil)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "/v2/apps/web/blobs/"+digest, rec.Header().Get("Location"))

	rec = do(router, http.MethodHead, "/v2/apps/web/blobs/"+digest, nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "11", rec.Header().Get("Content-Length"))

	rec = do(router, http.MethodGet, "/v2/apps/web/blobs/"+digest, nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, blob, rec.Body.Bytes())
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))

	rec = do(router, http.MethodGet, "/v2/apps/web/blobs/"+sha256Of([]byte("other")), nil, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = do(router, http.MethodHead, "/v2/apps/web/blobs/"+sha256Of([]byte("other")), nil, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOCIDist_BlobMonolithicDigestMismatch(t *testing.T) {
	router := newTestRouter(t, newFakeOCIBackend(), openGates(), OCIDistLimits{})
	rec := do(router, http.MethodPost, "/v2/apps/web/blobs/uploads/?digest="+sha256Of([]byte("not-it")), []byte("layer"), nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "DIGEST_INVALID")
}

func startUploadFor(t *testing.T, router http.Handler, name string) string {
	t.Helper()
	rec := do(router, http.MethodPost, "/v2/"+name+"/blobs/uploads/", nil, nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	id := rec.Header().Get("Docker-Upload-UUID")
	require.NotEmpty(t, id)
	assert.Equal(t, "/v2/"+name+"/blobs/uploads/"+id, rec.Header().Get("Location"))
	return id
}

func TestOCIDist_BlobChunkedUpload(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{})
	id := startUploadFor(t, router, "apps/web")

	rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("hello "), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "0-5", rec.Header().Get("Range"))

	rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("wor"), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "0-8", rec.Header().Get("Range"))

	full := []byte("hello world")
	rec = do(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of(full), []byte("ld"), nil)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, sha256Of(full), rec.Header().Get("Docker-Content-Digest"))

	got, err := backend.GetBlob(context.Background(), sha256Of(full))
	require.NoError(t, err)
	assert.Equal(t, full, got)

	// The session is released on commit: a second PUT is unknown.
	rec = do(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of(full), nil, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// doChunked sends a request as net/http presents a Transfer-Encoding:
// chunked one: the length is unknown, so ContentLength is -1.
func doChunked(router http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestOCIDist_BlobCommitChunkedTail(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{})
	id := startUploadFor(t, router, "apps/web")

	rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("hello "), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)

	full := []byte("hello world")
	rec = doChunked(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of(full), []byte("world"))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	got, err := backend.GetBlob(context.Background(), sha256Of(full))
	require.NoError(t, err)
	assert.Equal(t, full, got)
}

func TestOCIDist_BlobCommitChunkedEmptyBody(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{})
	id := startUploadFor(t, router, "apps/web")

	full := []byte("hello world")
	rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, full, nil)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rec = doChunked(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of(full), nil)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	got, err := backend.GetBlob(context.Background(), sha256Of(full))
	require.NoError(t, err)
	assert.Equal(t, full, got)
}

func TestOCIDist_BlobCommitChunkedTailTooLarge(t *testing.T) {
	backend := newFakeOCIBackend()
	router := newTestRouter(t, backend, openGates(), OCIDistLimits{MaxChunkBytes: 4})
	id := startUploadFor(t, router, "apps/web")

	full := []byte("hello world")
	rec := doChunked(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of(full), full)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())

	_, err := backend.GetBlob(context.Background(), sha256Of(full))
	assert.Error(t, err)
}

func TestOCIDist_BlobChunkedUploadErrors(t *testing.T) {
	router := newTestRouter(t, newFakeOCIBackend(), openGates(), OCIDistLimits{})

	t.Run("unknown session", func(t *testing.T) {
		rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/nope", []byte("x"), nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		rec = do(router, http.MethodPut, "/v2/apps/web/blobs/uploads/nope?digest=sha256:00", []byte("x"), nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("put without digest", func(t *testing.T) {
		id := startUploadFor(t, router, "apps/web")
		rec := do(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id, nil, nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
	t.Run("digest mismatch releases the session", func(t *testing.T) {
		id := startUploadFor(t, router, "apps/web")
		rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abc"), nil)
		require.Equal(t, http.StatusAccepted, rec.Code)
		rec = do(router, http.MethodPut, "/v2/apps/web/blobs/uploads/"+id+"?digest="+sha256Of([]byte("zzz")), nil, nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abc"), nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestOCIDist_UploadCancel(t *testing.T) {
	router := newTestRouter(t, newFakeOCIBackend(), openGates(), OCIDistLimits{})
	id := startUploadFor(t, router, "apps/web")
	rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abc"), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rec = do(router, http.MethodDelete, "/v2/apps/web/blobs/uploads/"+id, nil, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	rec = do(router, http.MethodDelete, "/v2/apps/web/blobs/uploads/"+id, nil, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abc"), nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOCIDist_UploadLimits(t *testing.T) {
	limits := OCIDistLimits{
		MaxChunkBytes:    8,
		MaxBlobBytes:     12,
		MaxInFlightBytes: 20,
	}

	t.Run("chunk over the limit is 413", func(t *testing.T) {
		router := newTestRouter(t, newFakeOCIBackend(), openGates(), limits)
		id := startUploadFor(t, router, "apps/web")
		rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, bytes.Repeat([]byte("a"), 9), nil)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.Contains(t, rec.Body.String(), "BLOB_UPLOAD_INVALID")
	})
	t.Run("blob over the per-session limit is 413 and the session is released", func(t *testing.T) {
		router := newTestRouter(t, newFakeOCIBackend(), openGates(), limits)
		id := startUploadFor(t, router, "apps/web")
		rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, bytes.Repeat([]byte("a"), 8), nil)
		require.Equal(t, http.StatusAccepted, rec.Code)
		rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, bytes.Repeat([]byte("a"), 5), nil)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("a"), nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("monolithic body over the blob limit is 413", func(t *testing.T) {
		router := newTestRouter(t, newFakeOCIBackend(), openGates(), limits)
		blob := bytes.Repeat([]byte("a"), 13)
		rec := do(router, http.MethodPost, "/v2/apps/web/blobs/uploads/?digest="+sha256Of(blob), blob, nil)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
	t.Run("in-flight total over the limit is 429", func(t *testing.T) {
		router := newTestRouter(t, newFakeOCIBackend(), openGates(), limits)
		first := startUploadFor(t, router, "apps/web")
		second := startUploadFor(t, router, "apps/web")
		third := startUploadFor(t, router, "apps/web")
		for _, id := range []string{first, second} {
			rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, bytes.Repeat([]byte("a"), 8), nil)
			require.Equal(t, http.StatusAccepted, rec.Code)
		}
		rec := do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+third, bytes.Repeat([]byte("a"), 8), nil)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Contains(t, rec.Body.String(), "TOOMANYREQUESTS")

		// Cancelling one session frees its bytes for the next.
		rec = do(router, http.MethodDelete, "/v2/apps/web/blobs/uploads/"+first, nil, nil)
		require.Equal(t, http.StatusNoContent, rec.Code)
		rec = do(router, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+third, bytes.Repeat([]byte("a"), 8), nil)
		assert.Equal(t, http.StatusAccepted, rec.Code)
	})
}

func TestOCIDist_IdleSessionsAreEvicted(t *testing.T) {
	h := NewOCIDistHandlers(logging.DefaultLogger(), newFakeOCIBackend(), OCIDistLimits{SessionIdle: time.Minute})
	base := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	now := base
	h.now = func() time.Time { return now }
	root := mux.NewRouter()
	h.registerRoutes(root, openGates())

	id := startUploadFor(t, root, "apps/web")
	rec := do(root, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abcd"), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, int64(4), h.inFlight.Load())

	// Activity inside the idle window keeps the session.
	now = base.Add(30 * time.Second)
	assert.Equal(t, 0, h.evictIdle())
	rec = do(root, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("e"), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Past the window, the next upload start sweeps it and releases its bytes.
	now = now.Add(2 * time.Minute)
	other := startUploadFor(t, root, "apps/web")
	assert.NotEqual(t, id, other)
	rec = do(root, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("f"), nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, int64(0), h.inFlight.Load())
}

func TestOCIDistLimits_Defaults(t *testing.T) {
	got := OCIDistLimits{}.withDefaults()
	assert.Equal(t, DefaultOCIDistLimits(), got)
	assert.Positive(t, got.MaxManifestBytes)
	assert.Positive(t, got.MaxChunkBytes)
	assert.Positive(t, got.MaxBlobBytes)
	assert.Positive(t, got.MaxInFlightBytes)
	assert.Positive(t, got.SessionIdle)

	custom := OCIDistLimits{MaxChunkBytes: 1}.withDefaults()
	assert.Equal(t, int64(1), custom.MaxChunkBytes)
	assert.Equal(t, DefaultOCIDistLimits().MaxBlobBytes, custom.MaxBlobBytes)
}

func TestOCIDistErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrOCIDistBackendRequired{}).Error(), "backend")
	assert.Contains(t, (&ErrOCIDistGateRequired{Surface: "write"}).Error(), "write")
	assert.Contains(t, (&ErrUploadUnknown{}).Error(), "upload")
}

// TestOCIDist_AppendAfterReleaseIsRefused pins the interleaving the review
// caught: a PATCH that looked its session up before a concurrent PUT,
// cancel or eviction released it must not append to the orphan, and must
// not count bytes nothing will ever subtract.
func TestOCIDist_AppendAfterReleaseIsRefused(t *testing.T) {
	h := NewOCIDistHandlers(logging.DefaultLogger(), newFakeOCIBackend(), OCIDistLimits{})
	root := mux.NewRouter()
	h.registerRoutes(root, openGates())

	id := startUploadFor(t, root, "apps/web")
	rec := do(root, http.MethodPatch, "/v2/apps/web/blobs/uploads/"+id, []byte("abcd"), nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, int64(4), h.inFlight.Load())

	// The PATCH handler's lookup happened here...
	sess, ok := h.lookupUpload(id)
	require.True(t, ok)

	// ...and the concurrent cancel released the session before its append.
	rec = do(root, http.MethodDelete, "/v2/apps/web/blobs/uploads/"+id, nil, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, int64(0), h.inFlight.Load())

	_, err := h.appendChunk(id, sess, []byte("efgh"))
	var unknown *ErrUploadUnknown
	require.True(t, errors.As(err, &unknown), "got %v", err)
	assert.Equal(t, int64(0), h.inFlight.Load(), "an orphaned session must not count bytes")
	assert.Nil(t, sess.buffer)

	rec = httptest.NewRecorder()
	writeBodyError(rec, err, "BLOB_UPLOAD_INVALID")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "BLOB_UPLOAD_UNKNOWN")
}
