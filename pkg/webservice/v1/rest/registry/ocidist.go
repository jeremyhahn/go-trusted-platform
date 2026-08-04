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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// OCIDistHandlers implements the OCI Distribution Spec at /v2/. The
// scope is the manifest+blob upload+download surface that lets
// `crane`, `skopeo`, and `oras` push and pull against this registry.
// Authorization is delegated to the upstream JWT middleware; this
// router only speaks the spec.
//
// Spec reference: https://github.com/opencontainers/distribution-spec
//
// Endpoints implemented:
//
//	GET    /v2/                                       - API version check
//	GET    /v2/_catalog                               - list repositories
//	GET    /v2/{name:.+}/tags/list                    - list tags in a repo
//	HEAD   /v2/{name:.+}/manifests/{reference}        - manifest exists
//	GET    /v2/{name:.+}/manifests/{reference}        - fetch manifest
//	PUT    /v2/{name:.+}/manifests/{reference}        - upload manifest
//	DELETE /v2/{name:.+}/manifests/{reference}        - delete manifest
//	HEAD   /v2/{name:.+}/blobs/{digest}               - blob exists
//	GET    /v2/{name:.+}/blobs/{digest}               - download blob
//	POST   /v2/{name:.+}/blobs/uploads/               - start upload
//	PATCH  /v2/{name:.+}/blobs/uploads/{uuid}         - upload chunk
//	PUT    /v2/{name:.+}/blobs/uploads/{uuid}?digest= - complete upload
//
// The handlers delegate manifest+blob persistence to the same
// *registry.Registry that backs the gRPC adapter, via a backend
// interface that exposes the surfaces needed for distribution-spec
// semantics (which don't fit cleanly through the Push/Pull JSON
// envelope used by the platform-curated API).
type OCIDistHandlers struct {
	logger  *logging.Logger
	backend OCIDistBackend
	uploads sync.Map // uploadID -> *uploadSession
}

// OCIDistBackend is the registry surface the OCI distribution
// handlers need. It is satisfied by *pkg/registry.Registry plus a
// small adapter that exposes the underlying QuicBaaSStorage; we don't
// rely on grpcapi.RegistryService here because the spec's
// blob-then-manifest dance doesn't fit the JSON-envelope contract.
type OCIDistBackend interface {
	// PutBlob persists a content-addressable blob. The digest must
	// match the SHA-256 of the supplied content.
	PutBlob(ctx context.Context, digest string, content []byte) error
	// GetBlob returns the bytes at the supplied digest.
	GetBlob(ctx context.Context, digest string) ([]byte, error)
	// BlobExists reports whether the blob is present.
	BlobExists(ctx context.Context, digest string) (bool, error)
	// PutManifest persists a manifest under name:reference.
	PutManifest(ctx context.Context, name, reference string, mediaType string, content []byte) (digest string, err error)
	// GetManifest returns the manifest bytes + media type.
	GetManifest(ctx context.Context, name, reference string) (mediaType string, content []byte, err error)
	// DeleteManifest removes a tag (does not GC blobs).
	DeleteManifest(ctx context.Context, name, reference string) error
	// ListRepositories enumerates known repository names.
	ListRepositories(ctx context.Context, limit int) ([]string, error)
	// ListTags enumerates tags within a repository.
	ListTags(ctx context.Context, name string) ([]string, error)
}

// uploadSession tracks a blob upload-in-progress. The spec uses a
// chunked upload protocol: client POSTs to start, PATCHes data, then
// PUTs with the final digest to commit. We accumulate bytes in
// memory; a production deployment with very large layers would stream
// to disk, but the in-memory path is fine for the GiB-scale layers
// typical of VM images.
type uploadSession struct {
	mu     sync.Mutex
	name   string
	buffer []byte
}

// NewOCIDistHandlers constructs handlers bound to a backend.
func NewOCIDistHandlers(logger *logging.Logger, backend OCIDistBackend) *OCIDistHandlers {
	return &OCIDistHandlers{logger: logger, backend: backend}
}

// RegisterOCIDistRoutes attaches the /v2/ surface to the supplied
// parent router (typically the root API router, NOT the /api/v1
// subrouter — the spec mandates /v2/ at the host root).
func RegisterOCIDistRoutes(parent *mux.Router, logger *logging.Logger, backend OCIDistBackend) {
	if backend == nil {
		return
	}
	h := NewOCIDistHandlers(logger, backend)
	v2 := parent.PathPrefix("/v2").Subrouter()
	v2.HandleFunc("", h.versionCheck).Methods("GET")
	v2.HandleFunc("/", h.versionCheck).Methods("GET")
	v2.HandleFunc("/_catalog", h.catalog).Methods("GET")
	v2.HandleFunc("/{name:.+}/tags/list", h.listTags).Methods("GET")
	v2.HandleFunc("/{name:.+}/manifests/{reference}", h.headManifest).Methods("HEAD")
	v2.HandleFunc("/{name:.+}/manifests/{reference}", h.getManifest).Methods("GET")
	v2.HandleFunc("/{name:.+}/manifests/{reference}", h.putManifest).Methods("PUT")
	v2.HandleFunc("/{name:.+}/manifests/{reference}", h.deleteManifest).Methods("DELETE")
	v2.HandleFunc("/{name:.+}/blobs/uploads/", h.startUpload).Methods("POST")
	v2.HandleFunc("/{name:.+}/blobs/uploads/{uuid}", h.patchUpload).Methods("PATCH")
	v2.HandleFunc("/{name:.+}/blobs/uploads/{uuid}", h.putUpload).Methods("PUT")
	v2.HandleFunc("/{name:.+}/blobs/{digest}", h.headBlob).Methods("HEAD")
	v2.HandleFunc("/{name:.+}/blobs/{digest}", h.getBlob).Methods("GET")
}

func (h *OCIDistHandlers) versionCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}

func (h *OCIDistHandlers) catalog(w http.ResponseWriter, r *http.Request) {
	repos, err := h.backend.ListRepositories(r.Context(), 0)
	if err != nil {
		writeOCIError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"repositories": repos})
}

func (h *OCIDistHandlers) listTags(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	tags, err := h.backend.ListTags(r.Context(), name)
	if err != nil {
		writeOCIError(w, http.StatusNotFound, "NAME_UNKNOWN", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": name,
		"tags": tags,
	})
}

func (h *OCIDistHandlers) headManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mediaType, body, err := h.backend.GetManifest(r.Context(), vars["name"], vars["reference"])
	if err != nil {
		writeOCIError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", err.Error())
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", manifestDigest(body))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
}

func (h *OCIDistHandlers) getManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mediaType, body, err := h.backend.GetManifest(r.Context(), vars["name"], vars["reference"])
	if err != nil {
		writeOCIError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", err.Error())
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", manifestDigest(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *OCIDistHandlers) putManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOCIError(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
		return
	}
	mediaType := r.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = "application/vnd.oci.image.manifest.v1+json"
	}
	digest, err := h.backend.PutManifest(r.Context(), vars["name"], vars["reference"], mediaType, body)
	if err != nil {
		writeOCIError(w, http.StatusInternalServerError, "MANIFEST_INVALID", err.Error())
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", vars["name"], vars["reference"]))
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (h *OCIDistHandlers) deleteManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if err := h.backend.DeleteManifest(r.Context(), vars["name"], vars["reference"]); err != nil {
		writeOCIError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *OCIDistHandlers) headBlob(w http.ResponseWriter, r *http.Request) {
	digest := mux.Vars(r)["digest"]
	exists, err := h.backend.BlobExists(r.Context(), digest)
	if err != nil || !exists {
		writeOCIError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob does not exist")
		return
	}
	data, err := h.backend.GetBlob(r.Context(), digest)
	if err != nil {
		writeOCIError(w, http.StatusNotFound, "BLOB_UNKNOWN", err.Error())
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusOK)
}

func (h *OCIDistHandlers) getBlob(w http.ResponseWriter, r *http.Request) {
	digest := mux.Vars(r)["digest"]
	data, err := h.backend.GetBlob(r.Context(), digest)
	if err != nil {
		writeOCIError(w, http.StatusNotFound, "BLOB_UNKNOWN", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *OCIDistHandlers) startUpload(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	id, err := newUploadID()
	if err != nil {
		writeOCIError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	h.uploads.Store(id, &uploadSession{name: name})

	// Spec § monolithic upload: clients may send the entire blob in
	// the POST body along with ?digest= to commit immediately.
	if digest := r.URL.Query().Get("digest"); digest != "" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeOCIError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		if err := h.commitBlob(r.Context(), digest, body); err != nil {
			writeOCIError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
			return
		}
		h.uploads.Delete(id)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (h *OCIDistHandlers) patchUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, ok := h.uploadSession(vars["uuid"])
	if !ok {
		writeOCIError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOCIError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
		return
	}
	sess.mu.Lock()
	sess.buffer = append(sess.buffer, body...)
	bufferedLen := len(sess.buffer)
	sess.mu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", sess.name, vars["uuid"]))
	w.Header().Set("Range", fmt.Sprintf("0-%d", bufferedLen-1))
	w.Header().Set("Docker-Upload-UUID", vars["uuid"])
	w.WriteHeader(http.StatusAccepted)
}

func (h *OCIDistHandlers) putUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, ok := h.uploadSession(vars["uuid"])
	if !ok {
		writeOCIError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload")
		return
	}
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		writeOCIError(w, http.StatusBadRequest, "DIGEST_INVALID", "digest query param required on PUT")
		return
	}
	// A final body chunk may accompany the PUT (clients that batched
	// the tail into the commit call).
	if r.ContentLength > 0 {
		tail, err := io.ReadAll(r.Body)
		if err != nil {
			writeOCIError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		sess.mu.Lock()
		sess.buffer = append(sess.buffer, tail...)
		sess.mu.Unlock()
	}
	sess.mu.Lock()
	buf := append([]byte(nil), sess.buffer...)
	sess.mu.Unlock()
	if err := h.commitBlob(r.Context(), digest, buf); err != nil {
		writeOCIError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
		return
	}
	h.uploads.Delete(vars["uuid"])
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", sess.name, digest))
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// commitBlob verifies the supplied content matches the digest before
// handing it to the backend. This is the spec's integrity check —
// callers attest by digest; we MUST refuse to write content whose
// hash doesn't match.
func (h *OCIDistHandlers) commitBlob(ctx context.Context, digest string, content []byte) error {
	want := strings.TrimPrefix(digest, "sha256:")
	got := sha256.Sum256(content)
	if hex.EncodeToString(got[:]) != want {
		return &MessageError{Msg: fmt.Sprintf("digest mismatch: claimed %s, computed sha256:%x", digest, got)}
	}
	return h.backend.PutBlob(ctx, digest, content)
}

// uploadSession returns the in-progress upload bound to uuid, or
// ok=false if none exists.
func (h *OCIDistHandlers) uploadSession(uuid string) (*uploadSession, bool) {
	v, ok := h.uploads.Load(uuid)
	if !ok {
		return nil, false
	}
	sess, ok := v.(*uploadSession)
	return sess, ok
}

func newUploadID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func manifestDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeOCIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"errors": []map[string]interface{}{{
			"code":    code,
			"message": message,
		}},
	})
}

// Unused but reserved so the OCI Distribution router can compute
// canonical blob digests offline when needed (e.g. validation tools).
var _ = path.Clean
