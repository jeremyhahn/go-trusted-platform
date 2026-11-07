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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// OCIDistHandlers implements the OCI Distribution Spec at /v2/. The
// scope is the manifest+blob upload+download surface that lets
// `crane`, `skopeo`, and `oras` push and pull against this registry.
//
// This router only speaks the spec. It does not authenticate anybody:
// every route is mounted behind the read or the write gate the caller
// hands to RegisterOCIDistRoutes, and registration refuses to proceed
// without both (#549). The backend it delegates to does not
// authenticate either — *pkg/registry.Registry's distribution surface
// is storage plus state checks; VerifyClient is the platform-curated
// API's control, not this one's — so the gates are the only control
// in front of push, pull and delete.
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
//	DELETE /v2/{name:.+}/blobs/uploads/{uuid}         - cancel upload
//
// The handlers delegate manifest+blob persistence to the same
// *registry.Registry that backs the gRPC adapter, via a backend
// interface that exposes the surfaces needed for distribution-spec
// semantics (which don't fit cleanly through the Push/Pull JSON
// envelope used by the platform-curated API).
type OCIDistHandlers struct {
	logger  *logging.Logger
	backend OCIDistBackend
	limits  OCIDistLimits
	uploads sync.Map // uploadID -> *uploadSession
	// inFlight is the number of upload bytes currently buffered across
	// every open session; the MaxInFlightBytes cap is enforced on it.
	inFlight atomic.Int64
	// now is the clock idle eviction reads; tests substitute it.
	now func() time.Time
}

// OCIDistGates are the two authentication chains the distribution
// surface mounts behind: Read wraps every pull-side route (version
// check, catalog, tags, manifest and blob GET/HEAD) and Write wraps every
// push-side route (manifest PUT/DELETE, blob uploads and cancels). They
// are separate so the read policy can widen without widening writes.
// Both are required.
type OCIDistGates struct {
	Read  func(http.Handler) http.Handler
	Write func(http.Handler) http.Handler
}

// OCIDistLimits bounds the memory the upload protocol may pin. Uploads
// are accumulated in memory until the client commits them, so an
// anonymous or hostile client that starts sessions and never commits
// would otherwise grow the heap without bound. A zero field takes the
// default from DefaultOCIDistLimits.
type OCIDistLimits struct {
	// MaxManifestBytes caps a manifest PUT body.
	MaxManifestBytes int64
	// MaxChunkBytes caps one PATCH or PUT body.
	MaxChunkBytes int64
	// MaxBlobBytes caps the bytes one upload session may accumulate, and a
	// monolithic POST body.
	MaxBlobBytes int64
	// MaxInFlightBytes caps the bytes buffered across all open sessions.
	MaxInFlightBytes int64
	// SessionIdle is how long a session may go without a chunk before it
	// is evicted and its bytes released.
	SessionIdle time.Duration
}

const (
	defaultMaxManifestBytes int64 = 4 << 20
	defaultMaxChunkBytes    int64 = 256 << 20
	defaultMaxBlobBytes     int64 = 4 << 30
	defaultMaxInFlightBytes int64 = 8 << 30
	defaultSessionIdle            = 15 * time.Minute
)

// DefaultOCIDistLimits returns the limits used when a field is left zero:
// 4 MiB manifests, 256 MiB chunks, 4 GiB per blob, 8 GiB in flight, and a
// 15 minute idle window.
func DefaultOCIDistLimits() OCIDistLimits {
	return OCIDistLimits{
		MaxManifestBytes: defaultMaxManifestBytes,
		MaxChunkBytes:    defaultMaxChunkBytes,
		MaxBlobBytes:     defaultMaxBlobBytes,
		MaxInFlightBytes: defaultMaxInFlightBytes,
		SessionIdle:      defaultSessionIdle,
	}
}

// withDefaults fills every zero field from DefaultOCIDistLimits.
func (l OCIDistLimits) withDefaults() OCIDistLimits {
	d := DefaultOCIDistLimits()
	if l.MaxManifestBytes <= 0 {
		l.MaxManifestBytes = d.MaxManifestBytes
	}
	if l.MaxChunkBytes <= 0 {
		l.MaxChunkBytes = d.MaxChunkBytes
	}
	if l.MaxBlobBytes <= 0 {
		l.MaxBlobBytes = d.MaxBlobBytes
	}
	if l.MaxInFlightBytes <= 0 {
		l.MaxInFlightBytes = d.MaxInFlightBytes
	}
	if l.SessionIdle <= 0 {
		l.SessionIdle = d.SessionIdle
	}
	return l
}

// ErrOCIDistBackendRequired is returned when the distribution surface is
// asked to mount with no backend. A nil backend used to be a silent skip;
// a caller that asks for the surface and does not get it must be told.
type ErrOCIDistBackendRequired struct{}

// Error implements the error interface.
func (e *ErrOCIDistBackendRequired) Error() string {
	return "registry: the OCI distribution surface requires a backend"
}

// ErrOCIDistGateRequired is returned when a read or write gate is missing.
// The surface never mounts ungated.
type ErrOCIDistGateRequired struct {
	// Surface names the missing gate: "read" or "write".
	Surface string
}

// Error implements the error interface.
func (e *ErrOCIDistGateRequired) Error() string {
	return "registry: the OCI distribution surface requires a " + e.Surface + " gate"
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
// PUTs with the final digest to commit. Bytes accumulate in memory
// under OCIDistLimits; a deployment with very large layers would stream
// to disk, but the bounded in-memory path is fine for the GiB-scale
// layers typical of VM images.
type uploadSession struct {
	mu         sync.Mutex
	name       string
	buffer     []byte
	lastActive time.Time
	// released is set under mu by releaseSession. A handler that looked
	// the session up before a concurrent commit, cancel or eviction
	// released it still holds the pointer; the flag is what stops it
	// appending to an orphan and counting bytes nothing will ever
	// subtract.
	released bool
}

// NewOCIDistHandlers constructs handlers bound to a backend. Zero limit
// fields take DefaultOCIDistLimits.
func NewOCIDistHandlers(logger *logging.Logger, backend OCIDistBackend, limits OCIDistLimits) *OCIDistHandlers {
	return &OCIDistHandlers{
		logger:  logger,
		backend: backend,
		limits:  limits.withDefaults(),
		now:     time.Now,
	}
}

// RegisterOCIDistRoutes attaches the /v2/ surface to the supplied parent
// router (the ROOT router, not the /api/v1 subrouter — the spec mandates
// /v2/ at the host root), every route behind its read or write gate. It
// refuses a nil backend and a missing gate with a typed error rather
// than mounting less than it was asked for.
func RegisterOCIDistRoutes(parent *mux.Router, logger *logging.Logger, backend OCIDistBackend, gates OCIDistGates, limits OCIDistLimits) error {
	if backend == nil {
		return &ErrOCIDistBackendRequired{}
	}
	if gates.Read == nil {
		return &ErrOCIDistGateRequired{Surface: "read"}
	}
	if gates.Write == nil {
		return &ErrOCIDistGateRequired{Surface: "write"}
	}
	NewOCIDistHandlers(logger, backend, limits).registerRoutes(parent, gates)
	return nil
}

// registerRoutes mounts the table. Reads go through gates.Read and writes
// through gates.Write; nothing is mounted bare.
func (h *OCIDistHandlers) registerRoutes(parent *mux.Router, gates OCIDistGates) {
	read := func(fn http.HandlerFunc) http.Handler { return gates.Read(fn) }
	write := func(fn http.HandlerFunc) http.Handler { return gates.Write(fn) }
	v2 := parent.PathPrefix("/v2").Subrouter()
	v2.Handle("", read(h.versionCheck)).Methods("GET")
	v2.Handle("/", read(h.versionCheck)).Methods("GET")
	v2.Handle("/_catalog", read(h.catalog)).Methods("GET")
	v2.Handle("/{name:.+}/tags/list", read(h.listTags)).Methods("GET")
	v2.Handle("/{name:.+}/manifests/{reference}", read(h.headManifest)).Methods("HEAD")
	v2.Handle("/{name:.+}/manifests/{reference}", read(h.getManifest)).Methods("GET")
	v2.Handle("/{name:.+}/manifests/{reference}", write(h.putManifest)).Methods("PUT")
	v2.Handle("/{name:.+}/manifests/{reference}", write(h.deleteManifest)).Methods("DELETE")
	v2.Handle("/{name:.+}/blobs/uploads/", write(h.startUpload)).Methods("POST")
	v2.Handle("/{name:.+}/blobs/uploads/{uuid}", write(h.patchUpload)).Methods("PATCH")
	v2.Handle("/{name:.+}/blobs/uploads/{uuid}", write(h.putUpload)).Methods("PUT")
	v2.Handle("/{name:.+}/blobs/uploads/{uuid}", write(h.deleteUpload)).Methods("DELETE")
	v2.Handle("/{name:.+}/blobs/{digest}", read(h.headBlob)).Methods("HEAD")
	v2.Handle("/{name:.+}/blobs/{digest}", read(h.getBlob)).Methods("GET")
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- not an HTML sink. putManifest constrains the stored
	// media type to the manifest types in manifestMediaTypes, all of which
	// are +json, and nosniff stops a browser second-guessing that.
	_, _ = w.Write(body)
}

// defaultManifestMediaType is assumed when a push omits Content-Type, as the
// distribution spec permits.
const defaultManifestMediaType = "application/vnd.oci.image.manifest.v1+json"

// manifestMediaTypes is the set of Content-Type values a manifest push may
// declare: the OCI image manifest and index, plus the Docker v2 schema
// manifest and manifest list that registries are still expected to accept.
// Anything else is rejected — the value is stored and replayed as the
// Content-Type of the corresponding pull, so it must never be able to name a
// type a browser will parse as markup.
var manifestMediaTypes = map[string]bool{
	"application/vnd.oci.image.manifest.v1+json":                true,
	"application/vnd.oci.image.index.v1+json":                   true,
	"application/vnd.docker.distribution.manifest.v2+json":      true,
	"application/vnd.docker.distribution.manifest.list.v2+json": true,
}

// isManifestMediaType reports whether mediaType is an accepted manifest
// media type. Parameters (charset, and so on) are ignored, and the type is
// matched case-insensitively, per RFC 9110.
func isManifestMediaType(mediaType string) bool {
	base, _, _ := strings.Cut(mediaType, ";")
	return manifestMediaTypes[strings.ToLower(strings.TrimSpace(base))]
}

func (h *OCIDistHandlers) putManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	body, err := readBounded(w, r, h.limits.MaxManifestBytes)
	if err != nil {
		writeBodyError(w, err, "MANIFEST_INVALID")
		return
	}
	mediaType := r.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = defaultManifestMediaType
	}
	// The stored media type is echoed verbatim as the Content-Type of the
	// GET that fetches this manifest back. Accepting the client's header
	// unchecked therefore let a push of `Content-Type: text/html` with a
	// markup body turn a later pull into stored XSS against anything that
	// renders registry responses in a browser. Constrain it to the manifest
	// media types the distribution spec defines.
	if !isManifestMediaType(mediaType) {
		writeOCIError(w, http.StatusBadRequest, "MANIFEST_INVALID",
			"unsupported manifest media type: "+mediaType)
		return
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- not an HTML sink. A blob is served as
	// application/octet-stream with nosniff, and the path that reaches it is
	// keyed by content digest, so the bytes are whatever the digest names.
	_, _ = w.Write(data)
}

func (h *OCIDistHandlers) startUpload(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	h.evictIdle()

	// Spec § monolithic upload: clients may send the entire blob in
	// the POST body along with ?digest= to commit immediately. It never
	// touches the session table, so it is bounded by the blob cap alone.
	if digest := r.URL.Query().Get("digest"); digest != "" {
		body, err := readBounded(w, r, h.limits.MaxBlobBytes)
		if err != nil {
			writeBodyError(w, err, "BLOB_UPLOAD_INVALID")
			return
		}
		if err := h.commitBlob(r.Context(), digest, body); err != nil {
			writeOCIError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	id, err := newUploadID()
	if err != nil {
		writeOCIError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	h.uploads.Store(id, &uploadSession{name: name, lastActive: h.now()})

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (h *OCIDistHandlers) patchUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, ok := h.lookupUpload(vars["uuid"])
	if !ok {
		writeOCIError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload")
		return
	}
	body, err := readBounded(w, r, h.limits.MaxChunkBytes)
	if err != nil {
		writeBodyError(w, err, "BLOB_UPLOAD_INVALID")
		return
	}
	bufferedLen, err := h.appendChunk(vars["uuid"], sess, body)
	if err != nil {
		writeBodyError(w, err, "BLOB_UPLOAD_INVALID")
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", sess.name, vars["uuid"]))
	w.Header().Set("Range", fmt.Sprintf("0-%d", bufferedLen-1))
	w.Header().Set("Docker-Upload-UUID", vars["uuid"])
	w.WriteHeader(http.StatusAccepted)
}

func (h *OCIDistHandlers) putUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, ok := h.lookupUpload(vars["uuid"])
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
	// the tail into the commit call). ContentLength is -1 on a chunked
	// request, so the body is read unless it is known to be empty, and
	// appended only when it carried bytes.
	if r.ContentLength != 0 {
		tail, err := readBounded(w, r, h.limits.MaxChunkBytes)
		if err != nil {
			writeBodyError(w, err, "BLOB_UPLOAD_INVALID")
			return
		}
		if len(tail) > 0 {
			if _, err := h.appendChunk(vars["uuid"], sess, tail); err != nil {
				writeBodyError(w, err, "BLOB_UPLOAD_INVALID")
				return
			}
		}
	}
	// The commit consumes the session either way: the buffer moves out
	// (no second copy of a multi-GiB layer) and its bytes are released,
	// and a client whose digest did not match starts over rather than
	// keeping a rejected buffer pinned.
	buf := h.releaseSession(vars["uuid"], sess)
	if err := h.commitBlob(r.Context(), digest, buf); err != nil {
		writeOCIError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
		return
	}
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

// deleteUpload cancels an in-progress upload (spec § cancelling an
// upload), releasing its bytes.
func (h *OCIDistHandlers) deleteUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, ok := h.lookupUpload(vars["uuid"])
	if !ok {
		writeOCIError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload")
		return
	}
	h.releaseSession(vars["uuid"], sess)
	w.WriteHeader(http.StatusNoContent)
}

// lookupUpload returns the in-progress upload bound to uuid, or
// ok=false if none exists.
func (h *OCIDistHandlers) lookupUpload(uuid string) (*uploadSession, bool) {
	v, ok := h.uploads.Load(uuid)
	if !ok {
		return nil, false
	}
	sess, ok := v.(*uploadSession)
	return sess, ok
}

// appendChunk adds chunk to the session under the per-blob and in-flight
// caps and returns the buffered length. A session released between the
// caller's lookup and this call (a concurrent commit, cancel or eviction)
// is refused as unknown, so no byte is ever counted against an orphan. A chunk that would push the
// session past MaxBlobBytes releases the session — the client cannot
// finish it, so holding its bytes only serves an attacker. A chunk that
// would push the whole table past MaxInFlightBytes is refused without
// touching the session, so the client may retry once room frees.
func (h *OCIDistHandlers) appendChunk(uuid string, sess *uploadSession, chunk []byte) (int, error) {
	n := int64(len(chunk))
	sess.mu.Lock()
	if sess.released {
		sess.mu.Unlock()
		return 0, &ErrUploadUnknown{}
	}
	if int64(len(sess.buffer))+n > h.limits.MaxBlobBytes {
		sess.mu.Unlock()
		h.releaseSession(uuid, sess)
		return 0, &ErrUploadTooLarge{Limit: h.limits.MaxBlobBytes}
	}
	if h.inFlight.Add(n) > h.limits.MaxInFlightBytes {
		h.inFlight.Add(-n)
		sess.mu.Unlock()
		return 0, &ErrUploadsSaturated{Limit: h.limits.MaxInFlightBytes}
	}
	sess.buffer = append(sess.buffer, chunk...)
	sess.lastActive = h.now()
	buffered := len(sess.buffer)
	sess.mu.Unlock()
	return buffered, nil
}

// releaseSession removes the session from the table, returns its buffer
// to the caller and releases the bytes it held from the in-flight total.
// It is idempotent: a session released twice contributes nothing twice.
func (h *OCIDistHandlers) releaseSession(uuid string, sess *uploadSession) []byte {
	if _, loaded := h.uploads.LoadAndDelete(uuid); !loaded {
		return nil
	}
	sess.mu.Lock()
	sess.released = true
	buf := sess.buffer
	sess.buffer = nil
	sess.mu.Unlock()
	h.inFlight.Add(-int64(len(buf)))
	return buf
}

// evictIdle releases every session that has seen no chunk within
// SessionIdle and reports how many it removed. It runs on each upload
// start so a table that only ever receives abandoned sessions still
// shrinks, and the in-flight cap bounds the heap between sweeps.
func (h *OCIDistHandlers) evictIdle() int {
	cutoff := h.now().Add(-h.limits.SessionIdle)
	evicted := 0
	h.uploads.Range(func(key, value any) bool {
		sess, ok := value.(*uploadSession)
		if !ok {
			return true
		}
		sess.mu.Lock()
		idle := sess.lastActive.Before(cutoff)
		sess.mu.Unlock()
		if idle {
			h.releaseSession(key.(string), sess)
			evicted++
		}
		return true
	})
	return evicted
}

// ErrUploadTooLarge is returned when a body or a session exceeds its cap.
type ErrUploadTooLarge struct {
	Limit int64
}

// Error implements the error interface.
func (e *ErrUploadTooLarge) Error() string {
	return fmt.Sprintf("upload exceeds the %d byte limit", e.Limit)
}

// ErrUploadUnknown is returned when a chunk arrives for a session that was
// released between lookup and append.
type ErrUploadUnknown struct{}

// Error implements the error interface.
func (e *ErrUploadUnknown) Error() string {
	return "no such upload"
}

// ErrUploadsSaturated is returned when the in-flight total is at its cap.
type ErrUploadsSaturated struct {
	Limit int64
}

// Error implements the error interface.
func (e *ErrUploadsSaturated) Error() string {
	return fmt.Sprintf("uploads in flight exceed the %d byte limit; retry later", e.Limit)
}

// readBounded reads at most limit bytes of the request body, reporting
// an ErrUploadTooLarge when the body is longer.
func readBounded(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &ErrUploadTooLarge{Limit: limit}
		}
		return nil, err
	}
	return body, nil
}

// writeBodyError maps a body-read or buffering failure to the spec's
// error envelope: 404 for a released session, 413 for a cap, 429 for
// saturation, 400 otherwise.
func writeBodyError(w http.ResponseWriter, err error, code string) {
	var tooLarge *ErrUploadTooLarge
	var saturated *ErrUploadsSaturated
	var unknown *ErrUploadUnknown
	switch {
	case errors.As(err, &unknown):
		writeOCIError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", err.Error())
	case errors.As(err, &tooLarge):
		writeOCIError(w, http.StatusRequestEntityTooLarge, code, err.Error())
	case errors.As(err, &saturated):
		writeOCIError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS", err.Error())
	default:
		writeOCIError(w, http.StatusBadRequest, code, err.Error())
	}
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
