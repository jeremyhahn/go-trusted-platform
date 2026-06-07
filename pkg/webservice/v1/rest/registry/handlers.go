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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// Handlers is the REST surface bound to a RegistryService.
type Handlers struct {
	logger     *logging.Logger
	service    grpcapi.RegistryService
	respWriter response.HttpWriter
}

// NewHandlers constructs a Handlers value. service may be nil — every
// handler nil-checks and returns 503 in that case.
func NewHandlers(logger *logging.Logger, service grpcapi.RegistryService, respWriter response.HttpWriter) *Handlers {
	return &Handlers{logger: logger, service: service, respWriter: respWriter}
}

// ImageSummary is the wire-shape returned by ListImages. It is
// deliberately flatter than the proto RegistryArtifact: the WebUI
// needs repository / tag / digest / size / pushed_at, not the full
// layered manifest. Inspect returns the richer shape when the user
// drills into a specific image.
type ImageSummary struct {
	Repository  string            `json:"repository"`
	Tag         string            `json:"tag"`
	Digest      string            `json:"digest,omitempty"`
	MediaType   string            `json:"media_type,omitempty"`
	Size        int64             `json:"size"`
	Layers      int               `json:"layers"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
}

// ListImagesResponse is the body returned by GET /compute/images.
type ListImagesResponse struct {
	Images []ImageSummary `json:"images"`
	Total  int            `json:"total"`
}

// ListImages handles GET /api/v1/compute/images. Optional query
// params: repository, limit, offset.
func (h *Handlers) ListImages(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.respWriter.Error500(w, r, ErrRegistryNotConfigured{})
		return
	}
	q := r.URL.Query()
	req := &grpcapi.RegistryListRequest{
		Repository: q.Get("repository"),
		Limit:      parseInt32(q.Get("limit"), 200),
		Offset:     parseInt32(q.Get("offset"), 0),
	}
	resp, err := h.service.List(r.Context(), req)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	out := ListImagesResponse{
		Images: make([]ImageSummary, 0, len(resp.Artifacts)),
		Total:  int(resp.Total),
	}
	for _, a := range resp.Artifacts {
		out.Images = append(out.Images, artifactToSummary(a))
	}
	h.respWriter.Success200(w, r, out)
}

// GetImage handles GET /api/v1/compute/images/{repository...}. The
// response shape is driven by the Accept header: JSON (default)
// returns the inspect envelope used by the WebUI; the platform
// pull-envelope content type returns the raw manifest+layers JSON
// so platformctl can stream the image bytes back.
func (h *Handlers) GetImage(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.respWriter.Error500(w, r, ErrRegistryNotConfigured{})
		return
	}
	repo, tag, ok := parseRef(mux.Vars(r)["repository"])
	if !ok {
		h.respWriter.Error400(w, r, ErrInvalidImageReference{})
		return
	}
	accept := r.Header.Get("Accept")
	if wantsPullEnvelope(accept) {
		pullResp, err := h.service.Pull(r.Context(), &grpcapi.RegistryPullRequest{
			Repository: repo,
			Reference:  tag,
		})
		if err != nil {
			var nf grpcapi.ErrArtifactNotFound
			if errors.As(err, &nf) {
				h.respWriter.Error404(w, r, err)
				return
			}
			h.respWriter.Error500(w, r, err)
			return
		}
		w.Header().Set("Content-Type", contentTypePullEnvelope)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pullResp.Data)
		return
	}
	resp, err := h.service.Inspect(r.Context(), &grpcapi.RegistryInspectRequest{
		Repository: repo,
		Reference:  tag,
	})
	if err != nil {
		var nf grpcapi.ErrArtifactNotFound
		if errors.As(err, &nf) {
			h.respWriter.Error404(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, resp.Detail)
}

// PushImage handles POST /api/v1/compute/images. The request body is
// the same JSON envelope of *registry.Image that gRPC PushStream
// consumes — manifest + base64 layers — under the platform's
// content-type. JSON metadata travels in the Trusted-Platform headers
// so the multipart-streaming complexity an OCI distribution-spec
// client expects can land separately under /v2/.
//
// Required headers:
//
//	X-Trusted-Platform-Repository: repo name
//	X-Trusted-Platform-Tag:        tag (optional; default "latest")
//	X-Trusted-Platform-Encrypt:    "true" to encrypt-on-push
//	X-Trusted-Platform-Overwrite:  "true" to allow overwrite
//
// The body is application/x-trusted-platform-image (JSON envelope).
func (h *Handlers) PushImage(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.respWriter.Error500(w, r, ErrRegistryNotConfigured{})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if len(body) == 0 {
		h.respWriter.Error400(w, r, ErrEmptyPushBody{})
		return
	}
	repo := r.Header.Get("X-Trusted-Platform-Repository")
	tag := r.Header.Get("X-Trusted-Platform-Tag")
	if repo == "" {
		// Fall back to URL query for convenience curl usage.
		repo = r.URL.Query().Get("repository")
		tag = r.URL.Query().Get("tag")
	}
	if repo == "" {
		h.respWriter.Error400(w, r, ErrMissingRepositoryHeader{})
		return
	}
	if tag == "" {
		tag = "latest"
	}
	annotations := map[string]string{}
	if r.Header.Get("X-Trusted-Platform-Encrypt") == "true" {
		annotations["encrypt"] = "true"
	}
	if r.Header.Get("X-Trusted-Platform-Overwrite") == "true" {
		annotations["overwrite"] = "true"
	}
	resp, err := h.service.PushStream(
		r.Context(),
		&grpcapi.RegistryPushMetadata{
			Repository:  repo,
			Tag:         tag,
			Annotations: annotations,
		},
		strings.NewReader(string(body)),
	)
	if err != nil {
		var exists grpcapi.ErrArtifactAlreadyExists
		if errors.As(err, &exists) {
			h.respWriter.Error400(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, resp)
}

// PullPayload is the WebUI / platformctl-facing shape of a pull
// response. The Layers slice carries base64-encoded layer content so
// the wire payload remains a single JSON document.
type PullPayload struct {
	Manifest   json.RawMessage `json:"manifest"`
	ConfigB64  string          `json:"config_b64,omitempty"`
	LayersB64  []string        `json:"layers_b64"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func wantsPullEnvelope(accept string) bool {
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		mt := strings.TrimSpace(part)
		if i := strings.Index(mt, ";"); i >= 0 {
			mt = mt[:i]
		}
		if mt == contentTypePullEnvelope {
			return true
		}
	}
	return false
}

// contentTypePullEnvelope identifies the JSON envelope that wraps the
// full manifest + layer bytes for pull. Using a custom media type
// keeps it out of the way of the OCI distribution-spec types served
// at /v2/.
const contentTypePullEnvelope = "application/x-trusted-platform-image"

// ErrEmptyPushBody is returned when a POST arrives with no body.
type ErrEmptyPushBody struct{}

func (ErrEmptyPushBody) Error() string {
	return "registry: push body cannot be empty"
}

// ErrMissingRepositoryHeader is returned when POST is invoked without
// X-Trusted-Platform-Repository.
type ErrMissingRepositoryHeader struct{}

func (ErrMissingRepositoryHeader) Error() string {
	return "registry: X-Trusted-Platform-Repository header (or ?repository=) is required"
}

// DeleteImage handles DELETE /api/v1/compute/images/{repository...}.
func (h *Handlers) DeleteImage(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.respWriter.Error500(w, r, ErrRegistryNotConfigured{})
		return
	}
	repo, tag, ok := parseRef(mux.Vars(r)["repository"])
	if !ok {
		h.respWriter.Error400(w, r, ErrInvalidImageReference{})
		return
	}
	resp, err := h.service.Delete(r.Context(), &grpcapi.RegistryDeleteRequest{
		Repository: repo,
		Reference:  tag,
	})
	if err != nil {
		var nf grpcapi.ErrArtifactNotFound
		if errors.As(err, &nf) {
			h.respWriter.Error404(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, resp)
}

// Status handles GET /api/v1/compute/images/status. Returns a
// summary used by the WebUI's registry-health widget.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.respWriter.Error500(w, r, ErrRegistryNotConfigured{})
		return
	}
	resp, err := h.service.Status(r.Context())
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, resp)
}

func parseInt32(s string, def int32) int32 {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return int32(n)
}

// parseRef splits "repo[:tag]" into its components. Returns ok=false
// when repo is empty after stripping.
func parseRef(p string) (string, string, bool) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", "", false
	}
	// Tag separator is the LAST colon — OCI references can include
	// port numbers (e.g. registry.example:5000/foo/bar:latest).
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == ':' {
			repo := p[:i]
			tag := p[i+1:]
			// A colon embedded in a port (no slash after it) shouldn't
			// be treated as a tag separator. We detect this by
			// checking that the suffix contains a slash.
			if strings.Contains(tag, "/") {
				return p, "", true
			}
			return repo, tag, repo != ""
		}
	}
	return p, "", true
}

func artifactToSummary(a *grpcapi.RegistryArtifact) ImageSummary {
	s := ImageSummary{
		Repository:  a.Repository,
		Tag:         a.Tag,
		Digest:      a.Digest,
		Size:        a.Size,
		Annotations: a.Annotations,
	}
	if a.Manifest != nil {
		s.MediaType = a.Manifest.MediaType
		s.Layers = len(a.Manifest.Layers)
		if a.Digest == "" {
			s.Digest = a.Manifest.Digest
		}
	}
	if !a.CreatedAt.IsZero() {
		s.CreatedAt = a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if !a.UpdatedAt.IsZero() {
		s.UpdatedAt = a.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return s
}

// ErrRegistryNotConfigured is returned when /compute/images endpoints
// are hit before the platform daemon has wired a RegistryService.
type ErrRegistryNotConfigured struct{}

func (ErrRegistryNotConfigured) Error() string {
	return "registry: image registry not configured on this daemon"
}

// ErrInvalidImageReference is returned when the path-based reference
// is missing or malformed.
type ErrInvalidImageReference struct{}

func (ErrInvalidImageReference) Error() string {
	return "registry: invalid image reference (expected repository[:tag])"
}
