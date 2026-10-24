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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// errBackendDown stands in for any registry failure the handlers do not
// map to a specific status.
var errBackendDown = errors.New("registry backend down")

// fakeRegistryService records the request each handler sends and answers
// with the canned response or error set by the test.
type fakeRegistryService struct {
	listReq    *grpcapi.RegistryListRequest
	listResp   *grpcapi.RegistryListResponse
	listErr    error
	inspectReq *grpcapi.RegistryInspectRequest
	inspect    *grpcapi.RegistryInspectResponse
	inspectErr error
	pullReq    *grpcapi.RegistryPullRequest
	pull       *grpcapi.RegistryPullResponse
	pullErr    error
	pushMeta   *grpcapi.RegistryPushMetadata
	pushBody   []byte
	push       *grpcapi.RegistryPushResponse
	pushErr    error
	deleteReq  *grpcapi.RegistryDeleteRequest
	deleteResp *grpcapi.RegistryDeleteResponse
	deleteErr  error
	status     *grpcapi.RegistryStatusResponse
	statusErr  error
}

func (f *fakeRegistryService) Push(context.Context, *grpcapi.RegistryPushRequest) (*grpcapi.RegistryPushResponse, error) {
	return nil, grpcapi.ErrRegistryOperationFailed{Operation: "push", Reason: "not used by the REST handlers"}
}

func (f *fakeRegistryService) PushStream(_ context.Context, meta *grpcapi.RegistryPushMetadata, r io.Reader) (*grpcapi.RegistryPushResponse, error) {
	f.pushMeta = meta
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	f.pushBody = body
	return f.push, f.pushErr
}

func (f *fakeRegistryService) Pull(_ context.Context, req *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullResponse, error) {
	f.pullReq = req
	return f.pull, f.pullErr
}

func (f *fakeRegistryService) PullStream(context.Context, *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullStreamResponse, error) {
	return nil, grpcapi.ErrRegistryOperationFailed{Operation: "pull-stream", Reason: "not used by the REST handlers"}
}

func (f *fakeRegistryService) List(_ context.Context, req *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	f.listReq = req
	return f.listResp, f.listErr
}

func (f *fakeRegistryService) Inspect(_ context.Context, req *grpcapi.RegistryInspectRequest) (*grpcapi.RegistryInspectResponse, error) {
	f.inspectReq = req
	return f.inspect, f.inspectErr
}

func (f *fakeRegistryService) Delete(_ context.Context, req *grpcapi.RegistryDeleteRequest) (*grpcapi.RegistryDeleteResponse, error) {
	f.deleteReq = req
	return f.deleteResp, f.deleteErr
}

func (f *fakeRegistryService) Status(context.Context) (*grpcapi.RegistryStatusResponse, error) {
	return f.status, f.statusErr
}

// envelope is the JSON shape response.HttpWriter writes.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// newImagesRouter mounts the image routes the way the daemon does, with
// the real response writer, so status codes and envelopes are the ones
// clients see. A nil service is passed through as an untyped nil so the
// handlers see the "not configured" case.
func newImagesRouter(svc *fakeRegistryService) *mux.Router {
	logger := logging.DefaultLogger()
	var service grpcapi.RegistryService
	if svc != nil {
		service = svc
	}
	root := mux.NewRouter()
	NewRouter(logger, service, response.NewResponseWriter(logger, nil)).RegisterRoutes(root)
	return root
}

func serve(t *testing.T, router http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return env
}

func TestImageRoutes_NilServiceIsNotConfigured(t *testing.T) {
	router := newImagesRouter(nil)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/compute/images"},
		{http.MethodGet, "/compute/images/"},
		{http.MethodPost, "/compute/images"},
		{http.MethodPost, "/compute/images/"},
		{http.MethodGet, "/compute/images/status"},
		{http.MethodGet, "/compute/images/alpine:3.20"},
		{http.MethodDelete, "/compute/images/alpine:3.20"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := serve(t, router, httptest.NewRequest(tc.method, tc.path, strings.NewReader("x")))
			require.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.Equal(t, ErrRegistryNotConfigured{}.Error(), decodeEnvelope(t, rec).Error)
		})
	}
}

func TestImageRoutes_UnknownMethodIsNotRouted(t *testing.T) {
	svc := &fakeRegistryService{}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodPut, "/compute/images/alpine", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Nil(t, svc.inspectReq)
	assert.Nil(t, svc.deleteReq)
}

func TestListImages_PassesQueryAndSummarisesArtifacts(t *testing.T) {
	created := time.Date(2026, 3, 1, 12, 0, 0, 0, time.FixedZone("EST", -5*3600))
	svc := &fakeRegistryService{listResp: &grpcapi.RegistryListResponse{
		Total: 7,
		Artifacts: []*grpcapi.RegistryArtifact{{
			Repository: "library/alpine",
			Tag:        "3.20",
			Size:       4096,
			CreatedAt:  created,
			Manifest: &grpcapi.RegistryArtifactManifest{
				Digest:    "sha256:abc",
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Layers:    []*grpcapi.RegistryArtifactLayer{{}, {}},
			},
		}},
	}}
	rec := serve(t, newImagesRouter(svc),
		httptest.NewRequest(http.MethodGet, "/compute/images?repository=library/alpine&limit=5&offset=10", nil))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, &grpcapi.RegistryListRequest{Repository: "library/alpine", Limit: 5, Offset: 10}, svc.listReq)
	env := decodeEnvelope(t, rec)
	require.True(t, env.Success)
	var out ListImagesResponse
	require.NoError(t, json.Unmarshal(env.Payload, &out))
	assert.Equal(t, ListImagesResponse{
		Total: 7,
		Images: []ImageSummary{{
			Repository: "library/alpine",
			Tag:        "3.20",
			Digest:     "sha256:abc",
			MediaType:  "application/vnd.oci.image.manifest.v1+json",
			Size:       4096,
			Layers:     2,
			CreatedAt:  "2026-03-01T17:00:00Z",
		}},
	}, out)
}

func TestListImages_DefaultsPagingAndReturnsEmptyList(t *testing.T) {
	svc := &fakeRegistryService{listResp: &grpcapi.RegistryListResponse{}}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodGet, "/compute/images/?limit=lots", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, &grpcapi.RegistryListRequest{Limit: 200, Offset: 0}, svc.listReq)
	// An empty registry must serialise as [] rather than null, so
	// clients can range over images without a nil check.
	assert.JSONEq(t, `{"images":[],"total":0}`, string(decodeEnvelope(t, rec).Payload))
}

func TestListImages_ServiceErrorIs500(t *testing.T) {
	svc := &fakeRegistryService{listErr: errBackendDown}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodGet, "/compute/images", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, errBackendDown.Error(), decodeEnvelope(t, rec).Error)
}

func TestGetImage_InspectReturnsDetail(t *testing.T) {
	svc := &fakeRegistryService{inspect: &grpcapi.RegistryInspectResponse{Detail: &grpcapi.RegistryArtifactDetail{
		Tags: []string{"3.20", "latest"},
	}}}
	rec := serve(t, newImagesRouter(svc),
		httptest.NewRequest(http.MethodGet, "/compute/images/registry.example:5000/library/alpine:3.20", nil))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, &grpcapi.RegistryInspectRequest{Repository: "registry.example:5000/library/alpine", Reference: "3.20"}, svc.inspectReq)
	assert.Nil(t, svc.pullReq)
	var detail grpcapi.RegistryArtifactDetail
	require.NoError(t, json.Unmarshal(decodeEnvelope(t, rec).Payload, &detail))
	assert.Equal(t, []string{"3.20", "latest"}, detail.Tags)
}

func TestGetImage_StatusRouteIsNotAnImage(t *testing.T) {
	svc := &fakeRegistryService{status: &grpcapi.RegistryStatusResponse{Version: "1.2.3", ReadOnly: true}}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodGet, "/compute/images/status", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, svc.inspectReq, "/status must reach Status, not GetImage")
	var status grpcapi.RegistryStatusResponse
	require.NoError(t, json.Unmarshal(decodeEnvelope(t, rec).Payload, &status))
	assert.Equal(t, "1.2.3", status.Version)
	assert.True(t, status.ReadOnly)
}

func TestStatus_ServiceErrorIs500(t *testing.T) {
	svc := &fakeRegistryService{statusErr: errBackendDown}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodGet, "/compute/images/status", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, errBackendDown.Error(), decodeEnvelope(t, rec).Error)
}

func TestGetImage_PullEnvelopeStreamsRawBytes(t *testing.T) {
	svc := &fakeRegistryService{pull: &grpcapi.RegistryPullResponse{Data: []byte(`{"manifest":{}}`)}}
	req := httptest.NewRequest(http.MethodGet, "/compute/images/alpine", nil)
	req.Header.Set("Accept", "application/json, "+contentTypePullEnvelope+"; q=0.9")
	rec := serve(t, newImagesRouter(svc), req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, contentTypePullEnvelope, rec.Header().Get("Content-Type"))
	assert.Equal(t, `{"manifest":{}}`, rec.Body.String())
	assert.Equal(t, &grpcapi.RegistryPullRequest{Repository: "alpine"}, svc.pullReq)
	assert.Nil(t, svc.inspectReq)
}

func TestGetImage_Errors(t *testing.T) {
	notFound := grpcapi.ErrArtifactNotFound{Repository: "alpine", Reference: "9"}
	cases := []struct {
		name     string
		path     string
		pull     bool
		svc      *fakeRegistryService
		wantCode int
		wantErr  string
	}{
		{"empty repository", "/compute/images/:9", false, &fakeRegistryService{}, http.StatusBadRequest, ErrInvalidImageReference{}.Error()},
		{"inspect not found", "/compute/images/alpine:9", false, &fakeRegistryService{inspectErr: notFound}, http.StatusNotFound, notFound.Error()},
		{"inspect failure", "/compute/images/alpine:9", false, &fakeRegistryService{inspectErr: errBackendDown}, http.StatusInternalServerError, errBackendDown.Error()},
		{"pull not found", "/compute/images/alpine:9", true, &fakeRegistryService{pullErr: notFound}, http.StatusNotFound, notFound.Error()},
		{"pull failure", "/compute/images/alpine:9", true, &fakeRegistryService{pullErr: errBackendDown}, http.StatusInternalServerError, errBackendDown.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.pull {
				req.Header.Set("Accept", contentTypePullEnvelope)
			}
			rec := serve(t, newImagesRouter(tc.svc), req)
			require.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantErr, decodeEnvelope(t, rec).Error)
		})
	}
}

func TestPushImage_HeadersBuildMetadata(t *testing.T) {
	svc := &fakeRegistryService{push: &grpcapi.RegistryPushResponse{BytesReceived: 5}}
	req := httptest.NewRequest(http.MethodPost, "/compute/images?repository=ignored&tag=ignored", strings.NewReader("image"))
	req.Header.Set("X-Trusted-Platform-Repository", "library/alpine")
	req.Header.Set("X-Trusted-Platform-Tag", "3.20")
	req.Header.Set("X-Trusted-Platform-Encrypt", "true")
	req.Header.Set("X-Trusted-Platform-Overwrite", "true")
	rec := serve(t, newImagesRouter(svc), req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, &grpcapi.RegistryPushMetadata{
		Repository:  "library/alpine",
		Tag:         "3.20",
		Annotations: map[string]string{"encrypt": "true", regsvc.AnnotationOverwrite: "true"},
	}, svc.pushMeta)
	assert.Equal(t, "image", string(svc.pushBody))
	var out grpcapi.RegistryPushResponse
	require.NoError(t, json.Unmarshal(decodeEnvelope(t, rec).Payload, &out))
	assert.Equal(t, int64(5), out.BytesReceived)
}

func TestPushImage_QueryFallbackDefaultsTagToLatest(t *testing.T) {
	svc := &fakeRegistryService{push: &grpcapi.RegistryPushResponse{}}
	req := httptest.NewRequest(http.MethodPost, "/compute/images/?repository=busybox", strings.NewReader("image"))
	req.Header.Set("X-Trusted-Platform-Encrypt", "yes")
	rec := serve(t, newImagesRouter(svc), req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// Only the literal "true" opts in to encryption or overwrite.
	assert.Equal(t, &grpcapi.RegistryPushMetadata{
		Repository:  "busybox",
		Tag:         "latest",
		Annotations: map[string]string{},
	}, svc.pushMeta)
}

func TestPushImage_Errors(t *testing.T) {
	errRead := errors.New("client hung up")
	exists := grpcapi.ErrArtifactAlreadyExists{Repository: "busybox", Reference: "latest"}
	cases := []struct {
		name     string
		body     io.Reader
		repo     string
		svc      *fakeRegistryService
		wantCode int
		wantErr  string
	}{
		{"unreadable body", iotest.ErrReader(errRead), "busybox", &fakeRegistryService{}, http.StatusBadRequest, errRead.Error()},
		{"empty body", strings.NewReader(""), "busybox", &fakeRegistryService{}, http.StatusBadRequest, ErrEmptyPushBody{}.Error()},
		{"missing repository", strings.NewReader("image"), "", &fakeRegistryService{}, http.StatusBadRequest, ErrMissingRepositoryHeader{}.Error()},
		{"already exists", strings.NewReader("image"), "busybox", &fakeRegistryService{pushErr: exists}, http.StatusBadRequest, exists.Error()},
		{"push failure", strings.NewReader("image"), "busybox", &fakeRegistryService{pushErr: errBackendDown}, http.StatusInternalServerError, errBackendDown.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/compute/images", tc.body)
			if tc.repo != "" {
				req.Header.Set("X-Trusted-Platform-Repository", tc.repo)
			}
			rec := serve(t, newImagesRouter(tc.svc), req)
			require.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantErr, decodeEnvelope(t, rec).Error)
		})
	}
}

func TestDeleteImage_RemovesReference(t *testing.T) {
	svc := &fakeRegistryService{deleteResp: &grpcapi.RegistryDeleteResponse{Digest: "sha256:abc", BytesFreed: 42}}
	rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodDelete, "/compute/images/library/alpine:3.20", nil))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, &grpcapi.RegistryDeleteRequest{Repository: "library/alpine", Reference: "3.20"}, svc.deleteReq)
	var out grpcapi.RegistryDeleteResponse
	require.NoError(t, json.Unmarshal(decodeEnvelope(t, rec).Payload, &out))
	assert.Equal(t, "sha256:abc", out.Digest)
	assert.Equal(t, int64(42), out.BytesFreed)
}

func TestDeleteImage_Errors(t *testing.T) {
	notFound := grpcapi.ErrArtifactNotFound{Repository: "alpine", Reference: "9"}
	cases := []struct {
		name     string
		path     string
		svc      *fakeRegistryService
		wantCode int
		wantErr  string
	}{
		{"empty repository", "/compute/images/:9", &fakeRegistryService{}, http.StatusBadRequest, ErrInvalidImageReference{}.Error()},
		{"not found", "/compute/images/alpine:9", &fakeRegistryService{deleteErr: notFound}, http.StatusNotFound, notFound.Error()},
		{"delete failure", "/compute/images/alpine:9", &fakeRegistryService{deleteErr: errBackendDown}, http.StatusInternalServerError, errBackendDown.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, newImagesRouter(tc.svc), httptest.NewRequest(http.MethodDelete, tc.path, nil))
			require.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantErr, decodeEnvelope(t, rec).Error)
		})
	}
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in       string
		wantRepo string
		wantTag  string
		wantOK   bool
	}{
		{"alpine", "alpine", "", true},
		{"alpine:3.20", "alpine", "3.20", true},
		{"/library/alpine:3.20", "library/alpine", "3.20", true},
		{"registry.example:5000/library/alpine", "registry.example:5000/library/alpine", "", true},
		{"registry.example:5000/library/alpine:3.20", "registry.example:5000/library/alpine", "3.20", true},
		{"alpine:", "alpine", "", true},
		{"", "", "", false},
		{"/", "", "", false},
		{":3.20", "", "3.20", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			repo, tag, ok := parseRef(tc.in)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantRepo, repo)
			assert.Equal(t, tc.wantTag, tag)
		})
	}
}

func TestParseInt32(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 200},
		{"25", 25},
		{"-1", -1},
		{"2147483647", 2147483647},
		{"abc", 200},
		{"1.5", 200},
		// Out-of-range values fall back to the default rather than
		// wrapping: 2147483648 must not become -2147483648.
		{"2147483648", 200},
		{"4294967297", 200},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, parseInt32(tc.in, 200))
		})
	}
}

func TestWantsPullEnvelope(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"application/json", false},
		{contentTypePullEnvelope, true},
		{"  " + contentTypePullEnvelope + "  ", true},
		{contentTypePullEnvelope + ";version=1", true},
		{"text/html, " + contentTypePullEnvelope + "; q=0.5", true},
		{contentTypePullEnvelope + "+json", false},
	}
	for _, tc := range cases {
		t.Run(tc.accept, func(t *testing.T) {
			assert.Equal(t, tc.want, wantsPullEnvelope(tc.accept))
		})
	}
}

func TestArtifactToSummary(t *testing.T) {
	updated := time.Date(2026, 4, 2, 8, 30, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   *grpcapi.RegistryArtifact
		want ImageSummary
	}{
		{
			name: "no manifest, no timestamps",
			in:   &grpcapi.RegistryArtifact{Repository: "busybox", Tag: "latest", Size: 9},
			want: ImageSummary{Repository: "busybox", Tag: "latest", Size: 9},
		},
		{
			name: "artifact digest wins over manifest digest",
			in: &grpcapi.RegistryArtifact{
				Repository:  "busybox",
				Digest:      "sha256:artifact",
				Annotations: map[string]string{"encrypt": "true"},
				UpdatedAt:   updated,
				Manifest:    &grpcapi.RegistryArtifactManifest{Digest: "sha256:manifest", MediaType: "m"},
			},
			want: ImageSummary{
				Repository:  "busybox",
				Digest:      "sha256:artifact",
				MediaType:   "m",
				Annotations: map[string]string{"encrypt": "true"},
				UpdatedAt:   "2026-04-02T08:30:00Z",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, artifactToSummary(tc.in))
		})
	}
}
